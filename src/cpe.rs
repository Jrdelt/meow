//! CPE name handling: Nmap reports CPE 2.2 URIs (`cpe:/a:vendor:product:1.0`)
//! while the NVD API expects CPE 2.3 formatted strings
//! (`cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*`).

/// The fields of a CPE name that vulnerability lookups use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeParts {
    /// `a` (application), `o` (operating system) or `h` (hardware).
    pub part: char,
    pub vendor: String,
    pub product: String,
    /// `None` when the version is unknown (`*` or `-`).
    pub version: Option<String>,
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(value) = text
                .get(i + 1..i + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(value);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Encodes one decoded attribute value for a CPE 2.3 formatted string.
fn encode_23(value: &str) -> String {
    if value.is_empty() {
        return "*".to_owned();
    }
    if value == "-" {
        return "-".to_owned();
    }
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii() && !ch.is_ascii_control() && ch != ' ' {
            out.push('\\');
            out.push(ch);
        }
    }
    if out.is_empty() {
        "*".to_owned()
    } else {
        out
    }
}

/// Converts a CPE 2.2 URI to a CPE 2.3 formatted string. A value that is
/// already 2.3 is returned normalised to lower case. Returns `None` for
/// anything that is not a CPE name.
pub fn to_cpe23(cpe: &str) -> Option<String> {
    let cpe = cpe.trim();
    if let Some(rest) = strip_prefix_ci(cpe, "cpe:2.3:") {
        let fields = split_23(rest);
        if fields.len() != 11 || !matches!(fields[0].as_str(), "a" | "o" | "h" | "*") {
            return None;
        }
        return Some(format!("cpe:2.3:{}", rest.to_ascii_lowercase()));
    }
    let rest = strip_prefix_ci(cpe, "cpe:/")?;
    let mut fields: Vec<&str> = rest.split(':').collect();
    if fields.len() > 7 || fields[0].len() != 1 {
        return None;
    }
    let part = fields[0].to_ascii_lowercase();
    if !matches!(part.as_str(), "a" | "o" | "h") {
        return None;
    }
    fields.resize(7, "");
    if fields[1].is_empty() || fields[2].is_empty() {
        return None;
    }

    // 2.2 packs four extra attributes into the edition field as
    // `~edition~sw_edition~target_sw~target_hw~other`.
    let mut edition = fields[5].to_owned();
    let mut extended = [String::new(), String::new(), String::new(), String::new()];
    if let Some(packed) = fields[5].strip_prefix('~') {
        let mut parts = packed.split('~');
        edition = parts.next().unwrap_or("").to_owned();
        for slot in &mut extended {
            *slot = parts.next().unwrap_or("").to_owned();
        }
    }

    let mut out = format!("cpe:2.3:{part}");
    let ordered = [
        fields[1],
        fields[2],
        fields[3],
        fields[4],
        edition.as_str(),
        fields[6],
        extended[0].as_str(),
        extended[1].as_str(),
        extended[2].as_str(),
        extended[3].as_str(),
    ];
    for value in ordered {
        out.push(':');
        out.push_str(&encode_23(&percent_decode(value)));
    }
    Some(out)
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

/// Splits the attribute part of a 2.3 string on unescaped colons.
fn split_23(rest: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut chars = rest.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let field = fields.last_mut().expect("never empty");
                field.push(ch);
                field.extend(chars.next());
            }
            ':' => fields.push(String::new()),
            other => fields.last_mut().expect("never empty").push(other),
        }
    }
    fields
}

/// Extracts part, vendor, product and version from a 2.2 or 2.3 name.
pub fn parts(cpe: &str) -> Option<CpeParts> {
    let cpe23 = to_cpe23(cpe)?;
    let fields = split_23(cpe23.strip_prefix("cpe:2.3:")?);
    let plain = |field: &str| field.replace('\\', "");
    let version = Some(plain(&fields[3])).filter(|v| v != "*" && v != "-");
    Some(CpeParts {
        part: fields[0].chars().next()?,
        vendor: plain(&fields[1]),
        product: plain(&fields[2]),
        version,
    })
}

/// The numeric version inside a decorated one: `for_windows_9.5` is `9.5`,
/// and underscore-separated numeric segments (`openssl_1_1_1k`) become `1.1.1k`.
/// A version that already starts with a digit and has no underscore-separated
/// numeric segments, or holds no digits at all, is kept.
pub fn clean_version(version: &str) -> String {
    let starts_numeric = |text: &str| text.starts_with(|c: char| c.is_ascii_digit());
    let pieces: Vec<&str> = version.split('_').filter(|p| !p.is_empty()).collect();
    let Some(first_num) = pieces.iter().position(|piece| starts_numeric(piece)) else {
        return version.to_owned();
    };
    let tail = &pieces[first_num..];
    if tail.len() == 1 {
        return tail[0].to_owned();
    }
    if tail.iter().any(|piece| piece.contains('.')) {
        return tail.join("_");
    }
    tail.join(".")
}

/// The same CPE name with another version.
pub fn with_version(cpe: &str, version: &str) -> Option<String> {
    let cpe23 = to_cpe23(cpe)?;
    let mut fields = split_23(cpe23.strip_prefix("cpe:2.3:")?);
    fields[3] = encode_23(version);
    Some(format!("cpe:2.3:{}", fields.join(":")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_cpe_22_becomes_cpe_23() {
        for (old, new) in [
            (
                "cpe:/a:openbsd:openssh:8.2p1",
                "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*",
            ),
            (
                "cpe:/a:nginx:nginx:1.18.0",
                "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            ),
            (
                "cpe:/o:linux:linux_kernel",
                "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
            ),
            (
                "cpe:/o:microsoft:windows_server_2019::-",
                "cpe:2.3:o:microsoft:windows_server_2019:*:-:*:*:*:*:*:*",
            ),
            (
                "CPE:/A:Apache:HTTP_Server:2.4.41",
                "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
            ),
            (
                "cpe:/a:vendor:prod%2b%2b:1.0:sp1:~~pro~x64~~:en",
                "cpe:2.3:a:vendor:prod\\+\\+:1.0:sp1:*:en:pro:x64:*:*",
            ),
            (
                "cpe:/h:cisco:asa_5505",
                "cpe:2.3:h:cisco:asa_5505:*:*:*:*:*:*:*:*",
            ),
        ] {
            assert_eq!(to_cpe23(old).as_deref(), Some(new), "{old}");
        }
    }

    #[test]
    fn cpe_23_passes_through_normalised() {
        let name = "cpe:2.3:a:OpenBSD:openssh:8.2p1:*:*:*:*:*:*:*";
        assert_eq!(
            to_cpe23(name).as_deref(),
            Some("cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*")
        );
        let escaped = "cpe:2.3:a:vendor:prod\\:x:1.0:*:*:*:*:*:*:*";
        assert_eq!(to_cpe23(escaped).as_deref(), Some(escaped));
    }

    #[test]
    fn non_cpe_strings_are_rejected() {
        for bad in [
            "",
            "openssh 8.2",
            "cpe:/",
            "cpe:/x:vendor:product",
            "cpe:/a:vendor",
            "cpe:/a::product:1.0",
            "cpe:/a:a:b:c:d:e:f:g:h",
            "cpe:2.3:a:too:short",
            "cpe:2.3:z:v:p:1:*:*:*:*:*:*:*",
        ] {
            assert_eq!(to_cpe23(bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn lookup_parts_are_extracted() {
        assert_eq!(
            parts("cpe:/a:openbsd:openssh:8.2p1"),
            Some(CpeParts {
                part: 'a',
                vendor: "openbsd".into(),
                product: "openssh".into(),
                version: Some("8.2p1".into()),
            })
        );
        assert_eq!(parts("cpe:/o:linux:linux_kernel").unwrap().version, None);
        assert_eq!(
            parts("cpe:2.3:a:vendor:prod\\+\\+:-:*:*:*:*:*:*:*").unwrap(),
            CpeParts {
                part: 'a',
                vendor: "vendor".into(),
                product: "prod++".into(),
                version: None,
            }
        );
        assert_eq!(clean_version("for_windows_9.5"), "9.5");
        assert_eq!(clean_version("openssl_1_1_1"), "1.1.1");
        assert_eq!(clean_version("openssl_1_1_1k"), "1.1.1k");
        assert_eq!(clean_version("1_1_1"), "1.1.1");
        assert_eq!(clean_version("1.18.0"), "1.18.0");
    }
}

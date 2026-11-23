//! Web inspection: favicon hashes, header analysis, WAF/CDN detection, the `headers` stage
//! page fetch and the `js` stage script fetch.

use super::*;

// ---------------------------------------------------------------------------
// 5. MurmurHash3 (32-bit x86), Favicon Fingerprinting & HTTP Security Headers
// ---------------------------------------------------------------------------

/// Standard 32-bit MurmurHash3 (`x86_32`) implementation in pure Rust.
pub fn murmur3_32(data: &[u8], seed: u32) -> i32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    let mut h1 = seed;
    let (chunks, rem) = data.as_chunks::<4>();
    for chunk in chunks {
        let mut k1 = u32::from_le_bytes(*chunk);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    let mut k1 = 0u32;
    if rem.len() == 3 {
        k1 ^= (rem[2] as u32) << 16;
    }
    if rem.len() >= 2 {
        k1 ^= (rem[1] as u32) << 8;
    }
    if !rem.is_empty() {
        k1 ^= rem[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }
    h1 ^= data.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;
    h1 as i32
}

fn base64_mime_with_newlines(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut raw = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        raw.push(TABLE[((n >> 18) & 0x3f) as usize]);
        raw.push(TABLE[((n >> 12) & 0x3f) as usize]);
        raw.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize]
        } else {
            b'='
        });
        raw.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize]
        } else {
            b'='
        });
    }
    let mut out = String::with_capacity(raw.len() + raw.len() / 76 + 2);
    for line in raw.chunks(76) {
        out.push_str(std::str::from_utf8(line).unwrap_or(""));
        out.push('\n');
    }
    out
}

/// Computes the Shodan-compatible MurmurHash3 32-bit signed hash of raw
/// `/favicon.ico` bytes (base64-encoded with RFC 2045 76-char line breaks).
pub fn favicon_hash(favicon_bytes: &[u8]) -> i32 {
    let encoded = base64_mime_with_newlines(favicon_bytes);
    murmur3_32(encoded.as_bytes(), 0)
}

/// Matches a Shodan-compatible `/favicon.ico` MurmurHash3 value to known
/// web frameworks, appliances, and control panels.
pub fn lookup_favicon_framework(hash: i32) -> Option<&'static str> {
    match hash {
        116323821 => Some("Spring Boot"),
        81586312 => Some("Jenkins"),
        1278323681 | 516963061 => Some("GitLab"),
        945408572 | -1454535736 => Some("Fortinet FortiGate"),
        -1250546953 | 1708740998 => Some("Grafana"),
        -297069493 => Some("Apache Tomcat"),
        99395752 => Some("Atlassian Jira / Confluence"),
        -1166125415 => Some("PhpMyAdmin"),
        -689713512 => Some("Cockpit Web Console"),
        1485257654 => Some("OWASP Juice Shop"),
        -1507567067 => Some("VMware ESXi / vSphere"),
        -1666941817 => Some("Kibana"),
        1848946384 => Some("Citrix NetScaler / ADC"),
        -335199379 => Some("SonicWall"),
        708578229 => Some("WordPress"),
        -305179312 => Some("Nextcloud"),
        _ => None,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderAnalysis {
    pub present_security: BTreeMap<String, String>,
    pub missing_security: Vec<String>,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub location: Option<String>,
    pub waf: Option<String>,
}

/// Analyzes HTTP response headers (case-insensitive) for security headers,
/// server/framework banners, and WAF/CDN signatures.
pub fn analyze_http_headers(headers: &[(String, String)]) -> HeaderAnalysis {
    let mut present_security = BTreeMap::new();
    let mut missing_security = Vec::new();
    let mut server = None;
    let mut powered_by = None;
    let mut location = None;

    for &required in REQUIRED_SECURITY_HEADERS {
        if let Some((_, val)) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(required))
        {
            let clean_val = sanitize(val.trim(), 200);
            if !clean_val.is_empty() {
                present_security.insert(required.to_owned(), clean_val);
                continue;
            }
        }
        missing_security.push(required.to_owned());
    }

    for (k, v) in headers {
        let lower = k.to_ascii_lowercase();
        let val = sanitize(v.trim(), 200);
        if val.is_empty() {
            continue;
        }
        match lower.as_str() {
            "server" => server = Some(val),
            "x-powered-by" | "x-aspnet-version" | "x-generator" => {
                powered_by = Some(match powered_by {
                    Some(prev) => format!("{prev}, {val}"),
                    None => val,
                });
            }
            "location" => location = Some(val),
            _ => {}
        }
    }

    let waf = detect_waf_from_headers(headers);
    HeaderAnalysis {
        present_security,
        missing_security,
        server,
        powered_by,
        location,
        waf,
    }
}

/// Extracts the HTML `<title>` element from an HTML body snippet.
pub fn extract_html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after_tag = start + lower[start..].find('>')? + 1;
    let end = after_tag + lower[after_tag..].find("</title>")?;
    let raw = body.get(after_tag..end)?.trim();
    let collapsed: Vec<&str> = raw.split_whitespace().collect();
    let cleaned = sanitize(&collapsed.join(" "), 160);
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Extracts `Disallow:` entries from a `robots.txt` file.
pub fn parse_robots_txt(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(rest) = line
            .strip_prefix("Disallow:")
            .or_else(|| line.strip_prefix("disallow:"))
        {
            let path = sanitize(rest.trim(), 120);
            if !path.is_empty() && path != "/" && !out.contains(&path) {
                out.push(path);
                if out.len() >= 16 {
                    break;
                }
            }
        }
    }
    out
}

/// Extracts key `Contact:` and `Expires:` lines from `/.well-known/security.txt`.
pub fn parse_security_txt(body: &str) -> Option<String> {
    let mut parts = Vec::new();
    for line in body.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("contact:")
            || lower.starts_with("expires:")
            || lower.starts_with("policy:")
        {
            let cleaned = sanitize(line, 140);
            if !cleaned.is_empty() && !parts.contains(&cleaned) {
                parts.push(cleaned);
                if parts.len() >= 4 {
                    break;
                }
            }
        }
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

// ---------------------------------------------------------------------------
// 6. WAF / CDN Detection (`waf-cdn` task)
// ---------------------------------------------------------------------------

pub fn detect_waf_from_cnames(cnames: &[String]) -> Option<String> {
    for cname in cnames {
        let lower = cname.to_ascii_lowercase();
        if lower.contains("cloudflare") || lower.ends_with(".cdn.cloudflare.net") {
            return Some("Cloudflare".to_owned());
        }
        if lower.contains("akamai")
            || lower.contains("edgekey.net")
            || lower.contains("edgesuite.net")
            || lower.contains("akamaiedge.net")
        {
            return Some("Akamai".to_owned());
        }
        if lower.ends_with(".cloudfront.net") {
            return Some("Amazon CloudFront".to_owned());
        }
        if lower.contains("fastly.net") {
            return Some("Fastly".to_owned());
        }
        if lower.contains("incapdns.net") || lower.contains("impervadns.net") {
            return Some("Imperva / Incapsula".to_owned());
        }
        if lower.contains("sucuri.net") {
            return Some("Sucuri WAF".to_owned());
        }
        if lower.contains("azurefd.net") || lower.contains("trafficmanager.net") {
            return Some("Azure Front Door".to_owned());
        }
    }
    None
}

pub fn detect_waf_from_asn(asn_label: &str) -> Option<String> {
    let lower = asn_label.to_ascii_lowercase();
    if lower.contains("cloudflare") {
        Some("Cloudflare".to_owned())
    } else if lower.contains("fastly") {
        Some("Fastly".to_owned())
    } else if lower.contains("incapsula") || lower.contains("imperva") {
        Some("Imperva".to_owned())
    } else if lower.contains("sucuri") {
        Some("Sucuri".to_owned())
    } else {
        None
    }
}

pub fn detect_waf_from_headers(headers: &[(String, String)]) -> Option<String> {
    for (k, v) in headers {
        let key = k.to_ascii_lowercase();
        let val = v.to_ascii_lowercase();
        if key == "cf-ray"
            || key == "cf-cache-status"
            || (key == "server" && val.contains("cloudflare"))
        {
            return Some("Cloudflare".to_owned());
        }
        if key == "x-amz-cf-id"
            || key == "x-amz-cf-pop"
            || (key == "via" && val.contains("cloudfront"))
            || (key == "server" && val.contains("cloudfront"))
        {
            return Some("Amazon CloudFront".to_owned());
        }
        if key == "x-amzn-waf-action" || (key == "server" && val.contains("awselb")) {
            return Some("AWS WAF / ALB".to_owned());
        }
        if key.starts_with("x-akamai-")
            || key == "x-check-cacheable"
            || (key == "server" && val.contains("akamaighost"))
        {
            return Some("Akamai".to_owned());
        }
        if key == "x-fastly-request-id"
            || key == "fastly-restarts"
            || (key == "x-served-by" && val.contains("cache-"))
        {
            return Some("Fastly".to_owned());
        }
        if key == "x-iinfo"
            || (key == "x-cdn" && val.contains("incapsula"))
            || (key == "set-cookie" && (val.contains("visid_incap") || val.contains("incap_ses")))
        {
            return Some("Imperva / Incapsula".to_owned());
        }
        if key.starts_with("x-sucuri-") || (key == "server" && val.contains("sucuri")) {
            return Some("Sucuri WAF".to_owned());
        }
        if key == "x-azure-ref" {
            return Some("Azure Front Door".to_owned());
        }
    }
    None
}

/// Runs the `headers` (and `/favicon.ico`, `/robots.txt`, `/.well-known/security.txt`)
/// inspection for one `(address, port, tls)` web endpoint.
/// A `Set-Cookie` header with its value left out (it can be a live session
/// token): `sid=<value left out>; Path=/; HttpOnly`. Other headers as they are.
pub(super) fn redact_cookie_value(name: &str, value: &str) -> String {
    if !name.eq_ignore_ascii_case("set-cookie") {
        return value.to_owned();
    }
    let (pair, attributes) = value.split_once(';').unwrap_or((value, ""));
    let cookie = pair.split('=').next().unwrap_or("").trim();
    if attributes.is_empty() {
        format!("{cookie}=<value left out>")
    } else {
        format!("{cookie}=<value left out>;{attributes}")
    }
}

/// A client for one web server: the name pinned to the address it was
/// checked to resolve to, no redirects, no proxy. Returns it with the
/// server's base URL and the name pages are asked for.
pub(crate) async fn pinned_web_client(
    address: &str,
    hostname: Option<&str>,
    port: u16,
    tls: bool,
) -> Result<(reqwest::Client, String, String)> {
    let parsed_addr = HostAddr::parse(address)
        .with_context(|| format!("invalid web endpoint address '{address}'"))?;
    let resolved_hostname = match hostname {
        Some(h) => match HostAddr::parse(h) {
            Some(HostAddr::Name(domain)) => Some(domain),
            _ => bail!("invalid hostname '{h}' for web inspection"),
        },
        None => None,
    };
    let scheme = if tls { "https" } else { "http" };
    let host_for_url = resolved_hostname.as_deref().unwrap_or(address);
    let authority = match HostAddr::parse(host_for_url) {
        Some(HostAddr::Ip {
            addr: IpAddr::V6(v6),
            ..
        }) => format!("[{v6}]"),
        _ => host_for_url.to_owned(),
    };
    let default_port = (tls && port == 443) || (!tls && port == 80);
    let base_url = if default_port {
        format!("{scheme}://{authority}")
    } else {
        format!("{scheme}://{authority}:{port}")
    };

    let mut builder = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(REQUEST_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .user_agent(OSINT_USER_AGENT);

    match (&parsed_addr, &resolved_hostname) {
        (HostAddr::Ip { addr, zone }, Some(domain)) => {
            if zone.is_some() {
                bail!("zoned IPv6 address '{address}' cannot be pinned to '{domain}'");
            }
            if !is_allowed_resolved_ip_for_name(domain, *addr) {
                bail!("refusing web inspection of '{domain}' at disallowed IP {addr}");
            }
            builder = builder.resolve(domain, SocketAddr::new(*addr, port));
        }
        (HostAddr::Name(domain), _) => {
            let lookup = tokio::time::timeout(
                CONNECT_TIMEOUT,
                tokio::net::lookup_host((domain.as_str(), port)),
            )
            .await
            .with_context(|| format!("DNS lookup timed out for '{domain}'"))?
            .with_context(|| format!("DNS lookup failed for '{domain}'"))?;
            let pinned = lookup
                .map(|sa| sa.ip().to_canonical())
                .find(|ip| is_allowed_resolved_ip_for_name(domain, *ip))
                .with_context(|| {
                    format!("'{domain}' resolved only to disallowed special-use addresses")
                })?;
            builder = builder.resolve(domain, SocketAddr::new(pinned, port));
        }
        (HostAddr::Ip { .. }, None) => {}
    }

    let client = builder
        .build()
        .context("cannot build web inspector client")?;
    Ok((client, base_url, host_for_url.to_owned()))
}

/// The site's own script files at `paths` on one web server, as text: at
/// most `max_bytes` of each, and nothing that came back as an HTML page (a
/// single-page app answers every path with its index).
pub async fn fetch_scripts(
    address: &str,
    hostname: Option<&str>,
    port: u16,
    tls: bool,
    paths: &[String],
    max_bytes: usize,
) -> Result<Vec<(String, String)>> {
    let (client, base_url, _) = pinned_web_client(address, hostname, port, tls).await?;
    let mut out = Vec::new();
    for path in paths {
        if !path.starts_with('/') || path.contains("//") || path.chars().any(char::is_whitespace) {
            continue;
        }
        let Ok(resp) = client.get(format!("{base_url}{path}")).send().await else {
            continue;
        };
        if resp.status().as_u16() != 200 {
            continue;
        }
        let kind = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if kind.contains("html") || kind.starts_with("image/") || kind.starts_with("font/") {
            continue;
        }
        let Ok(bytes) = read_bytes_prefix(resp, max_bytes).await else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if text.trim_start().starts_with('<') {
            continue;
        }
        out.push((path.clone(), text));
    }
    Ok(out)
}

pub async fn inspect_web_endpoint(
    address: &str,
    hostname: Option<&str>,
    port: u16,
    tls: bool,
) -> Result<(Vec<Observation>, Option<String>, String)> {
    let (client, base_url, site) = pinned_web_client(address, hostname, port, tls).await?;
    let scheme = if tls { "https" } else { "http" };

    let root_resp = client
        .get(format!("{base_url}/"))
        .send()
        .await
        .with_context(|| format!("GET {base_url}/ failed"))?;
    let status = root_resp.status().as_u16();
    let raw_headers: Vec<(String, String)> = root_resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect();
    let body_bytes = read_bytes_prefix(root_resp, MAX_HTTP_BYTES)
        .await
        .unwrap_or_default();
    let body_text = String::from_utf8_lossy(&body_bytes);
    let title = extract_html_title(&body_text);
    let analysis = analyze_http_headers(&raw_headers);
    let print = crate::webfp::fingerprint(&raw_headers, &body_text, &site, tls);

    // Fetch /robots.txt, /.well-known/security.txt, and /favicon.ico concurrently.
    let fetch_plain = |path: &'static str| {
        let client = client.clone();
        let url = format!("{base_url}{path}");
        async move {
            let Ok(resp) = client.get(&url).send().await else {
                return None;
            };
            if resp.status().as_u16() != 200 {
                return None;
            }
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !ct.starts_with("text/plain") {
                return None;
            }
            let bytes = read_bytes_prefix(resp, 64 * 1024).await.ok()?;
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    let fetch_favicon = {
        let client = client.clone();
        let url = format!("{base_url}/favicon.ico");
        async move {
            let Ok(resp) = client.get(&url).send().await else {
                return None;
            };
            if resp.status().as_u16() != 200 {
                return None;
            }
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ct.contains("text/html") {
                return None;
            }
            let bytes = read_bytes_bounded(resp, MAX_FAVICON_BYTES).await.ok()?;
            if bytes.is_empty() || bytes.starts_with(b"<!DOCTYPE") || bytes.starts_with(b"<html") {
                return None;
            }
            Some(bytes)
        }
    };

    let (robots_body, sectxt_body, fav_bytes) = tokio::join!(
        fetch_plain("/robots.txt"),
        fetch_plain("/.well-known/security.txt"),
        fetch_favicon,
    );

    let robots_disallow = robots_body
        .as_deref()
        .map(parse_robots_txt)
        .unwrap_or_default();
    let security_txt = sectxt_body.as_deref().and_then(parse_security_txt);
    let (fav_hash, fav_framework) = match fav_bytes {
        Some(bytes) => {
            let h = favicon_hash(&bytes);
            let fw = lookup_favicon_framework(h).map(str::to_owned);
            (Some(h), fw)
        }
        None => (None, None),
    };

    let mut observations = Vec::new();
    let header_ev = raw_headers
        .iter()
        .take(20)
        .map(|(k, v)| format!("{k}: {}", redact_cookie_value(k, v)))
        .collect::<Vec<_>>()
        .join("\n");

    observations.push(Observation::Path {
        address: address.to_owned(),
        port,
        scheme: scheme.to_owned(),
        path: "/".to_owned(),
        status: Some(status),
        record: EvidenceRecord::observed(Source::HttpHeader, Confidence::High, &header_ev),
    });

    if let Some(srv) = &analysis.server {
        observations.push(Observation::Http {
            address: address.to_owned(),
            port,
            scheme: scheme.to_owned(),
            server: Some(srv.clone()),
            location: analysis.location.clone(),
            record: EvidenceRecord::observed(
                Source::HttpHeader,
                Confidence::High,
                &format!("Server: {srv}"),
            ),
        });
    }

    if let Some(pby) = &analysis.powered_by {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!("HTTP X-Powered-By banner: {pby}"),
            record: EvidenceRecord::observed(
                Source::HttpHeader,
                Confidence::High,
                &format!("X-Powered-By: {pby}"),
            ),
        });
    }

    if let Some(t) = &title {
        let t_hash = murmur3_32(t.as_bytes(), 0);
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!("HTTP page title: \"{t}\" (MurmurHash3 {t_hash})"),
            record: EvidenceRecord::observed(Source::HttpHeader, Confidence::High, t),
        });
    }

    if !analysis.missing_security.is_empty() {
        let claim = format!(
            "missing HTTP security headers: {}",
            analysis.missing_security.join(", ")
        );
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim,
            record: EvidenceRecord::observed(Source::HttpHeader, Confidence::High, &header_ev),
        });
    }

    for (hdr, val) in &analysis.present_security {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!("security header {hdr}: {val}"),
            record: EvidenceRecord::observed(
                Source::HttpHeader,
                Confidence::High,
                &format!("{hdr}: {val}"),
            ),
        });
    }

    if let Some(h) = fav_hash {
        let claim = match &fav_framework {
            Some(fw) => format!("favicon.ico MurmurHash3: {h} ({fw})"),
            None => format!("favicon.ico MurmurHash3: {h}"),
        };
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim,
            record: EvidenceRecord::observed(
                Source::Favicon,
                Confidence::High,
                &format!("{base_url}/favicon.ico mmh3={h}"),
            ),
        });
    }

    if !robots_disallow.is_empty() {
        let claim = format!("robots.txt disallow paths: {}", robots_disallow.join(", "));
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim,
            record: EvidenceRecord::observed(
                Source::HttpHeader,
                Confidence::High,
                robots_body.as_deref().unwrap_or(""),
            ),
        });
    }

    if let Some(sectxt) = &security_txt {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!("security.txt: {sectxt}"),
            record: EvidenceRecord::observed(
                Source::HttpHeader,
                Confidence::High,
                sectxt_body.as_deref().unwrap_or(""),
            ),
        });
    }

    if let Some(waf) = &analysis.waf {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!("WAF / CDN detected via HTTP headers: {waf}"),
            record: EvidenceRecord::observed(Source::WafCdn, Confidence::High, &header_ev),
        });
        observations.push(Observation::HostMeta {
            address: address.to_owned(),
            asn: None,
            bgp_prefix: None,
            country: None,
            ipv6_dns: None,
            waf_cdn: Some(waf.clone()),
            hops: Vec::new(),
            record: EvidenceRecord::observed(Source::WafCdn, Confidence::High, &header_ev),
        });
    }

    if !print.tech.is_empty() {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!("web stack: {}", print.tech.join(", ")),
            record: EvidenceRecord::observed(Source::HttpHeader, Confidence::Medium, &header_ev),
        });
    }
    observations.push(Observation::Fact {
        address: address.to_owned(),
        port: Some(port),
        protocol: "tcp".to_owned(),
        claim: format!(
            "security headers grade {}{}",
            print.header_grade,
            if print.header_notes.is_empty() {
                String::new()
            } else {
                format!(": {}", print.header_notes.join("; "))
            }
        ),
        record: EvidenceRecord::observed(Source::HttpHeader, Confidence::High, &header_ev),
    });
    for cookie in print.cookies.iter().filter(|c| !c.issues.is_empty()) {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!(
                "cookie {} ({}): {}",
                cookie.name,
                cookie.flags,
                cookie.issues.join("; ")
            ),
            record: EvidenceRecord::observed(
                Source::HttpHeader,
                Confidence::High,
                &format!("Set-Cookie: {} ({})", cookie.name, cookie.flags),
            ),
        });
    }

    let http_info = HttpInfo {
        scheme: scheme.to_owned(),
        server: analysis.server.clone(),
        location: analysis.location.clone(),
        title,
        powered_by: analysis.powered_by,
        waf: analysis.waf.clone(),
        favicon_hash: fav_hash,
        favicon_framework: fav_framework,
        security_headers: analysis.present_security,
        missing_headers: analysis.missing_security.clone(),
        robots_disallow,
        security_txt,
        tech: print.tech,
        cookies: print.cookies,
        header_grade: Some(print.header_grade),
        header_notes: print.header_notes,
        scripts: print.scripts,
        ..HttpInfo::default()
    };

    observations.push(Observation::WebMeta {
        address: address.to_owned(),
        port,
        http: Box::new(http_info),
        record: EvidenceRecord::observed(Source::HttpHeader, Confidence::High, &header_ev),
    });

    let summary = format!(
        "{port}/tcp ({} missing security headers)",
        analysis.missing_security.len()
    );
    Ok((observations, analysis.waf, summary))
}

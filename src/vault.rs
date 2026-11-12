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

static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<<([A-Z]+)_(\d+)>>").expect("valid regex"));
static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)")
        .expect("valid regex")
});
static AUTH_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:proxy-)?authorization\s*[:=]\s*(?:basic|bearer|digest|negotiate|ntlm|token)\s+([A-Za-z0-9+/=._~-]{4,})")
        .expect("valid regex")
});
static COOKIE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)\b(?:set-)?cookie\s*:\s*([^\r\n]{4,})").expect("valid regex")
});
static KEY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:x-api-key|api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|pwd|pass|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?id|private[_-]?key)\b["']?\s*[:=]\s*["']?([^\s"',;&<>]{4,})"#,
    )
    .expect("valid regex")
});
static URL_CREDENTIALS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"://([^/\s:@]{1,64}):([^/\s@]{1,128})@").expect("valid regex"));
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
        .expect("valid regex")
});
static KNOWN_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{10,}|(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|ssh-(?:rsa|ed25519|dss) [A-Za-z0-9+/=]{40,})",
    )
    .expect("valid regex")
});
static BLOB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_=-]{16,}").expect("valid regex"));
static IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid regex"));
static IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[^0-9a-f:.])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[\w.-]+)?)")
        .expect("valid regex")
});
static MAC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b").expect("valid regex")
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
    Regex::new(
        r#"(?:/(?:home|Users|root|var|etc|opt|srv|mnt|data|tmp|usr/local)(?:/[^\s"'<>:;,|]+)+|\b[A-Za-z]:\\(?:[^\s"'<>:;,|\\]+\\)*[^\s"'<>:;,|\\]+)"#,
    )
    .expect("valid regex")
});

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

/// A random-looking token: some unbroken run of letters and digits is long
/// and varied. Splitting on punctuation first keeps URL paths, package
/// names and dashed identifiers (`detail/CVE-2021-23017`) from qualifying.
fn is_high_entropy(blob: &str) -> bool {
    blob.split(|c: char| !c.is_ascii_alphanumeric()).any(|run| {
        run.len() >= ENTROPY_MIN_LEN
            && run.bytes().any(|b| b.is_ascii_digit())
            && run.bytes().any(|b| b.is_ascii_alphabetic())
            && entropy(run) >= ENTROPY_MIN_BITS
    })
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
    store: Option<Arc<Mutex<Db>>>,
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
        let mut vault = Self::default();
        {
            let guard = db.lock().unwrap_or_else(|p| p.into_inner());
            let mut statement = guard
                .conn()
                .prepare("SELECT token, kind, value, first_seen_utc FROM vault")?;
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
            Kind::Host => match value.parse::<IpAddr>() {
                Ok(ip) => ip.to_canonical().to_string(),
                Err(_) => value.to_ascii_lowercase(),
            },
            _ => value.to_owned(),
        };
        if let Some(token) = self.tokens.get(&(kind, value.clone())) {
            return token.clone();
        }
        let counter = self.counters.entry(kind).or_default();
        *counter += 1;
        let token = format!("<<{}_{:02}>>", kind.tag(), counter);
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
        }
        self.tokens.insert((kind, value), token.clone());
        self.entries.insert(token.clone(), entry);
        token
    }

    /// Marks a base domain as internal: it and every name below it are masked.
    pub fn register_domain_suffix(&mut self, suffix: &str) {
        let suffix = suffix
            .trim_start_matches("*.")
            .trim_matches('.')
            .to_ascii_lowercase();
        if suffix.contains('.') || INTERNAL_TLDS.contains(&suffix.as_str()) {
            self.suffixes.insert(suffix);
        }
    }

    /// Registers everything the graph knows to be private: host addresses,
    /// names, TLS SANs, redirect hosts, local interface addresses, gateways,
    /// neighbours and the operator's own user name.
    pub fn register_graph(&mut self, graph: &Graph) {
        let domain = |vault: &mut Self, name: &str| {
            let name = name.trim_start_matches("*.");
            if name.parse::<IpAddr>().is_ok() || !name.contains('.') {
                if !name.is_empty() && name.parse::<IpAddr>().is_err() {
                    vault.register(Kind::Dom, name);
                }
                return;
            }
            vault.register(Kind::Dom, name);
            // app.lab.local -> every *.lab.local name is internal too.
            let labels: Vec<&str> = name.split('.').collect();
            if labels.len() >= 3 {
                vault.register_domain_suffix(&labels[1..].join("."));
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
        group(&AUTH_HEADER, 1, Kind::Sec, &mut spans);
        group(&COOKIE, 1, Kind::Sec, &mut spans);
        group(&KEY_VALUE, 1, Kind::Sec, &mut spans);
        group(&URL_CREDENTIALS, 1, Kind::User, &mut spans);
        group(&URL_CREDENTIALS, 2, Kind::Sec, &mut spans);
        for found in BLOB.find_iter(text) {
            if is_base64_credentials(found.as_str()) || is_high_entropy(found.as_str()) {
                spans.push((found.start(), found.end(), Kind::Sec));
            }
        }

        whole(&MAC, Kind::Host, &mut spans);
        for found in IPV4.find_iter(text) {
            if found.as_str().parse::<IpAddr>().is_ok() {
                spans.push((found.start(), found.end(), Kind::Host));
            }
        }
        for found in IPV6.captures_iter(text) {
            let part = found.get(1).expect("group 1 always participates");
            let address = part.as_str().split('%').next().unwrap_or("");
            if address.parse::<Ipv6Addr>().is_ok() {
                spans.push((part.start(), part.end(), Kind::Host));
            }
        }
        for found in HOSTNAME.find_iter(text) {
            if self.is_internal_name(found.as_str()) {
                spans.push((found.start(), found.end(), Kind::Dom));
            }
        }
        whole(&FS_PATH, Kind::Path, &mut spans);
        group(&EMAIL_USER, 1, Kind::User, &mut spans);
        // Registered values that no pattern above would recognise (single
        // label host names, user names).
        for ((kind, value), _) in self
            .tokens
            .iter()
            .filter(|((kind, _), _)| matches!(kind, Kind::User | Kind::Dom))
        {
            if value.len() < 3 {
                continue;
            }
            let lower = text.to_ascii_lowercase();
            let needle = value.to_ascii_lowercase();
            let mut from = 0;
            while let Some(at) = lower[from..].find(&needle) {
                let (start, end) = (from + at, from + at + needle.len());
                let boundary =
                    |c: Option<char>| !c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
                if boundary(text[..start].chars().next_back())
                    && boundary(text[end..].chars().next())
                {
                    spans.push((start, end, *kind));
                }
                from = end;
            }
        }
        spans
    }

    /// Replaces every sensitive value in `text` by its placeholder.
    pub fn mask_text(&mut self, text: &str) -> String {
        let mut spans = self.detect(text);
        // Longest match first, so a secret is never left half-masked by a
        // shorter overlapping match.
        spans.sort_by(|a, b| (b.1 - b.0).cmp(&(a.1 - a.0)).then(a.0.cmp(&b.0)));
        let mut chosen: Vec<(usize, usize, Kind)> = Vec::new();
        for span in spans {
            let overlaps = chosen.iter().any(|kept| span.0 < kept.1 && kept.0 < span.1);
            if !overlaps && text.is_char_boundary(span.0) && text.is_char_boundary(span.1) {
                chosen.push(span);
            }
        }
        chosen.sort_by_key(|span| span.0);
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
        match value {
            Value::String(text) => Value::String(self.mask_text(text)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| self.mask_json(item)).collect())
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, item)| (key.clone(), self.mask_json(item)))
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

    /// Sensitive values that are still present in `text` after masking.
    /// Used as a last check before a request leaves the machine.
    pub fn leaks(&self, text: &str) -> Vec<String> {
        let lower = text.to_ascii_lowercase();
        let mut found: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.kind != Kind::Lit && entry.value.len() >= 4)
            .filter(|(_, entry)| lower.contains(&entry.value.to_ascii_lowercase()))
            .map(|(token, _)| token.clone())
            .collect();
        found.sort();
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

    /// An unmasker for a reply that arrives in pieces.
    pub fn stream(&self) -> StreamUnmasker<'_> {
        StreamUnmasker {
            vault: self,
            held: String::new(),
        }
    }
}

/// Unmasks streamed text. A placeholder may be split across chunks, so text
/// from a possible placeholder start (`<` or `<<...`) is held back until the
/// placeholder is complete or it is clear that it is not one.
pub struct StreamUnmasker<'a> {
    vault: &'a Vault,
    held: String,
}

impl StreamUnmasker<'_> {
    /// Adds a chunk and returns the text that is safe to show now.
    pub fn push(&mut self, chunk: &str) -> String {
        self.held.push_str(chunk);
        let cut = match self.held.rfind("<<") {
            // An opened placeholder without its closing `>>`, still short
            // enough to become one.
            Some(start)
                if !self.held[start..].contains(">>")
                    && self.held.len() - start <= MAX_TOKEN_LEN =>
            {
                start
            }
            _ if self.held.ends_with('<') => self.held.len() - 1,
            _ => self.held.len(),
        };
        let ready: String = self.held.drain(..cut).collect();
        self.vault.unmask(&ready)
    }

    /// Returns whatever is still held back, at the end of the stream.
    pub fn finish(&mut self) -> String {
        self.vault.unmask(&std::mem::take(&mut self.held))
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
        assert_eq!(vault.leaks("see 10.10.10.5"), ["<<HOST_01>>"]);
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
                "login?user=bob&password=<<SEC_05>>&next=/",
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
        assert_eq!(vault.leaks(&text), ["<<HOST_01>>"]);
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

        // Every possible split into two chunks, and byte-at-a-time.
        for cut in 0..=reply.len() {
            let mut stream = vault.stream();
            let mut out = stream.push(&reply[..cut]);
            out.push_str(&stream.push(&reply[cut..]));
            out.push_str(&stream.finish());
            assert_eq!(out, expected, "cut at {cut}");
        }
        let mut stream = vault.stream();
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

        // A lone "<<" that never closes is released once it is too long.
        let mut stream = vault.stream();
        let mut out = stream.push("shift <<");
        assert_eq!(out, "shift ");
        out.push_str(&stream.push(" by a very long expression that is no placeholder"));
        out.push_str(&stream.finish());
        assert_eq!(
            out,
            "shift << by a very long expression that is no placeholder"
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
}

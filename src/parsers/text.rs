//! Regex extraction from plain text: live PTY lines (`pty_regex`) and
//! imported log files (`log_regex`).
//!
//! The parser is stateful across lines so that, for example, the port table
//! of Nmap's normal output is attributed to the host named in the preceding
//! "Nmap scan report for" line, and `Server:` headers to the URL that was
//! just requested.

use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;

use crate::endpoint::{Endpoint, HostAddr, WebUrl};
use crate::evidence::{Confidence, EvidenceRecord, Source};
use crate::graph::Observation;

const MAX_LINE: usize = 4096;

static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s"'<>\\^`{|}]+"#).expect("valid regex"));
static NMAP_REPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Nmap scan report for (?:(\S+) \(([^)\s]+)\)|(\S+))\s*$").expect("valid regex")
});
static NMAP_PORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{1,5})/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)(?:\s+(.+))?$")
        .expect("valid regex")
});
static DISCOVERED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Discovered open port (\d{1,5})/(tcp|udp) on (\S+)").expect("valid regex")
});
static ENDPOINT_V4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^\w.:/])((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})\b").expect("valid regex")
});
static ENDPOINT_V6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\[[0-9A-Fa-f:.]+(?:%[\w.-]+)?\]:\d{1,5})\b").expect("valid regex")
});
static HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:[<>] )?(server|location):\s*(\S.*)$").expect("valid regex")
});

/// Addresses that say nothing about the lab: wildcard binds, loopback,
/// multicast and broadcast.
fn uninteresting(ip: IpAddr) -> bool {
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
}

fn split_service_info(raw: &str) -> (Option<String>, Option<String>, Option<String>) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (None, None, None);
    }
    let (head, extra_info) = match trimmed.strip_suffix(')') {
        Some(without_close) => match without_close.rfind(" (") {
            Some(pos) => {
                let extra = without_close[pos + 2..].trim();
                (
                    without_close[..pos].trim(),
                    (!extra.is_empty()).then(|| extra.to_owned()),
                )
            }
            None => (trimmed, None),
        },
        None => (trimmed, None),
    };
    let words: Vec<&str> = head.split_whitespace().collect();
    let version_start = words.iter().enumerate().skip(1).find_map(|(idx, word)| {
        let starts_ver = word.starts_with(|c: char| c.is_ascii_digit())
            || (word.starts_with(['v', 'V'])
                && word[1..].starts_with(|c: char| c.is_ascii_digit()))
            || word.to_ascii_lowercase().starts_with("for_windows_");
        starts_ver.then_some(idx)
    });
    match version_start {
        Some(idx) => (
            Some(words[..idx].join(" ")),
            Some(words[idx..].join(" ")),
            extra_info,
        ),
        None => (
            (!head.is_empty()).then(|| head.to_owned()),
            None,
            extra_info,
        ),
    }
}

pub struct TextParser {
    source: Source,
    /// Host named by the last "Nmap scan report for" line.
    scan_host: Option<String>,
    /// Origin of the last URL seen: (address, port, scheme).
    web: Option<(String, u16, String)>,
}

impl TextParser {
    /// `source` is [`Source::PtyRegex`] for live terminal lines or
    /// [`Source::LogRegex`] for imported files.
    pub fn new(source: Source) -> Self {
        Self {
            source,
            scan_host: None,
            web: None,
        }
    }

    fn record(&self, confidence: Confidence, line: &str) -> EvidenceRecord {
        EvidenceRecord::observed(self.source, confidence, line)
    }

    /// Extracts observations from one line of clean text.
    pub fn feed(&mut self, line: &str) -> Vec<Observation> {
        let line = line.trim_end();
        let mut out = Vec::new();
        if line.is_empty() || line.len() > MAX_LINE {
            return out;
        }

        if let Some(found) = NMAP_REPORT.captures(line) {
            let (name, address) = match (found.get(1), found.get(2), found.get(3)) {
                (Some(name), Some(address), _) => (Some(name.as_str()), address.as_str()),
                (_, _, Some(address)) => (None, address.as_str()),
                _ => (None, ""),
            };
            self.scan_host = HostAddr::parse(address).map(|a| a.canonical());
            if let Some(host) = &self.scan_host {
                out.push(Observation::Host {
                    address: host.clone(),
                    os: None,
                    mac: None,
                    record: self.record(Confidence::Medium, line),
                });
                if let Some(name) = name {
                    out.push(Observation::Hostname {
                        address: host.clone(),
                        hostname: name.to_owned(),
                        record: self.record(Confidence::Medium, line),
                    });
                }
            }
            return out;
        }

        if let (Some(host), Some(found)) = (&self.scan_host, NMAP_PORT.captures(line)) {
            if let Ok(port) = found[1].parse::<u16>() {
                let (product, version, extra_info) = found
                    .get(5)
                    .map(|m| split_service_info(m.as_str()))
                    .unwrap_or((None, None, None));
                out.push(Observation::Port {
                    address: host.clone(),
                    port,
                    protocol: found[2].to_owned(),
                    state: found[3].to_owned(),
                    service: Some(found[4].to_owned()).filter(|s| s != "unknown"),
                    product,
                    version,
                    extra_info,
                    cpes: Vec::new(),
                    record: self.record(Confidence::Medium, line),
                });
            }
            return out;
        }

        if let Some(found) = DISCOVERED.captures(line) {
            if let (Ok(port), Some(host)) = (found[1].parse::<u16>(), HostAddr::parse(&found[3])) {
                out.push(Observation::Port {
                    address: host.canonical(),
                    port,
                    protocol: found[2].to_owned(),
                    state: "open".to_owned(),
                    service: None,
                    product: None,
                    version: None,
                    extra_info: None,
                    cpes: Vec::new(),
                    record: self.record(Confidence::Medium, line),
                });
            }
            return out;
        }

        if let (Some((address, port, scheme)), Some(found)) = (&self.web, HEADER.captures(line)) {
            let value = found[2].trim().to_owned();
            let is_server = found[1].eq_ignore_ascii_case("server");
            out.push(Observation::Http {
                address: address.clone(),
                port: *port,
                scheme: scheme.clone(),
                server: is_server.then(|| value.clone()),
                location: (!is_server).then_some(value),
                record: EvidenceRecord::observed(Source::HttpHeader, Confidence::Medium, line),
            });
            return out;
        }

        // URLs first; what remains of the line is searched for host:port.
        let mut rest = String::with_capacity(line.len());
        let mut last = 0;
        for found in URL.find_iter(line) {
            rest.push_str(&line[last..found.start()]);
            rest.push(' ');
            last = found.end();
            let text = found
                .as_str()
                .trim_end_matches(['.', ',', ';', ':', ')', ']', '}', '!', '?']);
            let Some(url) = WebUrl::parse(text) else {
                continue;
            };
            if url.host.ip().is_some_and(uninteresting) || url.host.canonical() == "localhost" {
                continue;
            }
            let address = url.host.canonical();
            self.web = Some((address.clone(), url.port, url.scheme.clone()));
            out.push(Observation::Path {
                address,
                port: url.port,
                scheme: url.scheme,
                path: url.path,
                status: None,
                record: self.record(Confidence::Low, line),
            });
        }
        rest.push_str(&line[last..]);

        let mentions = ENDPOINT_V4
            .captures_iter(&rest)
            .chain(ENDPOINT_V6.captures_iter(&rest));
        for found in mentions {
            let Some(endpoint) = Endpoint::parse(&found[1]) else {
                continue;
            };
            let (Some(ip), Some(port)) = (endpoint.host.ip(), endpoint.port) else {
                continue;
            };
            if uninteresting(ip) {
                continue;
            }
            out.push(Observation::Port {
                address: endpoint.host.canonical(),
                port,
                protocol: "tcp".to_owned(),
                // Seen in text only: nothing shows the port is open.
                state: "unverified".to_owned(),
                service: None,
                product: None,
                version: None,
                extra_info: None,
                cpes: Vec::new(),
                record: self.record(Confidence::Low, line),
            });
        }
        out
    }

    /// Parses a whole document line by line.
    pub fn parse(source: Source, text: &str) -> Vec<Observation> {
        let mut parser = Self::new(source);
        text.lines().flat_map(|line| parser.feed(line)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Graph;

    const TERMINAL: &str = "\
$ nmap -sV 10.0.0.5
Starting Nmap 7.94 ( https://nmap.org ) at 2026-11-12 09:00 UTC
Nmap scan report for app.lab.local (10.0.0.5)
Host is up (0.0010s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
443/tcp  open  https   nginx 1.18.0
8009/tcp open  unknown
Nmap scan report for 2001:db8::a
80/tcp open  http
Nmap done: 2 IP addresses (2 hosts up) scanned in 6.51 seconds
$ curl -sI https://app.lab.local:8443/portal/
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Location: https://sso.lab.local/login
$ nc -vz 10.0.0.9 5432
Connection to 10.0.0.9 5432 port [tcp/postgresql] succeeded!
connect to [fe80::1%eth0]:22 and 10.0.0.9:6379, listening on 0.0.0.0:8000 and 127.0.0.1:631
Discovered open port 3306/tcp on 10.0.0.9
see http://127.0.0.1:8765/?token=abc and http://localhost/x
version 1.2.3.4:5 is not an endpoint? it is treated as one
";

    #[test]
    fn terminal_text_is_mined_for_hosts_ports_urls_and_headers() {
        let mut graph = Graph::default();
        graph.apply_all(TextParser::parse(Source::PtyRegex, TERMINAL));

        // nmap.org from the banner is a real URL and is kept; loopback,
        // wildcard and localhost addresses are not.
        let keys: Vec<_> = graph.hosts.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "1.2.3.4",
                "10.0.0.5",
                "10.0.0.9",
                "2001:db8::a",
                "fe80::1%eth0",
                "nmap.org"
            ]
        );

        let app = &graph.hosts["10.0.0.5"];
        assert_eq!(
            app.hostnames.iter().collect::<Vec<_>>(),
            ["app.lab.local", "sso.lab.local"]
        );
        let ssh = &app.ports["22/tcp"];
        assert_eq!(ssh.service.as_deref(), Some("ssh"));
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh.version.as_deref(), Some("8.2p1 Ubuntu 4ubuntu0.5"));
        assert_eq!(
            ssh.extra_info.as_deref(),
            Some("Ubuntu Linux; protocol 2.0")
        );
        assert_eq!(ssh.facts[0].record.source, Source::PtyRegex);
        assert_eq!(ssh.facts[0].record.confidence, Confidence::Medium);
        assert_eq!(app.ports["8009/tcp"].service, None);

        // The curl URL was by name; it resolves to the same host.
        let web = &app.ports["8443/tcp"];
        let http = web.http.as_ref().unwrap();
        assert_eq!(http.scheme, "https");
        assert_eq!(http.server.as_deref(), Some("nginx/1.18.0 (Ubuntu)"));
        assert_eq!(
            http.location.as_deref(),
            Some("https://sso.lab.local/login")
        );
        assert_eq!(web.paths.walk()[0].0, "/portal");

        let db = &graph.hosts["10.0.0.9"];
        assert!(db.ports["3306/tcp"].is_open());
        assert_eq!(db.ports["6379/tcp"].state, "unverified");
        assert!(
            !db.ports.contains_key("5432/tcp"),
            "'host port' without a colon is not matched"
        );
        assert_eq!(
            graph.hosts["fe80::1%eth0"].ports["22/tcp"].state,
            "unverified"
        );
        assert!(graph.hosts["2001:db8::a"].ports["80/tcp"].is_open());
    }

    #[test]
    fn nothing_is_ever_marked_beyond_observed() {
        use crate::evidence::VerificationStatus;
        for observation in TextParser::parse(Source::LogRegex, TERMINAL) {
            let json = serde_json::to_value(&observation).unwrap();
            assert_eq!(
                json["record"]["verification_status"],
                serde_json::to_value(VerificationStatus::Observed).unwrap()
            );
        }
    }

    #[test]
    fn headers_without_a_preceding_url_are_ignored() {
        let mut parser = TextParser::new(Source::PtyRegex);
        assert!(parser.feed("Server: nginx").is_empty());
        assert!(
            parser.feed("22/tcp open ssh").is_empty(),
            "no scan report yet"
        );
        assert!(parser.feed(&"x".repeat(MAX_LINE + 1)).is_empty());
        assert_eq!(
            parser
                .feed("GET http://10.0.0.5/a, then http://10.0.0.5/b.")
                .len(),
            2
        );
        assert_eq!(parser.feed("< Server: Apache").len(), 1);
    }
}

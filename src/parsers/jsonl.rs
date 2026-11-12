//! JSON Lines parsers: katana (`-jsonl`), feroxbuster (`--json`) and any
//! other tool that writes one object per line with a `url` field.

use serde_json::Value;

use crate::endpoint::WebUrl;
use crate::evidence::{Confidence, EvidenceRecord, Source};
use crate::graph::Observation;

fn header<'a>(headers: Option<&'a Value>, name: &str) -> Option<&'a str> {
    let map = headers?.as_object()?;
    map.iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| match value {
            Value::String(text) => Some(text.as_str()),
            // Some tools emit header values as one-element arrays.
            Value::Array(items) => items.first().and_then(Value::as_str),
            _ => None,
        })
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn status_of(value: Option<&Value>) -> Option<u16> {
    value?
        .as_u64()
        .and_then(|code| u16::try_from(code).ok())
        .filter(|code| (100..600).contains(code))
}

struct Hit<'a> {
    url: &'a str,
    status: Option<u16>,
    headers: Option<&'a Value>,
    source: Source,
}

fn classify(object: &Value) -> Option<Hit<'_>> {
    // feroxbuster: {"type":"response","url":...,"status":200,"headers":{...}}
    if let Some(kind) = object.get("type").and_then(Value::as_str) {
        if kind != "response" {
            return None; // statistics / configuration records
        }
        return Some(Hit {
            url: object.get("url")?.as_str()?,
            status: status_of(object.get("status")),
            headers: object.get("headers"),
            source: Source::FeroxJson,
        });
    }
    // katana: {"request":{"endpoint":...},"response":{"status_code":200,"headers":{...}}}
    if let Some(endpoint) = object.pointer("/request/endpoint").and_then(Value::as_str) {
        return Some(Hit {
            url: endpoint,
            status: status_of(object.pointer("/response/status_code")),
            headers: object.pointer("/response/headers"),
            source: Source::KatanaJsonl,
        });
    }
    // Generic: {"url": ..., "status_code": ...} (httpx and similar).
    let url = object
        .get("url")
        .or_else(|| object.get("endpoint"))
        .and_then(Value::as_str)?;
    Some(Hit {
        url,
        status: status_of(object.get("status_code").or_else(|| object.get("status"))),
        headers: object.get("headers"),
        source: Source::LogRegex,
    })
}

/// Parses one JSONL line into observations; `None` if it holds nothing usable.
pub fn parse_line(line: &str) -> Option<Vec<Observation>> {
    let object: Value = serde_json::from_str(line.trim()).ok()?;
    let hit = classify(&object)?;
    let url = WebUrl::parse(hit.url)?;
    let address = url.host.canonical();
    let confidence = match (hit.source, hit.status) {
        (Source::LogRegex, _) => Confidence::Medium,
        (_, Some(_)) => Confidence::High,
        (_, None) => Confidence::Medium,
    };
    let record = EvidenceRecord::observed(hit.source, confidence, line);

    let mut out = vec![Observation::Path {
        address: address.clone(),
        port: url.port,
        scheme: url.scheme.clone(),
        path: url.path.clone(),
        status: hit.status,
        record: record.clone(),
    }];
    let server = header(hit.headers, "server").map(str::to_owned);
    let location = header(hit.headers, "location").map(str::to_owned);
    if server.is_some() || location.is_some() {
        out.push(Observation::Http {
            address,
            port: url.port,
            scheme: url.scheme,
            server,
            location,
            record: EvidenceRecord {
                source: Source::HttpHeader,
                ..record
            },
        });
    }
    Some(out)
}

/// Parses a whole JSONL document. Returns the observations and the number
/// of non-empty lines that were skipped.
pub fn parse(text: &str) -> (Vec<Observation>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match parse_line(line) {
            Some(observations) => out.extend(observations),
            None => skipped += 1,
        }
    }
    (out, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Graph;

    const KATANA: &str = r#"{"timestamp":"2026-11-12T09:00:00Z","request":{"method":"GET","endpoint":"https://app.lab.local/portal/config/","tag":"a","attribute":"href","source":"https://app.lab.local/"},"response":{"status_code":200,"headers":{"server":"nginx/1.18.0","content_type":"text/html"}}}
{"timestamp":"2026-11-12T09:00:01Z","request":{"method":"GET","endpoint":"https://app.lab.local/static/app.js?v=3","tag":"script","attribute":"src"}}
{"timestamp":"2026-11-12T09:00:02Z","request":{"method":"GET","endpoint":"mailto:ops@lab.local"}}
"#;

    const FEROX: &str = r#"{"type":"configuration","target_url":"http://10.0.0.5:8080"}
{"type":"response","url":"http://10.0.0.5:8080/admin","path":"/admin","wildcard":false,"status":301,"method":"GET","content_length":0,"headers":{"location":"http://admin.lab.local:8080/admin/","server":"Apache/2.4.41"},"extension":""}
{"type":"response","url":"http://10.0.0.5:8080/admin/login.php","path":"/admin/login.php","status":200,"headers":{}}
{"type":"response","url":"http://[2001:db8::a]/backup.zip","status":403}
{"type":"statistics","requests":4614}
not json at all
"#;

    #[test]
    fn katana_lines_become_paths_and_headers() {
        let (observations, skipped) = parse(KATANA);
        assert_eq!(skipped, 1, "the mailto: link is not a web URL");
        let mut graph = Graph::default();
        graph.apply_all(observations);
        let port = &graph.hosts["app.lab.local"].ports["443/tcp"];
        assert_eq!(port.http.as_ref().unwrap().scheme, "https");
        assert_eq!(
            port.http.as_ref().unwrap().server.as_deref(),
            Some("nginx/1.18.0")
        );
        let paths: Vec<_> = port
            .paths
            .walk()
            .into_iter()
            .map(|(p, n)| (p, n.status))
            .collect();
        assert_eq!(
            paths,
            [
                ("/portal/".to_owned(), None),
                ("/portal/config".to_owned(), Some(200)),
                ("/static/".to_owned(), None),
                ("/static/app.js".to_owned(), None),
            ]
        );
        let record = port.paths.children["portal"].children["config"]
            .record
            .as_ref()
            .unwrap();
        assert_eq!(record.source, Source::KatanaJsonl);
        assert_eq!(record.confidence, Confidence::High);
        assert!(record.evidence.starts_with("{\"timestamp\""));
    }

    #[test]
    fn feroxbuster_lines_become_paths_and_redirect_names() {
        let (observations, skipped) = parse(FEROX);
        assert_eq!(skipped, 3, "configuration, statistics and the broken line");
        let mut graph = Graph::default();
        graph.apply_all(observations);

        let host = &graph.hosts["10.0.0.5"];
        assert!(host.hostnames.contains("admin.lab.local"));
        let port = &host.ports["8080/tcp"];
        assert_eq!(
            port.http.as_ref().unwrap().server.as_deref(),
            Some("Apache/2.4.41")
        );
        let paths: Vec<_> = port
            .paths
            .walk()
            .into_iter()
            .map(|(p, n)| (p, n.status))
            .collect();
        assert_eq!(
            paths,
            [
                ("/admin/".to_owned(), Some(301)),
                ("/admin/login.php".to_owned(), Some(200)),
            ]
        );
        assert_eq!(
            port.paths.children["admin"].record.as_ref().unwrap().source,
            Source::FeroxJson
        );
        let v6 = &graph.hosts["2001:db8::a"].ports["80/tcp"];
        assert_eq!(
            v6.paths.walk()[0],
            ("/backup.zip".to_owned(), &v6.paths.children["backup.zip"])
        );
    }

    #[test]
    fn generic_url_objects_are_accepted_with_lower_confidence() {
        let line = r#"{"url":"http://10.0.0.7/health","status_code":204,"webserver":"x"}"#;
        match &parse_line(line).unwrap()[0] {
            Observation::Path { status, record, .. } => {
                assert_eq!(*status, Some(204));
                assert_eq!(record.source, Source::LogRegex);
                assert_eq!(record.confidence, Confidence::Medium);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse_line(r#"{"url": 5}"#).is_none());
        assert!(parse_line(r#"["http://10.0.0.7/"]"#).is_none());
        assert!(parse_line(r#"{"type":"response","url":"http://x/","status":99999}"#).is_some());
    }
}

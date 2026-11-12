//! Nmap XML (`-oX`) parser.

use anyhow::{Context, Result};
use roxmltree::{Document, Node, ParsingOptions};

use crate::cpe::to_cpe23;
use crate::endpoint::{HostAddr, WebUrl};
use crate::evidence::{Confidence, EvidenceRecord, Source};
use crate::graph::Observation;

fn child<'a>(node: Node<'a, 'a>, name: &str) -> Option<Node<'a, 'a>> {
    node.children().find(|n| n.has_tag_name(name))
}

fn children<'a>(node: Node<'a, 'a>, name: &'a str) -> impl Iterator<Item = Node<'a, 'a>> {
    node.children().filter(move |n| n.has_tag_name(name))
}

fn attr(node: Node<'_, '_>, name: &str) -> Option<String> {
    node.attribute(name)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

/// The exact source text of an element, used as the evidence snippet.
fn raw<'a>(xml: &'a str, node: Node<'_, '_>) -> &'a str {
    xml.get(node.range()).unwrap_or("")
}

/// DNS names from an `ssl-cert` script's `Subject Alternative Name:` line.
fn sans_from_ssl_cert(output: &str) -> Vec<String> {
    let Some(start) = output.find("Subject Alternative Name:") else {
        return Vec::new();
    };
    let line = output[start + "Subject Alternative Name:".len()..]
        .lines()
        .next()
        .unwrap_or("");
    line.split(',')
        .filter_map(|entry| entry.trim().strip_prefix("DNS:"))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

/// The target of "Did not follow redirect to <url>" in an `http-title`.
fn redirect_from_title(output: &str) -> Option<String> {
    let rest = output.split("redirect to ").nth(1)?;
    let url = rest.split_whitespace().next()?;
    WebUrl::parse(url).map(|_| url.to_owned())
}

pub fn parse(xml: &str) -> Result<Vec<Observation>> {
    let options = ParsingOptions {
        allow_dtd: true, // nmap writes <!DOCTYPE nmaprun>
        ..ParsingOptions::default()
    };
    let doc = Document::parse_with_options(xml, options).context("not well-formed XML")?;
    let root = doc.root_element();
    if !root.has_tag_name("nmaprun") {
        anyhow::bail!(
            "not an Nmap XML file (root element is <{}>)",
            root.tag_name().name()
        );
    }

    let mut out = Vec::new();
    for host in children(root, "host") {
        let up = child(host, "status")
            .and_then(|s| s.attribute("state"))
            .is_none_or(|state| state == "up");
        if !up {
            continue;
        }
        let mut address = None;
        let mut mac = None;
        for node in children(host, "address") {
            match node.attribute("addrtype") {
                Some("mac") => mac = attr(node, "addr"),
                _ if address.is_none() => {
                    address = attr(node, "addr")
                        .and_then(|a| HostAddr::parse(&a))
                        .map(|a| a.canonical());
                }
                _ => {}
            }
        }
        let Some(address) = address else { continue };

        let os = child(host, "os")
            .and_then(|os| child(os, "osmatch"))
            .and_then(|m| attr(m, "name"));
        let host_evidence = child(host, "status").map_or("", |s| raw(xml, s));
        out.push(Observation::Host {
            address: address.clone(),
            os,
            mac,
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, host_evidence),
        });

        if let Some(names) = child(host, "hostnames") {
            for name in children(names, "hostname") {
                if let Some(hostname) = attr(name, "name") {
                    out.push(Observation::Hostname {
                        address: address.clone(),
                        hostname,
                        record: EvidenceRecord::observed(
                            Source::NmapXml,
                            Confidence::Medium,
                            raw(xml, name),
                        ),
                    });
                }
            }
        }

        let Some(ports) = child(host, "ports") else {
            continue;
        };
        for port in children(ports, "port") {
            let Some(number) = port.attribute("portid").and_then(|p| p.parse::<u16>().ok()) else {
                continue;
            };
            let state = child(port, "state")
                .and_then(|s| attr(s, "state"))
                .unwrap_or_else(|| "open".to_owned());
            if state != "open" && state != "open|filtered" {
                continue;
            }
            let protocol = attr(port, "protocol").unwrap_or_else(|| "tcp".to_owned());
            let service = child(port, "service");
            let tls = service.is_some_and(|s| s.attribute("tunnel") == Some("ssl"));
            let service_name = service.and_then(|s| attr(s, "name")).map(|name| {
                if tls && !name.contains("ssl") && name != "https" {
                    format!("ssl/{name}")
                } else {
                    name
                }
            });
            // conf 10 = probed and matched; "table" = guessed from the port number.
            let confidence = match service {
                Some(s)
                    if s.attribute("method") == Some("probed")
                        && s.attribute("conf") == Some("10") =>
                {
                    Confidence::High
                }
                Some(s) if s.attribute("method") == Some("table") => Confidence::Low,
                Some(_) => Confidence::Medium,
                None => Confidence::High,
            };
            let cpes = service
                .into_iter()
                .flat_map(|s| children(s, "cpe"))
                .filter_map(|c| c.text())
                .filter_map(to_cpe23)
                .collect();
            out.push(Observation::Port {
                address: address.clone(),
                port: number,
                protocol,
                state,
                service: service_name.clone(),
                product: service.and_then(|s| attr(s, "product")),
                version: service.and_then(|s| attr(s, "version")),
                extra_info: service.and_then(|s| attr(s, "extrainfo")),
                cpes,
                record: EvidenceRecord::observed(Source::NmapXml, confidence, raw(xml, port)),
            });

            let scheme = if tls || service_name.as_deref().is_some_and(|n| n.contains("https")) {
                "https"
            } else {
                "http"
            };
            for script in children(port, "script") {
                let output = script.attribute("output").unwrap_or("");
                match script.attribute("id") {
                    Some("ssl-cert") => {
                        for san in sans_from_ssl_cert(output) {
                            out.push(Observation::TlsSan {
                                address: address.clone(),
                                port: number,
                                san,
                                record: EvidenceRecord::observed(
                                    Source::TlsSan,
                                    Confidence::High,
                                    output,
                                ),
                            });
                        }
                    }
                    Some("http-server-header") => out.push(Observation::Http {
                        address: address.clone(),
                        port: number,
                        scheme: scheme.to_owned(),
                        server: Some(output.to_owned()),
                        location: None,
                        record: EvidenceRecord::observed(
                            Source::HttpHeader,
                            Confidence::High,
                            raw(xml, script),
                        ),
                    }),
                    Some("http-title") => {
                        if let Some(location) = redirect_from_title(output) {
                            out.push(Observation::Http {
                                address: address.clone(),
                                port: number,
                                scheme: scheme.to_owned(),
                                server: None,
                                location: Some(location),
                                record: EvidenceRecord::observed(
                                    Source::HttpHeader,
                                    Confidence::Medium,
                                    raw(xml, script),
                                ),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(out)
}

/// Open TCP ports per host in an Nmap XML document, for stage 2 of recon.
pub fn open_tcp_ports(xml: &str) -> Result<Vec<(String, Vec<u16>)>> {
    let mut by_host: Vec<(String, Vec<u16>)> = Vec::new();
    for observation in parse(xml)? {
        if let Observation::Port {
            address,
            port,
            protocol,
            state,
            ..
        } = observation
        {
            if protocol != "tcp" || state != "open" {
                continue;
            }
            match by_host.iter_mut().find(|(host, _)| *host == address) {
                Some((_, ports)) => ports.push(port),
                None => by_host.push((address, vec![port])),
            }
        }
    }
    Ok(by_host)
}

#[cfg(test)]
pub(crate) const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX out.xml 10.0.0.0/24" version="7.94">
<host starttime="1"><status state="up" reason="arp-response"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<address addr="00:0C:29:AA:BB:CC" addrtype="mac" vendor="VMware"/>
<hostnames><hostname name="App.Lab.Local" type="PTR"/></hostnames>
<ports>
<extraports state="closed" count="996"/>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:8.2p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.18.0" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:nginx:nginx:1.18.0</cpe></service>
<script id="ssl-cert" output="Subject: commonName=app.lab.local&#xa;Subject Alternative Name: DNS:app.lab.local, DNS:*.lab.local, IP Address:10.0.0.5&#xa;Not valid before: 2026-01-01"/>
<script id="http-server-header" output="nginx/1.18.0 (Ubuntu)"/>
<script id="http-title" output="Did not follow redirect to https://portal.lab.local/sso"/>
</port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy" method="table" conf="3"/></port>
<port protocol="tcp" portid="25"><state state="filtered"/><service name="smtp" method="table" conf="3"/></port>
<port protocol="udp" portid="161"><state state="open|filtered"/><service name="snmp" method="table" conf="3"/></port>
</ports>
<os><osmatch name="Linux 5.4" accuracy="96"/><osmatch name="Linux 4.15" accuracy="90"/></os>
</host>
<host><status state="down" reason="no-response"/><address addr="10.0.0.9" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="2001:DB8::A" addrtype="ipv6"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" method="probed" conf="10"/></port></ports></host>
</nmaprun>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Graph;

    #[test]
    fn sample_scan_becomes_hosts_ports_and_names() {
        let observations = parse(SAMPLE).unwrap();
        let mut graph = Graph::default();
        graph.apply_all(observations);

        assert_eq!(
            graph.hosts.keys().collect::<Vec<_>>(),
            ["10.0.0.5", "2001:db8::a"]
        );
        let host = &graph.hosts["10.0.0.5"];
        assert_eq!(host.os.as_deref(), Some("Linux 5.4"));
        assert_eq!(host.mac.as_deref(), Some("00:0C:29:AA:BB:CC"));
        assert_eq!(
            host.hostnames.iter().collect::<Vec<_>>(),
            ["app.lab.local", "portal.lab.local"]
        );
        // Filtered ports are not recorded; open|filtered UDP is.
        assert_eq!(
            host.ports.keys().collect::<Vec<_>>(),
            ["161/udp", "22/tcp", "443/tcp", "8080/tcp"]
        );

        let ssh = &host.ports["22/tcp"];
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(
            ssh.cpes.iter().collect::<Vec<_>>(),
            [
                "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*",
                "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
            ]
        );
        assert_eq!(ssh.facts[0].record.confidence, Confidence::High);
        assert!(ssh.facts[0]
            .record
            .evidence
            .starts_with("<port protocol=\"tcp\" portid=\"22\">"));

        let https = &host.ports["443/tcp"];
        assert_eq!(https.service.as_deref(), Some("ssl/http"));
        assert_eq!(https.web_scheme(), Some("https"));
        assert_eq!(
            https.tls_sans.iter().collect::<Vec<_>>(),
            ["*.lab.local", "app.lab.local"]
        );
        let http = https.http.as_ref().unwrap();
        assert_eq!(http.server.as_deref(), Some("nginx/1.18.0 (Ubuntu)"));
        assert_eq!(
            http.location.as_deref(),
            Some("https://portal.lab.local/sso")
        );

        // A service guessed from the port number is low confidence.
        assert_eq!(
            host.ports["8080/tcp"].facts[0].record.confidence,
            Confidence::Low
        );
        assert!(!host.ports["161/udp"].is_open());
        assert_eq!(
            graph.hosts["2001:db8::a"].ports["80/tcp"].web_scheme(),
            Some("http")
        );
    }

    #[test]
    fn open_tcp_ports_feed_the_service_stage() {
        assert_eq!(
            open_tcp_ports(SAMPLE).unwrap(),
            [
                ("10.0.0.5".to_owned(), vec![22, 443, 8080]),
                ("2001:db8::a".to_owned(), vec![80]),
            ]
        );
    }

    #[test]
    fn bad_input_is_an_error_not_a_panic() {
        assert!(parse("").is_err());
        assert!(parse("<nmaprun><host>").is_err());
        let err = parse("<html><body/></html>").unwrap_err();
        assert!(err.to_string().contains("not an Nmap XML file"));
        // Hosts without an address or ports without a number are skipped.
        let odd = r#"<nmaprun><host><status state="up"/></host>
            <host><address addr="10.0.0.7" addrtype="ipv4"/><ports><port protocol="tcp" portid="x"/></ports></host></nmaprun>"#;
        assert_eq!(parse(odd).unwrap().len(), 1);
    }

    #[test]
    fn entity_expansion_is_bounded() {
        let bomb = r#"<?xml version="1.0"?><!DOCTYPE nmaprun [
            <!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
            <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
            <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;"><!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
            <!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;"><!ENTITY h "&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;">
        ]><nmaprun><host><address addr="&h;" addrtype="ipv4"/></host></nmaprun>"#;
        // Either rejected or parsed without producing a host; never a hang.
        assert!(parse(bomb).map(|o| o.is_empty()).unwrap_or(true));
    }
}

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

/// The most of one attribute that is read. The graph keeps a line of a
/// product, a version or a name; megabytes of one are not carried along.
const MAX_ATTR: usize = 8 * 1024;

fn attr(node: Node<'_, '_>, name: &str) -> Option<String> {
    node.attribute(name)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| crate::evidence::head(v, MAX_ATTR).to_owned())
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

/// Ports tried and not open: (protocol, state) -> (count, port ranges).
type NotOpenGroups = std::collections::BTreeMap<(String, String), (u32, Vec<(u16, u16)>)>;

/// `1-21,23` as ranges; anything else in the list is skipped.
fn port_ranges(list: &str, into: &mut Vec<(u16, u16)>) {
    for part in list.split(',').take(4096) {
        let (low, high) = part.split_once('-').unwrap_or((part, part));
        if let (Ok(low), Ok(high)) = (low.trim().parse::<u16>(), high.trim().parse::<u16>()) {
            if low <= high {
                into.push((low, high));
            }
        }
    }
}

/// Ranges sorted and joined where they touch or overlap.
fn merge_ranges(mut ranges: Vec<(u16, u16)>) -> Vec<(u16, u16)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u16, u16)> = Vec::new();
    for (low, high) in ranges {
        match merged.last_mut() {
            Some(last) if u32::from(low) <= u32::from(last.1) + 1 => last.1 = last.1.max(high),
            _ => merged.push((low, high)),
        }
    }
    merged
}

/// Ranges as nmap writes them: sorted, joined where they touch.
fn format_ranges(ranges: Vec<(u16, u16)>) -> String {
    merge_ranges(ranges)
        .iter()
        .map(|&(low, high)| {
            if low == high {
                low.to_string()
            } else {
                format!("{low}-{high}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The ports of `tried` that are in none of the `known` ranges, as ranges.
fn unlisted_ports(tried: &[(u16, u16)], known: Vec<(u16, u16)>) -> Vec<(u16, u16)> {
    let known = merge_ranges(known);
    let (mut out, mut next) = (Vec::new(), 0);
    for (low, high) in merge_ranges(tried.to_vec()) {
        let mut from = u32::from(low);
        while known.get(next).is_some_and(|k| u32::from(k.1) < from) {
            next += 1;
        }
        for &(k_low, k_high) in known[next..].iter().take_while(|k| k.0 <= high) {
            if u32::from(k_low) > from {
                out.push((from as u16, k_low - 1));
            }
            from = from.max(u32::from(k_high) + 1);
        }
        if from <= u32::from(high) {
            out.push((from as u16, high));
        }
    }
    out
}

/// The target of "Did not follow redirect to `<url>`" in an `http-title`.
fn redirect_from_title(output: &str) -> Option<String> {
    let rest = output.split("redirect to ").nth(1)?;
    let url = rest.split_whitespace().next()?;
    WebUrl::parse(url).map(|_| url.to_owned())
}

fn clean_mac(raw: &str) -> Option<String> {
    let sep = if raw.contains(':') { ':' } else { '-' };
    let parts: Vec<&str> = raw.trim().split(sep).collect();
    if parts.len() != 6
        || !parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(
        parts
            .into_iter()
            .map(|p| p.to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// nmap nests its elements about eight deep.
const MAX_DEPTH: usize = 64;
/// Elements and the text between them. A full 50 MB of nmap's XML holds
/// about a million.
const MAX_NODES: u32 = 4_000_000;
/// Names read from one certificate, names of one host, groups of ports that
/// were not open, CPEs per service, and scripts per port/host: what the graph
/// keeps of each at most.
const MAX_NAMES_PER_CERT: usize = 128;
const MAX_NAMES_PER_HOST: usize = 16;
const MAX_NOT_OPEN_GROUPS: usize = 16;
const MAX_CPES_PER_PORT: usize = 64;
const MAX_SCRIPTS_PER_TARGET: usize = 64;
/// How much of one script's output is carried along. The graph keeps 2,000
/// bytes of it; a certificate that lists 160,000 names is megabytes.
const SCRIPT_OUTPUT_MAX: usize = 8000;

fn declares_entities(xml: &str) -> bool {
    let bytes = xml.as_bytes();
    bytes
        .windows(8)
        .any(|w| w.starts_with(b"<!") && w[2..].eq_ignore_ascii_case(b"ENTITY"))
}

/// Whether the elements of `xml` are nested more than `limit` deep. The
/// parser descends once per level, and a stack that overflows cannot be
/// caught: this has to be known before it starts.
fn nested_deeper_than(xml: &str, limit: usize) -> bool {
    let bytes = xml.as_bytes();
    let skip_to = |from: usize, end: &[u8]| -> usize {
        if from >= bytes.len() {
            return bytes.len();
        }
        bytes[from..]
            .windows(end.len())
            .position(|window| window == end)
            .map_or(bytes.len(), |at| from + at + end.len())
    };
    let (mut depth, mut at) = (0usize, 0usize);
    while at < bytes.len() {
        if bytes[at] != b'<' {
            at += 1;
            continue;
        }
        let rest = &bytes[at..];
        if rest.starts_with(b"<!--") {
            at = skip_to(at + 4, b"-->");
        } else if rest.starts_with(b"<![CDATA[") {
            at = skip_to(at + 9, b"]]>");
        } else if rest.starts_with(b"<?") {
            at = skip_to(at + 2, b"?>");
        } else if rest.starts_with(b"<!") {
            // `<!DOCTYPE ...>` may hold quoted literals, `[...]` internal
            // subsets, comments, or PIs containing `>` or `<![CDATA[`.
            let (mut i, mut brackets, mut quote) = (at + 2, 0usize, 0u8);
            while i < bytes.len() {
                if quote != 0 {
                    if bytes[i] == quote {
                        quote = 0;
                    }
                    i += 1;
                } else if bytes[i..].starts_with(b"<!--") {
                    i = skip_to(i + 4, b"-->");
                } else if bytes[i..].starts_with(b"<?") {
                    i = skip_to(i + 2, b"?>");
                } else {
                    match bytes[i] {
                        b'"' | b'\'' => quote = bytes[i],
                        b'[' => brackets += 1,
                        b']' => brackets = brackets.saturating_sub(1),
                        b'>' if brackets == 0 => {
                            i += 1;
                            break;
                        }
                        _ => {}
                    }
                    i += 1;
                }
            }
            at = i;
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            at = skip_to(at + 2, b">");
        } else {
            // A start tag ends at the first `>` outside a quoted value.
            let (mut end, mut quote) = (at + 1, 0u8);
            while end < bytes.len() {
                match bytes[end] {
                    b if quote != 0 && b == quote => quote = 0,
                    b'"' | b'\'' if quote == 0 => quote = bytes[end],
                    b'>' if quote == 0 => break,
                    _ => {}
                }
                end += 1;
            }
            if end < bytes.len() && bytes.get(end.wrapping_sub(1)) != Some(&b'/') {
                depth += 1;
                if depth > limit {
                    return true;
                }
            }
            at = end.saturating_add(1);
        }
    }
    false
}

/// Reads nmap's XML. `trusted_names`: the file is the output of the scan
/// this session ran, so the name it was pointed at (`type="user"`) is the
/// scanner's own resolution. Any other file (`meow add`) only claims it:
/// whoever wrote it chose the name and the address alike.
pub fn parse(xml: &str, trusted_names: bool) -> Result<Vec<Observation>> {
    // nmap writes `<!DOCTYPE nmaprun>` and declares nothing. A file that
    // declares entities of its own can make a few kilobytes stand for
    // gigabytes: a reference to one is replaced by its text each time.
    if declares_entities(xml) {
        anyhow::bail!("the file declares its own XML entities, which nmap never writes");
    }
    if nested_deeper_than(xml, MAX_DEPTH) {
        anyhow::bail!("the file's XML is nested more than {MAX_DEPTH} elements deep");
    }
    let options = ParsingOptions {
        allow_dtd: true, // nmap writes <!DOCTYPE nmaprun>
        nodes_limit: MAX_NODES,
        // External entities are never fetched or read: with no resolver
        // roxmltree drops them, and a reference to one is an error.
        entity_resolver: None,
    };
    let doc = Document::parse_with_options(xml, options).context("not well-formed XML")?;
    let root = doc.root_element();
    if !root.has_tag_name("nmaprun") {
        anyhow::bail!(
            "not an Nmap XML file (root element is <{}>)",
            root.tag_name().name()
        );
    }

    // What this session's own scan tried, by protocol: a port it tried and
    // did not list is in one of the host's `<extraports>` groups.
    let mut scanned: std::collections::BTreeMap<String, Vec<(u16, u16)>> =
        std::collections::BTreeMap::new();
    // Whether the scan of each protocol tells an open port from a closed or
    // filtered one. An ACK or window scan does not test openness, and a
    // FIN, NULL, Xmas or Maimon scan gets "closed" from every port of some
    // systems.
    let mut tells_open: std::collections::BTreeMap<String, bool> =
        std::collections::BTreeMap::new();
    if trusted_names {
        for info in children(root, "scaninfo").take(MAX_NOT_OPEN_GROUPS) {
            let Some(protocol) =
                attr(info, "protocol").and_then(|p| crate::graph::normalize_protocol(&p))
            else {
                continue;
            };
            let tells = attr(info, "type").is_some_and(|kind| {
                matches!(kind.as_str(), "syn" | "connect" | "udp" | "sctpinit")
            });
            *tells_open.entry(protocol.clone()).or_insert(tells) &= tells;
            port_ranges(
                info.attribute("services").unwrap_or(""),
                scanned.entry(protocol).or_default(),
            );
        }
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
                Some("mac") => mac = attr(node, "addr").and_then(|m| clean_mac(&m)),
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
        let os_known = os.is_some();
        let host_evidence = child(host, "status").map_or("", |s| raw(xml, s));
        out.push(Observation::Host {
            address: address.clone(),
            os,
            mac,
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, host_evidence),
        });

        if let Some(names) = child(host, "hostnames") {
            for name in children(names, "hostname").take(MAX_NAMES_PER_HOST) {
                if let Some(hostname) = attr(name, "name") {
                    // `user`: the name the scan was pointed at, resolved by
                    // the scanner. Anything else (`PTR`) is what the owner
                    // of the address makes its reverse record say.
                    let asked_for =
                        trusted_names && attr(name, "type").is_some_and(|kind| kind == "user");
                    out.push(Observation::Hostname {
                        address: address.clone(),
                        hostname,
                        record: EvidenceRecord::observed(
                            Source::NmapXml,
                            if asked_for {
                                Confidence::High
                            } else {
                                Confidence::Medium
                            },
                            raw(xml, name),
                        ),
                    });
                }
            }
        }

        host_scripts(xml, host, &address, os_known, &mut out);

        let Some(ports) = child(host, "ports") else {
            continue;
        };
        // What was tried and not open: (protocol, state) -> (count, ranges).
        let mut not_open: NotOpenGroups = NotOpenGroups::new();
        // The `<extraports>` states of each protocol, and the ports listed one by one.
        let mut extra_states: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        let mut listed: std::collections::BTreeSet<(String, u16)> =
            std::collections::BTreeSet::new();
        // The protocols on which the host answered some port (open, closed
        // or unfiltered). With every port filtered, nothing answered: a
        // blocked or dropped scan, or a host that is off, says nothing
        // about the ports.
        let mut answered: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let answers = |state: &str| matches!(state, "open" | "closed" | "unfiltered");
        for extra in children(ports, "extraports") {
            let state = attr(extra, "state").unwrap_or_else(|| "closed".to_owned());
            let count = extra
                .attribute("count")
                .and_then(|c| c.parse::<u32>().ok())
                .unwrap_or(0);
            let reasons: Vec<_> = children(extra, "extrareasons").collect();
            let protocol = match reasons.iter().find_map(|r| attr(*r, "proto")) {
                Some(raw_proto) => match crate::graph::normalize_protocol(&raw_proto) {
                    Some(valid) => valid,
                    None => continue,
                },
                None => "tcp".to_owned(),
            };
            if answers(&state) {
                answered.insert(protocol.clone());
            }
            let key = (protocol, state);
            if !not_open.contains_key(&key) && not_open.len() >= MAX_NOT_OPEN_GROUPS {
                continue;
            }
            let states = extra_states.entry(key.0.clone()).or_default();
            if !states.contains(&key.1) {
                states.push(key.1.clone());
            }
            let group = not_open.entry(key).or_default();
            group.0 = group.0.saturating_add(count);
            for reason in reasons {
                port_ranges(reason.attribute("ports").unwrap_or(""), &mut group.1);
            }
        }
        for port in children(ports, "port") {
            let Some(number) = port.attribute("portid").and_then(|p| p.parse::<u16>().ok()) else {
                continue;
            };
            let protocol = match attr(port, "protocol") {
                Some(raw_proto) => match crate::graph::normalize_protocol(&raw_proto) {
                    Some(valid) => valid,
                    None => continue,
                },
                None => "tcp".to_owned(),
            };
            let state = child(port, "state")
                .and_then(|s| attr(s, "state"))
                .unwrap_or_else(|| "open".to_owned());
            listed.insert((protocol.clone(), number));
            if answers(&state) {
                answered.insert(protocol.clone());
            }
            if state != "open" && state != "open|filtered" {
                let key = (protocol, state);
                if not_open.contains_key(&key) || not_open.len() < MAX_NOT_OPEN_GROUPS {
                    let group = not_open.entry(key).or_default();
                    group.0 = group.0.saturating_add(1);
                    group.1.push((number, number));
                }
                continue;
            }
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
                .take(MAX_CPES_PER_PORT)
                .collect();
            out.push(Observation::Port {
                address: address.clone(),
                port: number,
                protocol: protocol.clone(),
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
            for script in children(port, "script").take(MAX_SCRIPTS_PER_TARGET) {
                let output = script.attribute("output").unwrap_or("");
                match script.attribute("id") {
                    Some("ssl-cert") => {
                        for san in sans_from_ssl_cert(output)
                            .into_iter()
                            .take(MAX_NAMES_PER_CERT)
                        {
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
                        server: Some(crate::evidence::head(output, MAX_ATTR).to_owned()),
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
                // Every script's own words are kept, the three read above
                // included, so nothing nmap reported is lost.
                if let Some(id) = attr(script, "id") {
                    out.push(Observation::Script {
                        address: address.clone(),
                        port: Some(number),
                        protocol: protocol.clone(),
                        id,
                        output: crate::evidence::head(output, SCRIPT_OUTPUT_MAX).to_owned(),
                        record: EvidenceRecord::observed(
                            Source::NmapXml,
                            Confidence::High,
                            raw(xml, script),
                        ),
                    });
                }
            }
        }
        // An older nmap does not say which ports an `<extraports>` group
        // holds: the ports the scan tried and did not list are in it.
        for (protocol, tried) in &scanned {
            if let Some([state]) = extra_states.get(protocol).map(Vec::as_slice) {
                let key = (protocol.clone(), state.clone());
                if let Some(group) = not_open.get_mut(&key) {
                    let mut known = group.1.clone();
                    known.extend(
                        listed
                            .iter()
                            .filter(|(listed_protocol, _)| listed_protocol == protocol)
                            .map(|&(_, port)| (port, port)),
                    );
                    group.1.extend(unlisted_ports(tried, known));
                }
            }
        }
        for ((protocol, state), (count, ranges)) in not_open {
            let summary = format!(
                "<extraports protocol=\"{protocol}\" state=\"{state}\" count=\"{count}\"/>"
            );
            let own_scan = trusted_names
                && tells_open.get(&protocol) == Some(&true)
                && answered.contains(&protocol);
            out.push(Observation::NotOpen {
                address: address.clone(),
                protocol,
                state,
                count,
                ports: format_ranges(ranges),
                own_scan,
                record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, &summary),
            });
        }
    }
    Ok(out)
}

/// Host scripts (`<hostscript>`, e.g. `smb-os-discovery`) report on the
/// machine rather than a port. The SMB answer also names the operating
/// system when OS detection did not.
fn host_scripts(xml: &str, host: Node, address: &str, os_known: bool, out: &mut Vec<Observation>) {
    let Some(scripts) = child(host, "hostscript") else {
        return;
    };
    for script in children(scripts, "script").take(MAX_SCRIPTS_PER_TARGET) {
        let Some(id) = attr(script, "id") else {
            continue;
        };
        let output = script.attribute("output").unwrap_or("");
        let record = EvidenceRecord::observed(Source::NmapXml, Confidence::High, raw(xml, script));
        if id == "smb-os-discovery" && !os_known {
            let os = output
                .lines()
                .find_map(|line| line.trim().strip_prefix("OS:"))
                .map(|os| os.trim().to_owned())
                .filter(|os| !os.is_empty());
            if os.is_some() {
                out.push(Observation::Host {
                    address: address.to_owned(),
                    os,
                    mac: None,
                    record: record.clone(),
                });
            }
        }
        out.push(Observation::Script {
            address: address.to_owned(),
            port: None,
            protocol: "tcp".to_owned(),
            id,
            output: crate::evidence::head(output, SCRIPT_OUTPUT_MAX).to_owned(),
            record,
        });
    }
}

/// Open TCP ports per host in an Nmap XML document, for stage 2 of recon.
pub fn open_tcp_ports(xml: &str) -> Result<Vec<(String, Vec<u16>)>> {
    let mut by_host: Vec<(String, Vec<u16>)> = Vec::new();
    for observation in parse(xml, true)? {
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
    fn ports_tried_and_not_open_are_kept_by_state() {
        let xml = r#"<nmaprun><host><status state="up"/><address addr="192.0.2.7" addrtype="ipv4"/>
<ports><extraports state="closed" count="996"><extrareasons reason="conn-refused" count="996" proto="tcp" ports="1-21,23-79,81-442,444-1000"/></extraports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6p1"/></port>
<port protocol="tcp" portid="25"><state state="filtered"/></port>
<port protocol="tcp" portid="80"><state state="open"/></port>
<port protocol="tcp" portid="443"><state state="filtered"/></port>
</ports></host></nmaprun>"#;
        let mut graph = Graph::default();
        graph.apply_all(parse(xml, true).unwrap());
        let host = &graph.hosts["192.0.2.7"];
        assert_eq!(host.open_ports().count(), 2);
        let closed = &host.not_open["tcp closed"];
        assert_eq!(
            (closed.count, closed.ports.as_str()),
            (996, "1-21,23-79,81-442,444-1000")
        );
        let filtered = &host.not_open["tcp filtered"];
        assert_eq!((filtered.count, filtered.ports.as_str()), (2, "25,443"));
        // Older nmap gives only a count.
        let bare = r#"<nmaprun><host><status state="up"/><address addr="192.0.2.8" addrtype="ipv4"/>
<ports><extraports state="filtered" count="1000"/></ports></host></nmaprun>"#;
        graph.apply_all(parse(bare, true).unwrap());
        let group = &graph.hosts["192.0.2.8"].not_open["tcp filtered"];
        assert_eq!((group.count, group.ports.as_str()), (1000, ""));
        assert_eq!(
            format_ranges(vec![(5, 5), (1, 3), (4, 4), (10, 12), (11, 20)]),
            "1-5,10-20"
        );
    }

    #[test]
    fn a_rescan_that_finds_an_open_port_closed_closes_it() {
        // The first scan found 80 and 8080 open.
        let first = r#"<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
<port protocol="tcp" portid="8443"><state state="open"/></port>
<port protocol="tcp" portid="9000"><state state="open"/></port></ports></host></nmaprun>"#;
        // The rescan: 8080 listed as closed, 8443 in a group of closed
        // ports, 9000 tried (scaninfo) and not listed by an older nmap.
        let rescan = r#"<nmaprun><scaninfo type="syn" protocol="tcp" numservices="6" services="22,80,8080,8443,9000-9001"/>
<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports><extraports state="filtered" count="3"/>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.20.1"/></port>
<port protocol="tcp" portid="8080"><state state="closed"/></port>
<port protocol="tcp" portid="8443"><state state="filtered"/></port></ports></host></nmaprun>"#;
        let open = |graph: &Graph| {
            graph.hosts["192.0.2.10"]
                .open_ports()
                .map(|p| p.key())
                .collect::<Vec<_>>()
        };
        let mut graph = Graph::default();
        graph.apply_all(parse(first, true).unwrap());
        // The same file imported (`meow add`) closes nothing.
        graph.apply_all(parse(rescan, false).unwrap());
        assert_eq!(open(&graph), ["80/tcp", "8080/tcp", "8443/tcp", "9000/tcp"]);
        graph.apply_all(parse(rescan, true).unwrap());
        assert_eq!(open(&graph), ["80/tcp"]);
        let host = &graph.hosts["192.0.2.10"];
        assert_eq!(host.ports["8080/tcp"].state, "closed");
        assert_eq!(host.ports["8443/tcp"].state, "filtered");
        assert_eq!(host.ports["9000/tcp"].state, "filtered");
        assert_eq!(host.not_open["tcp filtered"].ports, "22,8443,9000-9001");
        // The port keeps its history.
        assert!(host.ports["8080/tcp"]
            .facts
            .iter()
            .any(|f| f.claim == "8080/tcp http nginx 1.18.0 open"));

        // Two groups and no list of ports: which port is in which is not known.
        let two = r#"<nmaprun><scaninfo type="syn" protocol="tcp" numservices="3" services="80,8080,9000"/>
<host><status state="up"/><address addr="192.0.2.11" addrtype="ipv4"/>
<ports><extraports state="filtered" count="1"/><extraports state="closed" count="1"/>
<port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>"#;
        for observation in parse(two, true).unwrap() {
            if let Observation::NotOpen {
                ports, own_scan, ..
            } = observation
            {
                assert_eq!((ports.as_str(), own_scan), ("", true));
            }
        }
        assert_eq!(
            unlisted_ports(
                &[(1, 10), (20, 30), (65535, 65535)],
                vec![(3, 4), (8, 22), (5, 5)]
            ),
            [(1, 2), (6, 7), (23, 30), (65535, 65535)]
        );
    }

    #[test]
    fn a_rescan_that_got_no_answer_or_cannot_tell_closes_nothing() {
        let first = r#"<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/></port>
<port protocol="tcp" portid="8080"><state state="open"/></port></ports></host></nmaprun>"#;
        let rescan = |kind: &str, ports: &str| {
            format!(
                r#"<nmaprun><scaninfo type="{kind}" protocol="tcp" numservices="1001" services="1-1000,8080"/>
<host><status state="up" reason="user-set"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports>{ports}</ports></host></nmaprun>"#
            )
        };
        let all = |state: &str| {
            format!(
                r#"<extraports state="{state}" count="1001"><extrareasons reason="no-response" count="1001" proto="tcp" ports="1-1000,8080"/></extraports>"#
            )
        };
        let open = |xml: &str| {
            let mut graph = Graph::default();
            graph.apply_all(parse(first, true).unwrap());
            graph.apply_all(parse(xml, true).unwrap());
            graph.hosts["192.0.2.10"]
                .open_ports()
                .map(|p| p.key())
                .collect::<Vec<_>>()
        };
        // Nothing answered (`-Pn`, a blocked or dropped scan, a host that
        // is off): every port filtered says nothing about them.
        assert_eq!(
            open(&rescan("syn", &all("filtered"))),
            ["80/tcp", "8080/tcp"]
        );
        // An ACK scan does not test openness; a FIN scan gets "closed"
        // from every port of some systems.
        assert_eq!(
            open(&rescan("ack", &all("filtered"))),
            ["80/tcp", "8080/tcp"]
        );
        assert_eq!(open(&rescan("fin", &all("closed"))), ["80/tcp", "8080/tcp"]);
        // No scaninfo: what the scan tested is not known.
        let bare = rescan("syn", &all("closed")).replace(
            r#"<scaninfo type="syn" protocol="tcp" numservices="1001" services="1-1000,8080"/>"#,
            "",
        );
        assert_eq!(open(&bare), ["80/tcp", "8080/tcp"]);
        // The host answered on 80: 8080, dropped now, is filtered.
        let answered = r#"<extraports state="filtered" count="1000"><extrareasons reason="no-response" count="1000" proto="tcp" ports="1-79,81-1000,8080"/></extraports>
<port protocol="tcp" portid="80"><state state="open"/></port>"#;
        assert_eq!(open(&rescan("syn", answered)), ["80/tcp"]);
        // A closed port is an answer too: a host with every service off.
        assert!(open(&rescan("connect", &all("closed"))).is_empty());
    }

    #[test]
    fn only_the_sessions_own_scan_resolves_the_name_it_was_given() {
        let xml = r#"<nmaprun><host><status state="up"/><address addr="198.51.100.66" addrtype="ipv4"/>
<hostnames><hostname name="intranet.example" type="user"/><hostname name="ptr.example" type="PTR"/></hostnames></host></nmaprun>"#;
        let confidence = |trusted: bool| -> Vec<(String, Confidence)> {
            parse(xml, trusted)
                .unwrap()
                .into_iter()
                .filter_map(|o| match o {
                    Observation::Hostname {
                        hostname, record, ..
                    } => Some((hostname, record.confidence)),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(
            confidence(true),
            [
                ("intranet.example".to_owned(), Confidence::High),
                ("ptr.example".to_owned(), Confidence::Medium)
            ]
        );
        // A file anyone may have written only claims it.
        assert!(confidence(false)
            .iter()
            .all(|(_, confidence)| *confidence == Confidence::Medium));
    }

    #[test]
    fn an_attribute_of_megabytes_is_not_carried_along() {
        let long = "A".repeat(2 * 1024 * 1024);
        let xml = format!(
            r#"<nmaprun><host><status state="up"/><address addr="192.0.2.77" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="{long}" version="1.0"/>
<script id="http-server-header" output="{long}"/></port></ports></host></nmaprun>"#
        );
        for observation in parse(&xml, true).unwrap() {
            match observation {
                Observation::Port { product, .. } => {
                    assert_eq!(product.map(|p| p.len()), Some(MAX_ATTR));
                }
                Observation::Http { server, .. } => {
                    assert_eq!(server.map(|s| s.len()), Some(MAX_ATTR));
                }
                _ => {}
            }
        }
    }

    #[test]
    fn sample_scan_becomes_hosts_ports_and_names() {
        let observations = parse(SAMPLE, true).unwrap();
        let mut graph = Graph::default();
        graph.apply_all(observations);

        assert_eq!(
            graph.hosts.keys().collect::<Vec<_>>(),
            ["10.0.0.5", "2001:db8::a"]
        );
        let host = &graph.hosts["10.0.0.5"];
        assert_eq!(host.os.as_deref(), Some("Linux 5.4"));
        assert_eq!(host.mac.as_deref(), Some("00:0C:29:AA:BB:CC"));
        assert_eq!(host.hostnames.iter().collect::<Vec<_>>(), ["app.lab.local"]);
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
    fn every_script_result_is_kept_and_smb_names_the_system() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV --script default -oX out.xml 192.0.2.10" version="7.94">
<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="for_Windows_9.5"/>
<script id="ssh-hostkey" output="&#xa;  256 aa:bb:cc (ECDSA)&#xa;  256 dd:ee:ff (ED25519)"/>
</port></ports>
<hostscript><script id="smb-os-discovery" output="&#xa;  OS: Windows 11 Pro 26100 (Windows 11 Pro 6.3)&#xa;  Computer name: example-pc"/>
<script id="smb2-security-mode" output="&#xa;  3:1:1: &#xa;    Message signing enabled but not required"/></hostscript>
</host></nmaprun>"#;
        let mut graph = Graph::default();
        graph.apply_all(parse(xml, true).unwrap());
        let host = &graph.hosts["192.0.2.10"];
        assert_eq!(
            host.os.as_deref(),
            Some("Windows 11 Pro 26100 (Windows 11 Pro 6.3)"),
            "no OS scan ran, so the SMB answer names the system"
        );
        let claims: Vec<&str> = host.facts.iter().map(|f| f.claim.as_str()).collect();
        assert!(
            claims
                .iter()
                .any(|c| c.starts_with("nmap script smb2-security-mode:")
                    && c.contains("Message signing enabled but not required")),
            "{claims:?}"
        );
        let port = &host.ports["22/tcp"];
        assert!(
            port.facts
                .iter()
                .any(|f| f.claim.starts_with("nmap script ssh-hostkey:")
                    && f.claim.contains("dd:ee:ff (ED25519)")),
            "{:?}",
            port.facts
        );
        assert!(port
            .facts
            .iter()
            .all(|f| f.record.source == Source::NmapXml));
    }

    #[test]
    fn bad_input_is_an_error_not_a_panic() {
        assert!(parse("", true).is_err());
        assert!(parse("<nmaprun><host>", true).is_err());
        let err = parse("<html><body/></html>", true).unwrap_err();
        assert!(err.to_string().contains("not an Nmap XML file"));
        // Hosts without an address or ports without a number are skipped.
        let odd = r#"<nmaprun><host><status state="up"/></host>
            <host><address addr="10.0.0.7" addrtype="ipv4"/><ports><port protocol="tcp" portid="x"/></ports></host></nmaprun>"#;
        assert_eq!(parse(odd, true).unwrap().len(), 1);
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
        assert!(parse(bomb, true).map(|o| o.is_empty()).unwrap_or(true));
    }

    #[test]
    fn a_small_hostile_file_cannot_take_the_memory_or_the_stack() {
        let started = std::time::Instant::now();
        // 23 KB that stand for 5.7 GB: entity a is 4,000 bytes, b is 250
        // times a, and one attribute holds 6,000 times b. Not nested deep
        // enough for the parser's own limit to see it.
        let bomb = format!(
            "<?xml version=\"1.0\"?><!DOCTYPE nmaprun [<!ENTITY a \"{}\"><!ENTITY b \"{}\">]>\
             <nmaprun><host><address addr=\"{}\" addrtype=\"ipv4\"/></host></nmaprun>",
            "a".repeat(4000),
            "&a;".repeat(250),
            "&b;".repeat(6000)
        );
        assert!(bomb.len() < 30_000);
        let error = format!("{:#}", parse(&bomb, true).unwrap_err());
        assert!(error.contains("declares its own XML entities"), "{error}");

        // 1,500 elements inside one another (10 KB) ended the program on a
        // stack overflow. So would 2,000,000 in a file of the size allowed.
        for depth in [1500usize, 2_000_000] {
            let deep = format!(
                "<nmaprun>{}{}</nmaprun>",
                "<a>".repeat(depth),
                "</a>".repeat(depth)
            );
            let error = format!("{:#}", parse(&deep, true).unwrap_err());
            assert!(
                error.contains("nested more than 64 elements deep"),
                "{error}"
            );
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(20));

        // What nmap writes is not deep, however much of it there is, and a
        // `>` or a tag-like text inside a value or a comment is not a level.
        assert!(!nested_deeper_than(SAMPLE, 8), "nmap's own output");
        assert!(nested_deeper_than(SAMPLE, 3));
        let wide = format!(
            "<r>{}</r>",
            "<a b=\"x>y\" c='<z>'/><!-- <d><d><d> --><e></e>".repeat(1000)
        );
        assert!(!nested_deeper_than(&wide, 2));
        assert!(nested_deeper_than("<a><b><c/></b></a>", 1));
        assert!(!nested_deeper_than("<a><b><c/></b></a>", 2));
        assert!(!nested_deeper_than("<![CDATA[<a><a><a>]]><?pi <a><a>?>", 0));
        assert!(
            parse(SAMPLE, true).is_ok(),
            "the DOCTYPE nmap writes is fine"
        );
    }

    #[test]
    fn one_element_yields_a_bounded_number_of_facts() {
        // A certificate with 160,000 names, a host with 4,000 kinds of
        // "not open" and 2 MB of padding before its ports, and 500 names.
        let names: String = (0..160_000)
            .map(|n| format!("DNS:n{n}.example, "))
            .collect();
        let states: String = (0..4000)
            .map(|n| {
                format!(
                    "<port protocol=\"tcp\" portid=\"{}\"><state state=\"s{n}\"/></port>",
                    n % 60000 + 1
                )
            })
            .collect();
        let hostnames: String = (0..500)
            .map(|n| format!("<hostname name=\"h{n}.example\" type=\"PTR\"/>"))
            .collect();
        let xml = format!(
            "<nmaprun><host><status state=\"up\"/><address addr=\"10.0.0.5\" addrtype=\"ipv4\"/>\
             <hostnames>{hostnames}</hostnames><ports>{}{states}\
             <extraports state=\"closed\" count=\"4294967295\"/><extraports state=\"closed\" count=\"4294967295\"/>\
             <port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/>\
             <script id=\"ssl-cert\" output=\"Subject Alternative Name: {names}\"/></port></ports></host></nmaprun>",
            " ".repeat(2 * 1024 * 1024)
        );
        let started = std::time::Instant::now();
        let observations = parse(&xml, true).unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        let count =
            |wanted: fn(&Observation) -> bool| observations.iter().filter(|o| wanted(o)).count();
        assert_eq!(
            count(|o| matches!(o, Observation::TlsSan { .. })),
            MAX_NAMES_PER_CERT
        );
        assert_eq!(
            count(|o| matches!(o, Observation::NotOpen { .. })),
            MAX_NOT_OPEN_GROUPS
        );
        assert_eq!(
            count(|o| matches!(o, Observation::Hostname { .. })),
            MAX_NAMES_PER_HOST
        );
        // Two counts that do not fit a number together do not end the program.
        assert!(observations.iter().any(|o| matches!(o, Observation::NotOpen { state, count, .. } if state == "closed" && *count == u32::MAX)));
        // Each record is cut from the start of its source, not walked whole.
        let weight: usize = observations
            .iter()
            .map(|o| serde_json::to_string(o).unwrap().len())
            .sum();
        assert!(weight < 2 * 1024 * 1024, "{weight}");
    }

    #[test]
    fn invalid_or_escape_injected_port_protocols_are_skipped() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.15" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp&#x9d;52;c;abc&#x9c;" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="evil" portid="8080">
        <state state="open"/>
      </port>
      <port portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH"/>
      </port>
      <port protocol="SCTP" portid="3868">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;
        let observations = parse(xml, true).unwrap();
        let mut graph = Graph::default();
        graph.apply_all(observations);
        let host = &graph.hosts["192.0.2.15"];
        assert_eq!(
            host.ports.keys().collect::<Vec<_>>(),
            ["22/tcp", "3868/sctp"]
        );
    }

    #[test]
    fn depth_scanner_resists_comment_pi_and_doctype_cdata_desync_and_caps_scripts() {
        let deep_body = format!(
            "<nmaprun>{}{}</nmaprun>",
            "<a>".repeat(200),
            "</a>".repeat(200)
        );
        for crafted in [
            format!("<!--><![CDATA[ -->{deep_body}"),
            format!("<?><![CDATA[ ?>{deep_body}"),
            format!("<!DOCTYPE nmaprun [ <!-- > <![CDATA[ --> ]>{deep_body}"),
        ] {
            assert!(
                nested_deeper_than(&crafted, MAX_DEPTH),
                "depth bypass was not caught: {}",
                &crafted[..48]
            );
            let err = format!("{:#}", parse(&crafted, true).unwrap_err());
            assert!(err.contains("nested more than 64 elements deep"), "{err}");
        }

        let lower_entity =
            "<?xml version=\"1.0\"?><!DOCTYPE nmaprun [<!entity a \"x\">]><nmaprun/>";
        assert!(format!("{:#}", parse(lower_entity, true).unwrap_err()).contains("XML entities"));

        let cpes: String = (0..300)
            .map(|n| format!("<cpe>cpe:/a:vendor:p{n}:1.0</cpe>"))
            .collect();
        let scripts: String = (0..300)
            .map(|n| format!("<script id=\"s{n}\" output=\"ok\"/>"))
            .collect();
        let xml = format!(
            "<nmaprun><host><status state=\"up\"/><address addr=\"192.0.2.99\" addrtype=\"ipv4\"/>\
             <ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>\
             <service name=\"http\">{cpes}</service>{scripts}</port></ports></host></nmaprun>"
        );
        let obs = parse(&xml, true).unwrap();
        let port_cpes = obs
            .iter()
            .find_map(|o| match o {
                Observation::Port { cpes, .. } => Some(cpes.len()),
                _ => None,
            })
            .unwrap();
        assert_eq!(port_cpes, MAX_CPES_PER_PORT);
        let script_count = obs
            .iter()
            .filter(|o| matches!(o, Observation::Script { .. }))
            .count();
        assert_eq!(script_count, MAX_SCRIPTS_PER_TARGET);
    }
}

//! DNS lookups: the `dns` stage, record parsing, UDP and DNS-over-HTTPS resolvers.

use super::*;

// ---------------------------------------------------------------------------
// 1. DNS (`dns` task) — DoH JSON + RFC 1035 UDP wire query + system resolver
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSummary {
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub cname: Vec<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
    pub ptr: Vec<String>,
}

/// Converts an IPv4 or IPv6 address into its reverse DNS `.in-addr.arpa` or
/// `.ip6.arpa` domain name for `PTR` queries.
pub fn reverse_dns_name(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut nibbles = Vec::with_capacity(32);
            for byte in v6.octets().iter().rev() {
                nibbles.push(format!("{:x}", byte & 0x0f));
                nibbles.push(format!("{:x}", byte >> 4));
            }
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

/// Converts an IPv4 or IPv6 address into its Team Cymru DNS origin zone name.
pub fn cymru_origin_name(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.origin.asn.cymru.com")
        }
        IpAddr::V6(v6) => {
            let mut nibbles = Vec::with_capacity(32);
            for byte in v6.octets().iter().rev() {
                nibbles.push(format!("{:x}", byte & 0x0f));
                nibbles.push(format!("{:x}", byte >> 4));
            }
            format!("{}.origin6.asn.cymru.com", nibbles.join("."))
        }
    }
}

/// Filters DNS `TXT` records for security-relevant and ownership tokens
/// (SPF, DMARC, DKIM, domain verification tokens).
pub fn is_notable_txt(txt: &str) -> bool {
    let lower = txt.trim().trim_matches('"').to_ascii_lowercase();
    lower.starts_with("v=spf1")
        || lower.starts_with("spf2.")
        || lower.starts_with("v=dmarc1")
        || lower.starts_with("v=dkim1")
        || lower.contains("-verification=")
        || lower.contains("_verification=")
        || lower.starts_with("google-site-verification=")
        || lower.starts_with("ms=")
        || lower.starts_with("docusign=")
        || lower.starts_with("apple-domain-verification=")
        || lower.starts_with("atlassian-domain-verification=")
        || lower.starts_with("facebook-domain-verification=")
        || lower.starts_with("stripe-verification=")
        || lower.starts_with("have-i-been-pwned-verification=")
        || lower.starts_with("protonmail-verification=")
}

/// Parses a DNS-over-HTTPS (Cloudflare / Google JSON schema) response for
/// the requested numeric record type (`rrtype`).
pub fn parse_doh_records(json: &Value, rrtype: u16) -> Vec<String> {
    let mut out = Vec::new();
    let Some(answers) = json.get("Answer").and_then(Value::as_array) else {
        return out;
    };
    for ans in answers {
        let Some(kind) = ans.get("type").and_then(Value::as_u64) else {
            continue;
        };
        if kind as u16 != rrtype {
            continue;
        }
        let Some(raw) = ans.get("data").and_then(Value::as_str) else {
            continue;
        };
        let cleaned = sanitize(raw.trim().trim_matches('"').trim_end_matches('.'), 400);
        if !cleaned.is_empty() && !out.contains(&cleaned) {
            out.push(cleaned);
        }
    }
    out
}

/// Builds a minimal RFC 1035 DNS query packet for `qname` and `qtype`.
pub fn build_dns_query(txid: u16, qname: &str, qtype: u16) -> Result<Vec<u8>> {
    let trimmed = qname.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        bail!("invalid DNS name '{qname}'");
    }
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&txid.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // RD = 1
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS label in '{qname}'");
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Ok(packet)
}

fn read_dns_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_offset = offset;
    let mut hops = 0usize;
    loop {
        if hops > 64 || offset >= packet.len() {
            return None;
        }
        hops += 1;
        let len = packet[offset];
        if len == 0 {
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (packet[offset + 1] as usize);
            if !jumped {
                end_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            continue;
        }
        if (len & 0xC0) != 0 {
            return None;
        }
        let label_len = len as usize;
        offset += 1;
        if offset + label_len > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[offset..offset + label_len]).ok()?;
        labels.push(label.to_owned());
        offset += label_len;
    }
    Some((labels.join("."), end_offset))
}

/// Parses an RFC 1035 DNS wire response for `expected_txid` and `qtype`.
pub fn parse_dns_wire_response(packet: &[u8], expected_txid: u16, qtype: u16) -> Vec<String> {
    let mut out = Vec::new();
    if packet.len() < 12 {
        return out;
    }
    let txid = u16::from_be_bytes([packet[0], packet[1]]);
    if txid != expected_txid {
        return out;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 {
        return out;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..qdcount {
        let Some((_, next)) = read_dns_name(packet, offset) else {
            return out;
        };
        if next + 4 > packet.len() {
            return out;
        }
        offset = next + 4;
    }
    for _ in 0..ancount.min(64) {
        let Some((_, next)) = read_dns_name(packet, offset) else {
            break;
        };
        if next + 10 > packet.len() {
            break;
        }
        let rtype = u16::from_be_bytes([packet[next], packet[next + 1]]);
        let rdlen = u16::from_be_bytes([packet[next + 8], packet[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start.saturating_add(rdlen);
        if rdata_end > packet.len() {
            break;
        }
        offset = rdata_end;
        if rtype != qtype {
            continue;
        }
        let rdata = &packet[rdata_start..rdata_end];
        let parsed = match rtype {
            1 if rdata.len() == 4 => {
                Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string())
            }
            28 if rdata.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(rdata);
                Some(Ipv6Addr::from(arr).to_string())
            }
            2 | 5 | 12 => read_dns_name(packet, rdata_start).map(|(n, _)| n),
            15 if rdata.len() >= 3 => {
                let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                read_dns_name(packet, rdata_start + 2).map(|(ex, _)| format!("{pref} {ex}"))
            }
            16 => {
                let mut pos = 0usize;
                let mut parts = Vec::new();
                while pos < rdata.len() {
                    let slen = rdata[pos] as usize;
                    pos += 1;
                    if pos + slen > rdata.len() {
                        break;
                    }
                    if let Ok(s) = std::str::from_utf8(&rdata[pos..pos + slen]) {
                        parts.push(s.to_owned());
                    }
                    pos += slen;
                }
                (!parts.is_empty()).then(|| parts.join(""))
            }
            // SRV: priority weight port target, as DNS-over-HTTPS writes it.
            33 if rdata.len() >= 7 => {
                let field = |at: usize| u16::from_be_bytes([rdata[at], rdata[at + 1]]);
                read_dns_name(packet, rdata_start + 6)
                    .map(|(target, _)| format!("{} {} {} {target}", field(0), field(2), field(4)))
            }
            // DS: key tag, algorithm, digest type (the digest is left out).
            43 if rdata.len() >= 4 => Some(format!(
                "{} {} {}",
                u16::from_be_bytes([rdata[0], rdata[1]]),
                rdata[2],
                rdata[3]
            )),
            // DNSKEY: flags, protocol, algorithm (the key is left out).
            48 if rdata.len() >= 4 => Some(format!(
                "{} {} {}",
                u16::from_be_bytes([rdata[0], rdata[1]]),
                rdata[2],
                rdata[3]
            )),
            // CAA: flags tag "value".
            257 if rdata.len() >= 2 => {
                let tag_len = rdata[1] as usize;
                (2 + tag_len <= rdata.len())
                    .then(|| {
                        let tag = std::str::from_utf8(&rdata[2..2 + tag_len]).ok()?;
                        let value = String::from_utf8_lossy(&rdata[2 + tag_len..]);
                        Some(format!("{} {tag} \"{value}\"", rdata[0]))
                    })
                    .flatten()
            }
            _ => None,
        };
        if let Some(val) = parsed {
            let cleaned = sanitize(val.trim().trim_end_matches('.'), 400);
            if !cleaned.is_empty() && !out.contains(&cleaned) {
                out.push(cleaned);
            }
        }
    }
    out
}

fn system_nameservers() -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Some(addr_str) = rest.split_whitespace().next() {
                    let clean_ip = addr_str.split('%').next().unwrap_or(addr_str);
                    if let Ok(ip) = IpAddr::from_str(clean_ip) {
                        servers.push(SocketAddr::new(ip, 53));
                    }
                }
            }
        }
    }
    if servers.is_empty() {
        servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));
        servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
    }
    servers
}

/// The query with an EDNS0 OPT record asking for answers up to 1232 bytes,
/// so that larger answers (DNSSEC keys, long TXT records) are not cut off.
pub(super) fn with_edns0(mut query: Vec<u8>) -> Vec<u8> {
    if query.len() >= 12 {
        query[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1
        query.push(0); // root name
        query.extend_from_slice(&41u16.to_be_bytes()); // OPT
        query.extend_from_slice(&1232u16.to_be_bytes()); // UDP payload size
        query.extend_from_slice(&0u32.to_be_bytes()); // extended RCODE, flags
        query.extend_from_slice(&0u16.to_be_bytes()); // no options
    }
    query
}

/// The response code of a DNS answer: 1 FORMERR and 4 NOTIMP mean the
/// server did not understand the EDNS0 query.
pub(super) fn dns_rcode(packet: &[u8]) -> Option<u8> {
    (packet.len() >= 4).then(|| packet[3] & 0x0F)
}

async fn query_dns_udp(qname: &str, qtype: u16) -> Result<Vec<String>> {
    let servers = system_nameservers();
    let mut txid_bytes = [0u8; 2];
    let txid = if getrandom::fill(&mut txid_bytes).is_ok() {
        u16::from_be_bytes(txid_bytes).max(1)
    } else {
        ((qtype.wrapping_mul(31337)) ^ (qname.len() as u16)).max(1)
    };
    let plain = build_dns_query(txid, qname, qtype)?;
    let extended = with_edns0(plain.clone());
    for server in servers.into_iter().take(2) {
        // EDNS0 first; the plain query again only if the server refused it.
        for query in [&extended, &plain] {
            match ask_dns_server(server, query, txid, qtype).await {
                DnsAnswer::Records(records) => return Ok(records),
                DnsAnswer::EdnsRefused if std::ptr::eq(query, &extended) => continue,
                _ => break,
            }
        }
    }
    Ok(Vec::new())
}

enum DnsAnswer {
    Records(Vec<String>),
    EdnsRefused,
    Nothing,
}

async fn ask_dns_server(server: SocketAddr, query: &[u8], txid: u16, qtype: u16) -> DnsAnswer {
    let bind_addr = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(sock) = UdpSocket::bind(bind_addr).await else {
        return DnsAnswer::Nothing;
    };
    if sock.connect(server).await.is_err() {
        return DnsAnswer::Nothing;
    }
    if !matches!(
        tokio::time::timeout(Duration::from_secs(3), sock.send(query)).await,
        Ok(Ok(_))
    ) {
        return DnsAnswer::Nothing;
    }
    let mut buf = [0u8; 2048];
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
        let answer = &buf[..n];
        let records = parse_dns_wire_response(answer, txid, qtype);
        if !records.is_empty() {
            return DnsAnswer::Records(records);
        }
        let same_query = answer.len() >= 2 && u16::from_be_bytes([answer[0], answer[1]]) == txid;
        if same_query && matches!(dns_rcode(answer), Some(1 | 4)) {
            return DnsAnswer::EdnsRefused;
        }
    }
    DnsAnswer::Nothing
}

async fn query_doh(client: &reqwest::Client, qname: &str, rrtype: u16) -> Result<Vec<String>> {
    let type_str = match rrtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        48 => "DNSKEY",
        257 => "CAA",
        _ => return Ok(Vec::new()),
    };
    for endpoint in [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ] {
        let resp = client
            .get(endpoint)
            .header("Accept", "application/dns-json")
            .query(&[("name", qname), ("type", type_str)])
            .send()
            .await;
        let Ok(resp) = resp else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(bytes) = read_bytes_bounded(resp, MAX_HTTP_BYTES).await else {
            continue;
        };
        if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
            return Ok(parse_doh_records(&json, rrtype));
        }
    }
    bail!("DoH endpoints unreachable")
}

/// Name endings that only mean something on a local network.
const LOCAL_SUFFIXES: &[&str] = &[
    "local",
    "localhost",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "private",
    "test",
    "invalid",
    "example",
    "localdomain",
    "home.arpa",
];

/// The address a reverse-lookup name (`5.0.0.10.in-addr.arpa`,
/// `...ip6.arpa`) asks about.
pub fn reverse_name_address(qname: &str) -> Option<IpAddr> {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let mut octets: Vec<u8> = rest
            .split('.')
            .map(|part| part.parse().ok())
            .collect::<Option<_>>()?;
        if octets.len() != 4 {
            return None;
        }
        octets.reverse();
        return Some(IpAddr::from([octets[0], octets[1], octets[2], octets[3]]));
    }
    let rest = name.strip_suffix(".ip6.arpa")?;
    let nibbles: Vec<u8> = rest
        .split('.')
        .map(|part| {
            u8::from_str_radix(part, 16)
                .ok()
                .filter(|_| part.len() == 1)
        })
        .collect::<Option<_>>()?;
    if nibbles.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, pair) in nibbles
        .iter()
        .rev()
        .collect::<Vec<_>>()
        .chunks(2)
        .enumerate()
    {
        bytes[index] = (pair[0] << 4) | pair[1];
    }
    Some(IpAddr::from(bytes))
}

/// Whether `qname` may be asked of a public resolver (DNS-over-HTTPS) or a
/// public log (crt.sh). Not a name that only exists on a local network, and
/// not the reverse name of a private address: those would tell a third
/// party what the user is looking at inside their own network.
pub fn may_ask_public_services(qname: &str) -> bool {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();
    if let Some(ip) = reverse_name_address(&name) {
        return !is_non_public_ip(ip);
    }
    if name.ends_with(".arpa") || !name.contains('.') {
        return false;
    }
    !LOCAL_SUFFIXES
        .iter()
        .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
}

/// Queries a DNS record type from this machine's own resolvers first, as
/// the system would, and only then, for names that may be asked publicly,
/// over DNS-over-HTTPS.
pub async fn resolve_rr(client: &reqwest::Client, qname: &str, rrtype: u16) -> Vec<String> {
    if let Ok(records) = query_dns_udp(qname, rrtype).await {
        if !records.is_empty() {
            return records;
        }
    }
    if !may_ask_public_services(qname) {
        return Vec::new();
    }
    query_doh(client, qname, rrtype).await.unwrap_or_default()
}

/// Runs the passive `dns` stage for `target`.
/// Returns `(observations, resolved_ips, summary_text)`.
pub async fn run_dns(target: &Target) -> Result<(Vec<Observation>, Vec<String>, String)> {
    let client = build_http_client(Duration::from_secs(6))?;
    let mut observations = Vec::new();
    let mut resolved_ips = Vec::new();

    match target {
        Target::Network(net) => Ok((
            observations,
            resolved_ips,
            format!("network range {net} (skipped)"),
        )),
        Target::Host(HostAddr::Ip { addr: ip, .. }) => {
            let ip_str = ip.to_canonical().to_string();
            resolved_ips.push(ip_str.clone());
            let ptr_name = reverse_dns_name(*ip);
            let ptrs = resolve_rr(&client, &ptr_name, 12).await;
            for ptr in &ptrs {
                let ev = format!("{ptr_name} IN PTR {ptr}");
                // A reverse record says what the owner of the address chose
                // to call it: a claim, never the name's resolution.
                observations.push(Observation::Hostname {
                    address: ip_str.clone(),
                    hostname: ptr.clone(),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::Medium, &ev),
                });
                observations.push(Observation::Fact {
                    address: ip_str.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: format!("PTR record: {ptr}"),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                });
            }
            let summary = if ptrs.is_empty() {
                "no PTR record".to_owned()
            } else {
                format!("PTR {}", ptrs.join(", "))
            };
            Ok((observations, resolved_ips, summary))
        }
        Target::Host(HostAddr::Name(domain)) => {
            let (mut a_recs, mut aaaa_recs, cname_recs, mx_recs, ns_recs, raw_txt) = tokio::join!(
                resolve_rr(&client, domain, 1),
                resolve_rr(&client, domain, 28),
                resolve_rr(&client, domain, 5),
                resolve_rr(&client, domain, 15),
                resolve_rr(&client, domain, 2),
                resolve_rr(&client, domain, 16),
            );

            // Fallback to OS resolver if both DoH and direct UDP were blocked.
            if a_recs.is_empty() && aaaa_recs.is_empty() {
                if let Ok(Ok(addrs)) = tokio::time::timeout(
                    Duration::from_secs(4),
                    tokio::net::lookup_host((domain.as_str(), 80)),
                )
                .await
                {
                    for sock in addrs {
                        match sock.ip().to_canonical() {
                            IpAddr::V4(v4) => {
                                let s = v4.to_string();
                                if !a_recs.contains(&s) {
                                    a_recs.push(s);
                                }
                            }
                            IpAddr::V6(v6) => {
                                let s = v6.to_string();
                                if !aaaa_recs.contains(&s) {
                                    aaaa_recs.push(s);
                                }
                            }
                        }
                    }
                }
            }

            for ip in &a_recs {
                if IpAddr::from_str(ip)
                    .is_ok_and(|addr| is_allowed_resolved_ip_for_name(domain, addr))
                    && !resolved_ips.contains(ip)
                {
                    resolved_ips.push(ip.clone());
                }
            }
            for ip in &aaaa_recs {
                if IpAddr::from_str(ip)
                    .is_ok_and(|addr| is_allowed_resolved_ip_for_name(domain, addr))
                    && !resolved_ips.contains(ip)
                {
                    resolved_ips.push(ip.clone());
                }
            }

            let primary_address = resolved_ips
                .first()
                .cloned()
                .unwrap_or_else(|| domain.clone());

            if primary_address != *domain {
                observations.push(Observation::Hostname {
                    address: primary_address.clone(),
                    hostname: domain.clone(),
                    record: EvidenceRecord::observed(
                        Source::Dns,
                        Confidence::High,
                        &format!("{domain} resolved to {primary_address}"),
                    ),
                });
                if let Ok(ip) = IpAddr::from_str(&primary_address) {
                    let ptr_name = reverse_dns_name(ip);
                    let ptrs = resolve_rr(&client, &ptr_name, 12).await;
                    for ptr in &ptrs {
                        let ev = format!("{ptr_name} IN PTR {ptr}");
                        // A claim of the address's owner (see above).
                        observations.push(Observation::Hostname {
                            address: primary_address.clone(),
                            hostname: ptr.clone(),
                            record: EvidenceRecord::observed(Source::Dns, Confidence::Medium, &ev),
                        });
                        observations.push(Observation::Fact {
                            address: primary_address.clone(),
                            port: None,
                            protocol: "ip".to_owned(),
                            claim: format!("PTR record: {ptr}"),
                            record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                        });
                    }
                }
            }

            for a in &a_recs {
                let ev = format!("{domain} IN A {a}");
                observations.push(Observation::Fact {
                    address: primary_address.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: format!("A record: {a}"),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                });
            }

            let ipv6_dns = if aaaa_recs.is_empty() {
                let ev = format!("{domain} IN AAAA -> NODATA (no AAAA record published)");
                observations.push(Observation::Fact {
                    address: primary_address.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: "no AAAA record published".to_owned(),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                });
                Some("no AAAA record published".to_owned())
            } else {
                for aaaa in &aaaa_recs {
                    let ev = format!("{domain} IN AAAA {aaaa}");
                    observations.push(Observation::Fact {
                        address: primary_address.clone(),
                        port: None,
                        protocol: "ip".to_owned(),
                        claim: format!("AAAA record: {aaaa}"),
                        record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                    });
                }
                Some(aaaa_recs.join(", "))
            };

            observations.push(Observation::HostMeta {
                address: primary_address.clone(),
                asn: None,
                bgp_prefix: None,
                country: None,
                ipv6_dns,
                waf_cdn: detect_waf_from_cnames(&cname_recs),
                hops: Vec::new(),
                record: EvidenceRecord::observed(Source::Dns, Confidence::High, domain),
            });

            for cname in &cname_recs {
                let ev = format!("{domain} IN CNAME {cname}");
                observations.push(Observation::Fact {
                    address: primary_address.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: format!("CNAME record: {cname}"),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                });
            }
            for mx in &mx_recs {
                let ev = format!("{domain} IN MX {mx}");
                observations.push(Observation::Fact {
                    address: primary_address.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: format!("MX record: {mx}"),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                });
            }
            for ns in &ns_recs {
                let ev = format!("{domain} IN NS {ns}");
                observations.push(Observation::Fact {
                    address: primary_address.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: format!("NS record: {ns}"),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                });
            }
            for txt in raw_txt.iter().filter(|t| is_notable_txt(t)) {
                let ev = format!("{domain} IN TXT \"{txt}\"");
                observations.push(Observation::Fact {
                    address: primary_address.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: format!("TXT record: {txt}"),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                });
            }

            let summary = format!(
                "{} A, {} AAAA, {} NS, {} MX",
                a_recs.len(),
                aaaa_recs.len(),
                ns_recs.len(),
                mx_recs.len()
            );
            Ok((observations, resolved_ips, summary))
        }
    }
}

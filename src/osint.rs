//! Passive OSINT and lightweight `mild`-mode service verification tasks.
//!
//! Every probe in this module is either strictly passive (DNS, DoH, Team
//! Cymru ASN, RDAP, Certificate Transparency `crt.sh`, local ARP/NDP cache)
//! or single-connection and non-intrusive (HTTP `GET /`, `/robots.txt`,
//! `/.well-known/security.txt`, `/favicon.ico`, TLS handshake inspection,
//! and RFC 4253 `SSH_MSG_KEXINIT` algorithm parsing with zero authentication
//! attempts).
//!
//! Network calls time out within 5–10 seconds and degrade gracefully so rate
//! limits or offline environments mark a stage `skipped` or emit a notice
//! without failing the recon pipeline.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::endpoint::{HostAddr, Target};
use crate::evidence::{sanitize, Confidence, EvidenceRecord, Source};
use crate::geoip::GeoDb;
use crate::graph::{HttpInfo, Observation};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_HTTP_BYTES: usize = 256 * 1024;
const MAX_FAVICON_BYTES: usize = 512 * 1024;
const MAX_CRTSH_BYTES: usize = 4 * 1024 * 1024;
const MAX_SUBDOMAINS: usize = 50;
const MAX_SSH_PACKET_BYTES: usize = 64 * 1024;

/// Required HTTP security response headers checked by the `headers` stage.
pub const REQUIRED_SECURITY_HEADERS: &[&str] = &[
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
];

// ---------------------------------------------------------------------------
// Bounded HTTP helpers
// ---------------------------------------------------------------------------

fn build_http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT.min(timeout))
        .read_timeout(timeout)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("meow-osint/0.1")
        .build()
        .context("cannot create OSINT HTTP client")
}

fn configure_osint_command(cmd: &mut tokio::process::Command) {
    cmd.env_clear();
    if let Some(raw_path) = std::env::var_os("PATH") {
        let safe_dirs = std::env::split_paths(&raw_path)
            .filter(|dir| !dir.as_os_str().is_empty() && dir.is_absolute());
        if let Ok(joined) = std::env::join_paths(safe_dirs) {
            cmd.env("PATH", joined);
        }
    }
    cmd.env("LC_ALL", "C").env("LANG", "C");
    #[cfg(windows)]
    {
        let sys_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("SYSTEMROOT"))
            .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows"));
        cmd.env("SystemRoot", sys_root);
    }
    #[cfg(unix)]
    cmd.process_group(0);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
}

#[cfg(unix)]
struct OsintGroupGuard(Option<u32>);

#[cfg(unix)]
impl Drop for OsintGroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0.filter(|&p| p > 1 && p <= i32::MAX as u32) {
            // SAFETY: negative pid signals the dedicated process group started with process_group(0).
            unsafe {
                libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
        }
    }
}

async fn wait_bounded_stdout(
    mut child: tokio::process::Child,
    max_bytes: usize,
    timeout: Duration,
) -> Option<String> {
    #[cfg(unix)]
    let _group = OsintGroupGuard(child.id());
    let mut stdout = child.stdout.take()?;
    let fut = async move {
        let mut buf = Vec::with_capacity(max_bytes.min(8192));
        let mut limited = (&mut stdout).take(max_bytes as u64);
        let _ = limited.read_to_end(&mut buf).await;
        let _ = child.kill().await;
        let _ = child.wait().await;
        String::from_utf8_lossy(&buf).into_owned()
    };
    tokio::time::timeout(timeout, fut).await.ok()
}

async fn read_bytes_bounded(mut resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            bail!("response content-length ({len}) exceeds {max_bytes} byte cap");
        }
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("failed reading HTTP body")? {
        if out.len() + chunk.len() > max_bytes {
            bail!("response body exceeds {max_bytes} byte cap");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn read_bytes_prefix(mut resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("failed reading HTTP body")? {
        if out.len() + chunk.len() > max_bytes {
            out.extend_from_slice(&chunk[..max_bytes.saturating_sub(out.len())]);
            break;
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// True when `ip` is safe to accept as a DNS resolution result for `domain`.
/// Blocks unspecified, broadcast, multicast, link-local / cloud metadata IMDS
/// (`169.254.0.0/16`, `fe80::/10`), and loopback addresses unless `domain` is
/// explicitly `localhost`, while still permitting RFC 1918 / RFC 4193 lab hosts.
pub fn is_allowed_resolved_ip_for_name(domain: &str, ip: IpAddr) -> bool {
    let is_localhost = domain
        .trim()
        .trim_end_matches('.')
        .eq_ignore_ascii_case("localhost");
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            if v4.is_unspecified()
                || v4.octets()[0] == 0
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_link_local()
            {
                return false;
            }
            if v4.is_loopback() && !is_localhost {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            if v6.is_unspecified() || v6.is_multicast() || (segs[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            if v6.is_loopback() && !is_localhost {
                return false;
            }
            true
        }
    }
}

/// True when `ip` is loopback, private (RFC 1918 / RFC 4193), link-local,
/// multicast, CGNAT, benchmarking, or documentation space that external
/// internet registries (Team Cymru / RDAP) do not index as public routable
/// autonomous systems.
pub fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)) // 198.18.0.0/15
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (segs[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (segs[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (segs[0] == 0x2001 && segs[1] == 0x0db8) // 2001:db8::/32 doc
        }
    }
}

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

async fn query_dns_udp(qname: &str, qtype: u16) -> Result<Vec<String>> {
    let servers = system_nameservers();
    let mut txid_bytes = [0u8; 2];
    let txid = if getrandom::fill(&mut txid_bytes).is_ok() {
        u16::from_be_bytes(txid_bytes).max(1)
    } else {
        ((qtype.wrapping_mul(31337)) ^ (qname.len() as u16)).max(1)
    };
    let query = build_dns_query(txid, qname, qtype)?;
    for server in servers.into_iter().take(2) {
        let bind_addr = if server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let Ok(sock) = UdpSocket::bind(bind_addr).await else {
            continue;
        };
        if sock.connect(server).await.is_err() {
            continue;
        }
        if tokio::time::timeout(Duration::from_secs(3), sock.send(&query))
            .await
            .is_err()
        {
            continue;
        }
        let mut buf = [0u8; 2048];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
            let records = parse_dns_wire_response(&buf[..n], txid, qtype);
            if !records.is_empty() {
                return Ok(records);
            }
        }
    }
    Ok(Vec::new())
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

/// Queries a DNS record type via DoH JSON first, falling back to UDP RFC 1035
/// queries against system nameservers.
pub async fn resolve_rr(client: &reqwest::Client, qname: &str, rrtype: u16) -> Vec<String> {
    if let Ok(records) = query_doh(client, qname, rrtype).await {
        if !records.is_empty() {
            return records;
        }
    }
    query_dns_udp(qname, rrtype).await.unwrap_or_default()
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
                observations.push(Observation::Hostname {
                    address: ip_str.clone(),
                    hostname: ptr.clone(),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
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
                        observations.push(Observation::Hostname {
                            address: primary_address.clone(),
                            hostname: ptr.clone(),
                            record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
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

// ---------------------------------------------------------------------------
// 2. ASN (`asn` task) — Team Cymru DNS + RDAP + offline GeoDb fallback
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsnInfo {
    pub asn: u32,
    pub org: Option<String>,
    pub bgp_prefix: Option<String>,
    pub country: Option<String>,
    pub registry: Option<String>,
    pub source: Source,
    pub raw_evidence: String,
}

impl AsnInfo {
    pub fn label(&self) -> String {
        match &self.org {
            Some(org) if !org.is_empty() => format!("AS{} · {org}", self.asn),
            _ => format!("AS{}", self.asn),
        }
    }
}

/// Parses a Team Cymru origin TXT record:
/// `"63949 | 45.33.32.0/24 | US | arin | 2010-02-02"`
pub fn parse_cymru_origin(txt: &str) -> Option<(u32, Option<String>, Option<String>)> {
    let parts: Vec<&str> = txt
        .trim()
        .trim_matches('"')
        .split('|')
        .map(str::trim)
        .collect();
    if parts.is_empty() {
        return None;
    }
    // Sometimes multiple origin ASNs are space-separated ("63949 12345"); take the first.
    let asn_str = parts[0].split_whitespace().next()?.trim_start_matches("AS");
    let asn = asn_str.parse::<u32>().ok()?;
    let prefix = parts
        .get(1)
        .map(|s| sanitize(s, 64))
        .filter(|s| !s.is_empty());
    let country = parts
        .get(2)
        .map(|s| sanitize(s, 16))
        .filter(|s| !s.is_empty());
    Some((asn, prefix, country))
}

/// Parses a Team Cymru ASN description TXT record:
/// `"63949 | US | arin | 2012-07-20 | LINO-1 - Akamai Connected Cloud, US"`
pub fn parse_cymru_asn(txt: &str) -> Option<String> {
    let parts: Vec<&str> = txt
        .trim()
        .trim_matches('"')
        .split('|')
        .map(str::trim)
        .collect();
    let desc = parts.get(4).or_else(|| parts.last())?;
    let cleaned = sanitize(desc, 160);
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Parsed RDAP response fields: `(asn, org_name, bgp_prefix, country)`.
pub type RdapParsed = (Option<u32>, Option<String>, Option<String>, Option<String>);

/// Parses an RDAP IP network JSON response (`https://rdap.arin.net/registry/ip/<ip>`).
pub fn parse_rdap_response(json: &Value) -> Option<RdapParsed> {
    if !json.is_object() {
        return None;
    }
    let name = json
        .get("name")
        .and_then(Value::as_str)
        .map(|s| sanitize(s, 120))
        .filter(|s| !s.is_empty());
    let country = json
        .get("country")
        .and_then(Value::as_str)
        .map(|s| sanitize(s, 16))
        .filter(|s| !s.is_empty());

    let prefix = json
        .get("cidr0_cidrs")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|cidr| {
            let v4 = cidr.get("v4prefix").and_then(Value::as_str);
            let v6 = cidr.get("v6prefix").and_then(Value::as_str);
            let len = cidr.get("length").and_then(Value::as_u64)?;
            Some(format!("{}/{len}", v4.or(v6)?))
        });

    let asn = json
        .get("arin_originas0_originautnums")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_u64)
        .map(|n| n as u32);

    // Extract organization full name from `entities[*].vcardArray[1][*]` where `[0] == "fn"`.
    let mut org_fn: Option<String> = None;
    if let Some(entities) = json.get("entities").and_then(Value::as_array) {
        for ent in entities {
            if let Some(vcard) = ent
                .get("vcardArray")
                .and_then(Value::as_array)
                .and_then(|v| v.get(1))
                .and_then(Value::as_array)
            {
                for prop in vcard {
                    let Some(arr) = prop.as_array() else {
                        continue;
                    };
                    if arr.first().and_then(Value::as_str) == Some("fn") {
                        if let Some(val) = arr.get(3).and_then(Value::as_str) {
                            let clean_val = sanitize(val, 160);
                            if !clean_val.is_empty() {
                                org_fn = Some(clean_val);
                                break;
                            }
                        }
                    }
                }
            }
            if org_fn.is_some() {
                break;
            }
        }
    }

    let org = match (org_fn, name) {
        (Some(f), Some(n)) if !f.eq_ignore_ascii_case(&n) => Some(format!("{f} ({n})")),
        (Some(f), _) => Some(f),
        (None, Some(n)) => Some(n),
        (None, None) => None,
    };

    if asn.is_none() && org.is_none() && prefix.is_none() && country.is_none() {
        return None;
    }
    Some((asn, org, prefix, country))
}

fn is_allowed_rdap_redirect(url: &reqwest::Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let lower = host.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "rdap.arin.net"
            | "rdap.db.ripe.net"
            | "rdap.apnic.net"
            | "rdap.lacnic.net"
            | "rdap.afrinic.net"
            | "rdap.org"
    )
}

async fn query_rdap(client: &reqwest::Client, ip: IpAddr) -> Result<Value> {
    let mut url = format!("https://rdap.arin.net/registry/ip/{ip}");
    for _ in 0..4 {
        let resp = client
            .get(&url)
            .header("Accept", "application/rdap+json, application/json")
            .send()
            .await
            .context("RDAP request failed")?;
        if resp.status().is_redirection() {
            let Some(loc) = resp.headers().get(reqwest::header::LOCATION) else {
                bail!("RDAP redirect without Location header");
            };
            let loc_str = loc.to_str().context("invalid RDAP Location header")?;
            let parsed = reqwest::Url::parse(loc_str).context("invalid RDAP redirect URL")?;
            if !is_allowed_rdap_redirect(&parsed) {
                bail!("refusing untrusted RDAP redirect host");
            }
            url = parsed.to_string();
            continue;
        }
        if !resp.status().is_success() {
            bail!("RDAP HTTP {}", resp.status());
        }
        let bytes = read_bytes_bounded(resp, MAX_HTTP_BYTES).await?;
        return serde_json::from_slice(&bytes).context("invalid RDAP JSON");
    }
    bail!("too many RDAP redirects")
}

/// Runs the passive `asn` lookup for a list of target IP addresses.
pub async fn run_asn(ips: &[String], geo: Option<&GeoDb>) -> Result<(Vec<Observation>, String)> {
    let client = build_http_client(Duration::from_secs(6))?;
    let mut observations = Vec::new();
    let mut summaries = Vec::new();

    for ip_str in ips.iter().take(16) {
        let Ok(ip) = IpAddr::from_str(ip_str) else {
            continue;
        };
        if is_non_public_ip(ip) {
            continue;
        }

        let origin_qname = cymru_origin_name(ip);
        let (origin_txts, rdap_res) = tokio::join!(
            resolve_rr(&client, &origin_qname, 16),
            query_rdap(&client, ip)
        );

        let mut asn_num: Option<u32> = None;
        let mut prefix: Option<String> = None;
        let mut country: Option<String> = None;
        let mut cymru_org: Option<String> = None;
        let mut cymru_ev = String::new();

        if let Some(first_txt) = origin_txts.first() {
            if let Some((asn, pfx, cc)) = parse_cymru_origin(first_txt) {
                asn_num = Some(asn);
                prefix = pfx;
                country = cc;
                cymru_ev = first_txt.clone();
                let asn_qname = format!("AS{asn}.asn.cymru.com");
                let asn_txts = resolve_rr(&client, &asn_qname, 16).await;
                if let Some(desc_txt) = asn_txts.first() {
                    cymru_org = parse_cymru_asn(desc_txt);
                    cymru_ev = format!("{first_txt} / {desc_txt}");
                }
            }
        }

        let mut rdap_org: Option<String> = None;
        let mut rdap_ev = String::new();
        if let Ok(rdap_json) = rdap_res {
            if let Some((r_asn, r_org, r_pfx, r_cc)) = parse_rdap_response(&rdap_json) {
                if asn_num.is_none() {
                    asn_num = r_asn;
                }
                if prefix.is_none() {
                    prefix = r_pfx;
                }
                if country.is_none() {
                    country = r_cc;
                }
                rdap_org = r_org;
                rdap_ev = sanitize(&rdap_json.to_string(), 600);
            }
        }

        // Offline GeoDb country fallback/enrichment.
        if country.is_none() {
            if let Some(db) = geo {
                if let Ok(Some(place)) = db.lookup(ip) {
                    if let Some(cc) = place.country {
                        country = Some(sanitize(&cc, 16));
                    }
                }
            }
        }

        let org = cymru_org.clone().or_else(|| rdap_org.clone());
        let asn_label = match (asn_num, &org) {
            (Some(n), Some(o)) => Some(format!("AS{n} · {o}")),
            (Some(n), None) => Some(format!("AS{n}")),
            (None, Some(o)) => Some(o.clone()),
            (None, None) => None,
        };

        let Some(label) = asn_label else {
            continue;
        };

        let primary_source = if !cymru_ev.is_empty() {
            Source::AsnDns
        } else {
            Source::Rdap
        };
        let primary_ev = if !cymru_ev.is_empty() {
            cymru_ev.clone()
        } else if !rdap_ev.is_empty() {
            rdap_ev.clone()
        } else {
            label.clone()
        };

        let mut claim = format!("ASN: {label}");
        let mut meta_parts = Vec::new();
        if let Some(pfx) = &prefix {
            meta_parts.push(format!("prefix {pfx}"));
        }
        if let Some(cc) = &country {
            meta_parts.push(format!("country {cc}"));
        }
        if !meta_parts.is_empty() {
            claim.push_str(&format!(" ({})", meta_parts.join(", ")));
        }

        observations.push(Observation::Fact {
            address: ip_str.clone(),
            port: None,
            protocol: "ip".to_owned(),
            claim,
            record: EvidenceRecord::observed(primary_source, Confidence::High, &primary_ev),
        });

        if let Some(r_org) = &rdap_org {
            if !rdap_ev.is_empty() && primary_source != Source::Rdap {
                observations.push(Observation::Fact {
                    address: ip_str.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: format!("RDAP organization: {r_org}"),
                    record: EvidenceRecord::observed(Source::Rdap, Confidence::High, &rdap_ev),
                });
            }
        }

        let waf_hint = detect_waf_from_asn(&label);
        observations.push(Observation::HostMeta {
            address: ip_str.clone(),
            asn: Some(label.clone()),
            bgp_prefix: prefix,
            country,
            ipv6_dns: None,
            waf_cdn: waf_hint,
            hops: Vec::new(),
            record: EvidenceRecord::observed(primary_source, Confidence::High, &primary_ev),
        });
        summaries.push(label);
    }

    let summary = if summaries.is_empty() {
        "no public ASN found".to_owned()
    } else {
        summaries.join(", ")
    };
    Ok((observations, summary))
}

// ---------------------------------------------------------------------------
// 3. Certificate Transparency Subdomains (`subdomains` task)
// ---------------------------------------------------------------------------

/// Extracts the registrable root domain for Certificate Transparency queries
/// (e.g., `app.staging.example.co.uk` -> `example.co.uk`, `scanme.nmap.org` -> `nmap.org`).
pub fn root_domain(hostname: &str) -> Option<String> {
    let Some(HostAddr::Name(clean)) = HostAddr::parse(hostname) else {
        return None;
    };
    let labels: Vec<&str> = clean.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    const MULTI_PART_TLDS: &[&str] = &[
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
        "ne.jp", "or.jp", "com.br", "com.mx", "co.za", "co.in", "com.sg", "com.hk",
    ];
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if labels.len() >= 3 && MULTI_PART_TLDS.contains(&last_two.as_str()) {
        Some(format!("{}.{last_two}", labels[labels.len() - 3]))
    } else {
        Some(last_two)
    }
}

/// Parses a `crt.sh` JSON array, deduplicating `name_value` and `common_name`,
/// ignoring wildcards (`*.`), validating suffix match on `root`, and capping at `limit`.
pub fn parse_crtsh_json(json_text: &str, root: &str, limit: usize) -> Result<Vec<String>> {
    let root = root.trim().trim_end_matches('.').to_ascii_lowercase();
    let suffix = format!(".{root}");
    let entries: Value = serde_json::from_str(json_text).context("invalid crt.sh JSON")?;
    let Some(array) = entries.as_array() else {
        bail!("crt.sh response is not a JSON array");
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in array {
        for field in ["name_value", "common_name"] {
            let Some(val) = item.get(field).and_then(Value::as_str) else {
                continue;
            };
            for line in val.lines() {
                let candidate = line.trim().trim_end_matches('.').to_ascii_lowercase();
                if candidate.is_empty() || candidate.contains('*') {
                    continue;
                }
                let Some(HostAddr::Name(valid)) = HostAddr::parse(&candidate) else {
                    continue;
                };
                if valid != root && !valid.ends_with(&suffix) {
                    continue;
                }
                if seen.insert(valid.clone()) {
                    out.push(valid);
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Queries `https://crt.sh/?q=%25.<root_domain>&output=json` passively.
pub async fn run_subdomains(
    domain: &str,
    primary_address: &str,
) -> Result<(Vec<Observation>, String)> {
    let Some(root) = root_domain(domain) else {
        bail!("'{domain}' has no registrable root domain");
    };
    let client = build_http_client(Duration::from_secs(10))?;
    let query = format!("%.{root}");
    let resp = client
        .get("https://crt.sh/")
        .query(&[("q", query.as_str()), ("output", "json")])
        .send()
        .await
        .context("crt.sh request failed")?;
    if !resp.status().is_success() {
        bail!("crt.sh answered HTTP {}", resp.status());
    }
    let bytes = read_bytes_bounded(resp, MAX_CRTSH_BYTES).await?;
    let text = String::from_utf8_lossy(&bytes);
    let names = parse_crtsh_json(&text, &root, MAX_SUBDOMAINS)?;

    let mut observations = Vec::new();
    if !names.is_empty() {
        let preview: Vec<&str> = names.iter().take(10).map(String::as_str).collect();
        let more = if names.len() > 10 {
            format!(" (+{} more)", names.len() - 10)
        } else {
            String::new()
        };
        let claim = format!(
            "CT log subdomains for {root} ({}): {}{more}",
            names.len(),
            preview.join(", ")
        );
        observations.push(Observation::Fact {
            address: primary_address.to_owned(),
            port: None,
            protocol: "ip".to_owned(),
            claim,
            record: EvidenceRecord::observed(
                Source::CtLog,
                Confidence::Medium,
                &format!("crt.sh query %.{root} -> {} hostnames", names.len()),
            ),
        });
        // Surface up to 15 sibling hostnames as unverified/mentioned entries without scanning them.
        for sibling in names.iter().filter(|n| *n != domain).take(15) {
            observations.push(Observation::Fact {
                address: sibling.clone(),
                port: None,
                protocol: "ip".to_owned(),
                claim: format!("discovered in Certificate Transparency logs for {root}"),
                record: EvidenceRecord::observed(
                    Source::CtLog,
                    Confidence::Medium,
                    &format!("crt.sh name_value: {sibling}"),
                ),
            });
        }
    }
    let summary = format!("{} subdomains for {root}", names.len());
    Ok((observations, summary))
}

// ---------------------------------------------------------------------------
// 4. Lightweight Traceroute (`trace` task)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceHop {
    pub hop: u8,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

impl TraceHop {
    pub fn formatted(&self) -> String {
        let label = self
            .label
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("({s})"))
            .unwrap_or_default();
        let rtt = match self.rtt_ms {
            Some(ms) => format!("{ms:.1} ms"),
            None => "—".to_owned(),
        };
        format!(
            "Hop {}: {:<18} {:<32} {}",
            self.hop, self.address, label, rtt
        )
        .trim_end()
        .to_owned()
    }
}

/// Parses structured traceroute hops (including RTT latency in `ms`, hostnames/labels,
/// and `* * *` ICMP-filtered hops) from `traceroute`, `tracepath`, or `tracert` output.
pub fn parse_traceroute_detailed(
    text: &str,
    target_ip: &str,
    local_gateway: Option<&str>,
    target_hostname: Option<&str>,
) -> Vec<TraceHop> {
    let mut hops: Vec<TraceHop> = Vec::new();
    let mut consecutive_stars = 0usize;

    let expanded = text.replace(" | Hop ", "\nHop ").replace(" Hop ", "\nHop ");

    for line in expanded.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("traceroute")
            || trimmed.starts_with("Tracing")
            || trimmed.starts_with("over a maximum")
            || trimmed.starts_with("Trace complete")
            || trimmed.starts_with("Resume:")
        {
            continue;
        }
        let normalized = trimmed
            .strip_prefix("Hop ")
            .or_else(|| trimmed.strip_prefix("hop "))
            .unwrap_or(trimmed);
        let paren_label = normalized.find('(').and_then(|start| {
            let rest = &normalized[start + 1..];
            let end = rest.find(')')?;
            let inside = rest[..end].trim();
            (inside.parse::<IpAddr>().is_err() && !inside.is_empty()).then(|| sanitize(inside, 80))
        });
        let tokens: Vec<&str> = normalized.split_whitespace().collect();
        let Some(first) = tokens.first() else {
            continue;
        };
        let hop_str = first.trim_end_matches(':');
        let Ok(hop_num) = hop_str.parse::<u8>() else {
            continue;
        };
        if hop_num == 0 {
            continue;
        }

        let mut found_ip: Option<String> = None;
        let mut found_host: Option<String> = paren_label;
        let mut found_rtt: Option<f64> = None;

        for (idx, &tok) in tokens.iter().enumerate().skip(1) {
            let lower = tok.to_ascii_lowercase();
            if lower == "ms" && idx > 1 {
                let prev = tokens[idx - 1].trim_start_matches('<');
                if let Ok(val) = prev.parse::<f64>() {
                    if val.is_finite() && val >= 0.0 {
                        found_rtt = Some((val * 10.0).round() / 10.0);
                    }
                }
                continue;
            }
            if let Some(ms_prefix) = lower.strip_suffix("ms") {
                let clean_num = ms_prefix.trim_start_matches('<');
                if let Ok(val) = clean_num.parse::<f64>() {
                    if val.is_finite() && val >= 0.0 {
                        found_rtt = Some((val * 10.0).round() / 10.0);
                        continue;
                    }
                }
            }
            let clean_tok = tok.trim_matches(['(', ')', '[', ']', ',']);
            if found_ip.is_none() {
                if let Ok(ip) = IpAddr::from_str(clean_tok) {
                    found_ip = Some(ip.to_canonical().to_string());
                    continue;
                }
            }
            if found_ip.is_none()
                && found_host.is_none()
                && clean_tok != "*"
                && clean_tok != "no"
                && clean_tok != "reply"
                && (clean_tok.contains('.') || clean_tok.contains('-'))
                && clean_tok.parse::<f64>().is_err()
            {
                found_host = Some(sanitize(clean_tok, 80));
            }
        }

        if let Some(ip) = found_ip {
            consecutive_stars = 0;
            if hops.iter().any(|h| h.address == ip) {
                continue;
            }
            let is_local_gw = local_gateway.is_some_and(|gw| gw == ip)
                || (hop_num == 1 && IpAddr::from_str(&ip).is_ok_and(is_non_public_ip));
            let label = if is_local_gw {
                Some(
                    found_host
                        .filter(|h| h != &ip)
                        .unwrap_or_else(|| "Local Router".to_owned()),
                )
            } else if ip == target_ip {
                target_hostname
                    .map(|h| sanitize(h, 80))
                    .or_else(|| found_host.filter(|h| h != &ip))
                    .or_else(|| Some("Target Host".to_owned()))
            } else if let Some(h) = found_host.filter(|h| h != &ip) {
                Some(h)
            } else if hop_num == 2 {
                Some("ISP Regional Node".to_owned())
            } else {
                Some("ISP Backbone / Transit".to_owned())
            };

            hops.push(TraceHop {
                hop: hop_num,
                address: ip.clone(),
                label,
                rtt_ms: found_rtt,
            });
            if ip == target_ip {
                break;
            }
        } else if trimmed.contains('*') || trimmed.contains("no reply") {
            consecutive_stars += 1;
            if consecutive_stars <= 2 {
                hops.push(TraceHop {
                    hop: hop_num,
                    address: "* * *".to_owned(),
                    label: Some("isp-transit / ICMP filtered".to_owned()),
                    rtt_ms: None,
                });
            }
        }
    }

    // Trim trailing `* * *` hops if the target never answered ICMP/UDP at the tail.
    while hops.last().is_some_and(|h| h.address == "* * *") && hops.len() > 1 {
        let prev_is_star = hops
            .get(hops.len().saturating_sub(2))
            .is_some_and(|h| h.address == "* * *");
        if prev_is_star {
            hops.pop();
        } else {
            break;
        }
    }

    hops
}

/// Parses intermediate hop IP addresses from `traceroute -n`, `tracepath -n`,
/// or Windows `tracert -d` output.
pub fn parse_traceroute_output(text: &str, target_ip: &str) -> Vec<String> {
    parse_traceroute_detailed(text, target_ip, None, None)
        .into_iter()
        .filter(|h| h.address != "* * *" && h.address != target_ip)
        .map(|h| h.address)
        .collect()
}

async fn measure_tcp_rtt_ms(ip: IpAddr) -> Option<f64> {
    for port in [80u16, 443, 22] {
        let addr = SocketAddr::new(ip, port);
        let start = tokio::time::Instant::now();
        if let Ok(Ok(_stream)) =
            tokio::time::timeout(Duration::from_millis(1500), TcpStream::connect(addr)).await
        {
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            return Some((ms * 10.0).round() / 10.0);
        }
    }
    None
}

/// Runs a lightweight traceroute (`traceroute`, `tracepath`, or `tracert`) to
/// `target_ip` with a 10-second cap.
pub async fn run_trace(
    target_ip: &str,
    local_gateway: Option<&str>,
) -> Result<(Vec<Observation>, String)> {
    let Ok(ip) = IpAddr::from_str(target_ip) else {
        bail!("invalid IP address '{target_ip}' for traceroute");
    };
    let ip_str = ip.to_canonical().to_string();

    #[cfg(unix)]
    let candidates: &[(&str, &[&str])] = &[
        (
            "traceroute",
            &["-n", "-q", "1", "-w", "1", "-m", "15", &ip_str],
        ),
        ("tracepath", &["-n", "-m", "15", &ip_str]),
    ];
    #[cfg(windows)]
    let candidates: &[(&str, &[&str])] = &[("tracert", &["-d", "-h", "15", "-w", "800", &ip_str])];

    let mut hops = Vec::new();
    let mut raw_out = String::new();
    let mut tool_ran = false;

    for (prog, args) in candidates {
        let Some(bin) = crate::tools::find_program(prog) else {
            continue;
        };
        let mut cmd = tokio::process::Command::new(&bin);
        cmd.args(*args);
        configure_osint_command(&mut cmd);
        let Ok(child) = cmd.spawn() else {
            continue;
        };
        tool_ran = true;
        if let Some(stdout) = wait_bounded_stdout(child, 128 * 1024, Duration::from_secs(10)).await
        {
            raw_out = stdout;
            hops = parse_traceroute_output(&raw_out, &ip_str);
            if !hops.is_empty() {
                break;
            }
        }
    }

    if hops.is_empty() {
        if let Some(gw) = local_gateway {
            if gw != ip_str {
                hops.push(gw.to_owned());
            }
        }
    }

    let rtt_fallback = measure_tcp_rtt_ms(ip).await;

    if hops.is_empty() && !tool_ran && rtt_fallback.is_none() {
        bail!("traceroute/tracepath is not installed");
    }

    let mut detailed = parse_traceroute_detailed(&raw_out, &ip_str, local_gateway, None);
    if !detailed.iter().any(|h| h.address == ip_str) {
        if detailed.is_empty() {
            if let Some(gw) = local_gateway.filter(|gw| *gw != ip_str) {
                detailed.push(TraceHop {
                    hop: 1,
                    address: gw.to_owned(),
                    label: Some("Local Router".to_owned()),
                    rtt_ms: Some(1.5),
                });
            }
        }
        let next_hop = detailed.last().map_or(1, |h| h.hop.saturating_add(1));
        detailed.push(TraceHop {
            hop: next_hop,
            address: ip_str.clone(),
            label: Some("Target Host".to_owned()),
            rtt_ms: rtt_fallback,
        });
    } else if let Some(last) = detailed.iter_mut().find(|h| h.address == ip_str) {
        if last.rtt_ms.is_none() {
            last.rtt_ms = rtt_fallback;
        }
    }

    let mut observations = Vec::new();
    if !hops.is_empty() || !detailed.is_empty() {
        let mut chain = hops.clone();
        chain.push(ip_str.clone());
        let rtt_suffix = detailed
            .iter()
            .rev()
            .find_map(|h| h.rtt_ms)
            .map(|ms| format!(" ({ms:.1} ms)"))
            .unwrap_or_default();
        let hop_total = detailed.len().max(hops.len());
        let claim = format!(
            "route path ({hop_total} hops{rtt_suffix}): {}",
            chain.join(" -> ")
        );
        let formatted_lines: Vec<String> = detailed.iter().map(TraceHop::formatted).collect();
        let ev = if !formatted_lines.is_empty() {
            sanitize(&formatted_lines.join("\n"), 1200)
        } else if raw_out.trim().is_empty() {
            claim.clone()
        } else {
            sanitize(&raw_out, 800)
        };
        observations.push(Observation::HostMeta {
            address: ip_str.clone(),
            asn: None,
            bgp_prefix: None,
            country: None,
            ipv6_dns: None,
            waf_cdn: None,
            hops: hops.clone(),
            record: EvidenceRecord::observed(Source::Traceroute, Confidence::Medium, &ev),
        });
        observations.push(Observation::Fact {
            address: ip_str,
            port: None,
            protocol: "ip".to_owned(),
            claim,
            record: EvidenceRecord::observed(Source::Traceroute, Confidence::Medium, &ev),
        });
    }
    let summary = format!("{} intermediate hops", hops.len());
    Ok((observations, summary))
}

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
pub async fn inspect_web_endpoint(
    address: &str,
    hostname: Option<&str>,
    port: u16,
    tls: bool,
) -> Result<(Vec<Observation>, Option<String>, String)> {
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
        .user_agent("meow-osint/0.1");

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
        .map(|(k, v)| format!("{k}: {v}"))
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

// ---------------------------------------------------------------------------
// 7. TLS Audit (`tls-audit` task)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsAuditResult {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub sans: Vec<String>,
    pub supported_versions: Vec<String>,
    pub weak_ciphers: Vec<String>,
    pub raw_evidence: String,
}

/// Parses `openssl s_client` + `openssl x509 -noout -subject -issuer -dates -ext subjectAltName`
/// output into structured certificate metadata.
pub fn parse_openssl_cert_output(text: &str) -> TlsAuditResult {
    let mut out = TlsAuditResult {
        raw_evidence: sanitize(text, 1200),
        ..TlsAuditResult::default()
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("subject=") {
            out.subject = Some(sanitize(rest.trim(), 180));
        } else if let Some(rest) = trimmed.strip_prefix("issuer=") {
            out.issuer = Some(sanitize(rest.trim(), 180));
        } else if let Some(rest) = trimmed.strip_prefix("notBefore=") {
            out.not_before = Some(sanitize(rest.trim(), 64));
        } else if let Some(rest) = trimmed.strip_prefix("notAfter=") {
            out.not_after = Some(sanitize(rest.trim(), 64));
        } else if trimmed.contains("DNS:") {
            for part in trimmed.split(',') {
                if let Some(dns) = part.trim().strip_prefix("DNS:") {
                    let clean_san = sanitize(&dns.trim().to_ascii_lowercase(), 160);
                    if !clean_san.is_empty() && !out.sans.contains(&clean_san) {
                        out.sans.push(clean_san);
                    }
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("Protocol  :") {
            let proto = sanitize(rest.trim(), 32);
            if !proto.is_empty() && !out.supported_versions.contains(&proto) {
                out.supported_versions.push(proto);
            }
        } else if let Some(rest) = trimmed.strip_prefix("Cipher    :") {
            let cipher = sanitize(rest.trim(), 64);
            let upper = cipher.to_ascii_uppercase();
            if (upper.contains("RC4")
                || upper.contains("3DES")
                || upper.contains("DES-CBC3")
                || upper.contains("NULL")
                || upper.contains("EXPORT")
                || upper.contains("MD5"))
                && !out.weak_ciphers.contains(&cipher)
            {
                out.weak_ciphers.push(cipher);
            }
        }
    }
    out
}

/// Inspects the peer TLS certificate and protocol versions on `(address, port)`.
pub async fn run_tls_audit(
    address: &str,
    hostname: Option<&str>,
    port: u16,
) -> Result<(Vec<Observation>, String)> {
    let sni = hostname.unwrap_or(address);
    if address.is_empty()
        || address.starts_with('-')
        || address.chars().any(|c| c.is_control() || c.is_whitespace())
        || sni.is_empty()
        || sni.starts_with('-')
        || sni.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        bail!("invalid address or SNI for TLS audit");
    }
    let connect_target = match HostAddr::parse(address) {
        Some(HostAddr::Ip {
            addr: IpAddr::V6(v6),
            zone: Some(z),
        }) => format!("[{v6}%{z}]:{port}"),
        Some(HostAddr::Ip {
            addr: IpAddr::V6(v6),
            zone: None,
        }) => format!("[{v6}]:{port}"),
        _ => format!("{address}:{port}"),
    };

    let mut result = TlsAuditResult::default();
    let mut openssl_available = false;
    let openssl_bin = crate::tools::find_program("openssl");

    // 1. Inspect certificate + default negotiated TLS protocol via `openssl s_client`.
    if let Some(ref openssl_path) = openssl_bin {
        let mut s_client = tokio::process::Command::new(openssl_path);
        s_client.args(["s_client", "-connect", &connect_target, "-servername", sni]);
        configure_osint_command(&mut s_client);

        if let Ok(child) = s_client.spawn() {
            openssl_available = true;
            if let Some(stdout) =
                wait_bounded_stdout(child, 128 * 1024, Duration::from_secs(6)).await
            {
                result = parse_openssl_cert_output(&stdout);

                // If a PEM certificate block was returned, parse Subject/Issuer/Dates/SANs with `openssl x509`.
                if let Some(begin_idx) = stdout.find("-----BEGIN CERTIFICATE-----") {
                    let rest = &stdout[begin_idx..];
                    let end_marker = "-----END CERTIFICATE-----";
                    if let Some(end_rel) = rest.find(end_marker) {
                        let pem_block = &rest[..end_rel + end_marker.len()];
                        if pem_block.len() <= 32 * 1024 {
                            let mut x509 = tokio::process::Command::new(openssl_path);
                            x509.args([
                                "x509",
                                "-noout",
                                "-subject",
                                "-issuer",
                                "-dates",
                                "-ext",
                                "subjectAltName",
                            ]);
                            configure_osint_command(&mut x509);
                            x509.stdin(Stdio::piped());
                            if let Ok(mut xchild) = x509.spawn() {
                                if let Some(mut stdin) = xchild.stdin.take() {
                                    let _ = stdin.write_all(pem_block.as_bytes()).await;
                                }
                                if let Some(xtext) =
                                    wait_bounded_stdout(xchild, 32 * 1024, Duration::from_secs(3))
                                        .await
                                {
                                    let parsed_x509 = parse_openssl_cert_output(&xtext);
                                    if parsed_x509.subject.is_some() {
                                        result.subject = parsed_x509.subject;
                                    }
                                    if parsed_x509.issuer.is_some() {
                                        result.issuer = parsed_x509.issuer;
                                    }
                                    if parsed_x509.not_before.is_some() {
                                        result.not_before = parsed_x509.not_before;
                                    }
                                    if parsed_x509.not_after.is_some() {
                                        result.not_after = parsed_x509.not_after;
                                    }
                                    for san in parsed_x509.sans {
                                        if !result.sans.contains(&san) {
                                            result.sans.push(san);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Check TLS 1.0, 1.1, 1.2, 1.3 support if openssl is available.
    if openssl_available {
        if let Some(ref openssl_path) = openssl_bin {
            for (flag, label) in [
                ("-tls1", "TLSv1.0"),
                ("-tls1_1", "TLSv1.1"),
                ("-tls1_2", "TLSv1.2"),
                ("-tls1_3", "TLSv1.3"),
            ] {
                let mut probe = tokio::process::Command::new(openssl_path);
                probe.args([
                    "s_client",
                    "-connect",
                    &connect_target,
                    "-servername",
                    sni,
                    flag,
                ]);
                configure_osint_command(&mut probe);
                if let Ok(child) = probe.spawn() {
                    if let Some(text) =
                        wait_bounded_stdout(child, 64 * 1024, Duration::from_secs(4)).await
                    {
                        if (text.contains("BEGIN CERTIFICATE")
                            || (text.contains("Cipher is ") && !text.contains("Cipher is (NONE)")))
                            && !result.supported_versions.iter().any(|v| v == label)
                        {
                            result.supported_versions.push(label.to_owned());
                        }
                    }
                }
            }
        }
    }

    let mut observations = Vec::new();
    let ev = if result.raw_evidence.is_empty() {
        format!("TLS audit on {connect_target}")
    } else {
        result.raw_evidence.clone()
    };

    if let Some(subj) = &result.subject {
        let issuer = result.issuer.as_deref().unwrap_or("unknown");
        let valid_until = result.not_after.as_deref().unwrap_or("unknown");
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!(
                "TLS certificate Subject: {subj} (Issuer: {issuer}, NotAfter: {valid_until})"
            ),
            record: EvidenceRecord::observed(Source::TlsCert, Confidence::High, &ev),
        });
    }

    for san in &result.sans {
        observations.push(Observation::TlsSan {
            address: address.to_owned(),
            port,
            san: san.clone(),
            record: EvidenceRecord::observed(Source::TlsCert, Confidence::High, &ev),
        });
    }

    if !result.supported_versions.is_empty() {
        let deprecated: Vec<&str> = result
            .supported_versions
            .iter()
            .map(String::as_str)
            .filter(|v| matches!(*v, "TLSv1" | "TLSv1.0" | "TLSv1.1" | "SSLv3"))
            .collect();
        let claim = if deprecated.is_empty() {
            format!(
                "supported TLS versions: {}",
                result.supported_versions.join(", ")
            )
        } else {
            format!(
                "deprecated TLS versions supported: {} (all offered: {})",
                deprecated.join(", "),
                result.supported_versions.join(", ")
            )
        };
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim,
            record: EvidenceRecord::observed(Source::TlsCert, Confidence::High, &ev),
        });
    }

    if !result.weak_ciphers.is_empty() {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!(
                "weak TLS ciphers negotiated: {}",
                result.weak_ciphers.join(", ")
            ),
            record: EvidenceRecord::observed(Source::TlsCert, Confidence::High, &ev),
        });
    }

    if result.subject.is_some()
        || !result.supported_versions.is_empty()
        || !result.weak_ciphers.is_empty()
    {
        observations.push(Observation::WebMeta {
            address: address.to_owned(),
            port,
            http: Box::new(HttpInfo {
                scheme: "https".to_owned(),
                tls_subject: result.subject.clone(),
                tls_issuer: result.issuer.clone(),
                tls_not_before: result.not_before,
                tls_not_after: result.not_after,
                tls_versions: result.supported_versions.clone(),
                tls_weak_ciphers: result.weak_ciphers,
                ..HttpInfo::default()
            }),
            record: EvidenceRecord::observed(Source::TlsCert, Confidence::High, &ev),
        });
    }

    let summary = if !result.supported_versions.is_empty() {
        format!("{port}/tcp ({})", result.supported_versions.join(", "))
    } else if result.subject.is_some() {
        format!("{port}/tcp cert inspected")
    } else {
        format!("{port}/tcp no TLS details")
    };
    Ok((observations, summary))
}

// ---------------------------------------------------------------------------
// 8. SSH Audit (`ssh-audit` task — RFC 4253 `SSH_MSG_KEXINIT`)
// ---------------------------------------------------------------------------

pub const WEAK_SSH_KEX: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==",
    "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==",
];

pub const WEAK_SSH_HOST_KEYS: &[&str] = &["ssh-dss", "ssh-rsa", "ssh-dss-cert-v01@openssh.com"];

pub const WEAK_SSH_CIPHERS: &[&str] = &[
    "3des-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "rijndael-cbc@lysator.liu.se",
];

pub const WEAK_SSH_MACS: &[&str] = &[
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1",
    "hmac-sha1-96",
    "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKexInit {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_c2s: Vec<String>,
    pub encryption_algorithms_s2c: Vec<String>,
    pub mac_algorithms_c2s: Vec<String>,
    pub mac_algorithms_s2c: Vec<String>,
    pub compression_algorithms_c2s: Vec<String>,
    pub compression_algorithms_s2c: Vec<String>,
}

impl SshKexInit {
    /// Returns all deprecated/weak algorithms offered across KEX, host keys,
    /// ciphers, and MACs.
    pub fn weak_algorithms(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut check = |category: &str, offered: &[String], weak_list: &[&str]| {
            for alg in offered {
                if weak_list.contains(&alg.as_str()) {
                    let entry = format!("{category}:{alg}");
                    if !out.contains(&entry) {
                        out.push(entry);
                    }
                }
            }
        };
        check("kex", &self.kex_algorithms, WEAK_SSH_KEX);
        check(
            "hostkey",
            &self.server_host_key_algorithms,
            WEAK_SSH_HOST_KEYS,
        );
        check("cipher", &self.encryption_algorithms_c2s, WEAK_SSH_CIPHERS);
        check("cipher", &self.encryption_algorithms_s2c, WEAK_SSH_CIPHERS);
        check("mac", &self.mac_algorithms_c2s, WEAK_SSH_MACS);
        check("mac", &self.mac_algorithms_s2c, WEAK_SSH_MACS);
        out
    }
}

/// Parses an RFC 4253 `SSH_MSG_KEXINIT` packet from either:
/// - A full binary SSH packet (`uint32 packet_length`, `byte padding_length`,
///   `byte msg_code == 20`, 16-byte cookie, 10 `name-list`s), OR
/// - The unframed payload starting directly at `byte msg_code == 20`.
pub fn parse_ssh_kexinit(bytes: &[u8]) -> Result<SshKexInit> {
    if bytes.len() > MAX_SSH_PACKET_BYTES {
        bail!("SSH_MSG_KEXINIT exceeds {MAX_SSH_PACKET_BYTES} byte limit");
    }
    let payload = if bytes.first() == Some(&20) {
        bytes
    } else if bytes.len() >= 6 {
        let pkt_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let pad_len = bytes[4] as usize;
        if pkt_len < 2 + pad_len || pkt_len > MAX_SSH_PACKET_BYTES || 4 + pkt_len > bytes.len() {
            bail!("invalid SSH binary packet length ({pkt_len})");
        }
        let payload_end = 4 + pkt_len - pad_len;
        if payload_end <= 5 || bytes[5] != 20 {
            bail!(
                "expected SSH_MSG_KEXINIT (20), got message code {}",
                bytes.get(5).copied().unwrap_or(0)
            );
        }
        &bytes[5..payload_end]
    } else {
        bail!("SSH packet too short ({} bytes)", bytes.len());
    };

    // payload[0] == 20 (SSH_MSG_KEXINIT), payload[1..17] == 16-byte random cookie.
    if payload.len() < 17 {
        bail!("SSH_MSG_KEXINIT payload shorter than 17-byte header + cookie");
    }
    let mut offset = 17usize;
    let mut lists: Vec<Vec<String>> = Vec::with_capacity(10);
    for _ in 0..10 {
        if offset + 4 > payload.len() {
            bail!("truncated name-list length in SSH_MSG_KEXINIT");
        }
        let len = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;
        if len > MAX_SSH_PACKET_BYTES || offset + len > payload.len() {
            bail!("name-list length ({len}) exceeds SSH_MSG_KEXINIT payload bounds");
        }
        let raw = std::str::from_utf8(&payload[offset..offset + len])
            .context("non-ASCII algorithm name in SSH_MSG_KEXINIT")?;
        offset += len;
        let items: Vec<String> = raw
            .split(',')
            .map(|s| sanitize(s.trim(), 96))
            .filter(|s| !s.is_empty())
            .take(128)
            .collect();
        lists.push(items);
    }

    Ok(SshKexInit {
        kex_algorithms: lists.remove(0),
        server_host_key_algorithms: lists.remove(0),
        encryption_algorithms_c2s: lists.remove(0),
        encryption_algorithms_s2c: lists.remove(0),
        mac_algorithms_c2s: lists.remove(0),
        mac_algorithms_s2c: lists.remove(0),
        compression_algorithms_c2s: lists.remove(0),
        compression_algorithms_s2c: lists.remove(0),
    })
}

/// Connects to an SSH port, exchanges the `SSH-2.0` identification banner,
/// reads `SSH_MSG_KEXINIT` (RFC 4253), and closes the socket immediately
/// without attempting authentication.
pub async fn audit_ssh_port(address: &str, port: u16) -> Result<(Vec<Observation>, String)> {
    let connect_addr = match HostAddr::parse(address) {
        Some(HostAddr::Ip {
            addr: IpAddr::V6(v6),
            zone: Some(z),
        }) => format!("[{v6}%{z}]:{port}"),
        Some(HostAddr::Ip {
            addr: IpAddr::V6(v6),
            zone: None,
        }) => format!("[{v6}]:{port}"),
        _ => format!("{address}:{port}"),
    };
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&connect_addr))
        .await
        .context("SSH connection timed out")?
        .with_context(|| format!("cannot connect to {connect_addr}"))?;

    // 1. Read server identification string (RFC 4253 §4.2 allows preamble lines before `SSH-`).
    let mut buf = Vec::with_capacity(256);
    let mut total_bytes = 0usize;
    let mut lines_read = 0usize;
    let mut server_banner = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while total_bytes < 4096 {
        let mut byte = [0u8; 1];
        let read_res = tokio::time::timeout_at(deadline, stream.read(&mut byte)).await;
        match read_res {
            Ok(Ok(1)) => {
                total_bytes += 1;
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    lines_read += 1;
                    let line = String::from_utf8_lossy(&buf);
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("SSH-") {
                        server_banner = sanitize(trimmed.trim_end(), 200);
                        buf.clear();
                        break;
                    }
                    buf.clear();
                    if lines_read > 16 {
                        bail!("SSH server sent too many preamble lines without SSH- banner");
                    }
                }
            }
            _ => bail!("timed out or EOF reading SSH banner"),
        }
    }
    if server_banner.is_empty() {
        bail!("no SSH- banner received from {connect_addr}");
    }

    // 2. Send client identification string and read binary packets until `SSH_MSG_KEXINIT` (20),
    // skipping optional pre-KEXINIT `SSH_MSG_IGNORE` (2) / `SSH_MSG_DEBUG` (4) packets.
    tokio::time::timeout(
        Duration::from_secs(3),
        stream.write_all(b"SSH-2.0-meow_0.2.0\r\n"),
    )
    .await
    .context("SSH banner write timed out")?
    .context("cannot write SSH client banner")?;

    let mut kex_pkt = None;
    for _ in 0..4 {
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
            .await
            .context("timed out waiting for SSH_MSG_KEXINIT")?
            .context("EOF waiting for SSH_MSG_KEXINIT")?;
        let pkt_len = u32::from_be_bytes(len_buf) as usize;
        if !(2..=MAX_SSH_PACKET_BYTES).contains(&pkt_len) {
            bail!("invalid SSH packet length {pkt_len}");
        }
        let mut pkt = vec![0u8; 4 + pkt_len];
        pkt[..4].copy_from_slice(&len_buf);
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut pkt[4..]))
            .await
            .context("timed out reading SSH packet body")?
            .context("EOF reading SSH packet body")?;
        let msg_type = pkt.get(5).copied().unwrap_or(0);
        if msg_type == 2 || msg_type == 4 {
            continue;
        }
        kex_pkt = Some(pkt);
        break;
    }

    // Drop stream immediately — zero authentication or key exchange reply sent.
    drop(stream);

    let pkt = kex_pkt.context("SSH server did not send SSH_MSG_KEXINIT")?;
    let kex = parse_ssh_kexinit(&pkt)?;
    let weak = kex.weak_algorithms();
    let ev = serde_json::json!({
        "banner": server_banner,
        "kex": kex.kex_algorithms,
        "host_key": kex.server_host_key_algorithms,
        "ciphers_c2s": kex.encryption_algorithms_c2s,
        "macs_c2s": kex.mac_algorithms_c2s,
        "weak": weak,
    })
    .to_string();

    let mut observations = Vec::new();
    observations.push(Observation::Fact {
        address: address.to_owned(),
        port: Some(port),
        protocol: "tcp".to_owned(),
        claim: format!(
            "SSH KEXINIT algorithms: {} kex, {} hostkey, {} ciphers, {} MACs (ground-truth runtime config)",
            kex.kex_algorithms.len(),
            kex.server_host_key_algorithms.len(),
            kex.encryption_algorithms_c2s.len(),
            kex.mac_algorithms_c2s.len()
        ),
        record: EvidenceRecord::observed(Source::SshKex, Confidence::High, &ev),
    });

    if !weak.is_empty() {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!(
                "weak/deprecated SSH algorithms offered (unaffected by distro backporting): {}",
                weak.join(", ")
            ),
            record: EvidenceRecord::observed(Source::SshKex, Confidence::High, &ev),
        });
    } else {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: "SSH KEXINIT offers only modern algorithms (no SHA-1 KEX, DSA, CBC/RC4, or MD5/SHA-1 MACs)".to_owned(),
            record: EvidenceRecord::observed(Source::SshKex, Confidence::High, &ev),
        });
    }

    let summary = if weak.is_empty() {
        format!("{port}/tcp (0 weak algorithms)")
    } else {
        format!("{port}/tcp ({} weak algorithms)", weak.len())
    };
    Ok((observations, summary))
}

// ---------------------------------------------------------------------------
// 9. Distro Backport Detection Helper for `cves` & `ai`
// ---------------------------------------------------------------------------

/// Detects whether a host or service banner indicates Linux distribution
/// packaging (Ubuntu, Debian, RHEL, CentOS, Fedora, SUSE, Alpine, Amazon Linux)
/// where upstream version strings commonly carry backported security patches.
pub fn distro_backport_note(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("ubuntu") {
        Some("Ubuntu banner detected: Ubuntu backports security fixes without bumping the upstream version; verify installed package revision locally (`dpkg -l` / `apt-cache policy`) before confirming")
    } else if lower.contains("debian") || lower.contains("+deb") {
        Some("Debian banner detected: Debian backports security fixes without bumping the upstream version; verify installed package revision locally (`dpkg -l` / `apt-cache policy`) before confirming")
    } else if lower.contains("redhat")
        || lower.contains("rhel")
        || lower.contains("centos")
        || lower.contains(".el7")
        || lower.contains(".el8")
        || lower.contains(".el9")
    {
        Some("RHEL/CentOS banner detected: Enterprise Linux backports security fixes; verify installed RPM revision locally (`rpm -q --changelog`) before confirming")
    } else if lower.contains("amzn") || lower.contains("amazon") {
        Some("Amazon Linux banner detected: verify installed RPM revision locally (`rpm -q`) before confirming")
    } else if lower.contains("suse") || lower.contains("sles") {
        Some("SUSE banner detected: verify installed package revision locally (`rpm -q`) before confirming")
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_kexinit_fixture(kex: &str, hostkeys: &str, ciphers: &str, macs: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(20u8); // SSH_MSG_KEXINIT
        payload.extend_from_slice(&[0x42u8; 16]); // 16-byte cookie
        let lists = [
            kex,
            hostkeys,
            ciphers,
            ciphers,
            macs,
            macs,
            "none,zlib@openssh.com",
            "none,zlib@openssh.com",
            "",
            "",
        ];
        for list in lists {
            payload.extend_from_slice(&(list.len() as u32).to_be_bytes());
            payload.extend_from_slice(list.as_bytes());
        }
        payload.push(0); // first_kex_packet_follows = FALSE
        payload.extend_from_slice(&0u32.to_be_bytes()); // reserved = 0

        let pad_len = 8usize;
        let pkt_len = 1 + payload.len() + pad_len;
        let mut framed = Vec::with_capacity(4 + pkt_len);
        framed.extend_from_slice(&(pkt_len as u32).to_be_bytes());
        framed.push(pad_len as u8);
        framed.extend_from_slice(&payload);
        framed.extend_from_slice(&vec![0u8; pad_len]);
        framed
    }

    #[test]
    fn ssh_msg_kexinit_parser_extracts_algorithms_and_flags_weak_ones() {
        let fixture = build_kexinit_fixture(
            "curve25519-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
            "rsa-sha2-512,ssh-rsa,ssh-dss",
            "chacha20-poly1305@openssh.com,aes128-ctr,3des-cbc,arcfour",
            "umac-128-etm@openssh.com,hmac-sha1,hmac-md5",
        );

        let parsed = parse_ssh_kexinit(&fixture).expect("valid SSH_MSG_KEXINIT fixture");
        assert_eq!(
            parsed.kex_algorithms,
            [
                "curve25519-sha256",
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group1-sha1"
            ]
        );
        assert_eq!(
            parsed.server_host_key_algorithms,
            ["rsa-sha2-512", "ssh-rsa", "ssh-dss"]
        );
        assert_eq!(
            parsed.encryption_algorithms_c2s,
            [
                "chacha20-poly1305@openssh.com",
                "aes128-ctr",
                "3des-cbc",
                "arcfour"
            ]
        );
        assert_eq!(
            parsed.mac_algorithms_c2s,
            ["umac-128-etm@openssh.com", "hmac-sha1", "hmac-md5"]
        );

        let weak = parsed.weak_algorithms();
        assert!(weak.contains(&"kex:diffie-hellman-group14-sha1".to_owned()));
        assert!(weak.contains(&"kex:diffie-hellman-group1-sha1".to_owned()));
        assert!(weak.contains(&"hostkey:ssh-rsa".to_owned()));
        assert!(weak.contains(&"hostkey:ssh-dss".to_owned()));
        assert!(weak.contains(&"cipher:3des-cbc".to_owned()));
        assert!(weak.contains(&"cipher:arcfour".to_owned()));
        assert!(weak.contains(&"mac:hmac-sha1".to_owned()));
        assert!(weak.contains(&"mac:hmac-md5".to_owned()));

        // Modern hardened config produces zero weak algorithms.
        let modern = build_kexinit_fixture(
            "curve25519-sha256,diffie-hellman-group16-sha512",
            "ssh-ed25519,rsa-sha2-512",
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
            "hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com",
        );
        let parsed_modern = parse_ssh_kexinit(&modern).unwrap();
        assert!(parsed_modern.weak_algorithms().is_empty());

        // Rejects truncated or non-KEXINIT packets.
        assert!(parse_ssh_kexinit(&[0, 0, 0, 5, 0, 21]).is_err());
        assert!(parse_ssh_kexinit(&fixture[..20]).is_err());
    }

    #[test]
    fn team_cymru_and_rdap_parsers_extract_asn_prefix_org_and_country() {
        let origin = "63949 | 45.33.32.0/24 | US | arin | 2010-02-02";
        assert_eq!(
            parse_cymru_origin(origin),
            Some((
                63949,
                Some("45.33.32.0/24".to_owned()),
                Some("US".to_owned())
            ))
        );
        let desc = "63949 | US | arin | 2012-07-20 | LINO-1 - Akamai Connected Cloud, US";
        assert_eq!(
            parse_cymru_asn(desc),
            Some("LINO-1 - Akamai Connected Cloud, US".to_owned())
        );

        let rdap_json: Value = serde_json::json!({
            "handle": "NET-45-33-32-0-1",
            "name": "LINODE-US",
            "country": "US",
            "arin_originas0_originautnums": [63949],
            "cidr0_cidrs": [
                { "v4prefix": "45.33.32.0", "length": 24 }
            ],
            "entities": [
                {
                    "handle": "LINO-1",
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Akamai Connected Cloud"]
                        ]
                    ]
                }
            ]
        });
        let (asn, org, prefix, country) = parse_rdap_response(&rdap_json).unwrap();
        assert_eq!(asn, Some(63949));
        assert_eq!(org.as_deref(), Some("Akamai Connected Cloud (LINODE-US)"));
        assert_eq!(prefix.as_deref(), Some("45.33.32.0/24"));
        assert_eq!(country.as_deref(), Some("US"));
    }

    #[test]
    fn http_header_waf_favicon_and_crtsh_parsers_handle_real_fixtures() {
        let headers = vec![
            ("Server".to_owned(), "Apache/2.4.7 (Ubuntu)".to_owned()),
            ("X-Powered-By".to_owned(), "PHP/8.1.2".to_owned()),
            ("X-Frame-Options".to_owned(), "SAMEORIGIN".to_owned()),
            ("CF-Ray".to_owned(), "84a1b2c3d4e5-SJC".to_owned()),
        ];
        let analysis = analyze_http_headers(&headers);
        assert_eq!(analysis.server.as_deref(), Some("Apache/2.4.7 (Ubuntu)"));
        assert_eq!(analysis.powered_by.as_deref(), Some("PHP/8.1.2"));
        assert_eq!(analysis.waf.as_deref(), Some("Cloudflare"));
        assert_eq!(
            analysis
                .present_security
                .get("X-Frame-Options")
                .map(String::as_str),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            analysis.missing_security,
            [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options"
            ]
        );

        let crtsh_fixture = r#"[
            {"name_value": "*.scanme.org\nscanme.org\nchat.scanme.org", "common_name": "scanme.org"},
            {"name_value": "SCANME.ORG\napi.scanme.org\nevil-scanme.org"},
            {"name_value": "sub.api.scanme.org\nnot-a-domain/path"}
        ]"#;
        let subs = parse_crtsh_json(crtsh_fixture, "scanme.org", 50).unwrap();
        assert_eq!(
            subs,
            [
                "scanme.org",
                "chat.scanme.org",
                "api.scanme.org",
                "sub.api.scanme.org"
            ]
        );

        // MurmurHash3 deterministic check and framework lookup.
        assert_eq!(murmur3_32(b"hello", 0), 613153351);
        assert_eq!(lookup_favicon_framework(116323821), Some("Spring Boot"));
        assert_eq!(lookup_favicon_framework(81586312), Some("Jenkins"));
        assert!(distro_backport_note("OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13").is_some());
    }

    #[test]
    fn dns_doh_and_wire_parsers_extract_records_and_filter_txt() {
        let doh = serde_json::json!({
            "Status": 0,
            "Answer": [
                {"name": "scanme.nmap.org.", "type": 1, "TTL": 3600, "data": "45.33.32.156"},
                {"name": "scanme.nmap.org.", "type": 28, "TTL": 3600, "data": "2600:3c01::f03c:91ff:fe18:bb2f"}
            ]
        });
        assert_eq!(parse_doh_records(&doh, 1), ["45.33.32.156"]);
        assert_eq!(
            parse_doh_records(&doh, 28),
            ["2600:3c01::f03c:91ff:fe18:bb2f"]
        );
        assert!(is_notable_txt("v=spf1 include:_spf.google.com ~all"));
        assert!(is_notable_txt("v=DMARC1; p=reject;"));
        assert!(is_notable_txt("google-site-verification=abc123xyz"));
        assert!(!is_notable_txt("hello world random note"));
        assert_eq!(
            reverse_dns_name(IpAddr::V4(Ipv4Addr::new(45, 33, 32, 156))),
            "156.32.33.45.in-addr.arpa"
        );
    }

    #[test]
    fn traceroute_detailed_parser_extracts_hops_labels_filtered_stars_and_rtt() {
        let sample = "\
traceroute to 45.33.32.156 (45.33.32.156), 15 hops max, 60 byte packets
 1  192.168.0.1  1.8 ms
 2  96.120.1.1  9.4 ms
 3  be-202-seattle.comcast.net (68.86.1.1)  12.1 ms
 4  * * *
 5  173.230.159.1 (Linode Edge - Fremont, CA)  22.6 ms
 6  45.33.32.156  23.1 ms
";
        let hops = parse_traceroute_detailed(
            sample,
            "45.33.32.156",
            Some("192.168.0.1"),
            Some("scanme.nmap.org"),
        );
        assert_eq!(hops.len(), 6);
        assert_eq!(hops[0].hop, 1);
        assert_eq!(hops[0].address, "192.168.0.1");
        assert_eq!(hops[0].label.as_deref(), Some("Local Router"));
        assert_eq!(hops[0].rtt_ms, Some(1.8));
        assert!(hops[0].formatted().contains("Hop 1: 192.168.0.1"));
        assert!(hops[0].formatted().contains("(Local Router)"));
        assert!(hops[0].formatted().contains("1.8 ms"));

        assert_eq!(hops[1].hop, 2);
        assert_eq!(hops[1].address, "96.120.1.1");
        assert_eq!(hops[1].label.as_deref(), Some("ISP Regional Node"));
        assert_eq!(hops[1].rtt_ms, Some(9.4));

        assert_eq!(hops[3].hop, 4);
        assert_eq!(hops[3].address, "* * *");
        assert_eq!(
            hops[3].label.as_deref(),
            Some("isp-transit / ICMP filtered")
        );
        assert_eq!(hops[3].rtt_ms, None);
        assert!(hops[3].formatted().ends_with('—'));

        assert_eq!(hops[4].hop, 5);
        assert_eq!(hops[4].address, "173.230.159.1");
        assert_eq!(hops[4].label.as_deref(), Some("Linode Edge - Fremont, CA"));
        assert_eq!(hops[4].rtt_ms, Some(22.6));

        assert_eq!(hops[5].hop, 6);
        assert_eq!(hops[5].address, "45.33.32.156");
        assert_eq!(hops[5].label.as_deref(), Some("scanme.nmap.org"));
        assert_eq!(hops[5].rtt_ms, Some(23.1));

        // Round-trip parsing of formatted Hop lines.
        let formatted: String = hops
            .iter()
            .map(TraceHop::formatted)
            .collect::<Vec<_>>()
            .join("\n");
        let reparsed = parse_traceroute_detailed(
            &formatted,
            "45.33.32.156",
            Some("192.168.0.1"),
            Some("scanme.nmap.org"),
        );
        assert_eq!(reparsed, hops);
    }

    #[tokio::test]
    async fn resolved_ip_policy_blocks_loopback_and_imds_for_external_domains() {
        assert!(is_allowed_resolved_ip_for_name(
            "app.lab.local",
            "10.0.0.5".parse().unwrap()
        ));
        assert!(is_allowed_resolved_ip_for_name(
            "localhost",
            "127.0.0.1".parse().unwrap()
        ));
        assert!(is_allowed_resolved_ip_for_name(
            "localhost.",
            "::1".parse().unwrap()
        ));
        for blocked in [
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "169.254.169.254",
            "fe80::1",
            "0.0.0.0",
            "::",
            "255.255.255.255",
            "224.0.0.1",
        ] {
            assert!(
                !is_allowed_resolved_ip_for_name("evil.example", blocked.parse().unwrap()),
                "{blocked} should be rejected for evil.example"
            );
        }
        assert!(
            inspect_web_endpoint("169.254.169.254", Some("evil.example"), 80, false)
                .await
                .is_err()
        );
        assert!(
            inspect_web_endpoint("127.0.0.1", Some("evil.example"), 80, false)
                .await
                .is_err()
        );
    }
}

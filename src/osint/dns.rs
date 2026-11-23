//! DNS lookups: the `dns` stage, record parsing, UDP and DNS-over-HTTPS resolvers.

use super::*;

mod routes;

pub(super) use routes::DnsRoutes;
#[cfg(test)]
pub(super) use routes::{
    effective_nrpt, nrpt_routes, parse_resolv_conf_with, parse_resolver_file, parse_scutil_dns,
    DomainRoute, NrptRule, NRPT_OVERRIDE_DNS,
};

// ---------------------------------------------------------------------------
// 1. DNS (`dns` task) — DoH JSON + RFC 1035 UDP wire query + system resolver
// ---------------------------------------------------------------------------

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

/// The text of a TXT record as DNS-over-HTTPS gives it: in presentation
/// form, one or more quoted strings (`"v=spf1 ... " "include:x -all"`). A
/// record over 255 bytes, such as a long SPF record, comes as several. The
/// strings are joined without spaces (RFC 7208 3.3), as the wire parser
/// joins them, and their escapes (`\"`, `\\`, `\059`) undone. Text that
/// does not start with a quote is taken as it is.
fn txt_text(data: &str) -> String {
    let data = data.trim();
    if !data.starts_with('"') {
        return data.to_owned();
    }
    let bytes = data.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut quoted = false;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'"' => quoted = !quoted,
            b'\\' => {
                let digits = bytes
                    .get(at + 1..at + 4)
                    .filter(|digits| digits.iter().all(u8::is_ascii_digit))
                    .map(|d| d.iter().fold(0u32, |n, d| n * 10 + u32::from(d - b'0')));
                match (digits, bytes.get(at + 1)) {
                    (Some(value), _) if value <= 255 => {
                        out.push(value as u8);
                        at += 3;
                    }
                    (_, Some(next)) => {
                        out.push(*next);
                        at += 1;
                    }
                    (_, None) => {}
                }
            }
            // Between two strings.
            b if !quoted && b.is_ascii_whitespace() => {}
            b => out.push(b),
        }
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The longest TXT record kept, in bytes: an SPF record split into several
/// strings, or a 4096-bit DKIM key, whole.
const MAX_TXT: usize = 1024;

/// A record's data as kept. A TXT record is cut between its terms and kept
/// longer than the requests to the model hold (400 bytes): a cut through a
/// domain an SPF record names (`include:acmehol`) would leave part of a name
/// the vault never sees whole, while the request's own cut goes back to a
/// space.
fn clean_record(rrtype: u16, data: &str) -> String {
    let data = data.trim().trim_end_matches('.');
    if rrtype == 16 {
        crate::evidence::sanitize_words(data, MAX_TXT)
    } else {
        sanitize(data, 400)
    }
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
        let raw = if kind == 16 {
            txt_text(raw)
        } else {
            raw.trim().trim_matches('"').to_owned()
        };
        let cleaned = clean_record(rrtype, &raw);
        if !cleaned.is_empty() && !out.contains(&cleaned) {
            out.push(cleaned);
        }
    }
    out
}

/// What a DNS-over-HTTPS answer says: its records, a definite "none"
/// (Status 0 without them: NODATA; Status 3: NXDOMAIN), or nothing to go by
/// (any other Status, none, or an answer cut short).
pub fn parse_doh_answer(json: &Value, rrtype: u16) -> Lookup {
    let truncated = json.get("TC").and_then(Value::as_bool) == Some(true);
    match json.get("Status").and_then(Value::as_u64) {
        Some(0) => match parse_doh_records(json, rrtype) {
            records if !records.is_empty() => Lookup::Found(records),
            _ if truncated => Lookup::Failed,
            _ => Lookup::NoRecords,
        },
        Some(3) => Lookup::NoRecords,
        _ => Lookup::Failed,
    }
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
            let cleaned = clean_record(rtype, &val);
            if !cleaned.is_empty() && !out.contains(&cleaned) {
                out.push(cleaned);
            }
        }
    }
    out
}

/// Where this machine sends DNS questions (see [`routes`]). Never a
/// public resolver in place of its own: with none, a question goes nowhere
/// but over DNS-over-HTTPS, and only for a public name.
async fn system_routes() -> DnsRoutes {
    #[cfg(target_os = "macos")]
    {
        routes::macos_routes().await
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        DnsRoutes::only(
            std::fs::read_to_string("/etc/resolv.conf")
                .map(|text| parse_resolv_conf(&text))
                .unwrap_or_default(),
        )
    }
    #[cfg(windows)]
    {
        routes::windows_routes()
    }
    #[cfg(not(any(unix, windows)))]
    {
        DnsRoutes::default()
    }
}

/// The servers the `nameserver` lines of a `resolv.conf` name. A link-local
/// one keeps its interface (`fe80::1%wlan0`), without which it cannot be
/// reached; it is left out when this machine has no such interface.
#[cfg(any(unix, test))]
pub(super) fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    routes::parse_resolv_conf_with(text, &routes::zone_index)
}

/// The DNS servers Windows uses, from `GetAdaptersAddresses`.
#[cfg(windows)]
pub(super) mod windows_dns {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME,
        GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };

    pub fn servers() -> Vec<SocketAddr> {
        let flags = GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_FRIENDLY_NAME;
        // Microsoft suggests 15 KB to start with; the call says how much it
        // needs when that is too little.
        let mut size: u32 = 16 * 1024;
        for _ in 0..4 {
            // In u64 words: the records hold 8-byte fields.
            let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
            size = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
            let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            // SAFETY: `first` points to `size` writable bytes, aligned for
            // the record, alive until the end of this iteration.
            let result = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    std::ptr::null(),
                    first,
                    &mut size,
                )
            };
            match result {
                // SAFETY: the call filled the buffer, which is still alive.
                NO_ERROR => return unsafe { read_adapters(first) },
                ERROR_BUFFER_OVERFLOW => continue,
                _ => return Vec::new(),
            }
        }
        Vec::new()
    }

    /// The DNS servers of the adapters that are up.
    ///
    /// # Safety
    /// `first` is null or the start of a list `GetAdaptersAddresses` filled
    /// in, in a buffer that is alive.
    unsafe fn read_adapters(first: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<SocketAddr> {
        let mut servers = Vec::new();
        let mut adapter = first;
        // SAFETY: each `Next` is null or the next record of the same list.
        while let Some(record) = unsafe { adapter.as_ref() } {
            if record.OperStatus == IfOperStatusUp {
                let mut entry = record.FirstDnsServerAddress.cast_const();
                // SAFETY: as above, for the adapter's list of DNS servers.
                while let Some(server) = unsafe { entry.as_ref() } {
                    let address = &server.Address;
                    // SAFETY: the system wrote a socket address of this
                    // length there.
                    let found =
                        unsafe { socket_address(address.lpSockaddr, address.iSockaddrLength) };
                    if let Some(found) = found.filter(|s| !servers.contains(s)) {
                        servers.push(found);
                    }
                    entry = server.Next.cast_const();
                }
            }
            adapter = record.Next.cast_const();
        }
        servers
    }

    /// The DNS server at `sockaddr`, on port 53.
    ///
    /// # Safety
    /// `sockaddr` is null or points to `length` readable bytes.
    pub(in crate::osint) unsafe fn socket_address(
        sockaddr: *const SOCKADDR,
        length: i32,
    ) -> Option<SocketAddr> {
        let length = usize::try_from(length).ok()?;
        if sockaddr.is_null() || length < std::mem::size_of::<SOCKADDR>() {
            return None;
        }
        // SAFETY: not null, and at least a SOCKADDR long.
        let family = unsafe { sockaddr.read_unaligned() }.sa_family;
        match family {
            AF_INET if length >= std::mem::size_of::<SOCKADDR_IN>() => {
                // SAFETY: an AF_INET address this long is a SOCKADDR_IN.
                let v4 = unsafe { sockaddr.cast::<SOCKADDR_IN>().read_unaligned() };
                // SAFETY: every variant of the union is the same 4 bytes.
                let octets = unsafe { v4.sin_addr.S_un.S_addr }.to_ne_bytes();
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), 53))
            }
            AF_INET6 if length >= std::mem::size_of::<SOCKADDR_IN6>() => {
                // SAFETY: an AF_INET6 address this long is a SOCKADDR_IN6.
                let v6 = unsafe { sockaddr.cast::<SOCKADDR_IN6>().read_unaligned() };
                // SAFETY: the variants of each union are the same bytes.
                let (bytes, scope) = unsafe { (v6.sin6_addr.u.Byte, v6.Anonymous.sin6_scope_id) };
                let ip = Ipv6Addr::from(bytes);
                // fec0:0:0:ffff::1 to 3: what Windows lists when no IPv6 DNS
                // server is set. Site-local addresses are long retired.
                if (ip.segments()[0] & 0xffc0) == 0xfec0 {
                    return None;
                }
                Some(SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, scope)))
            }
            _ => None,
        }
    }
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

/// What one of this machine's DNS servers said to a question.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum DnsAnswer {
    /// A well-formed answer to the question asked: its records, or none
    /// (NODATA, NXDOMAIN). It is final: nobody else is asked.
    Answered(Vec<String>),
    /// The server did not understand the EDNS0 query (FORMERR, NOTIMP).
    EdnsRefused,
    /// Nothing to go by: SERVFAIL, REFUSED, a referral, an answer cut short
    /// with no record left, or a packet that answers another question.
    Nothing,
}

/// Reads `packet` as the answer to question `txid`, about `qname` and
/// `qtype`.
pub(super) fn read_dns_answer(packet: &[u8], txid: u16, qname: &str, qtype: u16) -> DnsAnswer {
    if packet.len() < 12 || u16::from_be_bytes([packet[0], packet[1]]) != txid {
        return DnsAnswer::Nothing;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let Some(rcode) = dns_rcode(packet).filter(|_| flags & 0x8000 != 0) else {
        return DnsAnswer::Nothing;
    };
    if matches!(rcode, 1 | 4) {
        return DnsAnswer::EdnsRefused;
    }
    if !matches!(rcode, 0 | 3) {
        return DnsAnswer::Nothing;
    }
    // A final answer repeats the question it answers.
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let asked = read_dns_name(packet, 12).and_then(|(name, next)| {
        let kind = packet.get(next..next + 2)?;
        Some((name, u16::from_be_bytes([kind[0], kind[1]])))
    });
    let wanted = qname.trim_end_matches('.');
    let same_question =
        asked.is_some_and(|(name, kind)| kind == qtype && name.eq_ignore_ascii_case(wanted));
    if qdcount != 1 || !same_question {
        return DnsAnswer::Nothing;
    }
    let records = if rcode == 0 {
        parse_dns_wire_response(packet, txid, qtype)
    } else {
        Vec::new()
    };
    if records.is_empty() {
        // Cut short (TC), or neither recursive (RA) nor authoritative (AA):
        // a referral, which says nothing about the name.
        let truncated = flags & 0x0200 != 0;
        let resolved = flags & 0x0080 != 0 || flags & 0x0400 != 0;
        if truncated || !resolved {
            return DnsAnswer::Nothing;
        }
    }
    DnsAnswer::Answered(records)
}

async fn ask_dns_server(
    server: SocketAddr,
    query: &[u8],
    txid: u16,
    qname: &str,
    qtype: u16,
) -> DnsAnswer {
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
    match tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => read_dns_answer(&buf[..n], txid, qname, qtype),
        _ => DnsAnswer::Nothing,
    }
}

/// Asks `endpoints` in turn until one gives a definite answer.
async fn query_doh(
    client: &reqwest::Client,
    endpoints: &[String],
    qname: &str,
    rrtype: u16,
) -> Lookup {
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
        _ => return Lookup::Failed,
    };
    for endpoint in endpoints {
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
            let answer = parse_doh_answer(&json, rrtype);
            if answer.is_known() {
                return answer;
            }
        }
    }
    Lookup::Failed
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

/// The public DNS-over-HTTPS services, asked only when this machine's own
/// resolvers give no answer.
const DOH_ENDPOINTS: [&str; 2] = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
];

/// What a DNS lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The records of the type asked for.
    Found(Vec<String>),
    /// A definite answer that there are none: NODATA or NXDOMAIN.
    NoRecords,
    /// No answer: every server timed out, failed (SERVFAIL) or refused,
    /// DNS-over-HTTPS failed or was not allowed, or no server could be asked.
    Failed,
    /// "None" about an internal target's name from default servers that do
    /// not resolve the target to the system's addresses for it. The system
    /// resolves it some other way (a split-DNS resolver not found, the hosts
    /// file, multicast DNS), or the servers answer made-up names: the answer
    /// proves nothing.
    Unconfirmed,
}

impl Lookup {
    /// The records found; none unless [`Lookup::Found`].
    pub fn records(&self) -> &[String] {
        match self {
            Self::Found(records) => records,
            _ => &[],
        }
    }

    pub fn into_records(self) -> Vec<String> {
        match self {
            Self::Found(records) => records,
            _ => Vec::new(),
        }
    }

    /// Whether the answer is definite: records, or none at all.
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Found(_) | Self::NoRecords)
    }
}

impl From<Vec<String>> for Lookup {
    /// The answer that has these records: none is a definite "none".
    fn from(records: Vec<String>) -> Self {
        if records.is_empty() {
            Self::NoRecords
        } else {
            Self::Found(records)
        }
    }
}

/// Why this system resolves a name to no address, as the `dns` stage's
/// own DNS questions for its A and AAAA records found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Unresolved {
    /// DNS said the name has no A or AAAA record (NODATA or NXDOMAIN).
    NoRecords,
    /// A lookup got no answer (timeout, SERVFAIL, refused).
    Failed,
    /// DNS has an address for it, or would not say: this system resolves
    /// it some other way, or not at all.
    NotHere,
}

/// How many of a name's servers are asked, as glibc's resolver does.
const MAX_SERVERS: usize = 3;

/// Where the DNS questions of a stage go: where this machine sends them
/// (see [`routes`]), whose answer is final, NXDOMAIN and "no such record"
/// included (for an internal target, see [`Lookup::Unconfirmed`]). Only
/// when none gives an answer (none known, no reply, SERVFAIL, REFUSED) is a
/// public name asked over DNS-over-HTTPS: never a name that split DNS sends
/// to particular servers, and never in the run for an internal target.
pub struct Resolver {
    client: reqwest::Client,
    /// Read from the system at the first question.
    routes: tokio::sync::OnceCell<DnsRoutes>,
    doh: Vec<String>,
    /// Whether DNS-over-HTTPS may be used at all in this run.
    public: bool,
    /// The internal target and the system's addresses for it, once
    /// [`Resolver::keep_private`] named them.
    target: Option<(String, Vec<IpAddr>)>,
    /// Whether the default servers know the target (see
    /// [`Lookup::Unconfirmed`]).
    target_known: tokio::sync::OnceCell<bool>,
}

impl Resolver {
    /// This machine's resolvers, with `client` for DNS-over-HTTPS.
    pub fn system(client: reqwest::Client) -> Self {
        let doh = DOH_ENDPOINTS.iter().map(|e| (*e).to_owned()).collect();
        Self::on(client, tokio::sync::OnceCell::new(), doh)
    }

    /// `servers` for every name.
    #[cfg(test)]
    pub(super) fn with(
        client: reqwest::Client,
        servers: Vec<SocketAddr>,
        doh: Vec<String>,
    ) -> Self {
        Self::with_routes(client, DnsRoutes::only(servers), doh)
    }

    #[cfg(test)]
    pub(super) fn with_routes(
        client: reqwest::Client,
        routes: DnsRoutes,
        doh: Vec<String>,
    ) -> Self {
        Self::on(client, tokio::sync::OnceCell::from(routes), doh)
    }

    fn on(
        client: reqwest::Client,
        routes: tokio::sync::OnceCell<DnsRoutes>,
        doh: Vec<String>,
    ) -> Self {
        Self {
            client,
            routes,
            doh,
            public: true,
            target: None,
            target_known: tokio::sync::OnceCell::new(),
        }
    }

    /// Keeps every later question on this machine's resolvers: `target` is
    /// internal, and so is every name asked about it. A "none" then counts
    /// only from servers chosen for the name's domain, or from default
    /// servers that resolve `target` to one of `addresses`, the system's
    /// addresses for it.
    pub fn keep_private(&mut self, target: &str, addresses: &[String]) {
        self.public = false;
        let addresses = addresses
            .iter()
            .filter_map(|ip| ip.parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical())
            .collect();
        self.target = Some((target.trim_end_matches('.').to_ascii_lowercase(), addresses));
    }

    /// The records of type `rrtype` for `qname`.
    pub async fn resolve(&self, qname: &str, rrtype: u16) -> Lookup {
        let routes = self.routes.get_or_init(system_routes).await;
        let route = routes.route(qname);
        match self.ask_system(route.servers, qname, rrtype).await {
            Some(records) if !records.is_empty() => return Lookup::Found(records),
            Some(_) if self.public || route.matched || self.default_knows_target(routes).await => {
                return Lookup::NoRecords
            }
            Some(_) => return Lookup::Unconfirmed,
            None => {}
        }
        if !self.public || route.matched || !may_ask_public_services(qname) {
            return Lookup::Failed;
        }
        query_doh(&self.client, &self.doh, qname, rrtype).await
    }

    /// Whether the default servers resolve the internal target's own name
    /// to an address the system has for it, asked once, and only when they
    /// are the ones the system asks about it. Any other answer (a server
    /// that answers every name, a hosts-file entry it does not know) proves
    /// nothing.
    async fn default_knows_target(&self, routes: &DnsRoutes) -> bool {
        let Some((target, addresses)) = &self.target else {
            return false;
        };
        *self
            .target_known
            .get_or_init(|| async {
                let route = routes.route(target);
                if route.matched {
                    return false;
                }
                for (qtype, wanted) in [(1, true), (28, false)] {
                    // Only the families the system has an address of.
                    if !addresses.iter().any(|ip| ip.is_ipv4() == wanted) {
                        continue;
                    }
                    let found = self.ask_system(route.servers, target, qtype).await;
                    if found.unwrap_or_default().iter().any(|record| {
                        record
                            .parse::<IpAddr>()
                            .is_ok_and(|ip| addresses.contains(&ip.to_canonical()))
                    }) {
                        return true;
                    }
                }
                false
            })
            .await
    }

    /// The answer of `servers`, or `None` when none gave one.
    async fn ask_system(
        &self,
        servers: &[SocketAddr],
        qname: &str,
        qtype: u16,
    ) -> Option<Vec<String>> {
        let mut txid_bytes = [0u8; 2];
        let txid = if getrandom::fill(&mut txid_bytes).is_ok() {
            u16::from_be_bytes(txid_bytes).max(1)
        } else {
            ((qtype.wrapping_mul(31337)) ^ (qname.len() as u16)).max(1)
        };
        let plain = build_dns_query(txid, qname, qtype).ok()?;
        let extended = with_edns0(plain.clone());
        for server in servers.iter().take(MAX_SERVERS) {
            // EDNS0 first; the plain query again only if the server refused it.
            for query in [&extended, &plain] {
                match ask_dns_server(*server, query, txid, qname, qtype).await {
                    DnsAnswer::Answered(records) => return Some(records),
                    DnsAnswer::EdnsRefused if std::ptr::eq(query, &extended) => continue,
                    _ => break,
                }
            }
        }
        None
    }
}

/// Queries a DNS record type the way the stages do (see [`Resolver`]), for
/// a name that says nothing about the target (Team Cymru's).
pub async fn resolve_rr(client: &reqwest::Client, qname: &str, rrtype: u16) -> Vec<String> {
    Resolver::system(client.clone())
        .resolve(qname, rrtype)
        .await
        .into_records()
}

/// The addresses the system resolves `name` to, as the scanner gets them
/// (`/etc/hosts` included): IPv4, then IPv6.
pub(super) async fn system_addresses(name: &str) -> (Vec<String>, Vec<String>) {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    let found =
        tokio::time::timeout(Duration::from_secs(4), tokio::net::lookup_host((name, 80))).await;
    if let Ok(Ok(addrs)) = found {
        for sock in addrs {
            let ip = sock.ip().to_canonical();
            let list = if ip.is_ipv4() { &mut v4 } else { &mut v6 };
            let text = ip.to_string();
            if !list.contains(&text) {
                list.push(text);
            }
        }
    }
    (v4, v6)
}

/// Whether `name` is an internal target: a name only a local network
/// knows, or one with a non-public address among `known`, or, with none
/// known, among those the system resolves it to now. Nothing about such a
/// target goes to a public resolver.
pub async fn is_internal_target(name: &str, known: &[String]) -> bool {
    if !may_ask_public_services(name) {
        return true;
    }
    if known.iter().any(|ip| ip.parse::<IpAddr>().is_ok()) {
        return any_non_public(known);
    }
    let (v4, v6) = system_addresses(name).await;
    any_non_public(&v4) || any_non_public(&v6)
}

/// For an internal target (see [`is_internal_target`]), the addresses the
/// system resolves it to: `known`, or, with none known, those it resolves
/// it to now. `None` for a public target.
pub async fn internal_target_addresses(name: &str, known: &[String]) -> Option<Vec<String>> {
    let mut addresses: Vec<String> = known
        .iter()
        .filter(|ip| ip.parse::<IpAddr>().is_ok())
        .cloned()
        .collect();
    if addresses.is_empty() {
        let (v4, v6) = system_addresses(name).await;
        addresses = v4.into_iter().chain(v6).collect();
    }
    (!may_ask_public_services(name) || any_non_public(&addresses)).then_some(addresses)
}

fn any_non_public(addresses: &[String]) -> bool {
    addresses
        .iter()
        .filter_map(|ip| ip.parse::<IpAddr>().ok())
        .any(is_non_public_ip)
}

/// The address of a name the port scan goes to, of `addresses` the system
/// resolved it to (in the system's order): nmap scans the first IPv4
/// address, or with `-6` (`ipv6`) the first IPv6 one. The other family's
/// first when there is none of that one.
pub fn primary_address(addresses: &[String], ipv6: bool) -> Option<String> {
    let of_family = |v6: bool| {
        addresses
            .iter()
            .find(|ip| ip.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6() == v6))
    };
    of_family(ipv6).or_else(|| of_family(!ipv6)).cloned()
}

/// What the `dns` stage found: `(observations, resolved_ips, summary_text,
/// why a name has no address)`.
pub type DnsFound = (Vec<Observation>, Vec<String>, String, Option<Unresolved>);

/// Runs the passive `dns` stage for `target`, whose port scan goes to IPv6
/// addresses when `ipv6` (`-6`).
pub async fn run_dns(target: &Target, ipv6: bool) -> Result<DnsFound> {
    let resolver = Resolver::system(build_http_client(Duration::from_secs(6))?);
    let system = match target {
        Target::Host(HostAddr::Name(name)) => system_addresses(name).await,
        _ => (Vec::new(), Vec::new()),
    };
    Ok(run_dns_with(target, resolver, system, ipv6).await)
}

/// The `dns` stage with `resolver` for the records, and `system`, the IPv4
/// and IPv6 addresses the system resolved a name target to. What it finds
/// about the name is recorded on the address the port scan goes to (see
/// [`primary_address`]).
pub(super) async fn run_dns_with(
    target: &Target,
    mut resolver: Resolver,
    system: (Vec<String>, Vec<String>),
    ipv6: bool,
) -> DnsFound {
    let mut observations = Vec::new();
    let mut resolved_ips = Vec::new();

    match target {
        Target::Network(net) => (
            observations,
            resolved_ips,
            format!("network range {net} (skipped)"),
            None,
        ),
        Target::Host(HostAddr::Ip { addr: ip, .. }) => {
            let ip_str = ip.to_canonical().to_string();
            resolved_ips.push(ip_str.clone());
            let ptr_name = reverse_dns_name(*ip);
            let ptrs = resolver.resolve(&ptr_name, 12).await;
            for ptr in ptrs.records() {
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
            let summary = match &ptrs {
                Lookup::Found(found) => format!("PTR {}", found.join(", ")),
                Lookup::NoRecords => "no PTR record".to_owned(),
                _ => "PTR lookup failed".to_owned(),
            };
            (observations, resolved_ips, summary, None)
        }
        Target::Host(HostAddr::Name(domain)) => {
            // The addresses are the system's, as the scanner gets them
            // (`/etc/hosts` included); asked of DNS, to report, when it has
            // none.
            let (mut a_recs, mut aaaa_recs) = system;
            let from_system = !a_recs.is_empty() || !aaaa_recs.is_empty();
            // DNS's answers, to say which gave none.
            let (mut a_answer, mut aaaa_answer) = (None, None);
            if !from_system {
                let (a, aaaa) =
                    tokio::join!(resolver.resolve(domain, 1), resolver.resolve(domain, 28));
                (a_recs, aaaa_recs) = (a.records().to_vec(), aaaa.records().to_vec());
                (a_answer, aaaa_answer) = (Some(a), Some(aaaa));
            }
            if !may_ask_public_services(domain)
                || any_non_public(&a_recs)
                || any_non_public(&aaaa_recs)
            {
                // Only the system's addresses tell which DNS server knows
                // the name.
                let system: Vec<String> = a_recs
                    .iter()
                    .chain(&aaaa_recs)
                    .filter(|_| from_system)
                    .cloned()
                    .collect();
                resolver.keep_private(domain, &system);
            }
            // Whether the name publishes IPv6 when the system gave none
            // (Windows leaves it out on a machine without IPv6): reported,
            // never scanned.
            let ask_aaaa = from_system && aaaa_recs.is_empty();
            let resolver = &resolver;
            let (cname_answer, mx_answer, ns_answer, txt_answer, published_aaaa) = tokio::join!(
                resolver.resolve(domain, 5),
                resolver.resolve(domain, 15),
                resolver.resolve(domain, 2),
                resolver.resolve(domain, 16),
                async {
                    if ask_aaaa {
                        Some(resolver.resolve(domain, 28).await)
                    } else {
                        None
                    }
                },
            );
            if published_aaaa.is_some() {
                aaaa_answer = published_aaaa;
            }
            let unanswered: Vec<&Lookup> = [
                a_answer.as_ref(),
                aaaa_answer.as_ref(),
                Some(&cname_answer),
                Some(&mx_answer),
                Some(&ns_answer),
                Some(&txt_answer),
            ]
            .into_iter()
            .flatten()
            .filter(|answer| !answer.is_known())
            .collect();
            let failed_note = if unanswered.contains(&&Lookup::Unconfirmed) {
                Some("this machine's DNS server does not know the name")
            } else if !unanswered.is_empty() {
                Some("some DNS lookups failed")
            } else {
                None
            };
            let (cname_recs, mx_recs, ns_recs, raw_txt) = (
                cname_answer.records(),
                mx_answer.records(),
                ns_answer.records(),
                txt_answer.records(),
            );

            // Only the system's addresses are the target's. DNS's answer
            // for a name the system does not resolve (refused, blocked) is
            // reported, never probed.
            for ip in a_recs.iter().chain(&aaaa_recs).filter(|_| from_system) {
                if IpAddr::from_str(ip)
                    .is_ok_and(|addr| is_allowed_resolved_ip_for_name(domain, addr))
                    && !resolved_ips.contains(ip)
                {
                    resolved_ips.push(ip.clone());
                }
            }

            // The system gave no address: what DNS said of the A and AAAA
            // questions, for the scan stages to tell why nothing is up.
            let unresolved = (!from_system).then(|| {
                let answers = [&a_answer, &aaaa_answer].map(Option::as_ref);
                if !(a_recs.is_empty() && aaaa_recs.is_empty()) {
                    Unresolved::NotHere
                } else if answers.iter().all(|a| a == &Some(&Lookup::NoRecords)) {
                    Unresolved::NoRecords
                } else if answers.iter().any(|a| a == &Some(&Lookup::Failed)) {
                    Unresolved::Failed
                } else {
                    Unresolved::NotHere
                }
            });

            let primary_address =
                primary_address(&resolved_ips, ipv6).unwrap_or_else(|| domain.clone());

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
                    let ptrs = resolver.resolve(&ptr_name, 12).await;
                    for ptr in ptrs.records() {
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

            if aaaa_recs.is_empty() {
                aaaa_recs = aaaa_answer
                    .as_ref()
                    .map_or_else(Vec::new, |a| a.records().to_vec());
            }
            // "None" only when DNS said so.
            let ipv6_dns = if aaaa_recs.is_empty() && aaaa_answer != Some(Lookup::NoRecords) {
                None
            } else if aaaa_recs.is_empty() {
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
                waf_cdn: detect_waf_from_cnames(cname_recs),
                hops: Vec::new(),
                record: EvidenceRecord::observed(Source::Dns, Confidence::High, domain),
            });

            for cname in cname_recs {
                let ev = format!("{domain} IN CNAME {cname}");
                observations.push(Observation::Fact {
                    address: primary_address.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: format!("CNAME record: {cname}"),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                });
            }
            for mx in mx_recs {
                let ev = format!("{domain} IN MX {mx}");
                observations.push(Observation::Fact {
                    address: primary_address.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: format!("MX record: {mx}"),
                    record: EvidenceRecord::observed(Source::Dns, Confidence::High, &ev),
                });
            }
            for ns in ns_recs {
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

            let mut summary = format!(
                "{} A, {} AAAA, {} NS, {} MX",
                a_recs.len(),
                aaaa_recs.len(),
                ns_recs.len(),
                mx_recs.len()
            );
            if !from_system && !(a_recs.is_empty() && aaaa_recs.is_empty()) {
                summary.push_str("; this system does not resolve the name");
            }
            if let Some(note) = failed_note {
                summary.push_str("; ");
                summary.push_str(note);
            }
            (observations, resolved_ips, summary, unresolved)
        }
    }
}

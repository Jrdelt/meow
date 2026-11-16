//! Host, endpoint, scan-target and URL normalisation.
//!
//! Everything that enters the graph goes through here so that the same host
//! always gets the same key: `10.0.0.5`, `[fe80::1%eth0]:22`,
//! `App.Lab.Local.` and `https://app.lab.local:8443/portal/` are all reduced
//! to one canonical spelling.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use ipnetwork::IpNetwork;

/// Deepest URL path kept in a port's sub-path tree.
pub const MAX_PATH_DEPTH: usize = 16;
const MAX_SEGMENT_LEN: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostAddr {
    Ip {
        addr: IpAddr,
        /// IPv6 zone identifier (`%eth0`), kept for link-local addresses.
        zone: Option<String>,
    },
    Name(String),
}

impl HostAddr {
    /// Parses a bare host: an IPv4 or IPv6 address (optionally bracketed,
    /// optionally with a `%zone`) or a DNS name. No port.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if let Some(inner) = text.strip_prefix('[') {
            let inner = inner.strip_suffix(']')?;
            let (addr_text, zone) = match inner.split_once('%') {
                Some((addr, zone)) => (addr, Some(zone)),
                None => (inner, None),
            };
            let v6 = Ipv6Addr::from_str(addr_text).ok()?;
            let addr = IpAddr::V6(v6).to_canonical();
            let zone = match zone {
                None => None,
                Some(zone) if addr.is_ipv6() && valid_zone(zone) => Some(zone.to_owned()),
                Some(_) => return None,
            };
            return Some(HostAddr::Ip { addr, zone });
        }
        if text.contains(['[', ']']) {
            return None;
        }
        let (addr_text, zone) = match text.split_once('%') {
            Some((addr, zone)) => (addr, Some(zone)),
            None => (text, None),
        };
        if let Ok(addr) = IpAddr::from_str(addr_text) {
            let addr = addr.to_canonical();
            let zone = match zone {
                None => None,
                Some(zone) if addr.is_ipv6() && valid_zone(zone) => Some(zone.to_owned()),
                Some(_) => return None,
            };
            return Some(HostAddr::Ip { addr, zone });
        }
        if zone.is_some() {
            return None;
        }
        valid_hostname(text).map(HostAddr::Name)
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            HostAddr::Ip { addr, .. } => Some(*addr),
            HostAddr::Name(_) => None,
        }
    }

    pub fn is_name(&self) -> bool {
        matches!(self, HostAddr::Name(_))
    }

    /// The key used for this host everywhere in the graph.
    pub fn canonical(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for HostAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostAddr::Ip { addr, zone: None } => write!(f, "{addr}"),
            HostAddr::Ip {
                addr,
                zone: Some(zone),
            } => write!(f, "{addr}%{zone}"),
            HostAddr::Name(name) => f.write_str(name),
        }
    }
}

fn valid_zone(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= 32
        && zone
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Lower-cases and validates a DNS name; returns `None` for anything else
/// (including strings that look like malformed IP addresses).
fn valid_hostname(text: &str) -> Option<String> {
    let name = text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut last = "";
    for label in name.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return None;
        }
        last = label;
    }
    // A last label without letters means a (broken) IPv4 address or an
    // address range such as `10.0.0.1-50`, not a name.
    if !last.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(name)
}

/// A host with an optional port, as found in tool output.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub host: HostAddr,
    pub port: Option<u16>,
}

impl Endpoint {
    /// Accepts `10.0.0.5`, `10.0.0.5:443`, `::1`, `[::1]`, `[::1]:8080`,
    /// `[fe80::1%eth0]:22`, `fe80::1%eth0`, `name` and `name:8443`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if let Some(rest) = text.strip_prefix('[') {
            let (inside, after) = rest.split_once(']')?;
            let host = HostAddr::parse(&text[..inside.len() + 2])?;
            let port = match after {
                "" => None,
                _ => Some(parse_port(after.strip_prefix(':')?)?),
            };
            return Some(Self { host, port });
        }
        if let Ok(socket) = SocketAddr::from_str(text) {
            if socket.port() == 0 {
                return None;
            }
            return Some(Self {
                host: HostAddr::Ip {
                    addr: socket.ip().to_canonical(),
                    zone: None,
                },
                port: Some(socket.port()),
            });
        }
        // Two or more colons without brackets: a bare IPv6 address.
        if text.matches(':').count() >= 2 {
            return HostAddr::parse(text)
                .filter(|h| h.ip().is_some())
                .map(|host| Self { host, port: None });
        }
        match text.split_once(':') {
            Some((host, port)) => Some(Self {
                host: HostAddr::parse(host)?,
                port: Some(parse_port(port)?),
            }),
            None => HostAddr::parse(text).map(|host| Self { host, port: None }),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.host, self.port) {
            (host, None) => write!(f, "{host}"),
            (host @ HostAddr::Ip { addr, .. }, Some(port)) if addr.is_ipv6() => {
                write!(f, "[{host}]:{port}")
            }
            (host, Some(port)) => write!(f, "{host}:{port}"),
        }
    }
}

fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u16>().ok().filter(|port| *port != 0)
}

/// Something `meow recon` may be pointed at: one host or one CIDR range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Host(HostAddr),
    Network(IpNetwork),
}

impl Target {
    /// Only plain hosts and valid CIDR ranges are accepted, so the result is
    /// always safe to hand to a scanner as a single argument; callers use
    /// [`Target::check_size`] to cap range width.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.contains('/') {
            let network = IpNetwork::from_str(text).ok()?;
            let network = IpNetwork::new(network.network(), network.prefix()).ok()?;
            return Some(Target::Network(network));
        }
        HostAddr::parse(text).map(Target::Host)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match self {
            Target::Host(host) => host.ip() == Some(ip),
            Target::Network(network) => network.contains(ip),
        }
    }

    /// Refuses a range of more than [`MAX_RANGE_ADDRESSES`] addresses. A
    /// slip of the prefix (`/8` for `/24`, or `0.0.0.0/0`) would otherwise
    /// send a scan across networks nobody asked about.
    pub fn check_size(&self) -> Result<(), String> {
        let Target::Network(network) = self else {
            return Ok(());
        };
        let bits = match network {
            IpNetwork::V4(_) => 32,
            IpNetwork::V6(_) => 128,
        };
        let host_bits = bits - u32::from(network.prefix());
        if host_bits <= MAX_RANGE_BITS {
            return Ok(());
        }
        let size = if host_bits < 64 {
            group_thousands(1u64 << host_bits)
        } else {
            format!("2^{host_bits}")
        };
        Err(format!(
            "{network} covers {size} addresses; meow scans at most {} at once \
             (/{} or smaller for IPv4, /{} for IPv6). Queue the parts you mean one by one",
            group_thousands(MAX_RANGE_ADDRESSES),
            32 - MAX_RANGE_BITS,
            128 - MAX_RANGE_BITS
        ))
    }
}

/// The largest range `meow recon` takes: an IPv4 `/16`.
const MAX_RANGE_BITS: u32 = 16;
pub const MAX_RANGE_ADDRESSES: u64 = 1 << MAX_RANGE_BITS;

/// `65536` as `65,536`.
fn group_thousands(number: u64) -> String {
    let digits = number.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Host(host) => write!(f, "{host}"),
            Target::Network(network) => write!(f, "{network}"),
        }
    }
}

/// An `http`/`https` URL reduced to what the graph stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUrl {
    pub scheme: String,
    pub host: HostAddr,
    pub port: u16,
    /// Normalised path: starts with `/`, no query or fragment.
    pub path: String,
}

impl WebUrl {
    pub fn parse(text: &str) -> Option<Self> {
        let url = url::Url::parse(text.trim()).ok()?;
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return None;
        }
        let host = match url.host()? {
            url::Host::Domain(name) => HostAddr::parse(name)?,
            url::Host::Ipv4(addr) => HostAddr::Ip {
                addr: IpAddr::V4(addr),
                zone: None,
            },
            url::Host::Ipv6(addr) => HostAddr::Ip {
                addr: IpAddr::V6(addr).to_canonical(),
                zone: None,
            },
        };
        let port = url.port_or_known_default().filter(|p| *p != 0)?;
        let mut path = String::new();
        for segment in path_segments(url.path()) {
            path.push('/');
            path.push_str(segment);
        }
        if path.is_empty() || (url.path().ends_with('/') && path.len() > 1) {
            path.push('/');
        }
        Some(Self {
            scheme: scheme.to_owned(),
            host,
            port,
            path,
        })
    }

    /// `scheme://host[:port]` with the port omitted when it is the default.
    pub fn origin(&self) -> String {
        web_origin(&self.scheme, &self.host.canonical(), self.port)
    }
}

/// Builds `scheme://host[:port]`, bracketing IPv6 addresses and stripping any
/// `%zone` scope suffix so the URL is valid RFC 3986.
pub fn web_origin(scheme: &str, host: &str, port: u16) -> String {
    let bare = host.split('%').next().unwrap_or(host);
    let host = match Ipv6Addr::from_str(bare) {
        Ok(_) => format!("[{bare}]"),
        Err(_) => bare.to_owned(),
    };
    let default = if scheme == "https" { 443 } else { 80 };
    if port == default {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

/// Splits a URL path into clean segments for the sub-path tree: empty and
/// `.` segments are dropped, `..` pops its parent segment, the query and
/// fragment are cut off, and overly deep or long paths are truncated.
pub fn path_segments(path: &str) -> Vec<&str> {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let mut out = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            out.pop();
            continue;
        }
        if out.len() >= MAX_PATH_DEPTH {
            break;
        }
        let mut end = segment.len().min(MAX_SEGMENT_LEN);
        while !segment.is_char_boundary(end) {
            end -= 1;
        }
        out.push(&segment[..end]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_is_at_most_a_sixteen_bit_one() {
        for fine in [
            "10.0.0.5",
            "example.org",
            "10.0.0.0/24",
            "10.20.0.0/16",
            "192.0.2.7/32",
            "fd00::/112",
            "fd00::5/128",
        ] {
            assert_eq!(Target::parse(fine).unwrap().check_size(), Ok(()), "{fine}");
        }
        let refused = |text: &str| Target::parse(text).unwrap().check_size().unwrap_err();
        assert!(refused("10.0.0.0/15").starts_with("10.0.0.0/15 covers 131,072 addresses"));
        assert!(refused("10.0.0.0/8").contains("covers 16,777,216 addresses"));
        assert!(refused("0.0.0.0/0").contains("covers 4,294,967,296 addresses"));
        assert!(refused("fd00::/111").contains("covers 131,072 addresses"));
        assert!(refused("fd00::/64").contains("covers 2^64 addresses"));
        assert!(refused("::/0").contains("covers 2^128 addresses"));
        assert!(refused("::/0")
            .contains("at most 65,536 at once (/16 or smaller for IPv4, /112 for IPv6)"));
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1000), "1,000");
        assert_eq!(group_thousands(1234567), "1,234,567");
    }

    fn endpoint(text: &str) -> Option<(String, Option<u16>)> {
        Endpoint::parse(text).map(|e| (e.host.canonical(), e.port))
    }

    #[test]
    fn ipv4_and_names_with_and_without_ports() {
        assert_eq!(endpoint("10.0.0.5"), Some(("10.0.0.5".into(), None)));
        assert_eq!(
            endpoint(" 10.0.0.5:443 "),
            Some(("10.0.0.5".into(), Some(443)))
        );
        assert_eq!(
            endpoint("App.Lab.Local."),
            Some(("app.lab.local".into(), None))
        );
        assert_eq!(endpoint("dc01:8443"), Some(("dc01".into(), Some(8443))));
        assert_eq!(
            endpoint("xn--bcher-kva.example"),
            Some(("xn--bcher-kva.example".into(), None))
        );
    }

    #[test]
    fn ipv6_in_every_spelling() {
        assert_eq!(endpoint("::1"), Some(("::1".into(), None)));
        assert_eq!(endpoint("[::1]"), Some(("::1".into(), None)));
        assert_eq!(endpoint("[::1]:8080"), Some(("::1".into(), Some(8080))));
        assert_eq!(
            endpoint("[2001:DB8:0:0::00A]:443"),
            Some(("2001:db8::a".into(), Some(443)))
        );
        assert_eq!(
            endpoint("fe80::1%eth0"),
            Some(("fe80::1%eth0".into(), None))
        );
        assert_eq!(
            endpoint("[fe80::1%eth0]:22"),
            Some(("fe80::1%eth0".into(), Some(22)))
        );
        assert_eq!(
            endpoint("fe80::1ff:fe23:4567:890a%3"),
            Some(("fe80::1ff:fe23:4567:890a%3".into(), None))
        );
        // IPv4-mapped IPv6 is the same host as the IPv4 address.
        assert_eq!(
            endpoint("[::ffff:10.0.0.5]:80"),
            Some(("10.0.0.5".into(), Some(80)))
        );
    }

    #[test]
    fn endpoints_display_in_canonical_form() {
        for (input, shown) in [
            ("[::1]:8080", "[::1]:8080"),
            ("::1", "::1"),
            ("[FE80::1%eth0]:22", "[fe80::1%eth0]:22"),
            ("10.0.0.5:443", "10.0.0.5:443"),
            ("Host.Example:80", "host.example:80"),
        ] {
            assert_eq!(Endpoint::parse(input).unwrap().to_string(), shown);
        }
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in [
            "",
            " ",
            "10.0.0.256",
            "10.0.0",
            "1.2.3.4.5",
            "10.0.0.5:0",
            "10.0.0.5:70000",
            "10.0.0.5:http",
            "[::1",
            "[::1]x",
            "[::1]:",
            "[example.com]:80",
            "[cargo.toml]",
            "[10.0.0.5]",
            "10.0.0.5%eth0",
            "fe80::1%",
            "fe80::1%e th0",
            "-oN/tmp/x",
            "host name",
            "a..b",
            "-bad.example",
            "exa$mple.com",
            "http://example.com",
            "user@host",
        ] {
            assert_eq!(Endpoint::parse(bad), None, "accepted {bad:?}");
        }
        assert_eq!(HostAddr::parse("[cargo.toml]"), None);
    }

    #[test]
    fn recon_targets_are_hosts_or_cidr_ranges_only() {
        let show = |text: &str| Target::parse(text).map(|t| t.to_string());
        assert_eq!(show("10.0.0.5"), Some("10.0.0.5".into()));
        assert_eq!(show("10.0.0.77/24"), Some("10.0.0.0/24".into()));
        assert_eq!(show("10.10.0.0/16"), Some("10.10.0.0/16".into()));
        assert_eq!(show("2001:db8::1/64"), Some("2001:db8::/64".into()));
        assert_eq!(show("fe80::1%eth0"), Some("fe80::1%eth0".into()));
        assert_eq!(
            show("Scanme.Example.org"),
            Some("scanme.example.org".into())
        );
        assert_eq!(show("::1"), Some("::1".into()));
        assert_eq!(show("0.0.0.0/0"), Some("0.0.0.0/0".into()));
        assert_eq!(show("::/0"), Some("::/0".into()));
        for bad in [
            "-iL/etc/passwd",
            "--script=x",
            "10.0.0.5 10.0.0.6",
            "10.0.0.1-50",
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "[2001:db8::1]/64",
            "fe80::1%eth0/64",
            "example.com/24",
            "10.0.0.5:80",
            "fe80::1%",
            "",
        ] {
            assert_eq!(Target::parse(bad), None, "accepted {bad:?}");
        }

        let net = Target::parse("192.168.56.0/24").unwrap();
        assert!(net.contains("192.168.56.10".parse().unwrap()));
        assert!(!net.contains("192.168.57.10".parse().unwrap()));
    }

    #[test]
    fn urls_are_reduced_to_origin_and_clean_path() {
        let url = WebUrl::parse("HTTPS://App.Lab.Local:8443//portal/./config/?x=1#top").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host.canonical(), "app.lab.local");
        assert_eq!(url.port, 8443);
        assert_eq!(url.path, "/portal/config/");
        assert_eq!(url.origin(), "https://app.lab.local:8443");

        let url = WebUrl::parse("http://[2001:db8::1]/a/b.php").unwrap();
        assert_eq!((url.port, url.path.as_str()), (80, "/a/b.php"));
        assert_eq!(url.origin(), "http://[2001:db8::1]");
        assert_eq!(
            web_origin("http", "fe80::1%eth0", 8080),
            "http://[fe80::1]:8080"
        );

        assert_eq!(WebUrl::parse("http://10.0.0.5").unwrap().path, "/");
        assert_eq!(
            WebUrl::parse("https://10.0.0.5:443/").unwrap().origin(),
            "https://10.0.0.5"
        );
        for bad in [
            "ftp://x/",
            "javascript:alert(1)",
            "/relative",
            "http://",
            "http://10.0.0.5:0/",
            "mailto:a@b",
        ] {
            assert_eq!(WebUrl::parse(bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn path_segments_are_bounded() {
        assert_eq!(
            path_segments("/portal//config/./x?y=/z#f"),
            ["portal", "config", "x"]
        );
        assert_eq!(path_segments("/portal/old/../admin/../../root"), ["root"]);
        assert_eq!(path_segments("/"), Vec::<&str>::new());
        let deep = "/a".repeat(40);
        assert_eq!(path_segments(&deep).len(), MAX_PATH_DEPTH);
        let long = format!("/{}", "é".repeat(200));
        let segments = path_segments(&long);
        assert!(segments[0].len() <= MAX_SEGMENT_LEN);
        assert!(segments[0].chars().all(|c| c == 'é'));
    }
}

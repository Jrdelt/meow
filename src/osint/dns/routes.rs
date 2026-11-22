//! Where the system sends a DNS question about a name: which servers, chosen
//! by the name's domain where the system routes by domain (split DNS).
//!
//! - Linux and the BSDs: the servers of `/etc/resolv.conf`, for every name.
//! - macOS: the resolvers `scutil --dns` lists, which include those of VPNs,
//!   Tailscale and `/etc/resolver/*`: the one whose domain is the longest
//!   ending of the name, else the default one.
//! - Windows: the Name Resolution Policy Table (NRPT) in the registry, the
//!   most specific rule for the name, else the network adapters' servers.

use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::str::FromStr;

/// The servers for one domain's names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::osint) struct DomainRoute {
    /// The domain, lowercase without dots at the ends: the route is for it
    /// and every name under it. Empty: for every name (NRPT `.`).
    pub domain: String,
    /// For the name itself only, not those under it (an NRPT rule for one
    /// name).
    pub exact: bool,
    /// For the reverse names (`PTR`) of the addresses in this network
    /// instead (an NRPT subnet rule).
    pub network: Option<ipnetwork::IpNetwork>,
    /// Its servers. `None`: the default servers, as for a name no route is
    /// for (an NRPT rule that does not say where questions go).
    pub servers: Option<Vec<SocketAddr>>,
    /// Among routes that match a name equally well, the lowest comes first.
    pub order: u32,
}

impl DomainRoute {
    /// How well the route matches `name` (lowercase, no final dot): the
    /// higher, the more specific. `None` when it does not.
    fn specificity(&self, name: &str) -> Option<usize> {
        if let Some(network) = self.network {
            let address = super::reverse_name_address(name)?;
            if !network.contains(address) {
                return None;
            }
            // As many labels as the network's reverse zone, half a label
            // more for a prefix that ends inside one.
            let bits = if network.is_ipv4() { 8 } else { 4 };
            let prefix = usize::from(network.prefix());
            return Some((2 + prefix / bits) * 2 + usize::from(prefix % bits != 0));
        }
        if self.domain.is_empty() {
            return Some(0);
        }
        let labels = self.domain.split('.').count();
        if name == self.domain {
            Some(labels * 2 + usize::from(self.exact))
        } else if !self.exact
            && name.len() > self.domain.len()
            && name.ends_with(&self.domain)
            && name.as_bytes()[name.len() - self.domain.len() - 1] == b'.'
        {
            Some(labels * 2)
        } else {
            None
        }
    }
}

/// This machine's DNS configuration: the default servers, and the routes
/// for particular domains.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::osint) struct DnsRoutes {
    pub default: Vec<SocketAddr>,
    pub domains: Vec<DomainRoute>,
}

/// The servers to ask about a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::osint) struct Route<'a> {
    pub servers: &'a [SocketAddr],
    /// Whether they were chosen for the name's domain. If not, they are the
    /// default servers.
    pub matched: bool,
}

impl DnsRoutes {
    /// Only `servers`, for every name.
    #[cfg(any(all(unix, not(target_os = "macos")), test))]
    pub fn only(servers: Vec<SocketAddr>) -> Self {
        Self {
            default: servers,
            domains: Vec::new(),
        }
    }

    /// The servers the system asks about `name`.
    pub fn route(&self, name: &str) -> Route<'_> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let best = self
            .domains
            .iter()
            .enumerate()
            .filter_map(|(at, route)| Some((route.specificity(&name)?, route.order, at, route)))
            // The most specific; then the lowest order, then the first.
            .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then(b.2.cmp(&a.2)));
        match best.and_then(|(_, _, _, route)| route.servers.as_deref()) {
            Some(servers) => Route {
                servers,
                matched: true,
            },
            None => Route {
                servers: &self.default,
                matched: false,
            },
        }
    }
}

/// The interface a zone names (`en0`, or its number `4`), by its index.
pub(in crate::osint) fn zone_index(zone: &str) -> Option<u32> {
    if let Ok(index) = zone.parse::<u32>() {
        return (index != 0).then_some(index);
    }
    #[cfg(unix)]
    {
        let name = std::ffi::CString::new(zone).ok()?;
        // SAFETY: a NUL-terminated string that outlives the call.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        (index != 0).then_some(index)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// The DNS server `text` (`address` or `address%zone`) on `port`. An IPv6
/// address keeps the interface its zone names (`zone` looks it up), or
/// `scope` without one. `None` when the zone names no interface here, or
/// for a link-local address with no interface: nothing could reach it.
pub(in crate::osint) fn server_address(
    text: &str,
    port: u16,
    scope: u32,
    zone: &dyn Fn(&str) -> Option<u32>,
) -> Option<SocketAddr> {
    let (address, named) = match text.split_once('%') {
        Some((address, named)) => (address, Some(named)),
        None => (text, None),
    };
    match IpAddr::from_str(address).ok()? {
        IpAddr::V4(ip) => Some(SocketAddr::new(IpAddr::V4(ip), port)),
        IpAddr::V6(ip) => {
            let scope = match named {
                Some(named) => zone(named)?,
                None => scope,
            };
            let link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
            if link_local && scope == 0 {
                return None;
            }
            Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)))
        }
    }
}

/// `servers` read with [`server_address`], each once.
fn servers_of<'a>(
    servers: impl IntoIterator<Item = &'a str>,
    port: u16,
    scope: u32,
    zone: &dyn Fn(&str) -> Option<u32>,
) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for server in servers {
        if let Some(found) = server_address(server.trim(), port, scope, zone) {
            if !out.contains(&found) {
                out.push(found);
            }
        }
    }
    out
}

/// The servers the `nameserver` lines of a `resolv.conf` name, with the
/// interface of a link-local one (`fe80::1%wlan0`) that `zone` finds.
#[cfg(any(unix, test))]
pub(in crate::osint) fn parse_resolv_conf_with(
    text: &str,
    zone: &dyn Fn(&str) -> Option<u32>,
) -> Vec<SocketAddr> {
    let named = text.lines().filter_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some("nameserver"))
            .then(|| words.next())
            .flatten()
    });
    servers_of(named, 53, 0, zone)
}

/// A domain name a route can be for: letters, digits, `-` and `_`.
#[cfg(any(target_os = "macos", windows, test))]
fn is_domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// The routes in the output of macOS's `scutil --dns`: its first part, the
/// resolvers for unscoped questions. The first without a domain is the
/// default one; the others are for their domain, with no server at all for
/// a multicast DNS one (`local`), which a unicast question cannot reach.
/// Resolvers for questions bound to one interface or service are left out.
#[cfg(any(target_os = "macos", test))]
pub(in crate::osint) fn parse_scutil_dns(
    text: &str,
    zone: &dyn Fn(&str) -> Option<u32>,
) -> DnsRoutes {
    #[derive(Default)]
    struct Resolver {
        domain: Option<String>,
        servers: Vec<String>,
        if_index: u32,
        port: Option<u16>,
        order: Option<u32>,
        scoped: bool,
    }
    let mut resolvers: Vec<Resolver> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // "DNS configuration (for scoped queries)" and the like.
        if line.starts_with("DNS configuration (") {
            break;
        }
        if line.starts_with("resolver #") {
            resolvers.push(Resolver::default());
            continue;
        }
        let (Some(resolver), Some((key, value))) = (resolvers.last_mut(), line.split_once(':'))
        else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "domain" => resolver.domain = Some(value.trim_matches('.').to_ascii_lowercase()),
            key if key.starts_with("nameserver[") => resolver.servers.push(value.to_owned()),
            // "6 (en0)"
            "if_index" => {
                resolver.if_index = value
                    .split_whitespace()
                    .next()
                    .and_then(|index| index.parse().ok())
                    .unwrap_or(0);
            }
            "port" => resolver.port = value.parse().ok(),
            "order" => resolver.order = value.parse().ok(),
            "flags" => {
                resolver.scoped = value
                    .split(',')
                    .any(|flag| matches!(flag.trim(), "Scoped" | "Service-specific"));
            }
            _ => {}
        }
    }
    let mut routes = DnsRoutes::default();
    let mut default_seen = false;
    for resolver in resolvers.into_iter().filter(|r| !r.scoped) {
        let servers = servers_of(
            resolver.servers.iter().map(String::as_str),
            resolver.port.unwrap_or(53),
            resolver.if_index,
            zone,
        );
        match resolver.domain {
            None if !default_seen => {
                default_seen = true;
                routes.default = servers;
            }
            Some(domain) if is_domain(&domain) => routes.domains.push(DomainRoute {
                domain,
                exact: false,
                network: None,
                servers: Some(servers),
                order: resolver.order.unwrap_or(u32::MAX),
            }),
            _ => {}
        }
    }
    routes
}

/// The route a file of macOS's `/etc/resolver` gives (resolver(5)): for
/// the domain the file is named after, or its `domain` line, to its
/// `nameserver` lines. `None` without a server.
#[cfg(any(target_os = "macos", test))]
pub(in crate::osint) fn parse_resolver_file(
    file_name: &str,
    text: &str,
    zone: &dyn Fn(&str) -> Option<u32>,
) -> Option<DomainRoute> {
    let mut domain = file_name.trim_matches('.').to_ascii_lowercase();
    let (mut port, mut order, mut servers) = (53u16, u32::MAX, Vec::new());
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some("domain"), Some(name)) => domain = name.trim_matches('.').to_ascii_lowercase(),
            (Some("nameserver"), Some(server)) => servers.push(server.to_owned()),
            (Some("port"), Some(number)) => port = number.parse().unwrap_or(53),
            (Some("search_order"), Some(number)) => order = number.parse().unwrap_or(u32::MAX),
            _ => {}
        }
    }
    let servers = servers_of(servers.iter().map(String::as_str), port, 0, zone);
    (is_domain(&domain) && !servers.is_empty()).then_some(DomainRoute {
        domain,
        exact: false,
        network: None,
        servers: Some(servers),
        order,
    })
}

/// The output of `scutil --dns`, if it gives it within 3 seconds.
#[cfg(target_os = "macos")]
async fn scutil_dns() -> Option<String> {
    use tokio::io::AsyncReadExt;
    const MAX_BYTES: u64 = 256 * 1024;
    let mut child = tokio::process::Command::new("/usr/sbin/scutil")
        .arg("--dns")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let read = async {
        let mut stdout = child.stdout.take()?;
        let mut out = Vec::new();
        (&mut stdout)
            .take(MAX_BYTES)
            .read_to_end(&mut out)
            .await
            .ok()?;
        drop(stdout);
        let status = child.wait().await.ok()?;
        status
            .success()
            .then(|| String::from_utf8_lossy(&out).into_owned())
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), read)
        .await
        .ok()
        .flatten()
}

/// The routes of the files in `/etc/resolver`.
#[cfg(target_os = "macos")]
fn resolver_files() -> Vec<DomainRoute> {
    use std::io::Read;
    let Ok(entries) = std::fs::read_dir("/etc/resolver") else {
        return Vec::new();
    };
    let mut routes = Vec::new();
    for entry in entries.flatten().take(64) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let mut text = String::new();
        let read = std::fs::File::open(entry.path())
            .and_then(|file| file.take(64 * 1024).read_to_string(&mut text));
        if read.is_ok() {
            routes.extend(parse_resolver_file(&name, &text, &zone_index));
        }
    }
    routes
}

/// macOS: the resolvers of `scutil --dns`, those of `/etc/resolver` it does
/// not list, and `/etc/resolv.conf` as the default when it gives none.
#[cfg(target_os = "macos")]
pub(in crate::osint) async fn macos_routes() -> DnsRoutes {
    let mut routes = scutil_dns()
        .await
        .map(|text| parse_scutil_dns(&text, &zone_index))
        .unwrap_or_default();
    for route in resolver_files() {
        if !routes.domains.iter().any(|r| r.domain == route.domain) {
            routes.domains.push(route);
        }
    }
    if routes.default.is_empty() {
        routes.default = std::fs::read_to_string("/etc/resolv.conf")
            .map(|text| super::parse_resolv_conf(&text))
            .unwrap_or_default();
    }
    routes
}

/// One rule of the Windows Name Resolution Policy Table, as the registry
/// keeps it.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::osint) struct NrptRule {
    /// `Name`: the namespaces it is for: `.corp.example.com` (the domain
    /// and the names under it), `host.example.com` (that name), a subnet
    /// `10.0.0.0/8` (its reverse names), or `.` (every name).
    pub names: Vec<String>,
    /// `GenericDNSServers`: its servers, separated by `;`.
    pub servers: String,
    /// `ConfigOptions`: [`NRPT_OVERRIDE_DNS`] when it sends questions to
    /// those servers.
    pub options: u32,
}

/// The `ConfigOptions` bit of an NRPT rule that sends questions to its own
/// servers.
#[cfg(any(windows, test))]
pub(in crate::osint) const NRPT_OVERRIDE_DNS: u32 = 0x8;

/// The rules Windows applies: those of Group Policy when there are any, as
/// it then ignores the local ones; else the local ones.
#[cfg(any(windows, test))]
pub(in crate::osint) fn effective_nrpt(
    policy: Vec<NrptRule>,
    local: Vec<NrptRule>,
) -> Vec<NrptRule> {
    if policy.is_empty() {
        local
    } else {
        policy
    }
}

/// The routes of NRPT `rules`, in their order.
#[cfg(any(windows, test))]
pub(in crate::osint) fn nrpt_routes(
    rules: &[NrptRule],
    zone: &dyn Fn(&str) -> Option<u32>,
) -> Vec<DomainRoute> {
    let mut routes = Vec::new();
    for (order, rule) in rules.iter().enumerate() {
        let servers = (rule.options & NRPT_OVERRIDE_DNS != 0).then(|| {
            servers_of(
                rule.servers
                    .split([';', ',', ' '])
                    .filter(|server| !server.is_empty()),
                53,
                0,
                zone,
            )
        });
        for name in &rule.names {
            let name = name.trim().to_ascii_lowercase();
            let (domain, exact, network) = if name == "." {
                (String::new(), false, None)
            } else if let Some(network) = name
                .contains('/')
                .then(|| ipnetwork::IpNetwork::from_str(&name).ok())
                .flatten()
            {
                (String::new(), false, Some(network))
            } else if let Some(suffix) = name.strip_prefix('.') {
                (suffix.trim_end_matches('.').to_owned(), false, None)
            } else {
                (name.trim_end_matches('.').to_owned(), true, None)
            };
            if network.is_none() && !domain.is_empty() && !is_domain(&domain) {
                continue;
            }
            routes.push(DomainRoute {
                domain,
                exact,
                network,
                servers: servers.clone(),
                order: u32::try_from(order).unwrap_or(u32::MAX),
            });
        }
    }
    routes
}

/// Reading the NRPT rules from the registry.
#[cfg(windows)]
pub(in crate::osint) mod nrpt {
    use super::NrptRule;
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_READ, KEY_WOW64_64KEY, RRF_RT_REG_DWORD, RRF_RT_REG_MULTI_SZ, RRF_RT_REG_SZ,
    };

    /// Group Policy's rules.
    const POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";
    /// The local rules (VPN profiles, Tailscale).
    const LOCAL: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    const MAX_RULES: u32 = 256;
    const MAX_VALUE_BYTES: u32 = 64 * 1024;

    /// The rules Windows applies.
    pub fn rules() -> Vec<NrptRule> {
        super::effective_nrpt(read(POLICY), read(LOCAL))
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    /// An open registry key, closed when dropped.
    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: a key this value opened, closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    impl Key {
        /// `path` (NUL-terminated) under `parent`, for reading.
        fn open(parent: HKEY, path: &[u16]) -> Option<Key> {
            let mut key: HKEY = std::ptr::null_mut();
            // SAFETY: `path` is NUL-terminated and `key` receives the handle.
            let status = unsafe {
                RegOpenKeyExW(
                    parent,
                    path.as_ptr(),
                    0,
                    KEY_READ | KEY_WOW64_64KEY,
                    &mut key,
                )
            };
            (status == ERROR_SUCCESS).then_some(Key(key))
        }

        /// The names of its subkeys, NUL-terminated.
        fn subkeys(&self) -> Vec<Vec<u16>> {
            let mut names = Vec::new();
            for index in 0..MAX_RULES {
                // Key names are at most 255 characters.
                let mut name = [0u16; 256];
                let mut length = name.len() as u32;
                // SAFETY: `name` holds `length` characters; the other
                // pointers are optional and null.
                let status = unsafe {
                    RegEnumKeyExW(
                        self.0,
                        index,
                        name.as_mut_ptr(),
                        &mut length,
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                if status == ERROR_NO_MORE_ITEMS {
                    break;
                }
                if status == ERROR_SUCCESS {
                    let length = (length as usize).min(name.len() - 1);
                    names.push(name[..length].iter().copied().chain(Some(0)).collect());
                }
            }
            names
        }

        /// The strings of value `name` (REG_SZ or REG_MULTI_SZ).
        fn strings(&self, name: &str) -> Vec<String> {
            let name = wide(name);
            let flags = RRF_RT_REG_SZ | RRF_RT_REG_MULTI_SZ;
            let mut size: u32 = 0;
            // SAFETY: with no buffer, the call only writes the size.
            let status = unsafe {
                RegGetValueW(
                    self.0,
                    std::ptr::null(),
                    name.as_ptr(),
                    flags,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut size,
                )
            };
            if status != ERROR_SUCCESS || size == 0 || size > MAX_VALUE_BYTES {
                return Vec::new();
            }
            let mut data = vec![0u16; (size as usize).div_ceil(2) + 1];
            let mut size = u32::try_from(data.len() * 2).unwrap_or(u32::MAX);
            // SAFETY: `data` holds `size` writable bytes.
            let status = unsafe {
                RegGetValueW(
                    self.0,
                    std::ptr::null(),
                    name.as_ptr(),
                    flags,
                    std::ptr::null_mut(),
                    data.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            if status != ERROR_SUCCESS {
                return Vec::new();
            }
            data.truncate((size as usize / 2).min(data.len()));
            data.split(|c| *c == 0)
                .filter(|part| !part.is_empty())
                .map(String::from_utf16_lossy)
                .collect()
        }

        /// Value `name` as a REG_DWORD.
        fn dword(&self, name: &str) -> Option<u32> {
            let name = wide(name);
            let mut value: u32 = 0;
            let mut size = std::mem::size_of::<u32>() as u32;
            // SAFETY: `value` holds the `size` bytes of a DWORD.
            let status = unsafe {
                RegGetValueW(
                    self.0,
                    std::ptr::null(),
                    name.as_ptr(),
                    RRF_RT_REG_DWORD,
                    std::ptr::null_mut(),
                    std::ptr::from_mut(&mut value).cast(),
                    &mut size,
                )
            };
            (status == ERROR_SUCCESS).then_some(value)
        }
    }

    /// The rules under `path`, one subkey each.
    fn read(path: &str) -> Vec<NrptRule> {
        let Some(base) = Key::open(HKEY_LOCAL_MACHINE, &wide(path)) else {
            return Vec::new();
        };
        base.subkeys()
            .iter()
            .filter_map(|name| {
                let rule = Key::open(base.0, name)?;
                Some(NrptRule {
                    names: rule.strings("Name"),
                    servers: rule.strings("GenericDNSServers").join(";"),
                    options: rule.dword("ConfigOptions").unwrap_or(0),
                })
            })
            .filter(|rule| !rule.names.is_empty())
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn registry_keys_and_values_are_read() {
            let open = |path: &str| Key::open(HKEY_LOCAL_MACHINE, &wide(path)).expect(path);
            let version = open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            let product = version.strings("ProductName");
            assert!(
                product
                    .first()
                    .is_some_and(|name| name.starts_with("Windows")),
                "{product:?}"
            );
            assert!(version
                .dword("CurrentMajorVersionNumber")
                .is_some_and(|v| v >= 10));
            assert!(version.strings("NoSuchValue").is_empty());
            assert!(version.dword("ProductName").is_none());
            assert!(!version.subkeys().is_empty());
            // A REG_MULTI_SZ value: one string each.
            let order = open(r"SYSTEM\CurrentControlSet\Control\ServiceGroupOrder");
            let groups = order.strings("List");
            assert!(groups.len() > 1, "{groups:?}");
            assert!(groups
                .iter()
                .all(|group| !group.is_empty() && !group.contains('\0')));
            // This machine's rules, whatever they are, read cleanly.
            for rule in rules() {
                assert!(!rule.names.is_empty(), "{rule:?}");
            }
            for server in super::super::windows_routes().default {
                assert_eq!(server.port(), 53);
            }
        }
    }
}

/// Windows: the NRPT rules, and the adapters' servers as the default.
#[cfg(windows)]
pub(in crate::osint) fn windows_routes() -> DnsRoutes {
    DnsRoutes {
        default: super::windows_dns::servers(),
        domains: nrpt_routes(&nrpt::rules(), &zone_index),
    }
}

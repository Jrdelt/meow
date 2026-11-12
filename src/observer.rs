//! Passive local network observer.
//!
//! Reads the operating system's own tables (interfaces, routes, ARP/NDP
//! neighbours, listening sockets) with unprivileged tools. It sends no
//! packets and needs no `sudo`, so it is safe in `light` mode.
//!
//! The text parsers for every platform are compiled everywhere so they can
//! be tested on any host; only [`observe`] is platform-specific.

use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::str::FromStr;

use ipnetwork::IpNetwork;
use serde::Serialize;

use crate::endpoint::Endpoint;
use crate::graph::{Interface, Listener, LocalNet, Neighbor, Route, SystemInfo};
use crate::timeutil::now_rfc3339;

/// Classifies an interface by its conventional name.
pub fn interface_kind(name: &str) -> &'static str {
    let name = name.to_ascii_lowercase();
    let starts = |prefixes: &[&str]| prefixes.iter().any(|p| name.starts_with(p));
    if name == "lo" || name.starts_with("lo0") || name.contains("loopback") {
        "loopback"
    } else if starts(&[
        "tun",
        "tap",
        "utun",
        "wg",
        "ppp",
        "ipsec",
        "tailscale",
        "zt",
        "nordlynx",
        "proton",
    ]) {
        "vpn"
    } else if starts(&[
        "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "bridge", "vnet", "awdl", "llw",
        "anpi",
    ]) {
        "virtual"
    } else if starts(&["wl", "wifi", "ath"]) {
        "wifi"
    } else if starts(&["eth", "en", "em", "eno", "ens", "enp"]) {
        "ethernet"
    } else {
        "other"
    }
}

fn interface<'a>(list: &'a mut Vec<Interface>, name: &str) -> &'a mut Interface {
    if let Some(index) = list.iter().position(|i| i.name == name) {
        return &mut list[index];
    }
    list.push(Interface {
        name: name.to_owned(),
        kind: interface_kind(name).to_owned(),
        up: true,
        addresses: Vec::new(),
    });
    list.last_mut().expect("just pushed")
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

fn canonical_ip(text: &str) -> Option<String> {
    let text = text.split('%').next().unwrap_or(text);
    IpAddr::from_str(text)
        .ok()
        .map(|ip| ip.to_canonical().to_string())
}

/// `a.b.c.d/len` or `addr/len` -> canonical network; `default` -> `0.0.0.0/0`.
fn canonical_destination(text: &str, ipv6: bool) -> Option<String> {
    if text == "default" {
        return Some(if ipv6 { "::/0" } else { "0.0.0.0/0" }.to_owned());
    }
    // "fe80::%en0/64": drop the zone, keep the prefix length.
    let text = match text.split_once('%') {
        Some((address, rest)) => match rest.split_once('/') {
            Some((_, prefix)) => format!("{address}/{prefix}"),
            None => address.to_owned(),
        },
        None => text.to_owned(),
    };
    let Ok(network) = IpNetwork::from_str(&text) else {
        return None;
    };
    IpNetwork::new(network.network(), network.prefix())
        .ok()
        .map(|n| n.to_string())
}

fn listener_from(protocol: &str, local: &str) -> Option<Listener> {
    // `*:22` and `*.22` mean every address.
    let local = local.replace("*:", "0.0.0.0:").replace("[*]:", "[::]:");
    let endpoint = Endpoint::parse(&local)?;
    Some(Listener {
        protocol: protocol.to_owned(),
        address: endpoint.host.ip()?.to_string(),
        port: endpoint.port?,
    })
}

// ---------------------------------------------------------------------------
// Linux: iproute2 and ss
// ---------------------------------------------------------------------------

pub mod linux {
    use super::*;

    /// `ip -o link show`: marks interfaces that are administratively down.
    pub fn links(text: &str, out: &mut Vec<Interface>) {
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let (Some(_index), Some(name), Some(flags)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let name = name.trim_end_matches(':').split('@').next().unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let up = flags.trim_matches(['<', '>']).split(',').any(|f| f == "UP");
            interface(out, name).up = up;
        }
    }

    /// `ip -o addr show`
    pub fn addresses(text: &str, out: &mut Vec<Interface>) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || !matches!(fields[2], "inet" | "inet6") {
                continue;
            }
            // Keep the host address with its prefix length (10.0.0.3/24).
            let Ok(network) = IpNetwork::from_str(fields[3]) else {
                continue;
            };
            push_unique(
                &mut interface(out, fields[1]).addresses,
                network.to_string(),
            );
        }
    }

    /// `ip route show` / `ip -6 route show`
    pub fn routes(text: &str, ipv6: bool, out: &mut Vec<Route>) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let Some(first) = fields.first() else {
                continue;
            };
            if matches!(
                *first,
                "unreachable" | "blackhole" | "prohibit" | "broadcast" | "local" | "multicast"
            ) {
                continue;
            }
            let after = |key: &str| {
                fields
                    .iter()
                    .position(|f| *f == key)
                    .and_then(|i| fields.get(i + 1))
            };
            let (Some(destination), Some(device)) =
                (canonical_destination(first, ipv6), after("dev"))
            else {
                continue;
            };
            push_unique(
                out,
                Route {
                    destination,
                    gateway: after("via").and_then(|g| canonical_ip(g)),
                    interface: (*device).to_owned(),
                },
            );
        }
    }

    /// `ip neigh show`
    pub fn neighbors(text: &str, out: &mut Vec<Neighbor>) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let after = |key: &str| {
                fields
                    .iter()
                    .position(|f| *f == key)
                    .and_then(|i| fields.get(i + 1))
            };
            let (Some(address), Some(device), Some(mac)) = (
                fields.first().and_then(|a| canonical_ip(a)),
                after("dev"),
                after("lladdr"),
            ) else {
                continue; // FAILED / INCOMPLETE entries have no lladdr
            };
            push_unique(
                out,
                Neighbor {
                    address,
                    mac: Some(mac.to_ascii_lowercase()),
                    interface: (*device).to_owned(),
                },
            );
        }
    }

    /// `ss -H -ltn` (tcp) or `ss -H -lun` (udp)
    pub fn listeners(text: &str, protocol: &str, out: &mut Vec<Listener>) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // State Recv-Q Send-Q Local:Port Peer:Port
            let Some(local) = fields.get(3) else { continue };
            // "127.0.0.53%lo:53" carries the interface as a zone.
            let local = match local.split_once('%') {
                Some((address, rest)) => match rest.rsplit_once(':') {
                    Some((_, port)) => format!("{address}:{port}"),
                    None => continue,
                },
                None => (*local).to_owned(),
            };
            let local = if local.contains("]:") || local.matches(':').count() == 1 {
                local
            } else {
                // Bare IPv6 with a port ("::1:631" is ambiguous; ss brackets it).
                continue;
            };
            if let Some(listener) = listener_from(protocol, &local) {
                push_unique(out, listener);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// macOS / BSD: ifconfig, netstat, arp
// ---------------------------------------------------------------------------

pub mod macos {
    use super::*;

    /// `0xffffff00` (macOS, the BSDs) or `255.255.255.0`.
    fn prefix_from_mask(mask: &str) -> Option<u8> {
        let value = match mask.strip_prefix("0x") {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => u32::from(mask.parse::<std::net::Ipv4Addr>().ok()?),
        };
        (value.leading_ones() + value.trailing_zeros() == 32).then(|| value.leading_ones() as u8)
    }

    /// `ifconfig`
    pub fn ifconfig(text: &str, out: &mut Vec<Interface>) {
        let mut current: Option<String> = None;
        for line in text.lines() {
            if !line.starts_with(char::is_whitespace) {
                let Some((name, rest)) = line.split_once(": ") else {
                    continue;
                };
                let up = rest
                    .split_once('<')
                    .and_then(|(_, flags)| flags.split_once('>'))
                    .is_some_and(|(flags, _)| flags.split(',').any(|f| f == "UP"));
                interface(out, name).up = up;
                current = Some(name.to_owned());
                continue;
            }
            let Some(name) = &current else { continue };
            let fields: Vec<&str> = line.split_whitespace().collect();
            let after = |key: &str| {
                fields
                    .iter()
                    .position(|f| *f == key)
                    .and_then(|i| fields.get(i + 1))
            };
            // An address is kept even if its mask cannot be read: a wrong
            // network size is a smaller fault than a missing address.
            let address = match fields.first().copied() {
                Some("inet") => fields.get(1).and_then(|a| canonical_ip(a)).map(|address| {
                    let prefix = after("netmask").and_then(|m| prefix_from_mask(m));
                    (address, prefix.unwrap_or(32))
                }),
                Some("inet6") => fields.get(1).and_then(|a| canonical_ip(a)).map(|address| {
                    let prefix = after("prefixlen").and_then(|p| p.parse::<u8>().ok());
                    (address, prefix.unwrap_or(128))
                }),
                _ => None,
            };
            if let Some((address, prefix)) = address {
                push_unique(
                    &mut interface(out, name).addresses,
                    format!("{address}/{prefix}"),
                );
            }
        }
    }

    /// Expands netstat's abbreviated IPv4 destinations: `10.10.10/23`,
    /// `192.168.1`, `127`.
    fn expand_destination(text: &str) -> Option<String> {
        if text == "default" {
            return Some("0.0.0.0/0".to_owned());
        }
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, prefix.parse::<u8>().ok()),
            None => (text, None),
        };
        let octets: Vec<&str> = address.split('.').collect();
        if octets.is_empty() || octets.len() > 4 || !octets.iter().all(|o| o.parse::<u8>().is_ok())
        {
            return None;
        }
        let prefix = prefix.unwrap_or(octets.len() as u8 * 8);
        let mut padded = octets.clone();
        padded.resize(4, "0");
        canonical_destination(&format!("{}/{prefix}", padded.join(".")), false)
    }

    /// `netstat -rn`
    pub fn routes(text: &str, out: &mut Vec<Route>) {
        let mut ipv6 = false;
        for line in text.lines() {
            if line.starts_with("Internet6") {
                ipv6 = true;
                continue;
            } else if line.starts_with("Internet") {
                ipv6 = false;
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Destination Gateway Flags Netif [Expire]
            if fields.len() < 4 || fields[0] == "Destination" {
                continue;
            }
            // Flag `I` on a default route: it is scoped to its interface and
            // only applies to sockets bound to it, so it says nothing about
            // where this machine's traffic goes. macOS keeps one such
            // "default" per interface, VPN tunnels and idle ones included.
            if fields[0] == "default" && fields[2].contains('I') {
                continue;
            }
            let destination = if ipv6 {
                canonical_destination(fields[0], true)
                    .or_else(|| canonical_ip(fields[0]).map(|ip| format!("{ip}/128")))
            } else {
                expand_destination(fields[0])
            };
            let Some(destination) = destination else {
                continue;
            };
            push_unique(
                out,
                Route {
                    destination,
                    // "link#4" and MAC addresses mean directly connected.
                    gateway: canonical_ip(fields[1]),
                    interface: fields[3].to_owned(),
                },
            );
        }
    }

    /// `arp -an`
    pub fn neighbors(text: &str, out: &mut Vec<Neighbor>) {
        for line in text.lines() {
            // ? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
            let Some(address) = line
                .split_once('(')
                .and_then(|(_, rest)| rest.split_once(')'))
                .and_then(|(address, _)| canonical_ip(address))
            else {
                continue;
            };
            let fields: Vec<&str> = line.split_whitespace().collect();
            let after = |key: &str| {
                fields
                    .iter()
                    .position(|f| *f == key)
                    .and_then(|i| fields.get(i + 1))
            };
            let (Some(mac), Some(device)) = (after("at"), after("on")) else {
                continue;
            };
            if !mac.contains(':') {
                continue; // (incomplete)
            }
            push_unique(
                out,
                Neighbor {
                    address,
                    mac: Some(mac.to_ascii_lowercase()),
                    interface: (*device).to_owned(),
                },
            );
        }
    }

    /// `netstat -an -p tcp`: local addresses are `addr.port`.
    pub fn listeners(text: &str, out: &mut Vec<Listener>) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Proto Recv-Q Send-Q Local-Address Foreign-Address (state) ...
            // The state is looked for by name: some versions add columns.
            let listening = fields.iter().skip(4).any(|field| *field == "LISTEN");
            if fields.len() < 6 || !fields[0].starts_with("tcp") || !listening {
                continue;
            }
            let Some((address, port)) = fields[3].rsplit_once('.') else {
                continue;
            };
            let Ok(port) = port.parse::<u16>() else {
                continue;
            };
            let address = match address {
                "*" if fields[0] == "tcp4" => "0.0.0.0".to_owned(),
                "*" => "::".to_owned(),
                other => match canonical_ip(other) {
                    Some(ip) => ip,
                    None => continue,
                },
            };
            push_unique(
                out,
                Listener {
                    protocol: "tcp".to_owned(),
                    address,
                    port,
                },
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Windows: route print, arp -a, netstat -an
// ---------------------------------------------------------------------------

pub mod windows {
    use super::*;
    use std::net::Ipv4Addr;

    fn prefix_from_mask(mask: Ipv4Addr) -> Option<u8> {
        let value = u32::from(mask);
        (value.leading_ones() + value.trailing_zeros() == 32).then(|| value.leading_ones() as u8)
    }

    /// `route print -4`. Column headings are localised, so rows are
    /// recognised by shape: destination, netmask, gateway, interface, metric.
    /// Interfaces are named after their address (`if-192.168.1.5`).
    pub fn routes(text: &str, interfaces: &mut Vec<Interface>, out: &mut Vec<Route>) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // The gateway column may be a localised phrase of several words
            // ("On-link", "Auf Verbindung"), so read the row from both ends.
            let count = fields.len();
            if count < 5 || fields[count - 1].parse::<u32>().is_err() {
                continue;
            }
            let (Ok(destination), Ok(mask), Ok(local)) = (
                Ipv4Addr::from_str(fields[0]),
                Ipv4Addr::from_str(fields[1]),
                Ipv4Addr::from_str(fields[count - 2]),
            ) else {
                continue;
            };
            let Some(prefix) = prefix_from_mask(mask) else {
                continue;
            };
            if destination.is_multicast() || destination.is_broadcast() || prefix == 32 {
                continue;
            }
            let name = format!("if-{local}");
            let gateway = (count == 5)
                .then(|| Ipv4Addr::from_str(fields[2]).ok())
                .flatten();
            let entry = interface(interfaces, &name);
            if local.is_loopback() {
                entry.kind = "loopback".to_owned();
            }
            // An on-link route for a real subnet reveals the interface's own prefix.
            if gateway.is_none() && prefix > 0 {
                push_unique(&mut entry.addresses, format!("{local}/{prefix}"));
            }
            push_unique(
                out,
                Route {
                    destination: format!("{destination}/{prefix}"),
                    gateway: gateway.map(|g| g.to_string()),
                    interface: name,
                },
            );
        }
    }

    /// `arp -a`
    pub fn neighbors(text: &str, out: &mut Vec<Neighbor>) {
        let mut current = String::new();
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if line.contains("---") {
                // "Interface: 192.168.1.5 --- 0x4" (label is localised)
                if let Some(ip) = fields.iter().find_map(|f| Ipv4Addr::from_str(f).ok()) {
                    current = format!("if-{ip}");
                }
                continue;
            }
            let [address, mac, _kind] = fields.as_slice() else {
                continue;
            };
            let Ok(ip) = Ipv4Addr::from_str(address) else {
                continue;
            };
            let is_mac = mac.len() == 17 && mac.split('-').count() == 6;
            if !is_mac || ip.is_multicast() || ip.is_broadcast() || *mac == "ff-ff-ff-ff-ff-ff" {
                continue;
            }
            push_unique(
                out,
                Neighbor {
                    address: ip.to_string(),
                    mac: Some(mac.replace('-', ":").to_ascii_lowercase()),
                    interface: current.clone(),
                },
            );
        }
    }

    /// `netstat -an -p tcp`. The state word is localised; a listener is a
    /// row whose remote address is the all-zero wildcard.
    pub fn listeners(text: &str, out: &mut Vec<Listener>) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 || !fields[0].eq_ignore_ascii_case("tcp") {
                continue;
            }
            if !matches!(fields[2], "0.0.0.0:0" | "[::]:0" | "*:*") {
                continue;
            }
            if let Some(listener) = listener_from("tcp", fields[1]) {
                push_unique(out, listener);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Route reasoning and warnings
// ---------------------------------------------------------------------------

/// The route the OS would use for `ip`: longest matching prefix.
pub fn route_for(local: &LocalNet, ip: IpAddr) -> Option<&Route> {
    local
        .routes
        .iter()
        .filter_map(|route| {
            let network = IpNetwork::from_str(&route.destination).ok()?;
            network.contains(ip).then_some((network.prefix(), route))
        })
        .max_by_key(|(prefix, _)| *prefix)
        .map(|(_, route)| route)
}

/// The interface that owns the address `ip`.
fn owner_of(local: &LocalNet, ip: IpAddr) -> Option<&Interface> {
    local.interfaces.iter().find(|interface| {
        interface
            .addresses
            .iter()
            .filter_map(|a| IpNetwork::from_str(a).ok())
            .any(|network| network.ip() == ip)
    })
}

/// One-line subnet / interface route warnings.
///
/// * A target that no route covers (for example the VPN is down).
/// * A local service bound to an interface that the lab cannot reach, so
///   targets could never connect back to it.
///
/// `targets` are the known lab hosts. Without any, the lab is assumed to be
/// behind the VPN interfaces that are up.
pub fn route_warnings(local: &LocalNet, targets: &[IpAddr]) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut lab: Vec<&str> = Vec::new();

    for target in targets {
        match route_for(local, *target) {
            Some(route) => {
                if !lab.contains(&route.interface.as_str()) {
                    lab.push(&route.interface);
                }
            }
            None if !local.routes.is_empty() => warnings.push(format!(
                "No route to {target}: no local interface or route covers it (is the VPN up?)"
            )),
            None => {}
        }
    }
    if lab.is_empty() {
        lab = local
            .interfaces
            .iter()
            .filter(|i| is_active_vpn(i))
            .map(|i| i.name.as_str())
            .collect();
    }
    if lab.is_empty() {
        return warnings;
    }
    let lab_addresses: Vec<String> = local
        .interfaces
        .iter()
        .filter(|i| lab.contains(&i.name.as_str()))
        .flat_map(|i| i.addresses.iter())
        .filter_map(|a| IpNetwork::from_str(a).ok())
        .filter(|n| n.is_ipv4())
        .map(|n| n.ip().to_string())
        .collect();

    for listener in &local.listeners {
        let Ok(ip) = IpAddr::from_str(&listener.address) else {
            continue;
        };
        if ip.is_unspecified() || ip.is_loopback() {
            continue; // every interface, or deliberately local
        }
        let Some(owner) = owner_of(local, ip) else {
            continue;
        };
        if lab.contains(&owner.name.as_str()) || owner.kind == "loopback" {
            continue;
        }
        let hint = match lab_addresses.first() {
            Some(address) => format!("bind to {address} or 0.0.0.0"),
            None => "bind to 0.0.0.0".to_owned(),
        };
        warnings.push(format!(
            "Listener {}/{}:{} is bound to {}, but the lab is reached via {}: targets cannot connect back ({hint})",
            listener.protocol,
            listener.address,
            listener.port,
            owner.name,
            lab.join(", "),
        ));
    }
    warnings
}

/// True if the interface has an address that can carry traffic to other
/// networks: not loopback and not link-local. macOS keeps many interfaces
/// (`utun0`..., `awdl0`, `llw0`) that are up with nothing but an `fe80::`
/// address; they say nothing about where the lab is.
pub fn has_routable_address(interface: &Interface) -> bool {
    routable_address(interface).is_some()
}

/// The interface's first address of one family that is neither loopback
/// nor link-local, in CIDR form.
fn usable_address(interface: &Interface, ipv4: bool) -> Option<&str> {
    interface
        .addresses
        .iter()
        .find(|address| {
            IpNetwork::from_str(address).is_ok_and(|network| match network.ip() {
                IpAddr::V4(ip) => ipv4 && !ip.is_loopback() && !ip.is_link_local(),
                IpAddr::V6(ip) => {
                    !ipv4 && !ip.is_loopback() && (ip.segments()[0] & 0xffc0) != 0xfe80
                }
            })
        })
        .map(String::as_str)
}

/// The address an interface is known by: its IPv4 address, or its IPv6
/// address when it has no IPv4 one. Never by the order the operating system
/// lists them in: macOS can put a global IPv6 address before the IPv4 one,
/// which then hid the address people know their machine by.
pub fn routable_address(interface: &Interface) -> Option<&str> {
    usable_address(interface, true).or_else(|| usable_address(interface, false))
}

/// A VPN interface that is up and actually addressed.
fn is_active_vpn(interface: &Interface) -> bool {
    interface.kind == "vpn" && interface.up && has_routable_address(interface)
}

/// One summary line for the session banner.
pub fn summary(local: &LocalNet) -> String {
    let up = local
        .interfaces
        .iter()
        .filter(|i| {
            i.up && !matches!(i.kind.as_str(), "loopback" | "virtual") && has_routable_address(i)
        })
        .count();
    let gateway = local
        .routes
        .iter()
        .find(|r| r.destination == "0.0.0.0/0")
        .and_then(|r| {
            r.gateway
                .as_ref()
                .map(|g| format!(", gateway {g} via {}", r.interface))
        })
        .unwrap_or_default();
    let vpn: Vec<String> = local
        .interfaces
        .iter()
        .filter(|i| is_active_vpn(i))
        .map(|i| format!("{} {}", i.name, routable_address(i).unwrap_or_default()))
        .collect();
    let vpn = if vpn.is_empty() {
        String::new()
    } else {
        format!(", VPN {}", vpn.join(", "))
    };
    format!(
        "{up} interfaces up{gateway}{vpn}, {} neighbours, {} listeners",
        local.neighbors.len(),
        local.listeners.len()
    )
}

// ---------------------------------------------------------------------------
// This machine, for the map and the HUD
// ---------------------------------------------------------------------------

/// One block of the "this machine" report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportSection {
    pub title: String,
    pub lines: Vec<String>,
    /// Shown in full by the map; the other sections start folded.
    pub open: bool,
    /// Something the operator should look at.
    pub warn: bool,
}

/// Everything the passive observer read about this machine, worded once for
/// both the map and the HUD. Short by design: the address, what the machine
/// is, its open ports and its interfaces; the long tables are folded away.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MachineReport {
    /// `address -> machine type -> OS -> version`.
    pub headline: String,
    /// One line per active VPN; empty when none is detected.
    pub vpn: Vec<String>,
    pub sections: Vec<ReportSection>,
    pub observed_utc: String,
}

pub fn is_default_route(route: &Route) -> bool {
    matches!(route.destination.as_str(), "0.0.0.0/0" | "::/0")
}

/// An interface this machine really uses: up, addressed, not internal.
fn in_use(interface: &Interface) -> bool {
    interface.up
        && has_routable_address(interface)
        && !matches!(interface.kind.as_str(), "loopback" | "virtual")
}

/// Up and addressed, internal networks (bridges, containers) included:
/// what the short interface list shows.
fn addressed(interface: &Interface) -> bool {
    interface.up && has_routable_address(interface) && interface.kind != "loopback"
}

/// The interfaces that carry a default route (IPv4's first), each with the
/// gateways of those routes.
fn default_carriers(local: &LocalNet) -> Vec<(&str, Vec<&str>)> {
    let mut defaults: Vec<&Route> = local
        .routes
        .iter()
        .filter(|r| is_default_route(r))
        .collect();
    defaults.sort_by_key(|route| route.destination != "0.0.0.0/0");
    let mut carriers: Vec<(&str, Vec<&str>)> = Vec::new();
    for route in defaults {
        let at = match carriers
            .iter()
            .position(|(name, _)| *name == route.interface)
        {
            Some(at) => at,
            None => {
                carriers.push((route.interface.as_str(), Vec::new()));
                carriers.len() - 1
            }
        };
        if let Some(gateway) = route.gateway.as_deref() {
            if !carriers[at].1.contains(&gateway) {
                carriers[at].1.push(gateway);
            }
        }
    }
    carriers
}

/// This machine's own address on its local network (without the prefix
/// length), for the map's "You" caption. The local link comes before a VPN
/// tunnel, and an interface with a default route before one without.
pub fn primary_address(local: &LocalNet) -> Option<String> {
    let carriers = default_carriers(local);
    let carries = |i: &Interface| carriers.iter().any(|(name, _)| *name == i.name);
    let mut candidates: Vec<&Interface> = local.interfaces.iter().filter(|i| in_use(i)).collect();
    candidates.sort_by_key(|i| (i.kind == "vpn", !carries(i)));
    candidates
        .into_iter()
        .find_map(routable_address)
        .map(|address| address.split('/').next().unwrap_or(address).to_owned())
}

/// A route to one single address.
fn is_host_route(network: &IpNetwork) -> bool {
    match network {
        IpNetwork::V4(n) => n.prefix() == 32,
        IpNetwork::V6(n) => n.prefix() == 128,
    }
}

/// Multicast, broadcast, link-local and loopback destinations: bookkeeping
/// of the operating system, not somewhere traffic to other machines goes.
fn is_bookkeeping(network: &IpNetwork) -> bool {
    match network.ip() {
        IpAddr::V4(ip) => {
            ip.is_multicast() || ip.is_broadcast() || ip.is_link_local() || ip.is_loopback()
        }
        IpAddr::V6(ip) => {
            ip.is_multicast() || ip.is_loopback() || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// True for a route worth reading: a default route or a real network.
fn is_meaningful(route: &Route) -> bool {
    is_default_route(route)
        || IpNetwork::from_str(&route.destination)
            .is_ok_and(|network| !is_host_route(&network) && !is_bookkeeping(&network))
}

/// What a VPN interface is used for, from the routes that go through it.
fn vpn_carries(local: &LocalNet, interface: &Interface) -> String {
    let routes: Vec<&Route> = local
        .routes
        .iter()
        .filter(|r| r.interface == interface.name)
        .collect();
    let mut networks: Vec<&str> = routes
        .iter()
        .filter(|r| is_meaningful(r))
        .map(|r| r.destination.as_str())
        .collect();
    networks.dedup();
    let hosts = routes
        .iter()
        .filter_map(|r| IpNetwork::from_str(&r.destination).ok())
        .filter(|network| is_host_route(network) && !is_bookkeeping(network))
        .count();
    let halves = ["0.0.0.0/1", "128.0.0.0/1"];
    if routes.iter().any(|r| is_default_route(r)) {
        return "carries the default route".to_owned();
    }
    if halves.iter().all(|half| networks.contains(half)) {
        // The usual way a VPN client takes everything without replacing
        // the default route.
        return "carries all IPv4 traffic (0.0.0.0/1 and 128.0.0.0/1)".to_owned();
    }
    let mut parts: Vec<String> = Vec::new();
    if !networks.is_empty() {
        parts.push(networks[..networks.len().min(4)].join(", "));
    }
    if networks.len() > 4 {
        parts.push(format!("{} more networks", networks.len() - 4));
    }
    match hosts {
        0 => {}
        1 => parts.push("1 single host".to_owned()),
        n => parts.push(format!("{n} single hosts")),
    }
    match parts.as_slice() {
        [] => "no route uses it".to_owned(),
        [only] => format!("carries {only}"),
        [first @ .., last] => format!("carries {} and {last}", first.join(", ")),
    }
}

/// `22/tcp, 80/tcp, ...`, shortened after sixteen.
fn port_list(ports: &std::collections::BTreeSet<(u16, &str)>) -> String {
    let mut shown: Vec<String> = ports
        .iter()
        .take(16)
        .map(|(port, protocol)| format!("{port}/{protocol}"))
        .collect();
    if ports.len() > 16 {
        shown.push(format!("and {} more", ports.len() - 16));
    }
    shown.join(", ")
}

/// The report shown as "This machine" by `meow map` and `meow hud`.
pub fn machine_report(local: &LocalNet) -> MachineReport {
    let known = |text: &str, otherwise: &str| match text.trim() {
        "" => otherwise.to_owned(),
        text => text.to_owned(),
    };
    let headline = [
        primary_address(local).unwrap_or_else(|| "no address".to_owned()),
        known(&local.system.kind, "computer"),
        known(&local.system.os, "OS not known"),
        known(&local.system.version, "version not known"),
    ]
    .join(" -> ");

    let vpn: Vec<String> = local
        .interfaces
        .iter()
        .filter(|i| is_active_vpn(i))
        .map(|interface| {
            format!(
                "{} {}: {}",
                interface.name,
                routable_address(interface).unwrap_or_default(),
                vpn_carries(local, interface)
            )
        })
        .collect();

    let section = |title: String, lines: Vec<String>, open: bool, warn: bool| ReportSection {
        title,
        lines,
        open,
        warn,
    };
    let mut sections = Vec::new();

    // Open ports: what other machines can reach, then what only this one can.
    let mut reachable = std::collections::BTreeSet::new();
    let mut local_only = std::collections::BTreeSet::new();
    for listener in &local.listeners {
        let port = (listener.port, listener.protocol.as_str());
        let loopback = listener
            .address
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
        if loopback {
            local_only.insert(port);
        } else {
            reachable.insert(port);
        }
    }
    local_only.retain(|port| !reachable.contains(port));
    let mut ports = Vec::new();
    if !reachable.is_empty() {
        ports.push(port_list(&reachable));
    }
    if !local_only.is_empty() {
        ports.push(format!("this machine only: {}", port_list(&local_only)));
    }
    if ports.is_empty() {
        ports.push("none listening".to_owned());
    }
    sections.push(section("Open ports".to_owned(), ports, true, false));

    // Interfaces: the ones in use, one line each, saying what each is for.
    let carriers = default_carriers(local);
    let gateways_of = |i: &Interface| carriers.iter().find(|(name, _)| *name == i.name);
    let rank = |i: &Interface| match i.kind.as_str() {
        _ if gateways_of(i).is_some() && i.kind != "vpn" => 0,
        "vpn" => 2,
        "virtual" => 3,
        _ => 1,
    };
    let mut links: Vec<&Interface> = local.interfaces.iter().filter(|i| addressed(i)).collect();
    links.sort_by_key(|i| rank(i));
    let mut interfaces: Vec<String> = links
        .iter()
        .map(|interface| {
            let what = match (interface.kind.as_str(), gateways_of(interface)) {
                ("vpn", _) => format!("VPN, {}", vpn_carries(local, interface)),
                ("virtual", _) => "virtual network on this machine".to_owned(),
                (_, Some((_, gateways))) => {
                    // The IPv4 gateway is the one people know; the IPv6
                    // one is a link-local address that says little.
                    let ipv4: Vec<&str> = gateways
                        .iter()
                        .copied()
                        .filter(|g| !g.contains(':'))
                        .collect();
                    match (ipv4.as_slice(), gateways.as_slice()) {
                        ([], []) => "default route without a gateway".to_owned(),
                        ([], all) => format!("gateway {}", all.join(" and ")),
                        (ipv4, _) => format!("gateway {}", ipv4.join(" and ")),
                    }
                }
                _ => "local network only".to_owned(),
            };
            format!(
                "{}  {}  {what}",
                interface.name,
                routable_address(interface).unwrap_or_default()
            )
        })
        .collect();
    if interfaces.is_empty() {
        interfaces.push(if local.interfaces.is_empty() {
            "unknown: the network tables could not be read".to_owned()
        } else {
            "not connected: no interface has a usable address".to_owned()
        });
    }
    sections.push(section("Interfaces".to_owned(), interfaces, true, false));

    if !local.warnings.is_empty() {
        let title = "Route warnings".to_owned();
        sections.push(section(title, local.warnings.clone(), true, true));
    }
    if !local.notes.is_empty() {
        // An empty table then means "not read", not "nothing there".
        let title = "Could not be read".to_owned();
        sections.push(section(title, local.notes.clone(), true, true));
    }

    // Folded away: the routes that matter, the neighbours, every interface.
    let shown_on = |name: &str| links.iter().any(|i| i.name == name);
    let mut routes: Vec<String> = local
        .routes
        .iter()
        .filter(|route| is_meaningful(route) && shown_on(&route.interface))
        .map(|route| {
            let to = match route.destination.as_str() {
                "0.0.0.0/0" => "default",
                "::/0" => "default (IPv6)",
                other => other,
            };
            match &route.gateway {
                Some(gateway) => format!("{to} via {gateway} on {}", route.interface),
                None => format!("{to} on {} (directly attached)", route.interface),
            }
        })
        .collect();
    let kept = routes.len();
    let left_out = local.routes.len() - kept;
    if left_out > 0 {
        routes.push(format!(
            "{left_out} more left out: single hosts, multicast, link-local and idle interfaces"
        ));
    }
    if routes.is_empty() {
        routes.push("none".to_owned());
    }
    let title = match left_out {
        0 => format!("Routes ({kept})"),
        _ => format!("Routes ({kept} of {})", local.routes.len()),
    };
    sections.push(section(title, routes, false, false));

    let mut neighbours: Vec<String> = local
        .neighbors
        .iter()
        .map(|n| {
            let mac = n.mac.as_deref().unwrap_or("no answer");
            format!("{}  {mac}  {}", n.address, n.interface)
        })
        .collect();
    if neighbours.is_empty() {
        neighbours.push("none".to_owned());
    }
    let title = format!("Neighbours ({})", local.neighbors.len());
    sections.push(section(title, neighbours, false, false));

    let listed = |i: &&Interface| has_routable_address(i) || i.kind == "loopback";
    let mut all: Vec<String> = local
        .interfaces
        .iter()
        .filter(listed)
        .map(|i| {
            let state = if i.up { "up" } else { "down" };
            format!(
                "{}  {}  {state}  {}",
                i.name,
                i.kind,
                i.addresses.join("  ")
            )
        })
        .collect();
    let idle: Vec<&str> = local
        .interfaces
        .iter()
        .filter(|i| !listed(i))
        .map(|i| i.name.as_str())
        .collect();
    if !idle.is_empty() {
        all.push(format!(
            "{} without a usable address: {}",
            idle.len(),
            idle.join(", ")
        ));
    }
    if all.is_empty() {
        all.push("none".to_owned());
    }
    let title = format!("All interfaces ({})", local.interfaces.len());
    sections.push(section(title, all, false, false));

    MachineReport {
        headline,
        vpn,
        sections,
        observed_utc: local.observed_utc.clone(),
    }
}

// ---------------------------------------------------------------------------
// Running the OS tools
// ---------------------------------------------------------------------------

/// Where system tools live when the PATH leaves them out (the `sbin`
/// directories are not on every user's PATH).
#[cfg(unix)]
const SYSTEM_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];
#[cfg(not(unix))]
const SYSTEM_DIRS: &[&str] = &[];

/// Runs a read-only OS tool and returns its stdout. A tool that cannot be
/// started, or that fails without printing anything, is recorded in `notes`:
/// the table it feeds is then unread, which is not the same as empty.
fn run(program: &str, args: &[&str], notes: &mut Vec<String>) -> String {
    run_from(program, args, SYSTEM_DIRS, notes)
}

fn run_from(program: &str, args: &[&str], dirs: &[&str], notes: &mut Vec<String>) -> String {
    let start = |program: &std::path::Path| {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
    };
    let mut result = start(std::path::Path::new(program));
    if matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::NotFound) {
        let elsewhere = dirs
            .iter()
            .map(|dir| std::path::Path::new(dir).join(program))
            .find(|candidate| candidate.is_file());
        if let Some(candidate) = elsewhere {
            result = start(&candidate);
        }
    }
    let command = format!("{program} {}", args.join(" "));
    let command = command.trim();
    match result {
        // The exit code alone is not a failure: some of these tools print a
        // usable table and still exit non-zero (for example when one entry
        // cannot be read). The parsers ignore what they do not recognise.
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout).into_owned();
            if text.trim().is_empty() && !output.status.success() {
                let note = format!("`{command}` failed ({}) and printed nothing", output.status);
                push_unique(notes, note);
            }
            text
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            push_unique(
                notes,
                format!("`{program}` is not installed or not on the PATH"),
            );
            String::new()
        }
        Err(error) => {
            push_unique(notes, format!("`{command}` could not be run: {error}"));
            String::new()
        }
    }
}

// ---------------------------------------------------------------------------
// What this machine is: type, operating system, version
// ---------------------------------------------------------------------------

/// Parsers for what each platform says about itself. Pure, so every
/// platform's parser is tested on every platform.
pub mod system {
    /// macOS `sysctl -n hw.model`: `MacBookPro18,3`, `Macmini9,1`, `Mac14,7`.
    /// Recent models are only called `MacNN,N`, which does not say which.
    pub fn mac_kind(model: &str) -> &'static str {
        let model = model.trim();
        let names = [
            ("MacBookPro", "MacBook Pro"),
            ("MacBookAir", "MacBook Air"),
            ("MacBook", "MacBook"),
            ("Macmini", "Mac mini"),
            ("iMacPro", "iMac Pro"),
            ("iMac", "iMac"),
            ("MacPro", "Mac Pro"),
            ("VirtualMac", "Mac (virtual machine)"),
            ("Mac", "Mac"),
        ];
        names
            .iter()
            .find(|(prefix, _)| model.starts_with(prefix))
            .map_or("", |(_, name)| name)
    }

    /// The value of `Key:   value` or `KEY="value"` lines.
    fn field(text: &str, key: &str, separator: char) -> String {
        text.lines()
            .filter_map(|line| line.split_once(separator))
            .find(|(name, _)| name.trim() == key)
            .map(|(_, value)| value.trim().trim_matches('"').to_owned())
            .unwrap_or_default()
    }

    /// macOS `sw_vers`: `ProductName: macOS`, `ProductVersion: 15.1`.
    pub fn sw_vers(text: &str) -> (String, String) {
        (
            field(text, "ProductName", ':'),
            field(text, "ProductVersion", ':'),
        )
    }

    /// Linux `/etc/os-release`: `NAME="Ubuntu"`, `VERSION_ID="24.04"`.
    pub fn os_release(text: &str) -> (String, String) {
        let version = match field(text, "VERSION_ID", '=') {
            id if id.is_empty() => field(text, "VERSION", '='),
            id => id,
        };
        (field(text, "NAME", '='), version)
    }

    /// Linux DMI: the SMBIOS chassis type number and the product name.
    pub fn chassis_kind(chassis_type: &str, product: &str) -> &'static str {
        let product = product.to_ascii_lowercase();
        let virtual_words = [
            "virtual",
            "kvm",
            "qemu",
            "vmware",
            "hvm",
            "bochs",
            "parallels",
        ];
        if virtual_words.iter().any(|word| product.contains(word)) {
            return "Virtual machine";
        }
        match chassis_type.trim().parse::<u8>().unwrap_or(0) {
            8..=10 | 14 | 31 | 32 => "Laptop",
            3..=7 | 13 | 15 | 16 | 35 | 36 => "Desktop",
            17 | 23 | 28 | 29 => "Server",
            _ => "",
        }
    }

    /// Windows `ver`: `Microsoft Windows [Version 10.0.22631.4460]`.
    pub fn windows_ver(text: &str) -> (String, String) {
        let version = text
            .split_once("[Version ")
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(version, _)| version.trim().to_owned())
            .unwrap_or_default();
        ("Windows".to_owned(), version)
    }
}

/// Asks this machine what it is. Cheap local lookups only; anything that
/// cannot be read is left empty and shown as "not known".
fn read_system() -> SystemInfo {
    // These are extras: a tool that is missing here is not worth a warning.
    let mut unused = Vec::new();
    let mut ask = |program: &str, args: &[&str]| run(program, args, &mut unused);
    let file = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    let (kind, (os, version)) = if cfg!(target_os = "macos") {
        (
            system::mac_kind(&ask("sysctl", &["-n", "hw.model"])).to_owned(),
            system::sw_vers(&ask("sw_vers", &[])),
        )
    } else if cfg!(windows) {
        (
            String::new(),
            system::windows_ver(&ask("cmd", &["/C", "ver"])),
        )
    } else {
        let kind = system::chassis_kind(
            &file("/sys/class/dmi/id/chassis_type"),
            &file("/sys/class/dmi/id/product_name"),
        );
        (
            kind.to_owned(),
            system::os_release(&file("/etc/os-release")),
        )
    };
    SystemInfo {
        kind,
        // The platform name is always known, whatever the tools say.
        os: match os.is_empty() {
            true => std::env::consts::OS.to_owned(),
            false => os,
        },
        version,
    }
}

/// What this machine is. It does not change while meow runs, so it is read
/// once.
pub fn system_info() -> SystemInfo {
    static SYSTEM: std::sync::OnceLock<SystemInfo> = std::sync::OnceLock::new();
    SYSTEM.get_or_init(read_system).clone()
}

/// Reads the local tables once. `targets` are the known lab hosts, used for
/// the route warnings.
pub fn observe(targets: &[IpAddr]) -> LocalNet {
    let mut local = LocalNet {
        observed_utc: now_rfc3339(),
        system: system_info(),
        ..LocalNet::default()
    };
    // Plain `if`s rather than `#[cfg]` blocks: every platform's branch is
    // type-checked on every platform, so a change cannot break a system it
    // was not built on.
    let notes = &mut local.notes;
    if cfg!(target_os = "linux") {
        linux::links(
            &run("ip", &["-o", "link", "show"], notes),
            &mut local.interfaces,
        );
        linux::addresses(
            &run("ip", &["-o", "addr", "show"], notes),
            &mut local.interfaces,
        );
        linux::routes(
            &run("ip", &["route", "show"], notes),
            false,
            &mut local.routes,
        );
        linux::routes(
            &run("ip", &["-6", "route", "show"], notes),
            true,
            &mut local.routes,
        );
        linux::neighbors(&run("ip", &["neigh", "show"], notes), &mut local.neighbors);
        linux::listeners(
            &run("ss", &["-H", "-ltn"], notes),
            "tcp",
            &mut local.listeners,
        );
        linux::listeners(
            &run("ss", &["-H", "-lun"], notes),
            "udp",
            &mut local.listeners,
        );
    } else if cfg!(windows) {
        windows::routes(
            &run("route", &["print", "-4"], notes),
            &mut local.interfaces,
            &mut local.routes,
        );
        windows::neighbors(&run("arp", &["-a"], notes), &mut local.neighbors);
        windows::listeners(
            &run("netstat", &["-an", "-p", "tcp"], notes),
            &mut local.listeners,
        );
    } else {
        // macOS and the BSDs.
        macos::ifconfig(&run("ifconfig", &[], notes), &mut local.interfaces);
        macos::routes(&run("netstat", &["-rn"], notes), &mut local.routes);
        macos::neighbors(&run("arp", &["-an"], notes), &mut local.neighbors);
        macos::listeners(
            &run("netstat", &["-an", "-p", "tcp"], notes),
            &mut local.listeners,
        );
    }
    local.warnings = route_warnings(&local, targets);
    local
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn linux_fixture() -> LocalNet {
        let mut local = LocalNet::default();
        linux::links(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n\
             2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP\n\
             3: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN\n\
             7: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN\n\
             9: veth12ab@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
            &mut local.interfaces,
        );
        linux::addresses(
            "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n\
             1: lo    inet6 ::1/128 scope host \\       valid_lft forever\n\
             2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global dynamic eth0\\ valid_lft 85000sec\n\
             2: eth0    inet6 fe80::a00:27ff:fe4e:66a1/64 scope link \\ valid_lft forever\n\
             7: tun0    inet 10.10.14.3/23 scope global tun0\\       valid_lft forever\n",
            &mut local.interfaces,
        );
        linux::routes(
            "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n\
             10.10.10.0/23 via 10.10.14.1 dev tun0\n\
             10.10.14.0/23 dev tun0 proto kernel scope link src 10.10.14.3\n\
             192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.5 metric 100\n\
             unreachable 172.31.0.0/16\n",
            false,
            &mut local.routes,
        );
        linux::routes(
            "fe80::/64 dev eth0 proto kernel metric 256 pref medium\ndefault via fe80::1 dev eth0 metric 1024\n",
            true,
            &mut local.routes,
        );
        linux::neighbors(
            "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n\
             192.168.1.77 dev eth0  FAILED\n\
             fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router STALE\n",
            &mut local.neighbors,
        );
        linux::listeners(
            "LISTEN 0      128          0.0.0.0:22         0.0.0.0:*\n\
             LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*\n\
             LISTEN 0      5        192.168.1.5:8000       0.0.0.0:*\n\
             LISTEN 0      5         10.10.14.3:9001       0.0.0.0:*\n\
             LISTEN 0      4096               *:9090             *:*\n\
             LISTEN 0      128             [::]:22            [::]:*\n\
             LISTEN 0      5              [::1]:631           [::]:*\n",
            "tcp",
            &mut local.listeners,
        );
        linux::listeners(
            "UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\n",
            "udp",
            &mut local.listeners,
        );
        local
    }

    #[test]
    fn linux_tables_are_parsed() {
        let local = linux_fixture();
        let names: Vec<_> = local
            .interfaces
            .iter()
            .map(|i| (i.name.as_str(), i.kind.as_str(), i.up, i.addresses.len()))
            .collect();
        assert_eq!(
            names,
            [
                ("lo", "loopback", true, 2),
                ("eth0", "ethernet", true, 2),
                ("wlan0", "wifi", false, 0),
                ("tun0", "vpn", true, 1),
                ("veth12ab", "virtual", true, 0),
            ]
        );
        assert_eq!(local.interfaces[3].addresses, ["10.10.14.3/23"]);
        assert_eq!(local.routes.len(), 6);
        assert_eq!(
            local.routes[0],
            Route {
                destination: "0.0.0.0/0".into(),
                gateway: Some("192.168.1.1".into()),
                interface: "eth0".into()
            }
        );
        assert_eq!(local.routes[5].destination, "::/0");
        assert_eq!(local.neighbors.len(), 2);
        assert_eq!(local.neighbors[0].mac.as_deref(), Some("00:11:22:33:44:55"));
        let listeners: Vec<_> = local
            .listeners
            .iter()
            .map(|l| format!("{}/{}:{}", l.protocol, l.address, l.port))
            .collect();
        assert_eq!(
            listeners,
            [
                "tcp/0.0.0.0:22",
                "tcp/127.0.0.53:53",
                "tcp/192.168.1.5:8000",
                "tcp/10.10.14.3:9001",
                "tcp/0.0.0.0:9090",
                "tcp/:::22",
                "tcp/::1:631",
                "udp/0.0.0.0:68",
            ]
        );
    }

    #[test]
    fn longest_prefix_route_wins() {
        let local = linux_fixture();
        assert_eq!(
            route_for(&local, ip("10.10.10.5")).unwrap().interface,
            "tun0"
        );
        assert_eq!(route_for(&local, ip("10.10.14.9")).unwrap().gateway, None);
        assert_eq!(
            route_for(&local, ip("8.8.8.8")).unwrap().gateway.as_deref(),
            Some("192.168.1.1")
        );
        assert_eq!(
            route_for(&local, ip("192.168.1.77")).unwrap().destination,
            "192.168.1.0/24"
        );
        assert_eq!(
            route_for(&local, ip("2001:db8::1")).unwrap().destination,
            "::/0"
        );
        assert!(route_for(&LocalNet::default(), ip("10.0.0.1")).is_none());
    }

    #[test]
    fn listener_on_the_wrong_interface_is_flagged_once() {
        let local = linux_fixture();
        // Lab hosts are behind the VPN.
        let warnings = route_warnings(&local, &[ip("10.10.10.5"), ip("10.10.10.9")]);
        assert_eq!(
            warnings,
            [
                "Listener tcp/192.168.1.5:8000 is bound to eth0, but the lab is reached via tun0: \
              targets cannot connect back (bind to 10.10.14.3 or 0.0.0.0)"
            ]
        );
        // With no known targets the VPN interface is assumed to be the lab.
        assert_eq!(route_warnings(&local, &[]), warnings);
        // If the lab is the LAN, the VPN-bound listener is the odd one out.
        let warnings = route_warnings(&local, &[ip("192.168.1.77")]);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("Listener tcp/10.10.14.3:9001 is bound to tun0"));
    }

    #[test]
    fn unreachable_targets_are_flagged_and_quiet_setups_stay_quiet() {
        let mut local = linux_fixture();
        local
            .routes
            .retain(|r| r.destination != "0.0.0.0/0" && r.interface != "tun0");
        local.interfaces.retain(|i| i.name != "tun0");
        let warnings = route_warnings(&local, &[ip("10.10.10.5")]);
        assert_eq!(
            warnings,
            ["No route to 10.10.10.5: no local interface or route covers it (is the VPN up?)"]
        );
        // No targets and no VPN: nothing to compare against, so no warnings.
        assert!(route_warnings(&local, &[]).is_empty());
        assert!(route_warnings(&LocalNet::default(), &[ip("10.0.0.1")]).is_empty());
    }

    /// As reported from a real Mac: the map did not show the machine's IPv4
    /// address. macOS lists addresses in the order they were configured, so
    /// a global IPv6 address can come before the IPv4 one.
    #[test]
    fn the_ipv4_address_is_shown_wherever_the_system_lists_it() {
        let mut local = LocalNet::default();
        macos::ifconfig(
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>\n\
             \tether a4:83:e7:11:22:33\n\
             \tinet6 fe80::aa:bb:cc:dd%en0 prefixlen 64 secured scopeid 0xb\n\
             \tinet6 2001:db8:4005:80a::200e prefixlen 64 autoconf secured\n\
             \tinet6 2001:db8:4005:80a:d5f:1:2:3 prefixlen 64 autoconf temporary\n\
             \tinet 10.44.8.20 netmask 0xfffffc00 broadcast 10.44.11.255\n\
             \tnat64 prefix 64:ff9b:: prefixlen 96\n\
             \tnd6 options=201<PERFORMNUD,DAD>\n\
             \tmedia: autoselect\n\
             \tstatus: active\n\
             en7: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tinet 192.168.50.2 netmask 255.255.255.0 broadcast 192.168.50.255\n\
             en8: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tinet 192.168.60.2 netmask garbled\n\
             en9: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tinet6 fe80::9%en9 prefixlen 64 scopeid 0xc\n\
             \tinet6 fd00::9 prefixlen 64\n",
            &mut local.interfaces,
        );
        macos::routes(
            "Internet:\nDestination        Gateway            Flags           Netif Expire\n\
             default            10.44.8.1       UGScg             en0\n",
            &mut local.routes,
        );
        let by_name = |name: &str| local.interfaces.iter().find(|i| i.name == name).unwrap();
        let en0 = by_name("en0");
        assert_eq!(
            en0.addresses,
            [
                "fe80::aa:bb:cc:dd/64",
                "2001:db8:4005:80a::200e/64",
                "2001:db8:4005:80a:d5f:1:2:3/64",
                "10.44.8.20/22",
            ]
        );
        assert_eq!(routable_address(en0), Some("10.44.8.20/22"));
        assert_eq!(primary_address(&local).as_deref(), Some("10.44.8.20"));
        let report = machine_report(&local);
        assert!(
            report.headline.starts_with("10.44.8.20 -> "),
            "{}",
            report.headline
        );
        // A dotted mask is read too, and an unreadable one does not cost
        // the address. Without any IPv4 address the IPv6 one is shown.
        assert_eq!(by_name("en7").addresses, ["192.168.50.2/24"]);
        assert_eq!(by_name("en8").addresses, ["192.168.60.2/32"]);
        assert_eq!(routable_address(by_name("en9")), Some("fd00::9/64"));
        let interfaces = &report.sections[1];
        assert_eq!(interfaces.title, "Interfaces");
        assert_eq!(
            interfaces.lines,
            [
                "en0  10.44.8.20/22  gateway 10.44.8.1",
                "en7  192.168.50.2/24  local network only",
                "en8  192.168.60.2/32  local network only",
                "en9  fd00::9/64  local network only",
            ]
        );
    }

    #[test]
    fn macos_tables_are_parsed() {
        let mut local = LocalNet::default();
        macos::ifconfig(
            "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
             \tinet 127.0.0.1 netmask 0xff000000\n\
             \tinet6 ::1 prefixlen 128\n\
             \tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1\n\
             en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tether a4:83:e7:11:22:33\n\
             \tinet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255\n\
             en5: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500\n\
             utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n\
             \tinet 10.10.14.3 --> 10.10.14.3 netmask 0xfffffe00\n",
            &mut local.interfaces,
        );
        let shown: Vec<_> = local
            .interfaces
            .iter()
            .map(|i| {
                (
                    i.name.as_str(),
                    i.kind.as_str(),
                    i.up,
                    i.addresses.join(" "),
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                (
                    "lo0",
                    "loopback",
                    true,
                    "127.0.0.1/8 ::1/128 fe80::1/64".to_owned()
                ),
                ("en0", "ethernet", true, "192.168.1.5/24".to_owned()),
                ("en5", "ethernet", false, String::new()),
                ("utun3", "vpn", true, "10.10.14.3/23".to_owned()),
            ]
        );

        macos::routes(
            "Routing tables\n\nInternet:\n\
             Destination        Gateway            Flags           Netif Expire\n\
             default            192.168.1.1        UGScg             en0\n\
             default            link#25            UCSIg       bridge100      !\n\
             default            link#27            UCSIg           utun3\n\
             10.10.10/23        10.10.14.1         UGSc            utun3\n\
             127                127.0.0.1          UCS               lo0\n\
             192.168.1          link#6             UCS               en0      !\n\
             192.168.1.1/32     link#6             UCS               en0      !\n\n\
             Internet6:\n\
             Destination                             Gateway                         Flags   Netif Expire\n\
             default                                 fe80::%utun0                    UGcIg   utun0\n\
             fe80::%en0/64                           link#6                          UCI       en0\n",
            &mut local.routes,
        );
        let shown: Vec<_> = local
            .routes
            .iter()
            .map(|r| {
                format!(
                    "{} {} {}",
                    r.destination,
                    r.gateway.as_deref().unwrap_or("-"),
                    r.interface
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                "0.0.0.0/0 192.168.1.1 en0",
                "10.10.10.0/23 10.10.14.1 utun3",
                "127.0.0.0/8 127.0.0.1 lo0",
                "192.168.1.0/24 - en0",
                "192.168.1.1/32 - en0",
                "fe80::/64 - en0",
            ],
            "interface-scoped defaults (flag I) are not where traffic goes"
        );

        macos::neighbors(
            "? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n\
             ? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n",
            &mut local.neighbors,
        );
        assert_eq!(local.neighbors.len(), 1);

        macos::listeners(
            "Active Internet connections (including servers)\n\
             Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n\
             tcp4       0      0  192.168.1.5.8000       *.*                    LISTEN\n\
             tcp46      0      0  *.8080                 *.*                    LISTEN\n\
             tcp4       0      0  *.22                   *.*                    LISTEN\n\
             tcp6       0      0  ::1.631                *.*                    LISTEN\n\
             tcp4       0      0  *.7000                 *.*                    LISTEN  131072 131072\n\
             tcp4       0      0  192.168.1.5.52100      17.1.2.3.443           ESTABLISHED\n",
            &mut local.listeners,
        );
        let shown: Vec<_> = local
            .listeners
            .iter()
            .map(|l| format!("{}:{}", l.address, l.port))
            .collect();
        assert_eq!(
            shown,
            [
                "192.168.1.5:8000",
                ":::8080",
                "0.0.0.0:22",
                "::1:631",
                "0.0.0.0:7000"
            ],
            "the state is found by name, extra columns or not"
        );

        let warnings = route_warnings(&local, &[ip("10.10.10.5")]);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("bound to en0, but the lab is reached via utun3"));
    }

    #[test]
    fn windows_tables_are_parsed_without_relying_on_labels() {
        let mut local = LocalNet::default();
        windows::routes(
            "===========================================================================\n\
             Interface List\n  4...a4 83 e7 11 22 33 ......Intel(R) Ethernet\n\
             IPv4 Route Table\nActive Routes:\n\
             Network Destination        Netmask          Gateway       Interface  Metric\n\
             \x20         0.0.0.0          0.0.0.0      192.168.1.1      192.168.1.5     25\n\
             \x20      10.10.10.0    255.255.254.0       10.10.14.1       10.10.14.3      1\n\
             \x20      10.10.14.0    255.255.254.0         On-link        10.10.14.3    257\n\
             \x20       127.0.0.0        255.0.0.0         On-link         127.0.0.1    331\n\
             \x20     192.168.1.0    255.255.255.0   Auf Verbindung      192.168.1.5    281\n\
             \x20     192.168.1.5  255.255.255.255         On-link       192.168.1.5    281\n\
             \x20       224.0.0.0        240.0.0.0         On-link       192.168.1.5    281\n",
            &mut local.interfaces,
            &mut local.routes,
        );
        let interfaces: Vec<_> = local
            .interfaces
            .iter()
            .map(|i| (i.name.as_str(), i.kind.as_str(), i.addresses.join(" ")))
            .collect();
        assert_eq!(
            interfaces,
            [
                ("if-192.168.1.5", "other", "192.168.1.5/24".to_owned()),
                ("if-10.10.14.3", "other", "10.10.14.3/23".to_owned()),
                ("if-127.0.0.1", "loopback", "127.0.0.1/8".to_owned()),
            ]
        );
        assert_eq!(local.routes.len(), 5);
        assert_eq!(
            route_for(&local, ip("10.10.10.5")).unwrap().interface,
            "if-10.10.14.3"
        );

        windows::neighbors(
            "\nInterface: 192.168.1.5 --- 0x4\n  Internet Address      Physical Address      Type\n\
             \x20 192.168.1.1           00-11-22-33-44-55     dynamic\n\
             \x20 192.168.1.255         ff-ff-ff-ff-ff-ff     static\n\
             \x20 224.0.0.22            01-00-5e-00-00-16     static\n",
            &mut local.neighbors,
        );
        assert_eq!(
            local.neighbors,
            [Neighbor {
                address: "192.168.1.1".into(),
                mac: Some("00:11:22:33:44:55".into()),
                interface: "if-192.168.1.5".into()
            }]
        );

        windows::listeners(
            "\nActive Connections\n\n  Proto  Local Address          Foreign Address        State\n\
             \x20 TCP    0.0.0.0:135            0.0.0.0:0              LISTENING\n\
             \x20 TCP    192.168.1.5:8000       0.0.0.0:0              ABH\u{d6}REN\n\
             \x20 TCP    192.168.1.5:52100      17.1.2.3:443           ESTABLISHED\n\
             \x20 TCP    [::]:445               [::]:0                 LISTENING\n",
            &mut local.listeners,
        );
        let shown: Vec<_> = local
            .listeners
            .iter()
            .map(|l| format!("{}:{}", l.address, l.port))
            .collect();
        assert_eq!(shown, ["0.0.0.0:135", "192.168.1.5:8000", ":::445"]);

        let warnings = route_warnings(&local, &[ip("10.10.10.5")]);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("Listener tcp/192.168.1.5:8000 is bound to if-192.168.1.5"));
    }

    #[test]
    fn link_local_only_interfaces_are_not_counted_or_called_vpns() {
        // What a Mac reports: the Wi-Fi interface plus a crowd of tunnel and
        // helper interfaces that are "up" with only an fe80:: address.
        let mut local = LocalNet::default();
        let mut text = String::from(
            "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n\
             en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tinet6 fe80::1c2a:3b4c:5d6e:7f80%en0 prefixlen 64 secured scopeid 0xb\n\
             \tinet 172.30.47.20 netmask 0xfffff800 broadcast 172.26.151.255\n\
             awdl0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tinet6 fe80::8c1f:64ff:fe01:2345%awdl0 prefixlen 64 scopeid 0xd\n",
        );
        for n in 0..8 {
            text.push_str(&format!(
                "utun{n}: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n\
                 \tinet6 fe80::ad3c:36a1:b46f:22{n}c%utun{n} prefixlen 64 scopeid 0x1{n}\n"
            ));
        }
        macos::ifconfig(&text, &mut local.interfaces);
        macos::routes(
            "Internet:\nDestination        Gateway            Flags           Netif Expire\n\
             default            172.30.47.1       UGScg             en0\n",
            &mut local.routes,
        );
        assert_eq!(local.interfaces.len(), 11);
        assert_eq!(
            summary(&local),
            "1 interfaces up, gateway 172.30.47.1 via en0, 0 neighbours, 0 listeners"
        );
        // Idle tunnels are not mistaken for the lab, so nothing is flagged.
        local.listeners.push(Listener {
            protocol: "tcp".into(),
            address: "172.30.47.20".into(),
            port: 8000,
        });
        assert!(route_warnings(&local, &[]).is_empty());

        // A tunnel with a real address is a VPN.
        local.interfaces.push(Interface {
            name: "utun9".into(),
            kind: "vpn".into(),
            up: true,
            addresses: vec!["fe80::1/64".into(), "10.10.14.3/23".into()],
        });
        assert!(summary(&local).contains("2 interfaces up"));
        assert!(summary(&local).contains("VPN utun9 10.10.14.3/23"));
        assert_eq!(route_warnings(&local, &[]).len(), 1);
    }

    /// A table that could not be read must not look like an empty one.
    #[cfg(unix)]
    #[test]
    fn tools_that_cannot_be_read_are_reported_not_hidden() {
        let mut notes = Vec::new();
        assert_eq!(run("meow-no-such-tool", &["-a"], &mut notes), "");
        assert_eq!(run("meow-no-such-tool", &["-b"], &mut notes), "");
        assert_eq!(
            notes,
            ["`meow-no-such-tool` is not installed or not on the PATH"],
            "one note per missing tool, however often it is called"
        );

        // Fails without a word: reported. Fails after printing a table: the
        // table is used. Succeeds with nothing to say: that is just empty.
        let mut notes = Vec::new();
        assert_eq!(run("sh", &["-c", "exit 3"], &mut notes), "");
        assert_eq!(
            notes,
            ["`sh -c exit 3` failed (exit status: 3) and printed nothing"]
        );
        let mut notes = Vec::new();
        assert_eq!(run("sh", &["-c", "echo row; exit 1"], &mut notes), "row\n");
        assert_eq!(run("sh", &["-c", "true"], &mut notes), "");
        assert!(notes.is_empty(), "{notes:?}");

        // A tool that is installed but not on the PATH is still found in
        // the system directories.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("meow-sbin-tool");
        std::fs::write(&tool, "#!/bin/sh\necho \"from sbin: $1\"\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dirs = ["/nonexistent", dir.path().to_str().unwrap()];
        let mut notes = Vec::new();
        assert_eq!(
            run_from("meow-sbin-tool", &["-an"], &dirs, &mut notes),
            "from sbin: -an\n"
        );
        assert!(notes.is_empty(), "{notes:?}");

        // The real observation never fails, whatever this machine has.
        let local = observe(&[]);
        assert!(!local.observed_utc.is_empty());
        if local.interfaces.is_empty() {
            assert!(!local.notes.is_empty(), "nothing read, and nothing said");
        }
    }

    #[test]
    fn machine_report_is_short_and_says_what_matters() {
        let local = linux_fixture();
        let report = machine_report(&local);
        // Nothing is known about the machine itself here: it says so.
        assert_eq!(
            report.headline,
            "192.168.1.5 -> computer -> OS not known -> version not known"
        );
        assert_eq!(
            report.vpn,
            ["tun0 10.10.14.3/23: carries 10.10.10.0/23, 10.10.14.0/23"]
        );
        assert_eq!(primary_address(&local).as_deref(), Some("192.168.1.5"));

        let shape: Vec<(&str, bool)> = report
            .sections
            .iter()
            .map(|s| (s.title.as_str(), s.open))
            .collect();
        assert_eq!(
            shape,
            [
                ("Open ports", true),
                ("Interfaces", true),
                ("Routes (5 of 6)", false),
                ("Neighbours (2)", false),
                ("All interfaces (5)", false),
            ],
            "two short blocks in view, the tables folded away"
        );
        let lines = |title: &str| -> Vec<String> {
            let found = report.sections.iter().find(|s| s.title.starts_with(title));
            found.unwrap().lines.clone()
        };
        // Ports other machines can reach first, each once (IPv4 and IPv6
        // sockets of one port are one port), then the local-only ones.
        assert_eq!(
            lines("Open ports"),
            [
                "22/tcp, 68/udp, 8000/tcp, 9001/tcp, 9090/tcp",
                "this machine only: 53/tcp, 631/tcp",
            ]
        );
        // One line per interface in use, saying what it is for. The IPv6
        // gateway (a link-local address) is left out beside the IPv4 one.
        assert_eq!(
            lines("Interfaces"),
            [
                "eth0  192.168.1.5/24  gateway 192.168.1.1",
                "tun0  10.10.14.3/23  VPN, carries 10.10.10.0/23, 10.10.14.0/23",
            ]
        );
        assert_eq!(
            lines("Routes"),
            [
                "default via 192.168.1.1 on eth0",
                "10.10.10.0/23 via 10.10.14.1 on tun0",
                "10.10.14.0/23 on tun0 (directly attached)",
                "192.168.1.0/24 on eth0 (directly attached)",
                "default (IPv6) via fe80::1 on eth0",
                "1 more left out: single hosts, multicast, link-local and idle interfaces",
            ]
        );
        assert_eq!(
            lines("Neighbours"),
            [
                "192.168.1.1  00:11:22:33:44:55  eth0",
                "fe80::1  00:11:22:33:44:55  eth0",
            ]
        );
        assert_eq!(
            lines("All interfaces"),
            [
                "lo  loopback  up  127.0.0.1/8  ::1/128",
                "eth0  ethernet  up  192.168.1.5/24  fe80::a00:27ff:fe4e:66a1/64",
                "tun0  vpn  up  10.10.14.3/23",
                "2 without a usable address: wlan0, veth12ab",
            ]
        );

        // A VPN that takes the default route says so; the local link stays
        // listed and stays the address "You" is known by.
        let mut full = local.clone();
        full.routes.retain(|r| !is_default_route(r));
        full.routes.push(Route {
            destination: "0.0.0.0/0".into(),
            gateway: None,
            interface: "tun0".into(),
        });
        full.warnings.push("a warning".into());
        full.notes
            .push("`arp` is not installed or not on the PATH".into());
        full.neighbors.push(Neighbor {
            address: "192.168.1.77".into(),
            mac: None,
            interface: "eth0".into(),
        });
        let report = machine_report(&full);
        assert_eq!(
            report.vpn,
            ["tun0 10.10.14.3/23: carries the default route"]
        );
        assert_eq!(
            report.sections[1].lines,
            [
                "eth0  192.168.1.5/24  local network only",
                "tun0  10.10.14.3/23  VPN, carries the default route",
            ]
        );
        assert_eq!(primary_address(&full).as_deref(), Some("192.168.1.5"));
        // What needs a look comes right after, in view and marked.
        let flagged: Vec<(&str, bool, bool)> = report.sections[2..4]
            .iter()
            .map(|s| (s.title.as_str(), s.open, s.warn))
            .collect();
        assert_eq!(
            flagged,
            [
                ("Route warnings", true, true),
                ("Could not be read", true, true)
            ]
        );
        assert_eq!(report.sections.iter().filter(|s| s.warn).count(), 2);
        let neighbours = report.sections.iter().find(|s| s.title == "Neighbours (3)");
        assert_eq!(
            neighbours.unwrap().lines.last().unwrap(),
            "192.168.1.77  no answer  eth0"
        );

        // The other way a VPN client takes everything: two half-routes.
        let mut halves = local.clone();
        for destination in ["0.0.0.0/1", "128.0.0.0/1"] {
            halves.routes.push(Route {
                destination: destination.into(),
                gateway: Some("10.10.14.1".into()),
                interface: "tun0".into(),
            });
        }
        assert_eq!(
            machine_report(&halves).vpn,
            ["tun0 10.10.14.3/23: carries all IPv4 traffic (0.0.0.0/1 and 128.0.0.0/1)"]
        );

        // Nothing read at all.
        let nothing = machine_report(&LocalNet::default());
        assert_eq!(
            nothing.headline,
            "no address -> computer -> OS not known -> version not known"
        );
        assert_eq!(nothing.sections[0].lines, ["none listening"]);
        assert_eq!(
            nothing.sections[1].lines,
            ["unknown: the network tables could not be read"]
        );
        assert_eq!(nothing.sections[2].title, "Routes (0)");
        assert_eq!(nothing.sections[2].lines, ["none"]);
        assert_eq!(primary_address(&LocalNet::default()), None);
    }

    /// The tables of a real Mac on a phone hotspot with a split-tunnel
    /// corporate VPN: 31 interfaces and 113 routes, of which a handful say
    /// anything. Modelled on a real machine; every address is a documentation or
    /// made-up one.
    #[test]
    fn a_real_macs_tables_come_out_as_a_few_lines() {
        let mut local = LocalNet::default();
        macos::ifconfig(
            "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
             \tinet 127.0.0.1 netmask 0xff000000\n\
             \tinet6 ::1 prefixlen 128\n\
             \tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1\n\
             gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280\n\
             en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tinet6 fe80::1:2:3:4%en0 prefixlen 64 secured scopeid 0xe\n\
             \tinet 192.168.50.5 netmask 0xfffffff0 broadcast 192.168.50.15\n\
             \tinet6 2001:db8:b027:de15:3e:7e78:d565:25b6 prefixlen 64 autoconf secured\n\
             utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n\
             \tinet6 fe80::9:a:b:c%utun0 prefixlen 64 scopeid 0x10\n\
             utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400\n\
             \tinet 10.99.2.24 --> 10.99.2.24 netmask 0xffffffff\n\
             bridge100: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500\n\
             \tinet 192.168.2.1 netmask 0xffffff00 broadcast 192.168.2.255\n\
             \tinet6 fe80::d:e:f:1%bridge100 prefixlen 64 scopeid 0x19\n\
             \tinet6 fd00:1234:5678:9abc:109c:8607:daf2:1b3a prefixlen 64 autoconf secured\n",
            &mut local.interfaces,
        );
        macos::routes(
            "Routing tables\n\nInternet:\n\
             Destination        Gateway            Flags               Netif Expire\n\
             default            192.168.50.1        UGScg                 en0\n\
             default            link#25            UCSIg           bridge100      !\n\
             default            link#27            UCSIg               utun5\n\
             10                 10.99.2.24        UGSc                utun5\n\
             10.1.16.11/32    10.99.2.24        UGSc                utun5\n\
             10.2.101.42/32   10.99.2.24        UGSc                utun5\n\
             198.51.100/24          10.99.2.24        UGSc                utun5\n\
             192.0.2.57/32     10.99.2.24        UGSc                utun5\n\
             192.0.2.47/32     10.99.2.24        UGSc                utun5\n\
             192.0.2.156/32    10.99.2.24        UGSc                utun5\n\
             127                127.0.0.1          UCS                   lo0\n\
             127.0.0.1          127.0.0.1          UH                    lo0\n\
             203.0.113            10.99.2.24        UGSc                utun5\n\
             203.0.113.4/32     192.168.50.1        UGHS                  en0\n\
             169.254            link#14            UCS                   en0      !\n\
             172.16/12          10.99.2.24        UGSc                utun5\n\
             10.99.2.24        127.0.0.1          UH                    lo0\n\
             192.168.50/28       link#14            UCS                   en0      !\n\
             192.168.50.1/32     link#14            UCS                   en0      !\n\
             192.168.50.5/32     link#14            UCS                   en0      !\n\
             192.168.2          link#25            UC              bridge100      !\n\
             224.0.0/4          link#14            UmCS                  en0      !\n\
             255.255.255.255/32 link#14            UCS                   en0      !\n\n\
             Internet6:\n\
             Destination                             Gateway                         Flags   Netif Expire\n\
             default                                 fe80::5:6:7:8%en0   UGcg      en0\n\
             default                                 fe80::%utun0                    UGcIg   utun0\n\
             ::1                                     ::1                             UHL       lo0\n\
             2001:db8:b027:de15::/64                link#14                         UC        en0\n\
             fd00:1234:5678:9abc::/64                link#25                         UC  bridge100\n\
             fe80::%en0/64                           link#14                         UCI       en0\n\
             fe80::%utun0/64                         fe80::9:a:b:c%utun0 UcI     utun0\n\
             ff00::/8                                ::1                             UmCI      lo0\n\
             ff00::/8                                link#14                         UmCI      en0\n\
             ff02::/32                               fe80::9:a:b:c%utun0 UmCI    utun0\n",
            &mut local.routes,
        );
        macos::neighbors(
            "? (192.168.50.1) at 2:0:5e:10:0:1 on en0 ifscope [ethernet]\n",
            &mut local.neighbors,
        );
        local.system = SystemInfo {
            kind: system::mac_kind("MacBookPro18,3\n").to_owned(),
            os: "macOS".into(),
            version: "15.1".into(),
        };

        let report = machine_report(&local);
        assert_eq!(
            report.headline,
            "192.168.50.5 -> MacBook Pro -> macOS -> 15.1"
        );
        // A split tunnel: the VPN carries the company's networks. Its
        // interface-scoped "default" entry is not a default route.
        let carries = "carries 10.0.0.0/8, 198.51.100.0/24, 203.0.113.0/24, 172.16.0.0/12 \
                       and 5 single hosts";
        assert_eq!(report.vpn, [format!("utun5 10.99.2.24/32: {carries}")]);
        assert_eq!(report.sections[0].lines, ["none listening"]);
        assert_eq!(
            report.sections[1].lines,
            [
                "en0  192.168.50.5/28  gateway 192.168.50.1".to_owned(),
                format!("utun5  10.99.2.24/32  VPN, {carries}"),
                "bridge100  192.168.2.1/24  virtual network on this machine".to_owned(),
            ]
        );
        let routes = &report.sections[2];
        assert_eq!(routes.title, "Routes (10 of 30)");
        assert_eq!(
            routes.lines,
            [
                "default via 192.168.50.1 on en0",
                "10.0.0.0/8 via 10.99.2.24 on utun5",
                "198.51.100.0/24 via 10.99.2.24 on utun5",
                "203.0.113.0/24 via 10.99.2.24 on utun5",
                "172.16.0.0/12 via 10.99.2.24 on utun5",
                "192.168.50.0/28 on en0 (directly attached)",
                "192.168.2.0/24 on bridge100 (directly attached)",
                "default (IPv6) via fe80::5:6:7:8 on en0",
                "2001:db8:b027:de15::/64 on en0 (directly attached)",
                "fd00:1234:5678:9abc::/64 on bridge100 (directly attached)",
                "20 more left out: single hosts, multicast, link-local and idle interfaces",
            ]
        );
        assert_eq!(report.sections[3].title, "Neighbours (1)");
        let all = &report.sections[4];
        assert_eq!(all.title, "All interfaces (6)");
        assert_eq!(
            all.lines.last().unwrap(),
            "2 without a usable address: gif0, utun0"
        );
        // The whole thing in view: a headline and five lines.
        let in_view: usize = report
            .sections
            .iter()
            .filter(|s| s.open)
            .map(|s| s.lines.len())
            .sum();
        assert_eq!(in_view, 4);
    }

    #[test]
    fn each_platform_says_what_kind_of_machine_it_is() {
        for (model, kind) in [
            ("MacBookPro18,3", "MacBook Pro"),
            ("MacBookAir10,1\n", "MacBook Air"),
            ("Macmini9,1", "Mac mini"),
            ("iMac21,1", "iMac"),
            ("Mac14,7", "Mac"),
            ("VirtualMac2,1", "Mac (virtual machine)"),
            ("", ""),
        ] {
            assert_eq!(system::mac_kind(model), kind, "{model}");
        }
        assert_eq!(
            system::sw_vers(
                "ProductName:\t\tmacOS\nProductVersion:\t\t15.1\nBuildVersion:\t\t24B83\n"
            ),
            ("macOS".to_owned(), "15.1".to_owned())
        );
        assert_eq!(
            system::os_release(
                "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n\
                 VERSION=\"24.04.1 LTS (Noble Numbat)\"\nID=ubuntu\n"
            ),
            ("Ubuntu".to_owned(), "24.04".to_owned())
        );
        // A rolling release has no VERSION_ID.
        assert_eq!(
            system::os_release("NAME=\"Arch Linux\"\nID=arch\n"),
            ("Arch Linux".to_owned(), String::new())
        );
        assert_eq!(
            system::windows_ver("\r\nMicrosoft Windows [Version 10.0.22631.4460]\r\n"),
            ("Windows".to_owned(), "10.0.22631.4460".to_owned())
        );
        assert_eq!(system::chassis_kind("10\n", "ThinkPad X1 Carbon"), "Laptop");
        assert_eq!(system::chassis_kind("3", "OptiPlex 7090"), "Desktop");
        assert_eq!(system::chassis_kind("23", "PowerEdge R650"), "Server");
        assert_eq!(system::chassis_kind("1", "KVM"), "Virtual machine");
        assert_eq!(system::chassis_kind("", ""), "");

        // The real thing never fails, and always knows at least the platform.
        let system = system_info();
        assert!(!system.os.is_empty());
        assert_eq!(observe(&[]).system, system);
    }

    #[test]
    fn summary_line_names_gateway_and_vpn() {
        assert_eq!(
            summary(&linux_fixture()),
            "2 interfaces up, gateway 192.168.1.1 via eth0, VPN tun0 10.10.14.3/23, 2 neighbours, 8 listeners"
        );
        assert_eq!(
            summary(&LocalNet::default()),
            "0 interfaces up, 0 neighbours, 0 listeners"
        );
    }

    #[test]
    fn observing_this_machine_never_fails() {
        // Whatever tools exist here, the observer must return a timestamped
        // result without panicking and without needing privileges.
        let local = observe(&[]);
        assert!(crate::timeutil::parse_rfc3339(&local.observed_utc).is_some());
        for interface in &local.interfaces {
            assert!(!interface.name.is_empty());
            for address in &interface.addresses {
                assert!(IpNetwork::from_str(address).is_ok(), "{address}");
            }
        }
    }
}

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

use crate::endpoint::Endpoint;
use crate::graph::{Interface, Listener, LocalNet, Neighbor, Route};
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

    fn prefix_from_hex_mask(mask: &str) -> Option<u8> {
        let value = u32::from_str_radix(mask.trim_start_matches("0x"), 16).ok()?;
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
            let address = match fields.first().copied() {
                Some("inet") => fields
                    .get(1)
                    .and_then(|a| canonical_ip(a))
                    .zip(after("netmask").and_then(|m| prefix_from_hex_mask(m))),
                Some("inet6") => fields
                    .get(1)
                    .and_then(|a| canonical_ip(a))
                    .zip(after("prefixlen").and_then(|p| p.parse::<u8>().ok())),
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
            if fields.len() < 6 || !fields[0].starts_with("tcp") || fields[5] != "LISTEN" {
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

/// The first address of the interface that is neither loopback nor
/// link-local, in CIDR form.
fn routable_address(interface: &Interface) -> Option<&str> {
    interface
        .addresses
        .iter()
        .find(|address| {
            IpNetwork::from_str(address).is_ok_and(|network| match network.ip() {
                IpAddr::V4(ip) => !ip.is_loopback() && !ip.is_link_local(),
                IpAddr::V6(ip) => !ip.is_loopback() && (ip.segments()[0] & 0xffc0) != 0xfe80,
            })
        })
        .map(String::as_str)
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
// Running the OS tools
// ---------------------------------------------------------------------------

/// Runs a read-only OS tool and returns its stdout, or an empty string if
/// it is missing.
fn run(program: &str, args: &[&str]) -> String {
    // The exit code is not checked: some of these tools print a usable table
    // and still exit non-zero (for example when one entry cannot be read).
    // The parsers ignore anything they do not recognise.
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

/// Reads the local tables once. `targets` are the known lab hosts, used for
/// the route warnings.
pub fn observe(targets: &[IpAddr]) -> LocalNet {
    let mut local = LocalNet {
        observed_utc: now_rfc3339(),
        ..LocalNet::default()
    };
    #[cfg(target_os = "linux")]
    {
        linux::links(&run("ip", &["-o", "link", "show"]), &mut local.interfaces);
        linux::addresses(&run("ip", &["-o", "addr", "show"]), &mut local.interfaces);
        linux::routes(&run("ip", &["route", "show"]), false, &mut local.routes);
        linux::routes(
            &run("ip", &["-6", "route", "show"]),
            true,
            &mut local.routes,
        );
        linux::neighbors(&run("ip", &["neigh", "show"]), &mut local.neighbors);
        linux::listeners(&run("ss", &["-H", "-ltn"]), "tcp", &mut local.listeners);
        linux::listeners(&run("ss", &["-H", "-lun"]), "udp", &mut local.listeners);
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        macos::ifconfig(&run("ifconfig", &[]), &mut local.interfaces);
        macos::routes(&run("netstat", &["-rn"]), &mut local.routes);
        macos::neighbors(&run("arp", &["-an"]), &mut local.neighbors);
        macos::listeners(&run("netstat", &["-an", "-p", "tcp"]), &mut local.listeners);
    }
    #[cfg(windows)]
    {
        windows::routes(
            &run("route", &["print", "-4"]),
            &mut local.interfaces,
            &mut local.routes,
        );
        windows::neighbors(&run("arp", &["-a"]), &mut local.neighbors);
        windows::listeners(&run("netstat", &["-an", "-p", "tcp"]), &mut local.listeners);
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
                "::/0 fe80:: utun0",
                "fe80::/64 - en0",
            ]
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
            ["192.168.1.5:8000", ":::8080", "0.0.0.0:22", "::1:631"]
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
             \tinet 172.26.147.20 netmask 0xfffff800 broadcast 172.26.151.255\n\
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
             default            172.26.147.1       UGScg             en0\n",
            &mut local.routes,
        );
        assert_eq!(local.interfaces.len(), 11);
        assert_eq!(
            summary(&local),
            "1 interfaces up, gateway 172.26.147.1 via en0, 0 neighbours, 0 listeners"
        );
        // Idle tunnels are not mistaken for the lab, so nothing is flagged.
        local.listeners.push(Listener {
            protocol: "tcp".into(),
            address: "172.26.147.20".into(),
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

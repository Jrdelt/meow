//! The network topology as a graph: this machine, its interfaces, the
//! gateways behind them and the hosts they lead to.
//!
//! Built on demand from [`Graph`] (the evidence store) with `petgraph`, and
//! rendered three ways: Cytoscape.js elements for the browser map, Mermaid
//! for `REPORT.md`, and a reachability answer for route reasoning.
//!
//! The browser map draws a classic network diagram: an Internet cloud,
//! routers, firewalls, servers, network segments and clients. Which picture a
//! node gets is its [`Role`], a drawing hint that always comes with the
//! observation it was derived from.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::str::FromStr;

use ipnetwork::IpNetwork;

use petgraph::algo::has_path_connecting;
use petgraph::graph::{Graph as PetGraph, NodeIndex};
use serde::Serialize;
use serde_json::{json, Value};

use crate::graph::{Graph, Host};
use crate::observer::{
    has_routable_address, is_default_route, primary_address, routable_address, route_for,
};

pub const LOCAL_ID: &str = "local";
/// Drawing only: what lies beyond a default route.
pub const INTERNET_ID: &str = "internet";
/// Most devices drawn from the neighbour table; the rest are counted.
const MAX_NEIGHBOURS: usize = 60;

/// Words in an OS guess or a service banner that mark a kind of device.
const FIREWALL_WORDS: &[&str] = &[
    "firewall",
    "pfsense",
    "opnsense",
    "fortigate",
    "fortios",
    "pan-os",
    "palo alto",
    "sonicwall",
    "watchguard",
    "check point",
    "cisco asa",
    "adaptive security appliance",
];
const ROUTER_WORDS: &[&str] = &[
    "router",
    "mikrotik",
    "openwrt",
    "dd-wrt",
    "edgeos",
    "vyos",
    "cisco ios",
    "junos",
    "access point",
];
const SWITCH_WORDS: &[&str] = &[
    "ethernet switch",
    "network switch",
    "managed switch",
    "catalyst",
    "procurve",
];

/// The picture a node gets on the map. A drawing hint derived from what was
/// observed, never a finding: it is always sent with the reason for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Internet,
    You,
    /// The network one interface is attached to, drawn as a hub.
    Segment,
    Router,
    Firewall,
    Switch,
    Server,
    Client,
}

impl Role {
    pub fn title(self) -> &'static str {
        match self {
            Role::Internet => "Internet",
            Role::You => "You",
            Role::Segment => "Network",
            Role::Router => "Router",
            Role::Firewall => "Firewall",
            Role::Switch => "Switch",
            Role::Server => "Server",
            Role::Client => "Client",
        }
    }
}

/// What is known about a host's operating system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsGuess {
    pub name: String,
    /// Empty when not known.
    pub version: String,
    /// Read off a service banner instead of reported by an OS scan.
    pub guessed: bool,
}

/// Distribution names as they appear in service banners.
const BANNER_SYSTEMS: &[(&str, &str)] = &[
    ("ubuntu", "Ubuntu"),
    ("debian", "Debian"),
    ("raspbian", "Raspbian"),
    ("red hat", "Red Hat"),
    ("rhel", "Red Hat"),
    ("centos", "CentOS"),
    ("fedora", "Fedora"),
    ("alpine", "Alpine Linux"),
    ("freebsd", "FreeBSD"),
    ("microsoft", "Windows"),
    ("windows", "Windows"),
];

/// The OpenSSH version each Ubuntu long-term release ships. The package
/// revision in the banner changes with every update; this part does not.
const UBUNTU_BY_OPENSSH: &[(&str, &str)] = &[
    ("6.6.1p1", "14.04"),
    ("7.2p2", "16.04"),
    ("7.6p1", "18.04"),
    ("8.2p1", "20.04"),
    ("8.9p1", "22.04"),
    ("9.6p1", "24.04"),
];

/// The operating system of a host: what an OS scan reported, or else what
/// its service banners give away (`OpenSSH 9.6p1 Ubuntu 3ubuntu13.20`).
pub fn host_os(host: &Host) -> Option<OsGuess> {
    if let Some(os) = host
        .os
        .as_deref()
        .map(str::trim)
        .filter(|os| !os.is_empty())
    {
        // "Linux 5.4", "Microsoft Windows 10 1809": the version starts at
        // the first word that begins with a digit.
        let words: Vec<&str> = os.split_whitespace().collect();
        let at = words
            .iter()
            .position(|word| word.starts_with(|c: char| c.is_ascii_digit()))
            .filter(|at| *at > 0)
            .unwrap_or(words.len());
        return Some(OsGuess {
            name: words[..at].join(" "),
            version: words[at..].join(" "),
            guessed: false,
        });
    }
    for port in host.ports.values() {
        let banner = [&port.product, &port.version, &port.extra_info]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        let lower = banner.to_lowercase();
        let Some((_, name)) = BANNER_SYSTEMS.iter().find(|(word, _)| lower.contains(word)) else {
            continue;
        };
        let upstream = port
            .version
            .as_deref()
            .and_then(|v| v.split_whitespace().next());
        let version = match *name {
            "Ubuntu" if lower.contains("openssh") => UBUNTU_BY_OPENSSH
                .iter()
                .find(|(openssh, _)| Some(*openssh) == upstream)
                .map(|(_, release)| (*release).to_owned()),
            // Debian package revisions name the release: `5+deb11u3`.
            "Debian" | "Raspbian" => lower.split("deb").skip(1).find_map(|rest| {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                (!digits.is_empty()).then_some(digits)
            }),
            _ => None,
        };
        return Some(OsGuess {
            name: (*name).to_owned(),
            version: version.unwrap_or_default(),
            guessed: true,
        });
    }
    None
}

/// `address -> machine type -> OS -> version`, the one-line answer to "what
/// is this?". Unknown parts say so; a guess is marked as one.
pub fn host_headline(graph: &Graph, host: &Host) -> String {
    let (role, _) = host_role(graph, host);
    let os = host_os(host);
    let known = |text: Option<&str>, otherwise: &str| match text {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => otherwise.to_owned(),
    };
    let mut line = [
        host.address.clone(),
        role.title().to_owned(),
        known(os.as_ref().map(|o| o.name.as_str()), "OS not known"),
        known(os.as_ref().map(|o| o.version.as_str()), "version not known"),
    ]
    .join(" -> ");
    if os.is_some_and(|o| o.guessed) {
        line.push_str(" (OS read off a service banner)");
    }
    line
}

/// `22/tcp ssh, 443/tcp https`: the ports seen open on a host.
pub fn host_open_ports(host: &Host) -> String {
    let ports: Vec<String> = host
        .open_ports()
        .map(|port| match &port.service {
            Some(service) => format!("{} {service}", port.key()),
            None => port.key(),
        })
        .collect();
    match ports.len() {
        0 => "none seen open".to_owned(),
        1..=12 => ports.join(", "),
        n => format!("{} and {} more", ports[..12].join(", "), n - 12),
    }
}

fn parse_host_ip(address: &str) -> Option<IpAddr> {
    let base = address.split('%').next().unwrap_or(address);
    base.parse::<IpAddr>().ok()
}

/// True for a neighbour-table entry that stands for one device: a resolved,
/// individual hardware address and an address that is not a group.
fn is_single_device(address: &str, mac: &str) -> bool {
    let group_mac = mac
        .split([':', '-'])
        .next()
        .and_then(|octet| u8::from_str_radix(octet, 16).ok())
        .is_none_or(|octet| octet & 1 == 1);
    let single_address = match parse_host_ip(address) {
        Some(IpAddr::V4(ip)) => !ip.is_multicast() && !ip.is_broadcast() && !ip.is_unspecified(),
        Some(IpAddr::V6(ip)) => !ip.is_multicast() && !ip.is_unspecified(),
        None => false,
    };
    !group_mac && single_address
}

/// The role of a host and what it was derived from. Text evidence wins over
/// position: a gateway whose OS guess says it is a firewall is a firewall.
/// A host known by a name alone, with nothing seen on it: the name was
/// printed in the session shell or a log, usually inside a URL, or listed
/// in the certificate logs, and nobody looked at the machine. There is no
/// address to place it by, so it is listed and never drawn. A name whose
/// own DNS records or mail checks were read, or that has the operator's
/// note, was looked at.
pub fn only_mentioned(host: &Host) -> bool {
    parse_host_ip(&host.address).is_none()
        && host.open_ports().count() == 0
        && host.advisories.is_empty()
        && host.os.is_none()
        && host.mac.is_none()
        && host.dns_security.is_none()
        && host.asn.is_none()
        && host.country.is_none()
        && host.ipv6_dns.is_none()
        && host.waf_cdn.is_none()
        && host.hops.is_empty()
        && host.not_open.is_empty()
        && host
            .facts
            .iter()
            .chain(host.ports.values().flat_map(|port| &port.facts))
            .all(is_mention)
        // A server or redirect header means something answered.
        && host.ports.values().all(|port| {
            port.http
                .as_ref()
                .is_none_or(|http| http.server.is_none() && http.location.is_none())
        })
}

/// How many hosts are on the map: all but the names only mentioned. The
/// report, the HUD, `meow list` and `meow add` count these.
pub fn map_host_count(graph: &Graph) -> usize {
    graph
        .hosts
        .values()
        .filter(|host| !only_mentioned(host))
        .count()
}

/// A fact that only says a name came up: in the terminal, a log or the
/// certificate logs, or how such a name answers in DNS (the `mail-dns`
/// stage's `DNS: ` line on a certificate-log name).
fn is_mention(fact: &crate::graph::Fact) -> bool {
    use crate::evidence::Source;
    match fact.record.source {
        Source::PtyRegex | Source::LogRegex | Source::CtLog => true,
        Source::Dns => fact.claim.starts_with("DNS: "),
        _ => false,
    }
}

pub fn host_role(graph: &Graph, host: &Host) -> (Role, String) {
    let mut text = host.os.clone().unwrap_or_default();
    for port in host.ports.values() {
        for part in [&port.product, &port.extra_info].into_iter().flatten() {
            text.push(' ');
            text.push_str(part);
        }
    }
    let text = text.to_lowercase();
    let mention = |words: &[&'static str]| words.iter().copied().find(|word| text.contains(word));
    let mentioned = |word: &str| format!("its OS guess or a service banner mentions \"{word}\"");

    if let Some(word) = mention(FIREWALL_WORDS) {
        return (Role::Firewall, mentioned(word));
    }
    let routes_through = graph
        .local
        .routes
        .iter()
        .any(|route| route.gateway.as_deref() == Some(host.address.as_str()));
    if routes_through {
        let why = "it is a gateway in this machine's routing table";
        return (Role::Router, why.to_owned());
    }
    if let Some(word) = mention(ROUTER_WORDS) {
        return (Role::Router, mentioned(word));
    }
    if let Some(word) = mention(SWITCH_WORDS) {
        return (Role::Switch, mentioned(word));
    }
    // A service that was only mentioned (a URL in a log, a line of terminal
    // output) still says what the machine is for.
    let mentioned_port = host
        .ports
        .values()
        .find(|port| port.state == "unverified")
        .map(|port| port.key());
    match (host.open_ports().count(), mentioned_port) {
        (0, None) => (Role::Client, "no service has been seen on it".to_owned()),
        (0, Some(port)) => (
            Role::Server,
            format!("a service on it was mentioned ({port}) but has not been seen open"),
        ),
        (1, _) => (Role::Server, "1 open port has been seen on it".to_owned()),
        (n, _) => (Role::Server, format!("{n} open ports have been seen on it")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Local,
    Interface,
    Gateway,
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
}

pub struct Topology {
    graph: PetGraph<Node, &'static str>,
    index: BTreeMap<String, NodeIndex>,
}

pub fn host_id(address: &str) -> String {
    format!("host:{address}")
}

impl Topology {
    fn node(&mut self, id: String, kind: NodeKind, label: String) -> NodeIndex {
        if let Some(index) = self.index.get(&id) {
            return *index;
        }
        let index = self.graph.add_node(Node {
            id: id.clone(),
            kind,
            label: crate::evidence::sanitize(&label, 200),
        });
        self.index.insert(id, index);
        index
    }

    fn edge(&mut self, from: NodeIndex, to: NodeIndex, kind: &'static str) {
        if from != to && self.graph.find_edge(from, to).is_none() {
            self.graph.add_edge(from, to, kind);
        }
    }

    fn interface(&mut self, graph: &Graph, name: &str) -> NodeIndex {
        // The address the interface is used with, not its link-local one
        // (macOS lists `fe80::` first).
        let address = graph
            .local
            .interfaces
            .iter()
            .find(|i| i.name == name)
            .and_then(|i| routable_address(i).or(i.addresses.first().map(String::as_str)))
            .unwrap_or_default()
            .to_owned();
        let label = format!("{name} {address}").trim().to_owned();
        let local = self.index[LOCAL_ID];
        let index = self.node(format!("if:{name}"), NodeKind::Interface, label);
        self.edge(local, index, "interface");
        index
    }

    /// A gateway is drawn as the host node if that address is a known host.
    fn gateway(&mut self, graph: &Graph, address: &str) -> NodeIndex {
        match graph.hosts.get(address) {
            Some(host) => self.node(host_id(address), NodeKind::Host, host.label()),
            None => self.node(
                format!("gw:{address}"),
                NodeKind::Gateway,
                format!("gateway {address}"),
            ),
        }
    }

    pub fn build(graph: &Graph) -> Self {
        let mut topology = Self {
            graph: PetGraph::new(),
            index: BTreeMap::new(),
        };
        topology.node(
            LOCAL_ID.to_owned(),
            NodeKind::Local,
            "this machine".to_owned(),
        );

        // Real interfaces that are up, each with its default gateway if any.
        let visible: Vec<String> = graph
            .local
            .interfaces
            .iter()
            .filter(|i| {
                i.up && has_routable_address(i)
                    && !matches!(i.kind.as_str(), "loopback" | "virtual")
            })
            .map(|i| i.name.clone())
            .collect();
        for name in &visible {
            topology.interface(graph, name);
        }
        for route in &graph.local.routes {
            if !is_default_route(route) || !visible.contains(&route.interface) {
                continue;
            }
            if let Some(gateway) = &route.gateway {
                let interface = topology.interface(graph, &route.interface);
                let node = topology.gateway(graph, gateway);
                topology.edge(interface, node, "gateway");
            }
        }

        for host in graph.hosts.values() {
            if only_mentioned(host) {
                continue;
            }
            let node = topology.node(host_id(&host.address), NodeKind::Host, host.label());
            let Some(ip) = parse_host_ip(&host.address) else {
                continue; // known by name only: no route can be derived
            };
            let Some(route) = route_for(&graph.local, ip) else {
                continue;
            };
            let interface = topology.interface(graph, &route.interface);
            match &route.gateway {
                Some(gateway) => {
                    let gw = topology.gateway(graph, gateway);
                    topology.edge(interface, gw, "gateway");
                    topology.edge(gw, node, "routed");
                }
                None => {
                    let host_addr = host.address.split('%').next().unwrap_or(&host.address);
                    let neighbour = graph
                        .local
                        .neighbors
                        .iter()
                        .any(|n| n.address == host.address || n.address == host_addr);
                    topology.edge(
                        interface,
                        node,
                        if neighbour { "neighbour" } else { "direct" },
                    );
                }
            }
        }
        topology
    }

    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.graph.node_weights()
    }

    /// (from, to, kind) for every edge.
    pub fn edges(&self) -> Vec<(&Node, &Node, &'static str)> {
        self.graph
            .edge_indices()
            .filter_map(|edge| {
                let (from, to) = self.graph.edge_endpoints(edge)?;
                Some((&self.graph[from], &self.graph[to], self.graph[edge]))
            })
            .collect()
    }

    /// Whether the local routing table gives a path from this machine to
    /// the host.
    pub fn reachable(&self, address: &str) -> bool {
        match (self.index.get(LOCAL_ID), self.index.get(&host_id(address))) {
            (Some(local), Some(host)) => has_path_connecting(&self.graph, *local, *host, None),
            _ => false,
        }
    }

    /// Role, reason and map caption of a node, plus the network of a segment.
    fn drawing(&self, graph: &Graph, node: &Node) -> (Role, String, String, Option<String>) {
        let routed = "it is a gateway in this machine's routing table";
        match node.kind {
            NodeKind::Local => {
                // Its own address on the network it reaches the rest through.
                let mut caption = Role::You.title().to_owned();
                if let Some(address) = primary_address(&graph.local) {
                    caption.push('\n');
                    caption.push_str(&crate::evidence::sanitize(&address, 80));
                }
                let why = "the machine meow runs on".to_owned();
                (Role::You, why, caption, None)
            }
            NodeKind::Interface => {
                let raw_name = node.id.strip_prefix("if:").unwrap_or(&node.id);
                let interface = graph.local.interfaces.iter().find(|i| i.name == raw_name);
                let clean_name = crate::evidence::sanitize(raw_name, 64);
                let word = match interface.map(|i| i.kind.as_str()) {
                    Some("ethernet") => "LAN",
                    Some("wifi") => "Wi-Fi",
                    Some("vpn") => "VPN",
                    _ => Role::Segment.title(),
                };
                let network = interface
                    .and_then(|i| routable_address(i).or(i.addresses.first().map(String::as_str)))
                    .and_then(|address| IpNetwork::from_str(address).ok())
                    .map(|n| format!("{}/{}", n.network(), n.prefix()));
                // Windows names connections "Wi-Fi" or "Ethernet" already.
                let says_it = [word, "wi-fi", "wlan", "ethernet", "vpn"]
                    .iter()
                    .any(|w| clean_name.to_lowercase().contains(&w.to_lowercase()));
                let mut caption = if says_it {
                    clean_name.clone()
                } else {
                    format!("{word} {clean_name}")
                };
                if let Some(network) = &network {
                    caption.push('\n');
                    caption.push_str(network);
                }
                let why = format!("the network this machine is attached to through {clean_name}");
                (Role::Segment, why, caption, network)
            }
            NodeKind::Gateway => {
                let address =
                    crate::evidence::sanitize(node.id.strip_prefix("gw:").unwrap_or(&node.id), 80);
                let caption = format!("{}\n{address}", Role::Router.title());
                (Role::Router, routed.to_owned(), caption, None)
            }
            NodeKind::Host => {
                let address = node.id.strip_prefix("host:").unwrap_or(&node.id);
                let Some(host) = graph.hosts.get(address) else {
                    let why = "nothing is known about it yet".to_owned();
                    return (Role::Client, why, node.label.clone(), None);
                };
                let (role, why) = host_role(graph, host);
                let clean_addr = crate::evidence::sanitize(&host.address, 200);
                let mut caption = format!("{}\n{clean_addr}", role.title());
                if let Some(name) = host.hostnames.iter().find(|n| **n != host.address) {
                    caption.push('\n');
                    caption.push_str(&crate::evidence::sanitize(name, 200));
                }
                (role, crate::evidence::sanitize(&why, 200), caption, None)
            }
        }
    }

    /// Where the default routes lead: the node ids (a gateway, or the
    /// interface itself for a route without one) and a description.
    fn default_routes(&self, graph: &Graph) -> Vec<(String, String)> {
        let mut found: Vec<(String, String)> = Vec::new();
        for route in graph.local.routes.iter().filter(|r| is_default_route(r)) {
            let (id, via) = match &route.gateway {
                Some(gateway) if graph.hosts.contains_key(gateway) => {
                    (host_id(gateway), format!("{gateway} ({})", route.interface))
                }
                Some(gateway) => (
                    format!("gw:{gateway}"),
                    format!("{gateway} ({})", route.interface),
                ),
                None => (format!("if:{}", route.interface), route.interface.clone()),
            };
            if self.index.contains_key(&id) && !found.iter().any(|(seen, _)| *seen == id) {
                found.push((id, via));
            }
        }
        found
    }

    /// Compact port list for map node subtitles (`"22, 80, 9929/tcp"`).
    fn host_ports_compact(host: &Host) -> String {
        let open: Vec<_> = host.open_ports().collect();
        if open.is_empty() {
            return String::new();
        }
        let all_tcp = open.iter().all(|p| p.protocol == "tcp");
        let shown: Vec<String> = open
            .iter()
            .take(5)
            .map(|p| {
                if all_tcp {
                    p.number.to_string()
                } else {
                    p.key()
                }
            })
            .collect();
        let mut line = shown.join(", ");
        if all_tcp {
            line.push_str("/tcp");
        }
        if open.len() > 5 {
            line.push_str(&format!(" +{}", open.len() - 5));
        }
        line
    }

    fn host_primary_hostname(host: &Host) -> Option<String> {
        let (_, assoc_hosts) = Self::host_associated_names(host);
        if let Some(first) = assoc_hosts.first() {
            return Some(first.clone());
        }
        host.hostnames
            .iter()
            .filter(|n| **n != host.address)
            .min_by_key(|n| (n.matches('.').count(), n.len()))
            .map(|n| crate::evidence::sanitize(n, 160))
    }

    /// Extracts unique Associated Domains (registrable root domains, e.g. `nmap.org`)
    /// and Associated Hosts (subdomains/hostnames, e.g. `scanme.nmap.org`) for a host.
    pub fn host_associated_names(host: &Host) -> (Vec<String>, Vec<String>) {
        let mut raw_names: BTreeSet<String> = BTreeSet::new();
        for name in &host.hostnames {
            if *name != host.address && parse_host_ip(name).is_none() {
                raw_names.insert(name.clone());
            }
        }
        for port in host.ports.values() {
            for san in &port.tls_sans {
                let trimmed = san.trim().trim_start_matches("*.").trim_end_matches('.');
                if !trimmed.is_empty() && parse_host_ip(trimmed).is_none() {
                    raw_names.insert(trimmed.to_ascii_lowercase());
                }
            }
        }
        for fact in &host.facts {
            if let Some(rest) = fact
                .claim
                .strip_prefix("PTR record: ")
                .or_else(|| fact.claim.strip_prefix("CNAME record: "))
            {
                let trimmed = rest.trim().trim_end_matches('.');
                if !trimmed.is_empty() && parse_host_ip(trimmed).is_none() {
                    raw_names.insert(trimmed.to_ascii_lowercase());
                }
            } else if fact.claim.starts_with("CT log subdomains for ") {
                if let Some((_, list_part)) = fact.claim.split_once(": ") {
                    let clean_part = list_part.split(" (+").next().unwrap_or(list_part);
                    for item in clean_part.split(',') {
                        let trimmed = item.trim().trim_start_matches("*.").trim_end_matches('.');
                        if !trimmed.is_empty() && parse_host_ip(trimmed).is_none() {
                            raw_names.insert(trimmed.to_ascii_lowercase());
                        }
                    }
                }
            }
        }

        let mut domains: BTreeSet<String> = BTreeSet::new();
        let mut sub_hosts: BTreeSet<String> = BTreeSet::new();
        let mut apex_hosts: BTreeSet<String> = BTreeSet::new();

        for name in &raw_names {
            let clean = crate::evidence::sanitize(
                name.trim().trim_start_matches("*.").trim_end_matches('.'),
                160,
            )
            .to_ascii_lowercase();
            if clean.is_empty() || parse_host_ip(&clean).is_some() {
                continue;
            }
            if let Some(root) = crate::osint::root_domain(&clean) {
                let clean_root = crate::evidence::sanitize(&root, 160);
                domains.insert(clean_root.clone());
                if clean != clean_root {
                    sub_hosts.insert(clean);
                } else {
                    apex_hosts.insert(clean);
                }
            } else {
                sub_hosts.insert(clean);
            }
        }

        if sub_hosts.is_empty() {
            sub_hosts.extend(apex_hosts);
        }

        (
            domains.into_iter().collect(),
            sub_hosts.into_iter().collect(),
        )
    }

    fn host_trace_hops(
        graph: &Graph,
        host: &Host,
        geo: Option<&crate::geoip::GeoDb>,
    ) -> Vec<crate::osint::TraceHop> {
        let local_gateway = graph
            .local
            .routes
            .iter()
            .find(|r| is_default_route(r))
            .and_then(|r| r.gateway.as_deref());
        let primary_name = Self::host_primary_hostname(host);
        // The latest route, as the report shows it: a route traced again
        // is moved last (see `Graph::record`).
        let route = host
            .facts
            .iter()
            .rfind(|f| f.record.source == crate::evidence::Source::Traceroute);
        let trace_evidence = route.map(|f| f.record.evidence.as_str());
        // The trace stage says so when the target itself gave no answer:
        // then the route ends at the last hop that did.
        let unanswered = route.is_some_and(|f| {
            f.claim.starts_with("route path") && f.claim.contains("target did not answer")
        });

        let mut hops = match trace_evidence {
            Some(ev) if !ev.is_empty() => crate::osint::parse_traceroute_detailed(
                ev,
                &host.address,
                local_gateway,
                primary_name.as_deref(),
            ),
            _ => Vec::new(),
        };

        if hops.is_empty() && !host.hops.is_empty() {
            for (idx, h) in host.hops.iter().enumerate() {
                let hop_num = (idx + 1) as u8;
                let is_gw = local_gateway.is_some_and(|gw| gw == h);
                let label = if h == "*" || h == "* * *" {
                    Some("isp-transit / ICMP filtered".to_owned())
                } else if is_gw || idx == 0 {
                    Some("Local Router".to_owned())
                } else if idx == 1 {
                    Some("ISP Regional Node".to_owned())
                } else {
                    Some("ISP Backbone / Transit".to_owned())
                };
                hops.push(crate::osint::TraceHop {
                    hop: hop_num,
                    address: if h == "*" {
                        "* * *".to_owned()
                    } else {
                        h.clone()
                    },
                    label,
                    rtt_ms: None,
                });
            }
        }

        if !hops.is_empty() && !unanswered && !hops.iter().any(|h| h.address == host.address) {
            let next_hop = hops.last().map_or(1, |h| h.hop.saturating_add(1));
            hops.push(crate::osint::TraceHop {
                hop: next_hop,
                address: host.address.clone(),
                label: primary_name.or_else(|| host.asn.clone()),
                rtt_ms: None,
            });
        }

        if let Some(db) = geo {
            let total = hops.len();
            for (idx, hop) in hops.iter_mut().enumerate() {
                if hop.address == host.address {
                    if hop.label.as_deref().is_none_or(|l| l == "Target Host") {
                        if let Some(name) = Self::host_primary_hostname(host) {
                            hop.label = Some(name);
                        }
                    }
                    continue;
                }
                let Ok(ip) = hop.address.parse::<IpAddr>() else {
                    continue;
                };
                if crate::osint::is_non_public_ip(ip) {
                    continue;
                }
                let generic = hop.label.as_deref().is_none_or(|l| {
                    matches!(
                        l,
                        "ISP Regional Node" | "ISP Backbone / Transit" | "Target Host"
                    )
                });
                if !generic {
                    continue;
                }
                if let Ok(Some(place)) = db.lookup(ip) {
                    let net = place
                        .network
                        .as_deref()
                        .or_else(|| (idx + 2 >= total).then_some(host.asn.as_deref()).flatten());
                    // The place goes in a field of its own (see
                    // `describe_hop`); the role names the network.
                    hop.label = match net {
                        Some(n) => Some(crate::evidence::sanitize(n, 80)),
                        None if idx + 2 >= total => Some("Edge Node".to_owned()),
                        None => hop.label.clone(),
                    };
                }
            }
        }

        hops
    }

    /// What kind of network an address belongs to, in words.
    fn address_scope(ip: IpAddr) -> &'static str {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                let [a, b, ..] = v4.octets();
                if v4.is_loopback() {
                    "loopback"
                } else if v4.is_private() {
                    "private (RFC 1918)"
                } else if v4.is_link_local() {
                    "link-local"
                } else if a == 100 && (b & 0xc0) == 64 {
                    "carrier-grade NAT (ISP internal)"
                } else if v4.is_documentation() || (a == 198 && (b & 0xfe) == 18) {
                    "reserved (documentation / testing)"
                } else if v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified() || a >= 240
                {
                    "reserved"
                } else {
                    "public IPv4"
                }
            }
            IpAddr::V6(v6) => {
                let first = v6.segments()[0];
                if v6.is_loopback() {
                    "loopback"
                } else if (first & 0xfe00) == 0xfc00 {
                    "unique local (private IPv6)"
                } else if (first & 0xffc0) == 0xfe80 {
                    "link-local"
                } else if v6.is_multicast() || v6.is_unspecified() {
                    "reserved"
                } else if first == 0x2001 && v6.segments()[1] == 0x0db8 {
                    "reserved (documentation)"
                } else {
                    "public IPv6"
                }
            }
        }
    }

    /// Adds what is known about one traceroute hop to its map data: where
    /// its address is (from the offline location database), the network it
    /// belongs to, what kind of address it is, the latency it adds, and for
    /// the last hop what recon found about the target itself. Nothing here
    /// is looked up outside this machine.
    fn describe_hop(
        out: &mut Value,
        hop: &crate::osint::TraceHop,
        host: &Host,
        geo: Option<&crate::geoip::GeoDb>,
        previous_rtt: Option<f64>,
    ) {
        let clean = |text: &str| crate::evidence::sanitize(text, 120);
        let is_target = hop.address == host.address;
        out["is_target"] = json!(is_target);
        if let (Some(now), Some(before)) = (hop.rtt_ms, previous_rtt) {
            out["rtt_delta_ms"] = json!(((now - before) * 10.0).round() / 10.0);
        }
        let Ok(ip) = hop.address.parse::<IpAddr>() else {
            out["scope"] = json!(if hop.address.contains('*') {
                "no reply (ICMP filtered or rate-limited)"
            } else {
                "name only"
            });
            return;
        };
        out["scope"] = json!(Self::address_scope(ip));
        out["ip_version"] = json!(if ip.to_canonical().is_ipv4() { 4 } else { 6 });
        // A hop's own name, when traceroute gave one (often a router's
        // reverse DNS, which names the carrier and the city).
        if let Some(label) = hop.label.as_deref() {
            if label.contains('.') && !label.contains(' ') && label != hop.address {
                out["reverse_dns"] = json!(clean(label));
            }
        }
        if !crate::osint::is_non_public_ip(ip) {
            if let Some(Ok(Some(place))) = geo.map(|db| db.lookup(ip)) {
                out["location"] = json!({
                    "city": place.city.as_deref().map(clean),
                    "region": place.region.as_deref().map(clean),
                    "country": place.country.as_deref().map(clean),
                    "latitude": (place.latitude * 1000.0).round() / 1000.0,
                    "longitude": (place.longitude * 1000.0).round() / 1000.0,
                });
                if let Some(network) = place.network.as_deref() {
                    out["network"] = json!(clean(network));
                }
            }
        }
        if is_target {
            let mut target = json!({
                "open_ports": host.open_ports().count(),
                "hostnames": host.hostnames.iter().take(8).map(|n| clean(n)).collect::<Vec<_>>(),
            });
            for (key, value) in [
                ("asn", &host.asn),
                ("bgp_prefix", &host.bgp_prefix),
                ("country", &host.country),
                ("waf_cdn", &host.waf_cdn),
                ("os", &host.os),
            ] {
                if let Some(value) = value.as_deref().filter(|v| !v.is_empty()) {
                    target[key] = json!(clean(value));
                }
            }
            out["target"] = target;
        }
    }

    /// Elements for Cytoscape.js. Every node carries its role (which picture
    /// to draw), the reason for it and a caption; host nodes also carry the
    /// counts the map uses for highlighting.
    pub fn cytoscape(&self, graph: &Graph) -> Value {
        self.cytoscape_with_geo(graph, None)
    }

    /// Elements for Cytoscape.js, enriched with offline GeoIP city/region
    /// lookups when `geo` is available.
    pub fn cytoscape_with_geo(&self, graph: &Graph, geo: Option<&crate::geoip::GeoDb>) -> Value {
        let mut max_hop_count: usize = 0;
        let mut best_rtt_ms: Option<f64> = None;
        let mut primary_trace_hops: Vec<Value> = Vec::new();

        let mut nodes: Vec<Value> = self
            .nodes()
            .map(|node| {
                let (role, why, caption, network) = self.drawing(graph, node);
                let mut data = json!({
                    "id": crate::evidence::sanitize(&node.id, 220),
                    "label": node.label,
                    "kind": node.kind,
                    "role": role, "why": why, "caption": caption,
                });
                if let Some(network) = network {
                    data["network"] = json!(network);
                }
                // The connection kind colours a network's line on the map.
                if node.kind == NodeKind::Interface {
                    let name = node.id.strip_prefix("if:").unwrap_or(&node.id);
                    let link = graph
                        .local
                        .interfaces
                        .iter()
                        .find(|i| i.name == name)
                        .map_or("other", |i| i.kind.as_str());
                    data["link"] = json!(crate::evidence::sanitize(link, 32));
                }
                let host = node
                    .id
                    .strip_prefix("host:")
                    .and_then(|address| graph.hosts.get(address));
                if let Some(host) = host {
                    data["address"] = json!(crate::evidence::sanitize(&host.address, 200));
                    data["headline"] =
                        json!(crate::evidence::sanitize(&host_headline(graph, host), 240));
                    data["ports_line"] =
                        json!(crate::evidence::sanitize(&host_open_ports(host), 240));
                    let compact = Self::host_ports_compact(host);
                    if !compact.is_empty() {
                        data["ports_compact"] =
                            json!(crate::evidence::sanitize(&compact, 120));
                    }
                    if let Some(primary) = Self::host_primary_hostname(host) {
                        data["primary_hostname"] = json!(primary);
                    }
                    let (assoc_domains, assoc_hosts) = Self::host_associated_names(host);
                    if !assoc_domains.is_empty() {
                        data["associated_domains"] = json!(assoc_domains);
                    }
                    if !assoc_hosts.is_empty() {
                        data["associated_hosts"] = json!(assoc_hosts);
                    }
                    data["open_ports"] = json!(host.open_ports().count());
                    // CVEs, and how many are known exploited, critical or high.
                    data["cves"] = json!(host.advisories.len());
                    data["serious_cves"] = json!(host
                        .advisories
                        .iter()
                        .filter(|a| crate::cve::is_serious(a))
                        .count());
                    data["kev"] = json!(host.advisories.iter().filter(|a| a.kev).count());
                    data["reachable"] = json!(self.reachable(&host.address));
                    // Known by name only: no address, so no route to derive.
                    data["by_name"] = json!(parse_host_ip(&host.address).is_none());
                    if let Some(asn) = &host.asn {
                        data["asn"] = json!(crate::evidence::sanitize(asn, 200));
                    }
                    if let Some(bgp) = &host.bgp_prefix {
                        data["bgp_prefix"] = json!(crate::evidence::sanitize(bgp, 80));
                    }
                    if let Some(country) = &host.country {
                        data["country"] = json!(crate::evidence::sanitize(country, 32));
                    }
                    if let (Some(db), Some(ip)) = (geo, parse_host_ip(&host.address)) {
                        if let Ok(Some(place)) = db.lookup(ip) {
                            if let Some(city) = place.city.filter(|c| !c.is_empty()) {
                                data["city"] = json!(crate::evidence::sanitize(&city, 80));
                            }
                            if data.get("country").is_none() {
                                if let Some(cc) = place.country.filter(|c| !c.is_empty()) {
                                    data["country"] = json!(crate::evidence::sanitize(&cc, 32));
                                }
                            }
                        }
                    }
                    if let Some(ipv6_dns) = &host.ipv6_dns {
                        data["ipv6_dns"] = json!(crate::evidence::sanitize(ipv6_dns, 200));
                    }
                    if let Some(waf) = &host.waf_cdn {
                        data["waf_cdn"] = json!(crate::evidence::sanitize(waf, 120));
                    }
                    if !host.hops.is_empty() {
                        data["hops"] = json!(host
                            .hops
                            .iter()
                            .map(|h| crate::evidence::sanitize(h, 120))
                            .collect::<Vec<_>>());
                    }
                    let trace_hops = Self::host_trace_hops(graph, host, geo);
                    if !trace_hops.is_empty() {
                        // As far as an answer came from: the target, or the
                        // last hop when it did not answer. Its time is the
                        // target's own, or none.
                        let hop_count = trace_hops
                            .iter()
                            .rev()
                            .find(|h| h.address != "* * *")
                            .map_or(trace_hops.len(), |h| usize::from(h.hop));
                        let rtt_ms = trace_hops
                            .iter()
                            .find(|h| h.address == host.address)
                            .and_then(|h| h.rtt_ms);
                        let mut previous_rtt: Option<f64> = None;
                        let serialized_hops: Vec<Value> = trace_hops
                            .iter()
                            .map(|h| {
                                let mut hop = json!({
                                    "hop": h.hop,
                                    "address": crate::evidence::sanitize(&h.address, 80),
                                    "label": h.label.as_deref().map(|l| crate::evidence::sanitize(l, 120)),
                                    "rtt_ms": h.rtt_ms,
                                    "formatted": crate::evidence::sanitize(&h.formatted(), 200),
                                });
                                Self::describe_hop(&mut hop, h, host, geo, previous_rtt);
                                if h.rtt_ms.is_some() {
                                    previous_rtt = h.rtt_ms;
                                }
                                hop
                            })
                            .collect();
                        data["hop_count"] = json!(hop_count);
                        if let Some(ms) = rtt_ms {
                            data["rtt_ms"] = json!(ms);
                            best_rtt_ms = Some(best_rtt_ms.map_or(ms, |prev| prev.max(ms)));
                        }
                        if hop_count > max_hop_count {
                            max_hop_count = hop_count;
                            primary_trace_hops = serialized_hops.clone();
                        }
                        data["trace_hops"] = json!(serialized_hops);
                    }
                }
                json!({ "data": data })
            })
            .collect();
        let mut edges: Vec<Value> = self
            .graph
            .edge_indices()
            .filter_map(|edge| {
                let (from, to) = self.graph.edge_endpoints(edge)?;
                Some((&self.graph[from], &self.graph[to], self.graph[edge]))
            })
            .enumerate()
            .map(|(i, (from, to, kind))| {
                json!({ "data": { "id": format!("e{i}"), "source": from.id, "target": to.id, "kind": kind } })
            })
            .collect();
        // Drawing only: a host no route leads to is tied to this machine
        // with an "unknown" link so it does not float free in the layout.
        for index in self.graph.node_indices() {
            let node = &self.graph[index];
            if node.kind != NodeKind::Host {
                continue;
            }
            let attached = self
                .graph
                .edges_directed(index, petgraph::Direction::Incoming)
                .next()
                .is_some();
            if !attached {
                edges.push(json!({ "data": {
                    "id": format!("u:{}", node.id), "source": LOCAL_ID, "target": node.id, "kind": "unknown",
                } }));
            }
        }
        // Drawing only: devices the operating system already has in its
        // neighbour table (ARP, NDP) and that are not hosts yet. Reading the
        // table sends nothing. IPv4 entries first, so a device that is also
        // listed under its IPv6 address is drawn once.
        let mut neighbours: Vec<_> = graph.local.neighbors.iter().collect();
        neighbours.sort_by_key(|n| n.address.contains(':'));
        let mut seen = BTreeSet::new();
        for host in graph.hosts.values() {
            if let (Some(mac), Some(ip)) = (host.mac.as_deref(), parse_host_ip(&host.address)) {
                if let Some(route) = route_for(&graph.local, ip) {
                    seen.insert((format!("if:{}", route.interface), mac.to_lowercase()));
                }
            }
        }
        let mut drawn = 0;
        let mut hidden: BTreeMap<String, usize> = BTreeMap::new();
        for neighbour in neighbours {
            let segment = format!("if:{}", neighbour.interface);
            let Some(mac) = neighbour.mac.as_deref() else {
                continue; // never answered: nothing says it exists
            };
            if !self.index.contains_key(&segment) || !is_single_device(&neighbour.address, mac) {
                continue;
            }
            let new = seen.insert((segment.clone(), mac.to_lowercase()));
            let known = graph.hosts.contains_key(&neighbour.address)
                || self
                    .index
                    .contains_key(&format!("gw:{}", neighbour.address));
            if !new || known {
                continue;
            }
            if drawn == MAX_NEIGHBOURS {
                *hidden.entry(segment).or_default() += 1;
                continue;
            }
            drawn += 1;
            let addr = crate::evidence::sanitize(&neighbour.address, 80);
            let clean_mac = crate::evidence::sanitize(mac, 32);
            let clean_if = crate::evidence::sanitize(&neighbour.interface, 64);
            let id = format!("nb:{addr}");
            nodes.push(json!({ "data": {
                "id": id, "label": addr, "kind": "neighbour",
                "role": Role::Client, "mac": clean_mac, "interface": clean_if,
                "caption": format!("{}\n{addr}", Role::Client.title()),
                "why": "it is in this machine's neighbour table (ARP or NDP) and \
                        nothing else is known about it; nothing was sent to it",
            } }));
            edges.push(json!({ "data": {
                "id": format!("n:{addr}"), "source": segment, "target": id,
                "kind": "neighbour",
            } }));
        }
        for node in &mut nodes {
            let more = node["data"]["id"].as_str().and_then(|id| hidden.get(id));
            if let Some(more) = more {
                node["data"]["hidden_neighbours"] = json!(more);
            }
        }

        // Drawing only: a default route leads to everything else, shown as
        // the Internet cloud. Nothing is sent there to find that out.
        let defaults = self.default_routes(graph);
        if !defaults.is_empty() {
            let via: Vec<String> = defaults
                .iter()
                .map(|(_, via)| crate::evidence::sanitize(via, 120))
                .collect();
            let mut internet_data = json!({
                "id": INTERNET_ID, "label": Role::Internet.title(), "kind": "internet",
                "role": Role::Internet, "caption": Role::Internet.title(),
                "why": format!(
                    "the default route sends everything that is not local through {}",
                    via.join(" and ")
                ),
            });
            if max_hop_count > 0 {
                internet_data["hop_count"] = json!(max_hop_count);
                internet_data["trace_hops"] = json!(primary_trace_hops);
            }
            if let Some(ms) = best_rtt_ms {
                internet_data["rtt_ms"] = json!(ms);
            }
            nodes.push(json!({ "data": internet_data }));
            for (i, (target, _)) in defaults.iter().enumerate() {
                edges.push(json!({ "data": {
                    "id": format!("i{i}"), "source": INTERNET_ID, "target": target, "kind": "internet",
                } }));
            }
        }
        // Listed, not drawn: names that were only printed somewhere.
        let mentioned: Vec<Value> = graph
            .hosts
            .values()
            .filter(|host| only_mentioned(host))
            .map(|host| {
                let ports: Vec<String> = host
                    .ports
                    .keys()
                    .map(|p| crate::evidence::sanitize(p, 32))
                    .collect();
                let paths: usize = host.ports.values().map(|port| port.paths.count()).sum();
                let mut entry = json!({
                    "name": crate::evidence::sanitize(&host.address, 200),
                    "ports": ports,
                    "paths": paths
                });
                // How the name answers in DNS (the `mail-dns` stage): a name
                // only the wildcard answers for may not exist at all.
                if let Some(text) = host
                    .facts
                    .iter()
                    .rev()
                    .find_map(|fact| fact.claim.strip_prefix("DNS: "))
                {
                    let status = if text.starts_with("only the wildcard") {
                        "wildcard"
                    } else if text.starts_with("no address record") {
                        "gone"
                    } else {
                        "resolves"
                    };
                    entry["dns"] = json!(crate::evidence::sanitize(text, 200));
                    entry["dns_status"] = json!(status);
                }
                entry
            })
            .collect();
        json!({ "nodes": nodes, "edges": edges, "mentioned": mentioned })
    }

    /// A Mermaid flowchart of the topology.
    pub fn mermaid(&self) -> String {
        fn label(text: &str) -> String {
            crate::evidence::sanitize(text, 200)
                .replace('\\', "/")
                .replace('"', "'")
                .replace(['[', ']', '{', '}', '<', '>', '|', '`', '#', ';', '&'], " ")
        }
        let mut out = String::from("graph LR\n");
        let name = |index: NodeIndex| format!("n{}", index.index());
        for index in self.graph.node_indices() {
            let node = &self.graph[index];
            let (open, close) = match node.kind {
                NodeKind::Local => ("([\"", "\"])"),
                NodeKind::Interface => ("[/\"", "\"/]"),
                NodeKind::Gateway => ("{{\"", "\"}}"),
                NodeKind::Host => ("[\"", "\"]"),
            };
            out.push_str(&format!(
                "    {}{open}{}{close}\n",
                name(index),
                label(&node.label)
            ));
        }
        for edge in self.graph.edge_indices() {
            if let Some((from, to)) = self.graph.edge_endpoints(edge) {
                out.push_str(&format!(
                    "    {} -->|{}| {}\n",
                    name(from),
                    self.graph[edge],
                    name(to)
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Confidence, EvidenceRecord, Source};
    use crate::graph::{Advisory, Interface, Neighbor, Observation, Route};

    fn lab() -> Graph {
        let mut graph = Graph::default();
        let interface = |name: &str, kind: &str, up: bool, address: &str| Interface {
            name: name.into(),
            kind: kind.into(),
            up,
            addresses: if address.is_empty() {
                vec![]
            } else {
                vec![address.into()]
            },
        };
        graph.local.interfaces = vec![
            interface("lo", "loopback", true, "127.0.0.1/8"),
            interface("eth0", "ethernet", true, "192.168.1.5/24"),
            interface("wlan0", "wifi", false, ""),
            interface("tun0", "vpn", true, "10.10.14.3/23"),
            interface("docker0", "virtual", true, "172.17.0.1/16"),
        ];
        let route = |destination: &str, gateway: Option<&str>, interface: &str| Route {
            destination: destination.into(),
            gateway: gateway.map(Into::into),
            interface: interface.into(),
        };
        graph.local.routes = vec![
            route("0.0.0.0/0", Some("192.168.1.1"), "eth0"),
            route("192.168.1.0/24", None, "eth0"),
            route("10.10.14.0/23", None, "tun0"),
            route("10.10.10.0/23", Some("10.10.14.1"), "tun0"),
            route("172.17.0.0/16", None, "docker0"),
        ];
        graph.local.neighbors = vec![Neighbor {
            address: "192.168.1.77".into(),
            mac: None,
            interface: "eth0".into(),
        }];
        for (address, port) in [
            ("10.10.10.5", 80),
            ("10.10.10.9", 22),
            ("192.168.1.77", 445),
            ("192.168.1.1", 53),
        ] {
            graph.apply(Observation::Port {
                address: address.into(),
                port,
                protocol: "tcp".into(),
                state: "open".into(),
                service: Some("x".into()),
                product: Some("nginx".into()),
                version: Some("1.18.0".into()),
                extra_info: None,
                cpes: vec![],
                record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
            });
        }
        graph.apply(Observation::Path {
            address: "app.lab.local".into(),
            port: 443,
            scheme: "https".into(),
            path: "/".into(),
            status: Some(200),
            record: EvidenceRecord::observed(Source::KatanaJsonl, Confidence::High, "x"),
        });
        graph.apply(Observation::Hostname {
            address: "10.10.10.5".into(),
            hostname: "web01.lab.local".into(),
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::Medium, "x"),
        });
        graph.add_advisory(
            "10.10.10.5",
            Advisory {
                fixed_in: None,
                last_affected: None,
                id: "CVE-2021-23017".into(),
                title: "t".into(),
                severity: None,
                cvss: None,
                kev: true,
                matched: "m".into(),
                port: Some("80/tcp".into()),
                references: vec![],
                record: EvidenceRecord::observed(Source::NvdApi, Confidence::Medium, "{}"),
            },
        );
        graph
    }

    #[test]
    fn hosts_hang_off_the_interface_and_gateway_that_reach_them() {
        let graph = lab();
        let topology = Topology::build(&graph);
        let mut edges: Vec<String> = topology
            .edges()
            .iter()
            .map(|(from, to, kind)| format!("{} -{kind}-> {}", from.id, to.id))
            .collect();
        edges.sort();
        assert_eq!(
            edges,
            [
                "gw:10.10.14.1 -routed-> host:10.10.10.5",
                "gw:10.10.14.1 -routed-> host:10.10.10.9",
                // The LAN gateway is also a scanned host, so it is one node.
                "if:eth0 -gateway-> host:192.168.1.1",
                "if:eth0 -neighbour-> host:192.168.1.77",
                "if:tun0 -gateway-> gw:10.10.14.1",
                "local -interface-> if:eth0",
                "local -interface-> if:tun0",
            ]
        );
        let ids: Vec<&str> = topology.nodes().map(|n| n.id.as_str()).collect();
        assert!(
            !ids.contains(&"if:lo") && !ids.contains(&"if:wlan0") && !ids.contains(&"if:docker0")
        );
        assert!(
            ids.contains(&"host:app.lab.local"),
            "name-only hosts are shown, unattached"
        );
        let web = topology
            .nodes()
            .find(|n| n.id == "host:10.10.10.5")
            .unwrap();
        assert_eq!(web.label, "10.10.10.5 (web01.lab.local)");
        let tun = topology.nodes().find(|n| n.id == "if:tun0").unwrap();
        assert_eq!(
            (tun.kind, tun.label.as_str()),
            (NodeKind::Interface, "tun0 10.10.14.3/23")
        );

        // macOS lists the link-local address first, and can list a global
        // IPv6 address before the IPv4 one; the label, the segment and the
        // "You" caption use the IPv4 address all the same.
        let mut mac = graph.clone();
        mac.local.interfaces[1].addresses = vec![
            "fe80::aa:bb:cc:dd/64".into(),
            "2001:db8:4005:80a::200e/64".into(),
            "192.168.1.5/24".into(),
        ];
        let topology = Topology::build(&mac);
        let eth = topology.nodes().find(|n| n.id == "if:eth0").unwrap();
        assert_eq!(eth.label, "eth0 192.168.1.5/24");
        let elements = topology.cytoscape(&mac);
        let nodes = elements["nodes"].as_array().unwrap();
        let segment = nodes.iter().find(|n| n["data"]["id"] == "if:eth0").unwrap();
        assert_eq!(segment["data"]["network"], "192.168.1.0/24");
        assert_eq!(segment["data"]["caption"], "LAN eth0\n192.168.1.0/24");
        assert_eq!(nodes[0]["data"]["caption"], "You\n192.168.1.5");
    }

    #[test]
    fn reachability_follows_the_routing_table() {
        let graph = lab();
        let topology = Topology::build(&graph);
        assert!(topology.reachable("10.10.10.5"));
        assert!(topology.reachable("192.168.1.77"));
        assert!(topology.reachable("192.168.1.1"));
        assert!(!topology.reachable("app.lab.local"), "no address, no route");
        assert!(!topology.reachable("10.99.0.1"), "unknown host");

        // With the VPN down the lab hosts fall back to the default route.
        let mut down = graph.clone();
        down.local.routes.retain(|r| r.interface != "tun0");
        down.local.interfaces.retain(|i| i.name != "tun0");
        let topology = Topology::build(&down);
        let via: Vec<String> = topology
            .edges()
            .iter()
            .filter(|(_, to, _)| to.id == "host:10.10.10.5")
            .map(|(from, _, _)| from.id.clone())
            .collect();
        assert_eq!(via, ["host:192.168.1.1"]);
        // And with no routes at all nothing is reachable.
        let mut isolated = graph.clone();
        isolated.local.routes.clear();
        assert!(!Topology::build(&isolated).reachable("10.10.10.5"));
    }

    #[test]
    fn cytoscape_elements_carry_counts_for_colouring() {
        let graph = lab();
        let elements = Topology::build(&graph).cytoscape(&graph);
        let nodes = elements["nodes"].as_array().unwrap();
        let edges = elements["edges"].as_array().unwrap();
        assert_eq!(nodes.len(), 10, "nine real nodes plus the Internet cloud");
        assert_eq!(
            edges.len(),
            9,
            "seven routed links, one 'unknown' link and one to the Internet"
        );
        let unknown: Vec<&Value> = edges
            .iter()
            .filter(|e| e["data"]["kind"] == "unknown")
            .collect();
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0]["data"]["source"], "local");
        assert_eq!(unknown[0]["data"]["target"], "host:app.lab.local");
        assert_eq!(
            nodes[0]["data"],
            json!({
                "id": "local", "label": "this machine", "kind": "local",
                "role": "you", "why": "the machine meow runs on",
                "caption": "You\n192.168.1.5",
            })
        );
        let web = nodes
            .iter()
            .find(|n| n["data"]["id"] == "host:10.10.10.5")
            .unwrap();
        assert_eq!(web["data"]["kind"], "host");
        assert_eq!(web["data"]["address"], "10.10.10.5");
        assert_eq!(web["data"]["open_ports"], 1);
        assert_eq!(web["data"]["cves"], 1);
        assert_eq!(web["data"]["serious_cves"], 1);
        assert_eq!(web["data"]["kev"], 1);
        assert_eq!(web["data"]["reachable"], true);
        assert_eq!(web["data"]["by_name"], false);
        let named = nodes
            .iter()
            .find(|n| n["data"]["id"] == "host:app.lab.local")
            .unwrap();
        assert_eq!(named["data"]["reachable"], false);
        assert_eq!(named["data"]["by_name"], true);
        // Every edge joins two existing nodes.
        let ids: Vec<&str> = nodes
            .iter()
            .map(|n| n["data"]["id"].as_str().unwrap())
            .collect();
        for edge in edges {
            assert!(ids.contains(&edge["data"]["source"].as_str().unwrap()));
            assert!(ids.contains(&edge["data"]["target"].as_str().unwrap()));
        }
    }

    #[test]
    fn every_node_gets_a_picture_and_the_reason_for_it() {
        let mut graph = lab();
        let fact = |address: &str, os: &str| Observation::Host {
            address: address.into(),
            os: Some(os.into()),
            mac: None,
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::Medium, "x"),
        };
        // Seen in the neighbour table only: nothing listening is known.
        graph.apply(Observation::Hostname {
            address: "192.168.1.50".into(),
            hostname: "laptop.lan".into(),
            record: EvidenceRecord::observed(Source::LocalNet, Confidence::Medium, "x"),
        });
        graph.apply(Observation::Port {
            address: "10.10.10.40".into(),
            port: 6379,
            protocol: "tcp".into(),
            state: "unverified".into(),
            service: None,
            product: None,
            version: None,
            extra_info: None,
            cpes: vec![],
            record: EvidenceRecord::observed(Source::LogRegex, Confidence::Low, "x"),
        });
        graph.apply(fact("192.168.1.2", "pfSense 2.7 (FreeBSD 14)"));
        graph.apply(fact("192.168.1.3", "MikroTik RouterOS 7.11"));
        graph.apply(fact("192.168.1.4", "Cisco Catalyst 2960 switch"));

        let elements = Topology::build(&graph).cytoscape(&graph);
        let node = |id: &str| -> Value {
            let nodes = elements["nodes"].as_array().unwrap();
            let found = nodes.iter().find(|n| n["data"]["id"] == id);
            found.unwrap_or_else(|| panic!("no node {id}"))["data"].clone()
        };
        let drawn = |id: &str| -> (String, String) {
            let data = node(id);
            let text = |key: &str| data[key].as_str().unwrap().to_owned();
            assert!(!text("why").is_empty(), "{id} has no reason");
            (text("role"), text("caption"))
        };
        let pair = |role: &str, caption: &str| (role.to_owned(), caption.to_owned());

        assert_eq!(drawn("local"), pair("you", "You\n192.168.1.5"));
        assert_eq!(drawn("internet"), pair("internet", "Internet"));
        assert_eq!(
            drawn("if:eth0"),
            pair("segment", "LAN eth0\n192.168.1.0/24")
        );
        assert_eq!(node("if:eth0")["network"], "192.168.1.0/24");
        assert_eq!(drawn("if:tun0"), pair("segment", "VPN tun0\n10.10.14.0/23"));
        assert_eq!(drawn("gw:10.10.14.1"), pair("router", "Router\n10.10.14.1"));
        // A scanned host that is also the default gateway is the router.
        assert_eq!(
            drawn("host:192.168.1.1"),
            pair("router", "Router\n192.168.1.1")
        );
        assert_eq!(
            drawn("host:10.10.10.5"),
            pair("server", "Server\n10.10.10.5\nweb01.lab.local")
        );
        assert_eq!(
            node("host:10.10.10.5")["why"],
            "1 open port has been seen on it"
        );
        assert_eq!(
            drawn("host:192.168.1.50"),
            pair("client", "Client\n192.168.1.50\nlaptop.lan")
        );
        assert_eq!(
            drawn("host:192.168.1.2"),
            pair("firewall", "Firewall\n192.168.1.2")
        );
        assert_eq!(
            node("host:192.168.1.2")["why"],
            "its OS guess or a service banner mentions \"pfsense\""
        );
        assert_eq!(
            node("host:192.168.1.50")["why"],
            "no service has been seen on it"
        );
        // Mentioned in a log only: its port was never probed.
        assert_eq!(drawn("host:10.10.10.40").0, "server");
        assert_eq!(
            node("host:10.10.10.40")["why"],
            "a service on it was mentioned (6379/tcp) but has not been seen open"
        );
        assert_eq!(drawn("host:192.168.1.3").0, "router");
        assert_eq!(drawn("host:192.168.1.4").0, "switch");

        // The cloud hangs off the default gateway and nothing else.
        let edges = elements["edges"].as_array().unwrap();
        let internet: Vec<&Value> = edges
            .iter()
            .filter(|e| e["data"]["kind"] == "internet")
            .collect();
        assert_eq!(internet.len(), 1);
        assert_eq!(internet[0]["data"]["source"], "internet");
        assert_eq!(internet[0]["data"]["target"], "host:192.168.1.1");
        assert!(node("internet")["why"]
            .as_str()
            .unwrap()
            .ends_with("through 192.168.1.1 (eth0)"));

        // Devices from the neighbour table are drawn as clients, once each.
        let mut seen = lab();
        let neighbour = |address: &str, mac: Option<&str>| Neighbor {
            address: address.into(),
            mac: mac.map(Into::into),
            interface: "eth0".into(),
        };
        seen.local.neighbors = vec![
            neighbour("fe80::20", Some("AA:BB:CC:00:00:20")), // the same device again
            neighbour("192.168.1.20", Some("aa:bb:cc:00:00:20")),
            neighbour("192.168.1.1", Some("aa:bb:cc:00:00:01")), // already the router
            neighbour("fe80::1", Some("aa:bb:cc:00:00:01")),     // the router again
            neighbour("192.168.1.99", None),                     // never answered
            neighbour("224.0.0.251", Some("1:0:5e:0:0:fb")),     // a group, not a device
            neighbour("192.168.1.255", Some("ff:ff:ff:ff:ff:ff")),
            neighbour("fe80::30", Some("0:1c:b3:9:85:15")), // macOS drops leading zeros
            Neighbor {
                address: "172.17.0.2".into(),
                mac: Some("02:42:ac:11:00:02".into()),
                interface: "docker0".into(), // not a drawn interface
            },
        ];
        let elements = Topology::build(&seen).cytoscape(&seen);
        let nodes = elements["nodes"].as_array().unwrap();
        let drawn: Vec<&Value> = nodes
            .iter()
            .filter(|n| n["data"]["kind"] == "neighbour")
            .collect();
        let ids: Vec<&str> = drawn
            .iter()
            .map(|n| n["data"]["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["nb:192.168.1.20", "nb:fe80::30"]);
        assert_eq!(drawn[0]["data"]["role"], "client");
        assert_eq!(drawn[0]["data"]["caption"], "Client\n192.168.1.20");
        assert_eq!(drawn[0]["data"]["mac"], "aa:bb:cc:00:00:20");
        assert!(drawn[0]["data"]["why"]
            .as_str()
            .unwrap()
            .contains("nothing was sent to it"));
        let edges = elements["edges"].as_array().unwrap();
        let link = edges
            .iter()
            .find(|e| e["data"]["target"] == "nb:192.168.1.20");
        assert_eq!(link.unwrap()["data"]["source"], "if:eth0");
        // They are a drawing aid only: not hosts, not in the report graph.
        assert!(!seen.hosts.contains_key("192.168.1.20"));
        assert!(!Topology::build(&seen).mermaid().contains("192.168.1.20"));

        // A crowded segment is capped, and says how many were left out.
        seen.local.neighbors = (0..MAX_NEIGHBOURS + 5)
            .map(|i| {
                neighbour(
                    &format!("192.168.1.{}", 100 + i),
                    Some(&format!("aa:00:00:00:01:{i:02x}")),
                )
            })
            .collect();
        let elements = Topology::build(&seen).cytoscape(&seen);
        let nodes = elements["nodes"].as_array().unwrap();
        let count = nodes.iter().filter(|n| n["data"]["kind"] == "neighbour");
        assert_eq!(count.count(), MAX_NEIGHBOURS);
        let segment = nodes.iter().find(|n| n["data"]["id"] == "if:eth0").unwrap();
        assert_eq!(segment["data"]["hidden_neighbours"], 5);

        // Without a default route there is no cloud; a default route without
        // a gateway (a point-to-point link) hangs it on the interface.
        let mut isolated = graph.clone();
        isolated
            .local
            .routes
            .retain(|r| r.destination != "0.0.0.0/0");
        let elements = Topology::build(&isolated).cytoscape(&isolated);
        let ids = |elements: &Value| -> Vec<String> {
            let nodes = elements["nodes"].as_array().unwrap();
            nodes
                .iter()
                .map(|n| n["data"]["id"].as_str().unwrap().to_owned())
                .collect()
        };
        assert!(!ids(&elements).contains(&"internet".to_owned()));
        isolated.local.routes.push(Route {
            destination: "::/0".into(),
            gateway: None,
            interface: "tun0".into(),
        });
        let elements = Topology::build(&isolated).cytoscape(&isolated);
        assert!(ids(&elements).contains(&"internet".to_owned()));
        let edges = elements["edges"].as_array().unwrap();
        let link = edges.iter().find(|e| e["data"]["kind"] == "internet");
        assert_eq!(link.unwrap()["data"]["target"], "if:tun0");
    }

    #[test]
    fn names_only_printed_in_the_terminal_are_listed_not_drawn() {
        let mut graph = Graph::default();
        let printed =
            |line: &str| EvidenceRecord::observed(Source::PtyRegex, Confidence::Low, line);
        // `curl https://claude.ai/...` in the session shell.
        graph.apply(Observation::Path {
            address: "claude.ai".into(),
            port: 443,
            scheme: "https".into(),
            path: "/install.sh".into(),
            status: None,
            record: printed("curl https://claude.ai/install.sh"),
        });
        // A name that answered with a server header was looked at.
        graph.apply(Observation::Path {
            address: "app.example.test".into(),
            port: 80,
            scheme: "http".into(),
            path: "/".into(),
            status: None,
            record: printed("http://app.example.test/"),
        });
        graph.apply(Observation::Http {
            address: "app.example.test".into(),
            port: 80,
            scheme: "http".into(),
            server: Some("nginx".into()),
            location: None,
            record: EvidenceRecord::observed(
                Source::HttpHeader,
                Confidence::Medium,
                "Server: nginx",
            ),
        });
        assert!(only_mentioned(&graph.hosts["claude.ai"]));
        assert!(!only_mentioned(&graph.hosts["app.example.test"]));

        let drawn = Topology::build(&graph).cytoscape(&graph);
        let ids: Vec<&str> = drawn["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["data"]["id"].as_str().unwrap())
            .collect();
        assert!(!ids.contains(&"host:claude.ai"), "{ids:?}");
        assert!(ids.contains(&"host:app.example.test"), "{ids:?}");
        assert_eq!(
            drawn["mentioned"],
            json!([ { "name": "claude.ai", "ports": ["443/tcp"], "paths": 1 } ])
        );

        // A certificate-log name the mail-dns stage found only the wildcard
        // answers for is listed as such.
        graph.apply(Observation::Fact {
            address: "old.example.test".into(),
            port: None,
            protocol: "ip".into(),
            claim: "DNS: only the wildcard *.example.test answers for this name; it may not exist"
                .into(),
            record: EvidenceRecord::observed(Source::Dns, Confidence::High, "lookup"),
        });
        let drawn = Topology::build(&graph).cytoscape(&graph);
        let old = drawn["mentioned"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "old.example.test")
            .expect("listed");
        assert_eq!(old["dns_status"], "wildcard");
        assert!(old["dns"]
            .as_str()
            .unwrap()
            .starts_with("only the wildcard"));
        assert!(only_mentioned(&graph.hosts["old.example.test"]));
    }

    #[test]
    fn a_name_whose_dns_was_read_or_that_has_a_note_was_looked_at() {
        let mut graph = Graph::default();
        let fact = |address: &str, claim: &str, source: Source| Observation::Fact {
            address: address.into(),
            port: None,
            protocol: "ip".into(),
            claim: claim.into(),
            record: EvidenceRecord::observed(source, Confidence::High, "x"),
        };
        // A mail-only domain: no address, so the dns and mail-dns stages
        // keep what they found on the name.
        graph.apply(fact(
            "example.org",
            "CT log subdomains for example.org (1): www.example.org",
            Source::CtLog,
        ));
        assert!(only_mentioned(&graph.hosts["example.org"]));
        graph.apply(Observation::DnsSecurity {
            address: "example.org".into(),
            info: Box::new(crate::graph::DnsSecurity {
                domain: "example.org".into(),
                grade: "D".into(),
                ..crate::graph::DnsSecurity::default()
            }),
            record: EvidenceRecord::observed(Source::Dns, Confidence::High, "mail-dns"),
        });
        // Its own records, before the mail checks ran.
        graph.apply(fact(
            "mail.example.net",
            "MX record: 10 mx.example.net",
            Source::Dns,
        ));
        // The operator's note on a name nobody scanned.
        graph.apply(Observation::Note {
            address: Some("admin.example.net".into()),
            text: "default credentials work on the login page".into(),
            record: EvidenceRecord::observed(Source::ManualNote, Confidence::High, "meow note"),
        });
        // A certificate-log name, looked up in DNS: still only mentioned.
        graph.apply(fact(
            "www.example.org",
            "discovered in Certificate Transparency logs for example.org",
            Source::CtLog,
        ));
        graph.apply(fact(
            "www.example.org",
            "DNS: resolves to 192.0.2.7",
            Source::Dns,
        ));
        for looked_at in ["example.org", "mail.example.net", "admin.example.net"] {
            assert!(!only_mentioned(&graph.hosts[looked_at]), "{looked_at}");
        }
        assert!(only_mentioned(&graph.hosts["www.example.org"]));
        let drawn = Topology::build(&graph).cytoscape(&graph);
        let mentioned: Vec<&str> = drawn["mentioned"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect();
        assert_eq!(mentioned, ["www.example.org"]);
    }

    #[test]
    fn a_host_is_summed_up_as_address_type_os_version() {
        let mut graph = Graph::default();
        fn port(
            graph: &mut Graph,
            address: &str,
            number: u16,
            service: &str,
            product: &str,
            version: &str,
        ) {
            graph.apply(Observation::Port {
                address: address.into(),
                port: number,
                protocol: "tcp".into(),
                state: "open".into(),
                service: Some(service.into()),
                product: Some(product.into()),
                version: Some(version.into()),
                extra_info: None,
                cpes: vec![],
                record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
            });
        }
        // A real scan result: no OS scan, but the SSH banner
        // names the distribution and its OpenSSH version names the release.
        port(
            &mut graph,
            "10.20.30.41",
            22,
            "ssh",
            "OpenSSH",
            "9.6p1 Ubuntu 3ubuntu13.20",
        );
        port(
            &mut graph,
            "10.0.0.2",
            22,
            "ssh",
            "OpenSSH",
            "8.4p1 Debian 5+deb11u3",
        );
        port(&mut graph, "10.0.0.2", 80, "http", "nginx", "1.18.0");
        // A release this table does not know: the name, not a made-up version.
        port(
            &mut graph,
            "10.0.0.3",
            22,
            "ssh",
            "OpenSSH",
            "9.7p1 Ubuntu 7ubuntu4",
        );
        port(&mut graph, "10.0.0.4", 80, "http", "nginx", "1.24.0");
        let os = |address: &str, os: &str| Observation::Host {
            address: address.into(),
            os: Some(os.into()),
            mac: None,
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::Medium, "x"),
        };
        graph.apply(os("10.0.0.5", "Linux 5.4"));
        graph.apply(os("10.0.0.6", "Microsoft Windows 10 1809"));
        // An OS scan result wins over a banner.
        port(
            &mut graph,
            "10.0.0.5",
            22,
            "ssh",
            "OpenSSH",
            "8.2p1 Ubuntu 4ubuntu0.11",
        );

        let host = |address: &str| &graph.hosts[address];
        let guess = |address: &str| host_os(host(address)).unwrap();
        assert_eq!(
            guess("10.20.30.41"),
            OsGuess {
                name: "Ubuntu".into(),
                version: "24.04".into(),
                guessed: true
            }
        );
        assert_eq!(
            host_headline(&graph, host("10.20.30.41")),
            "10.20.30.41 -> Server -> Ubuntu -> 24.04 (OS read off a service banner)"
        );
        assert_eq!(host_open_ports(host("10.20.30.41")), "22/tcp ssh");
        assert_eq!(
            host_headline(&graph, host("10.0.0.2")),
            "10.0.0.2 -> Server -> Debian -> 11 (OS read off a service banner)"
        );
        assert_eq!(host_open_ports(host("10.0.0.2")), "22/tcp ssh, 80/tcp http");
        assert_eq!(
            host_headline(&graph, host("10.0.0.3")),
            "10.0.0.3 -> Server -> Ubuntu -> version not known (OS read off a service banner)"
        );
        assert_eq!(host_os(host("10.0.0.4")), None);
        assert_eq!(
            host_headline(&graph, host("10.0.0.4")),
            "10.0.0.4 -> Server -> OS not known -> version not known"
        );
        assert_eq!(
            host_headline(&graph, host("10.0.0.5")),
            "10.0.0.5 -> Server -> Linux -> 5.4"
        );
        assert_eq!(
            host_headline(&graph, host("10.0.0.6")),
            "10.0.0.6 -> Client -> Microsoft Windows -> 10 1809"
        );
        assert_eq!(host_open_ports(host("10.0.0.6")), "none seen open");

        // The map gets the same two lines.
        let elements = Topology::build(&graph).cytoscape(&graph);
        let nodes = elements["nodes"].as_array().unwrap();
        let node = nodes
            .iter()
            .find(|n| n["data"]["id"] == "host:10.20.30.41")
            .unwrap();
        assert_eq!(
            node["data"]["headline"],
            "10.20.30.41 -> Server -> Ubuntu -> 24.04 (OS read off a service banner)"
        );
        assert_eq!(node["data"]["ports_line"], "22/tcp ssh");
    }

    #[test]
    fn mermaid_output_is_a_valid_looking_flowchart() {
        let mut graph = lab();
        graph
            .hosts
            .get_mut("10.10.10.9")
            .unwrap()
            .hostnames
            .insert("we\"ird[x]\\".into());
        graph.local.interfaces[0].name = "lo\x1b]0;pwn\x07\\".into();
        let text = Topology::build(&graph).mermaid();
        assert!(text.starts_with("graph LR\n"));
        assert!(text.contains("    n0([\"this machine\"])\n"), "{text}");
        assert!(text.contains("[/\"tun0 10.10.14.3/23\"/]"), "{text}");
        assert!(text.contains("{{\"gateway 10.10.14.1\"}}"), "{text}");
        assert!(text.contains("-->|routed|"), "{text}");
        assert!(text.contains("10.10.10.9 (we'ird x /)"), "{text}");
        assert!(!text.contains('\\') && !text.contains('\x1b'), "{text}");
        for line in text.lines().skip(1) {
            assert!(line.starts_with("    n"), "{line}");
        }
        // An empty workspace still renders.
        assert_eq!(
            Topology::build(&Graph::default()).mermaid(),
            "graph LR\n    n0([\"this machine\"])\n"
        );
    }

    #[test]
    fn zoned_ipv6_hosts_and_dual_stack_neighbours_are_handled_cleanly() {
        let mut graph = lab();
        graph.local.routes.push(Route {
            destination: "fe80::/64".into(),
            gateway: None,
            interface: "eth0".into(),
        });
        let record = EvidenceRecord::observed(Source::NmapXml, Confidence::High, "manual");
        graph.apply(Observation::Host {
            address: "fe80::20%eth0".into(),
            os: None,
            mac: None,
            record: record.clone(),
        });
        // A known IPv4 host whose MAC also appears under an IPv6 NDP entry on
        // the same interface must not be drawn a second time as `nb:fe80::99`.
        graph.apply(Observation::Host {
            address: "192.168.1.99".into(),
            os: None,
            mac: Some("aa:bb:cc:11:22:33".into()),
            record,
        });
        graph.local.neighbors.push(Neighbor {
            address: "fe80::99".into(),
            mac: Some("AA:BB:CC:11:22:33".into()),
            interface: "eth0".into(),
        });

        let topo = Topology::build(&graph);
        assert!(!only_mentioned(&graph.hosts["fe80::20%eth0"]));
        assert!(topo.reachable("fe80::20%eth0"));
        let elements = topo.cytoscape(&graph);
        let nodes = elements["nodes"].as_array().unwrap();
        let zoned = nodes
            .iter()
            .find(|n| n["data"]["id"] == "host:fe80::20%eth0")
            .unwrap();
        assert_eq!(zoned["data"]["by_name"], false);
        assert!(
            !nodes.iter().any(|n| n["data"]["id"] == "nb:fe80::99"),
            "dual-stack NDP entry for known host MAC was drawn twice"
        );
    }

    #[test]
    fn mermaid_and_cytoscape_strip_entity_escapes_and_hidden_controls() {
        let mut graph = lab();
        graph
            .hosts
            .get_mut("10.10.10.9")
            .unwrap()
            .hostnames
            .insert("bad&quot;] click n0\u{202e}".into());
        graph.local.neighbors.push(Neighbor {
            address: "192.168.1.88".into(),
            mac: Some("aa:bb:cc:dd:ee:ff\x1b[2J".into()),
            interface: "eth0".into(),
        });
        let topo = Topology::build(&graph);
        let mermaid = topo.mermaid();
        assert!(
            !mermaid.contains('&') && !mermaid.contains('\u{202e}'),
            "{mermaid}"
        );
        let cyto = topo.cytoscape(&graph).to_string();
        assert!(
            !cyto.contains('\x1b') && !cyto.contains('\u{202e}'),
            "{cyto}"
        );
    }

    #[test]
    fn a_hop_address_is_described_in_words() {
        for (address, scope) in [
            ("192.168.1.1", "private (RFC 1918)"),
            ("100.64.0.1", "carrier-grade NAT (ISP internal)"),
            ("169.254.1.1", "link-local"),
            ("8.8.8.8", "public IPv4"),
            ("198.51.100.7", "reserved (documentation / testing)"),
            ("2600:3c01::f03c:91ff:fe18:bb2f", "public IPv6"),
            ("fd00::1", "unique local (private IPv6)"),
            ("fe80::1", "link-local"),
            ("::ffff:10.0.0.1", "private (RFC 1918)"),
        ] {
            assert_eq!(
                Topology::address_scope(address.parse().unwrap()),
                scope,
                "{address}"
            );
        }
    }

    #[test]
    fn cytoscape_includes_traceroute_hops_compact_ports_and_internet_transit_summary() {
        let mut graph = lab();
        let record = EvidenceRecord::observed(Source::NmapXml, Confidence::High, "scan");
        graph.apply(Observation::Host {
            address: "45.33.32.156".into(),
            os: Some("Linux".into()),
            mac: None,
            record: record.clone(),
        });
        graph.apply(Observation::Hostname {
            address: "45.33.32.156".into(),
            hostname: "scanme.org".into(),
            record: record.clone(),
        });
        graph.apply(Observation::Hostname {
            address: "45.33.32.156".into(),
            hostname: "scanme.nmap.org".into(),
            record: record.clone(),
        });
        for port in [22u16, 80, 9929] {
            graph.apply(Observation::Port {
                address: "45.33.32.156".into(),
                port,
                protocol: "tcp".into(),
                state: "open".into(),
                service: Some("tcp".into()),
                product: None,
                version: None,
                extra_info: None,
                cpes: Vec::new(),
                record: record.clone(),
            });
        }
        let trace_ev = "\
Hop 1: 192.168.1.1          (Local Router)                     1.8 ms
Hop 2: 173.230.159.1        (Linode Edge - Fremont, CA)       22.6 ms
Hop 3: 45.33.32.156         (scanme.nmap.org)                 23.1 ms";
        let trace_rec = EvidenceRecord::observed(Source::Traceroute, Confidence::Medium, trace_ev);
        graph.apply(Observation::HostMeta {
            address: "45.33.32.156".into(),
            asn: Some("AS63949 · Akamai / Linode".into()),
            bgp_prefix: Some("45.33.32.0/24".into()),
            country: Some("US".into()),
            ipv6_dns: None,
            waf_cdn: None,
            hops: vec!["192.168.1.1".into(), "173.230.159.1".into()],
            record: trace_rec.clone(),
        });
        graph.apply(Observation::Fact {
            address: "45.33.32.156".into(),
            port: None,
            protocol: "tcp".into(),
            claim: "route path (3 hops (23.1 ms)): 192.168.1.1 -> 173.230.159.1 -> 45.33.32.156"
                .into(),
            record: trace_rec,
        });

        let topo = Topology::build(&graph);
        let cyto = topo.cytoscape(&graph);
        let nodes = cyto["nodes"].as_array().unwrap();
        let host = nodes
            .iter()
            .find(|n| n["data"]["id"] == "host:45.33.32.156")
            .unwrap();
        assert_eq!(host["data"]["primary_hostname"], "scanme.nmap.org");
        assert_eq!(
            host["data"]["associated_domains"],
            serde_json::json!(["nmap.org", "scanme.org"])
        );
        assert_eq!(
            host["data"]["associated_hosts"],
            serde_json::json!(["scanme.nmap.org"])
        );
        assert_eq!(host["data"]["ports_compact"], "22, 80, 9929/tcp");
        assert_eq!(host["data"]["asn"], "AS63949 · Akamai / Linode");
        assert_eq!(host["data"]["hop_count"], 3);
        assert_eq!(host["data"]["rtt_ms"], 23.1);
        assert_eq!(host["data"]["trace_hops"].as_array().unwrap().len(), 3);
        // Each hop says what kind of address it is and the latency it adds;
        // the last one carries what recon found about the target.
        let hops = host["data"]["trace_hops"].as_array().unwrap();
        assert_eq!(hops[0]["scope"], "private (RFC 1918)");
        assert_eq!(hops[0]["is_target"], false);
        assert!(hops[0].get("rtt_delta_ms").is_none());
        assert_eq!(hops[1]["scope"], "public IPv4");
        assert_eq!(hops[1]["rtt_delta_ms"], 20.8);
        assert_eq!(hops[2]["is_target"], true);
        assert_eq!(hops[2]["rtt_delta_ms"], 0.5);
        assert_eq!(hops[2]["reverse_dns"], "scanme.nmap.org");
        assert_eq!(hops[2]["target"]["asn"], "AS63949 · Akamai / Linode");
        assert_eq!(hops[2]["target"]["bgp_prefix"], "45.33.32.0/24");
        assert_eq!(hops[2]["target"]["open_ports"], 3);
        // Without the location database there is no place, and no guess.
        assert!(hops.iter().all(|hop| hop.get("location").is_none()));

        let internet = nodes
            .iter()
            .find(|n| n["data"]["id"] == "internet")
            .unwrap();
        assert_eq!(internet["data"]["hop_count"], 3);
        assert_eq!(internet["data"]["rtt_ms"], 23.1);
        assert_eq!(internet["data"]["trace_hops"].as_array().unwrap().len(), 3);
    }

    /// A route whose target did not answer ends at the last hop that did:
    /// the map adds no target hop and gives no latency for the route.
    #[test]
    fn a_route_to_a_silent_target_ends_at_its_last_answer() {
        use crate::osint::TraceHop;
        let mut graph = lab();
        let hop = |hop: u8, address: &str, rtt_ms: Option<f64>| TraceHop {
            hop,
            address: address.into(),
            label: None,
            rtt_ms,
        };
        // As the trace stage writes it: four hops, then silence to hop 15.
        let lines: Vec<String> = [
            hop(1, "198.51.100.1", Some(0.5)),
            hop(2, "198.51.100.2", Some(3.1)),
            hop(3, "198.51.100.3", Some(9.9)),
            hop(4, "198.51.100.4", Some(12.4)),
            hop(5, "* * *", None),
        ]
        .iter()
        .map(TraceHop::formatted)
        .collect();
        let record =
            EvidenceRecord::observed(Source::Traceroute, Confidence::Medium, &lines.join("\n"));
        let target = "203.0.113.9";
        graph.apply(Observation::HostMeta {
            address: target.into(),
            asn: None,
            bgp_prefix: None,
            country: None,
            ipv6_dns: None,
            waf_cdn: None,
            hops: (1..=4).map(|n| format!("198.51.100.{n}")).collect(),
            record: record.clone(),
        });
        graph.apply(Observation::Fact {
            address: target.into(),
            port: None,
            protocol: "ip".into(),
            claim: "route path (4 hops, target did not answer): 198.51.100.1 -> 198.51.100.2 \
                    -> 198.51.100.3 -> 198.51.100.4"
                .into(),
            record,
        });
        let cyto = Topology::build(&graph).cytoscape(&graph);
        let nodes = cyto["nodes"].as_array().unwrap();
        let node = |id: &str| {
            nodes
                .iter()
                .find(|n| n["data"]["id"] == id)
                .unwrap_or_else(|| panic!("no {id}"))["data"]
                .clone()
        };
        for data in [node("host:203.0.113.9"), node("internet")] {
            assert_eq!(data["hop_count"], 4, "{data}");
            assert!(data.get("rtt_ms").is_none(), "{data}");
            let hops = data["trace_hops"].as_array().unwrap();
            let addresses: Vec<&str> = hops
                .iter()
                .map(|h| h["address"].as_str().unwrap())
                .collect();
            assert_eq!(
                addresses,
                [
                    "198.51.100.1",
                    "198.51.100.2",
                    "198.51.100.3",
                    "198.51.100.4",
                    "* * *"
                ]
            );
            assert!(hops.iter().all(|h| h["is_target"] == false), "{hops:?}");
        }
    }

    /// After a retest the map shows the latest route, as the report does,
    /// also when that is a route traced once before.
    #[test]
    fn a_retest_shows_the_latest_route() {
        use crate::osint::TraceHop;
        let mut graph = lab();
        let target = "192.0.2.10";
        let trace = |graph: &mut Graph, hops: &[(&str, Option<f64>)], claim: &str| {
            let lines: Vec<String> = hops
                .iter()
                .enumerate()
                .map(|(at, (address, rtt_ms))| {
                    TraceHop {
                        hop: at as u8 + 1,
                        address: (*address).into(),
                        label: None,
                        rtt_ms: *rtt_ms,
                    }
                    .formatted()
                })
                .collect();
            let record =
                EvidenceRecord::observed(Source::Traceroute, Confidence::Medium, &lines.join("\n"));
            graph.apply(Observation::HostMeta {
                address: target.into(),
                asn: None,
                bgp_prefix: None,
                country: None,
                ipv6_dns: None,
                waf_cdn: None,
                hops: hops
                    .iter()
                    .map(|(address, _)| (*address).to_owned())
                    .filter(|address| address != target && address != "* * *")
                    .collect(),
                record: record.clone(),
            });
            graph.apply(Observation::Fact {
                address: target.into(),
                port: None,
                protocol: "ip".into(),
                claim: claim.into(),
                record,
            });
        };
        let shown = |graph: &Graph| {
            let cyto = Topology::build(graph).cytoscape(graph);
            let data = cyto["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|n| n["data"]["id"] == format!("host:{target}"))
                .unwrap()["data"]
                .clone();
            let hops: Vec<String> = data["trace_hops"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h["address"].as_str().unwrap().to_owned())
                .collect();
            (data["hop_count"].clone(), data["rtt_ms"].clone(), hops)
        };
        let silent = [("198.51.100.1", Some(0.5)), ("198.51.100.2", Some(2.0))];
        let silent_claim =
            "route path (2 hops, target did not answer): 198.51.100.1 -> 198.51.100.2";
        trace(&mut graph, &silent, silent_claim);
        assert_eq!(
            shown(&graph),
            (
                json!(2),
                Value::Null,
                vec!["198.51.100.1".into(), "198.51.100.2".into()]
            )
        );
        let answered = [
            ("198.51.100.7", Some(1.0)),
            ("198.51.100.8", Some(3.0)),
            ("198.51.100.9", Some(5.0)),
            (target, Some(6.0)),
        ];
        trace(
            &mut graph,
            &answered,
            "route path (4 hops (6.0 ms)): 198.51.100.7 -> 198.51.100.8 -> 198.51.100.9 -> 192.0.2.10",
        );
        assert_eq!(
            shown(&graph),
            (
                json!(4),
                json!(6.0),
                vec![
                    "198.51.100.7".into(),
                    "198.51.100.8".into(),
                    "198.51.100.9".into(),
                    target.into()
                ]
            )
        );
        assert_eq!(
            graph.hosts[target].hops,
            ["198.51.100.7", "198.51.100.8", "198.51.100.9"]
        );
        // The first route again: it is the latest now.
        trace(&mut graph, &silent, silent_claim);
        assert_eq!(shown(&graph).2, ["198.51.100.1", "198.51.100.2"]);
        assert_eq!(graph.hosts[target].hops, ["198.51.100.1", "198.51.100.2"]);
    }
}

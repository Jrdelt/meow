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

use crate::checklist;
use crate::evidence::VerificationStatus;
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
    fn title(self) -> &'static str {
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

/// True for a neighbour-table entry that stands for one device: a resolved,
/// individual hardware address and an address that is not a group.
fn is_single_device(address: &str, mac: &str) -> bool {
    let group_mac = mac
        .split([':', '-'])
        .next()
        .and_then(|octet| u8::from_str_radix(octet, 16).ok())
        .is_none_or(|octet| octet & 1 == 1);
    let single_address = match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => !ip.is_multicast() && !ip.is_broadcast() && !ip.is_unspecified(),
        Ok(IpAddr::V6(ip)) => !ip.is_multicast() && !ip.is_unspecified(),
        Err(_) => false,
    };
    !group_mac && single_address
}

/// The role of a host and what it was derived from. Text evidence wins over
/// position: a gateway whose OS guess says it is a firewall is a firewall.
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
            label,
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
            let node = topology.node(host_id(&host.address), NodeKind::Host, host.label());
            let Ok(ip) = host.address.parse::<IpAddr>() else {
                continue; // known by name only: no route can be derived
            };
            let Some(route) = route_for(&graph.local, ip) else {
                continue;
            };
            let interface = topology.interface(graph, &route.interface);
            match &route.gateway {
                Some(gateway) => {
                    let via = topology.gateway(graph, gateway);
                    topology.edge(interface, via, "gateway");
                    topology.edge(via, node, "routed");
                }
                None => {
                    let neighbour = graph
                        .local
                        .neighbors
                        .iter()
                        .any(|n| n.address == host.address);
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
                    caption.push_str(&address);
                }
                let why = "the machine meow runs on".to_owned();
                (Role::You, why, caption, None)
            }
            NodeKind::Interface => {
                let name = node.id.strip_prefix("if:").unwrap_or(&node.id);
                let interface = graph.local.interfaces.iter().find(|i| i.name == name);
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
                let mut caption = format!("{word} {name}");
                if let Some(network) = &network {
                    caption.push('\n');
                    caption.push_str(network);
                }
                let why = format!("the network this machine is attached to through {name}");
                (Role::Segment, why, caption, network)
            }
            NodeKind::Gateway => {
                let address = node.id.strip_prefix("gw:").unwrap_or(&node.id);
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
                let mut caption = format!("{}\n{}", role.title(), host.address);
                if let Some(name) = host.hostnames.iter().find(|n| **n != host.address) {
                    caption.push('\n');
                    caption.push_str(name);
                }
                (role, why, caption, None)
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

    /// Elements for Cytoscape.js. Every node carries its role (which picture
    /// to draw), the reason for it and a caption; host nodes also carry the
    /// counts the map uses for highlighting.
    pub fn cytoscape(&self, graph: &Graph) -> Value {
        let mut nodes: Vec<Value> = self
            .nodes()
            .map(|node| {
                let (role, why, caption, network) = self.drawing(graph, node);
                let mut data = json!({
                    "id": node.id, "label": node.label, "kind": node.kind,
                    "role": role, "why": why, "caption": caption,
                });
                if let Some(network) = network {
                    data["network"] = json!(network);
                }
                let host = node
                    .id
                    .strip_prefix("host:")
                    .and_then(|address| graph.hosts.get(address));
                if let Some(host) = host {
                    let open = |status: VerificationStatus| {
                        host.advisories
                            .iter()
                            .filter(|a| a.record.verification_status == status)
                            .count()
                    };
                    data["address"] = json!(host.address);
                    data["open_ports"] = json!(host.open_ports().count());
                    data["hypotheses"] = json!(open(VerificationStatus::UnverifiedHypothesis));
                    data["confirmed"] = json!(open(VerificationStatus::Confirmed));
                    data["kev"] = json!(host.advisories.iter().any(|a| a.kev));
                    data["ready"] = json!(checklist::host_research_ready(graph, host));
                    data["reachable"] = json!(self.reachable(&host.address));
                    // Known by name only: no address, so no route to derive.
                    data["by_name"] = json!(host.address.parse::<IpAddr>().is_err());
                }
                json!({ "data": data })
            })
            .collect();
        let mut edges: Vec<Value> = self
            .edges()
            .iter()
            .enumerate()
            .map(|(i, (from, to, kind))| {
                json!({ "data": { "id": format!("e{i}"), "source": from.id, "target": to.id, "kind": kind } })
            })
            .collect();
        // Drawing only: a host no route leads to is tied to this machine
        // with an "unknown" link so it does not float free in the layout.
        for node in self.nodes().filter(|n| n.kind == NodeKind::Host) {
            let attached = self.edges().iter().any(|(_, to, _)| to.id == node.id);
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
            let id = format!("nb:{}", neighbour.address);
            nodes.push(json!({ "data": {
                "id": id, "label": neighbour.address, "kind": "neighbour",
                "role": Role::Client, "mac": mac, "interface": neighbour.interface,
                "caption": format!("{}\n{}", Role::Client.title(), neighbour.address),
                "why": "it is in this machine's neighbour table (ARP or NDP) and \
                        nothing else is known about it; nothing was sent to it",
            } }));
            edges.push(json!({ "data": {
                "id": format!("n:{}", neighbour.address), "source": segment, "target": id,
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
            let via: Vec<&str> = defaults.iter().map(|(_, via)| via.as_str()).collect();
            nodes.push(json!({ "data": {
                "id": INTERNET_ID, "label": Role::Internet.title(), "kind": "internet",
                "role": Role::Internet, "caption": Role::Internet.title(),
                "why": format!(
                    "the default route sends everything that is not local through {}",
                    via.join(" and ")
                ),
            } }));
            for (i, (target, _)) in defaults.iter().enumerate() {
                edges.push(json!({ "data": {
                    "id": format!("i{i}"), "source": INTERNET_ID, "target": target, "kind": "internet",
                } }));
            }
        }
        json!({ "nodes": nodes, "edges": edges })
    }

    /// A Mermaid flowchart of the topology.
    pub fn mermaid(&self) -> String {
        fn label(text: &str) -> String {
            text.replace('"', "'")
                .replace(['[', ']', '{', '}', '<', '>', '|', '`'], " ")
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
                id: "CVE-2021-23017".into(),
                title: "t".into(),
                severity: None,
                cvss: None,
                kev: true,
                matched: "m".into(),
                port: Some("80/tcp".into()),
                references: vec![],
                record: EvidenceRecord::hypothesis(Source::NvdApi, Confidence::Medium, "{}"),
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

        // macOS lists the link-local address first; the label and the
        // segment use the address the interface is really used with.
        let mut mac = graph.clone();
        mac.local.interfaces[1].addresses = vec![
            "fe80::1c71:9b2d:2156:23ce/64".into(),
            "192.168.1.5/24".into(),
        ];
        let topology = Topology::build(&mac);
        let eth = topology.nodes().find(|n| n.id == "if:eth0").unwrap();
        assert_eq!(eth.label, "eth0 192.168.1.5/24");
        let elements = topology.cytoscape(&mac);
        let nodes = elements["nodes"].as_array().unwrap();
        let segment = nodes.iter().find(|n| n["data"]["id"] == "if:eth0").unwrap();
        assert_eq!(segment["data"]["network"], "192.168.1.0/24");
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
        assert_eq!(web["data"]["hypotheses"], 1);
        assert_eq!(web["data"]["confirmed"], 0);
        assert_eq!(web["data"]["kev"], true);
        assert_eq!(web["data"]["ready"], true);
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
    fn mermaid_output_is_a_valid_looking_flowchart() {
        let mut graph = lab();
        graph
            .hosts
            .get_mut("10.10.10.9")
            .unwrap()
            .hostnames
            .insert("we\"ird[x]".into());
        let text = Topology::build(&graph).mermaid();
        assert!(text.starts_with("graph LR\n"));
        assert!(text.contains("    n0([\"this machine\"])\n"), "{text}");
        assert!(text.contains("[/\"tun0 10.10.14.3/23\"/]"), "{text}");
        assert!(text.contains("{{\"gateway 10.10.14.1\"}}"), "{text}");
        assert!(text.contains("-->|routed|"), "{text}");
        assert!(text.contains("10.10.10.9 (we'ird x )"), "{text}");
        for line in text.lines().skip(1) {
            assert!(line.starts_with("    n"), "{line}");
        }
        // An empty workspace still renders.
        assert_eq!(
            Topology::build(&Graph::default()).mermaid(),
            "graph LR\n    n0([\"this machine\"])\n"
        );
    }
}

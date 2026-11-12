//! The network topology as a graph: this machine, its interfaces, the
//! gateways behind them and the hosts they lead to.
//!
//! Built on demand from [`Graph`] (the evidence store) with `petgraph`, and
//! rendered three ways: Cytoscape.js elements for the browser map, Mermaid
//! for `REPORT.md`, and a reachability answer for route reasoning.

use std::collections::BTreeMap;
use std::net::IpAddr;

use petgraph::algo::has_path_connecting;
use petgraph::graph::{Graph as PetGraph, NodeIndex};
use serde::Serialize;
use serde_json::{json, Value};

use crate::checklist;
use crate::evidence::VerificationStatus;
use crate::graph::Graph;
use crate::observer::route_for;

pub const LOCAL_ID: &str = "local";

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
        let address = graph
            .local
            .interfaces
            .iter()
            .find(|i| i.name == name)
            .and_then(|i| i.addresses.first().cloned())
            .unwrap_or_default();
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
                i.up && !i.addresses.is_empty()
                    && !matches!(i.kind.as_str(), "loopback" | "virtual")
            })
            .map(|i| i.name.clone())
            .collect();
        for name in &visible {
            topology.interface(graph, name);
        }
        for route in &graph.local.routes {
            if !matches!(route.destination.as_str(), "0.0.0.0/0" | "::/0")
                || !visible.contains(&route.interface)
            {
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

    /// Elements for Cytoscape.js. Host nodes carry the counts the map uses
    /// for colouring.
    pub fn cytoscape(&self, graph: &Graph) -> Value {
        let nodes: Vec<Value> = self
            .nodes()
            .map(|node| {
                let mut data = json!({ "id": node.id, "label": node.label, "kind": node.kind });
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
        assert_eq!(nodes.len(), 9);
        assert_eq!(edges.len(), 8, "seven routed links plus one 'unknown' link");
        let unknown: Vec<&Value> = edges
            .iter()
            .filter(|e| e["data"]["kind"] == "unknown")
            .collect();
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0]["data"]["source"], "local");
        assert_eq!(unknown[0]["data"]["target"], "host:app.lab.local");
        assert_eq!(
            nodes[0]["data"],
            json!({ "id": "local", "label": "this machine", "kind": "local" })
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

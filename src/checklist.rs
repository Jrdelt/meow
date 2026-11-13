//! Progressive verification checklist for an advisory.
//!
//! An advisory matched by CVE grounding is only a hypothesis. The checklist
//! shows, step by step, what evidence exists for it, and reports when the
//! stack and route evidence is strong enough to justify grounded deep
//! research (`[R] Deep Research Ready`). The final step, the verdict, is
//! always the operator's.

use std::net::IpAddr;

use crate::evidence::{Confidence, Source, VerificationStatus};
use crate::graph::{Advisory, Graph, Host, Port};
use crate::observer::route_for;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub label: &'static str,
    pub done: bool,
    pub detail: String,
    /// Whether this step counts towards "deep research ready".
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checklist {
    pub items: Vec<Check>,
}

impl Checklist {
    /// Stack and route evidence are both sufficient.
    pub fn research_ready(&self) -> bool {
        self.items.iter().filter(|c| c.required).all(|c| c.done)
    }

    /// (steps done, steps in total)
    pub fn progress(&self) -> (usize, usize) {
        (
            self.items.iter().filter(|c| c.done).count(),
            self.items.len(),
        )
    }
}

fn check(label: &'static str, required: bool, result: Option<String>, missing: &str) -> Check {
    Check {
        label,
        done: result.is_some(),
        detail: result.unwrap_or_else(|| missing.to_owned()),
        required,
    }
}

/// A version that came from an actual probe, not a guess from the port number.
fn probed_version(port: &Port) -> Option<String> {
    let version = port.version.as_ref()?;
    let probed = port.facts.iter().any(|fact| {
        fact.record.confidence >= Confidence::Medium
            && matches!(
                fact.record.source,
                Source::NmapXml | Source::PtyRegex | Source::LogRegex
            )
    });
    let from_cpe = port
        .cpes
        .iter()
        .any(|cpe| crate::cpe::parts(cpe).is_some_and(|p| p.version.is_some()));
    (probed || from_cpe)
        .then(|| format!("{} {version}", port.product.as_deref().unwrap_or("service")))
}

/// A second, independent source that names the same product.
fn corroboration(port: &Port) -> Option<String> {
    let product = port
        .product
        .as_deref()?
        .split_whitespace()
        .next()?
        .to_ascii_lowercase();
    if product.len() < 3 {
        return None;
    }
    let mut sources: Vec<Source> = port
        .facts
        .iter()
        .filter(|fact| fact.claim.to_ascii_lowercase().contains(&product))
        .map(|fact| fact.record.source)
        .collect();
    sources.sort_unstable();
    sources.dedup();
    (sources.len() >= 2).then(|| {
        let names: Vec<&str> = sources.iter().map(|s| s.as_str()).collect();
        format!("{product} seen by {}", names.join(" and "))
    })
}

fn route_evidence(graph: &Graph, host: &Host) -> Option<String> {
    let ip: IpAddr = host.address.parse().ok()?;
    if let Some(neighbor) = graph
        .local
        .neighbors
        .iter()
        .find(|n| n.address == host.address)
    {
        return Some(format!("neighbour on {}", neighbor.interface));
    }
    let route = route_for(&graph.local, ip)?;
    Some(match &route.gateway {
        Some(gateway) => format!("via {gateway} on {}", route.interface),
        None => format!("directly connected on {}", route.interface),
    })
}

/// Builds the checklist for one advisory on one host.
pub fn for_advisory(graph: &Graph, host: &Host, advisory: &Advisory) -> Checklist {
    let port = advisory.port.as_ref().and_then(|key| host.ports.get(key));
    // Package advisories (OSV) are not tied to a port.
    let unported = advisory.port.is_none();
    let verdict = match advisory.record.verification_status {
        VerificationStatus::Confirmed => Some("Confirmed by the operator".to_owned()),
        VerificationStatus::FalsePositive => {
            Some("Marked false positive by the operator".to_owned())
        }
        _ => None,
    };
    let items = vec![
        check(
            "Service identified",
            true,
            port.and_then(|p| p.product.clone().or_else(|| p.service.clone()))
                .map(|name| format!("{name} on {}", advisory.port.as_deref().unwrap_or("?")))
                .or_else(|| {
                    unported
                        .then(|| advisory.matched.clone())
                        .filter(|m| m.starts_with("pkg:"))
                }),
            "no product or service name for the matched port",
        ),
        check(
            "Version from a probe",
            true,
            port.and_then(probed_version).or_else(|| {
                unported
                    .then(|| advisory.matched.clone())
                    .filter(|m| m.contains('@'))
            }),
            "version unknown or only guessed from the port number",
        ),
        check(
            "Second source agrees on the stack",
            false,
            port.and_then(corroboration),
            "only one source names this product",
        ),
        check(
            "Route to the host",
            true,
            route_evidence(graph, host),
            "no local route or neighbour entry covers this host",
        ),
        check(
            "Endpoint answered",
            true,
            port.filter(|p| p.is_open())
                .map(|p| format!("{} is open", p.key()))
                .or_else(|| {
                    (unported && host.open_ports().next().is_some())
                        .then(|| "host has open ports".to_owned())
                }),
            "the matched port has not been seen open",
        ),
        check(
            "Operator verdict",
            false,
            verdict,
            "still an unverified hypothesis",
        ),
    ];
    Checklist { items }
}

/// True when at least one open hypothesis on the host is ready for deep
/// research.
pub fn host_research_ready(graph: &Graph, host: &Host) -> bool {
    host.advisories
        .iter()
        .filter(|a| a.record.verification_status == VerificationStatus::UnverifiedHypothesis)
        .any(|a| for_advisory(graph, host, a).research_ready())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceRecord;
    use crate::graph::{Observation, Route};

    fn advisory(port: &str) -> Advisory {
        Advisory {
            fixed_in: None,
            last_affected: None,
            id: "CVE-2021-23017".into(),
            title: "resolver issue".into(),
            severity: None,
            cvss: None,
            kev: false,
            matched: "cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*".into(),
            port: Some(port.into()),
            references: vec![],
            record: EvidenceRecord::hypothesis(Source::NvdApi, Confidence::Medium, "{}"),
        }
    }

    fn port(method_confidence: Confidence, version: Option<&str>) -> Observation {
        Observation::Port {
            address: "10.10.10.5".into(),
            port: 80,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("http".into()),
            product: Some("nginx".into()),
            version: version.map(Into::into),
            extra_info: None,
            cpes: vec![],
            record: EvidenceRecord::observed(Source::NmapXml, method_confidence, "<port/>"),
        }
    }

    fn done(list: &Checklist) -> Vec<bool> {
        list.items.iter().map(|c| c.done).collect()
    }

    #[test]
    fn checklist_fills_in_as_evidence_arrives() {
        let mut graph = Graph::default();
        graph.apply(port(Confidence::Low, None));
        graph.add_advisory("10.10.10.5", advisory("80/tcp"));
        let list = |g: &Graph| {
            let host = &g.hosts["10.10.10.5"];
            for_advisory(g, host, &host.advisories[0])
        };

        // Only a guessed service on an open port.
        let first = list(&graph);
        assert_eq!(done(&first), [true, false, false, false, true, false]);
        assert!(!first.research_ready());
        assert_eq!(first.progress(), (2, 6));
        assert_eq!(
            first.items[3].detail,
            "no local route or neighbour entry covers this host"
        );

        // A probed version arrives.
        graph.apply(port(Confidence::High, Some("1.18.0")));
        assert_eq!(done(&list(&graph)), [true, true, false, false, true, false]);

        // The passive observer finds a route: stack + route are sufficient.
        graph.local.routes.push(Route {
            destination: "10.10.10.0/23".into(),
            gateway: Some("10.10.14.1".into()),
            interface: "tun0".into(),
        });
        let ready = list(&graph);
        assert_eq!(done(&ready), [true, true, false, true, true, false]);
        assert!(ready.research_ready());
        assert_eq!(ready.items[3].detail, "via 10.10.14.1 on tun0");
        assert!(host_research_ready(&graph, &graph.hosts["10.10.10.5"]));

        // A Server header corroborates; optional, but shown.
        graph.apply(Observation::Http {
            address: "10.10.10.5".into(),
            port: 80,
            scheme: "http".into(),
            server: Some("nginx/1.18.0".into()),
            location: None,
            record: EvidenceRecord::observed(
                Source::HttpHeader,
                Confidence::High,
                "Server: nginx/1.18.0",
            ),
        });
        let corroborated = list(&graph);
        assert!(corroborated.items[2].done);
        assert_eq!(
            corroborated.items[2].detail,
            "nginx seen by nmap_xml and http_header"
        );

        // The verdict is the operator's and closes the hypothesis.
        graph
            .set_advisory_status(
                "10.10.10.5",
                "CVE-2021-23017",
                VerificationStatus::Confirmed,
            )
            .unwrap();
        assert_eq!(list(&graph).progress(), (6, 6));
        assert!(
            !host_research_ready(&graph, &graph.hosts["10.10.10.5"]),
            "no open hypothesis is left to research"
        );
    }

    #[test]
    fn evidence_about_another_port_does_not_count() {
        let mut graph = Graph::default();
        graph.apply(port(Confidence::High, Some("1.18.0")));
        graph.add_advisory("10.10.10.5", advisory("443/tcp"));
        let host = &graph.hosts["10.10.10.5"];
        let list = for_advisory(&graph, host, &host.advisories[0]);
        assert_eq!(done(&list), [false, false, false, false, false, false]);
    }

    #[test]
    fn package_advisories_without_a_port_use_the_package_itself() {
        let mut graph = Graph::default();
        graph.apply(port(Confidence::High, Some("1.18.0")));
        let mut adv = advisory("80/tcp");
        adv.port = None;
        adv.matched = "pkg:npm/lodash@4.17.20".into();
        graph.add_advisory("10.10.10.5", adv);
        graph.local.neighbors.push(crate::graph::Neighbor {
            address: "10.10.10.5".into(),
            mac: None,
            interface: "eth0".into(),
        });
        let host = &graph.hosts["10.10.10.5"];
        let list = for_advisory(&graph, host, &host.advisories[0]);
        assert!(list.research_ready(), "{list:?}");
        assert_eq!(list.items[3].detail, "neighbour on eth0");
    }
}

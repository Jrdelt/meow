//! Stages that scan with `nmap` and look up what they found: `ports`, `udp`,
//! `services` and `cves`.

use super::*;

pub(crate) async fn ports(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let stage = cx.stage;
    let settings = cx.settings.clone();
    let preset = cx.preset.clone();
    let limits = cx.limits;
    let privileged = cx.privileged;
    let out = |suffix: &str| cx.out(suffix);
    let (command, notices) = ports_command(
        &settings,
        &preset,
        target,
        &split_recon_flags(&task.extra_flags).ports,
        privileged,
        &out(".xml"),
    );
    for notice in notices {
        state.notice(notice);
    }
    let outcome = cx
        .run_tool(&command, OutputKind::NmapXml, |seen| seen)
        .await;
    if outcome == RunOutcome::Stopped {
        remove_regular_file(&command.output);
        return Ok(StageEnd::ModeChanged);
    }
    if !matches!(outcome, RunOutcome::Exited(Some(0))) {
        remove_regular_file(&command.output);
        bail!(describe_failure(&command.program, &outcome, limits));
    }
    let (answered, observations) = read_scan_with_up(&command.output)?;
    let found = Found::of(&observations, target);
    found.save(&state.db_lock(), task.id, stage)?;
    let (changed, _) = record(state, observations, None);
    let silent = if answered == Some(0) {
        discovery_hint(&task.extra_flags)
    } else {
        String::new()
    };
    Ok(StageEnd::Done(format!(
        "{} hosts up, {} open ports ({changed} new facts){silent}",
        found.up,
        found.open_ports()
    )))
}

pub(crate) async fn udp(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let settings = cx.settings.clone();
    let mode = cx.mode;
    let limits = cx.limits;
    let privileged = cx.privileged;
    let out = |suffix: &str| cx.out(suffix);
    if mode != Mode::Aggressive {
        return Ok(StageEnd::Skipped(
            "UDP scanning runs only in aggressive mode: it is slow and needs root".to_owned(),
        ));
    }
    if !privileged {
        return Ok(StageEnd::Skipped(format!(
            "UDP scanning needs root (nmap -sU sends raw packets): start the session with sudo, or run `sudo nmap -sU -sV -p {UDP_PORTS} {target}` and `meow add` its XML"
        )));
    }
    // A host as named; a network only where the TCP scan found hosts.
    let targets: Vec<String> = match target {
        Target::Host(_) => vec![target.to_string()],
        Target::Network(_) => Found::load(&state.db_lock(), task.id, Stage::Ports, target)
            .hosts
            .keys()
            .take(16)
            .cloned()
            .collect(),
    };
    if targets.is_empty() {
        return Ok(StageEnd::Skipped(
            "no host in the range answered the TCP scan".to_owned(),
        ));
    }
    let ipv6 = match target {
        Target::Host(host) => host.ip().is_some_and(|ip| ip.is_ipv6()),
        Target::Network(network) => network.is_ipv6(),
    };
    let command = udp_command(&settings, &targets, ipv6, &out(".xml"));
    let outcome = cx
        .run_tool(&command, OutputKind::NmapXml, |seen| seen)
        .await;
    if outcome == RunOutcome::Stopped {
        remove_regular_file(&command.output);
        return Ok(StageEnd::ModeChanged);
    }
    if outcome == RunOutcome::NotInstalled {
        return Ok(StageEnd::Skipped(install_hint(&command.program)));
    }
    if !matches!(outcome, RunOutcome::Exited(Some(0))) {
        remove_regular_file(&command.output);
        bail!(describe_failure(&command.program, &outcome, limits));
    }
    let (_, mut observations) = read_scan_with_up(&command.output)?;
    Found::of(&observations, target).save(&state.db_lock(), task.id, cx.stage)?;
    let (mut open, mut maybe) = (0usize, 0usize);
    let mut notes = Vec::new();
    for observation in &observations {
        if let Observation::Port {
            address,
            port,
            protocol,
            state: port_state,
            ..
        } = observation
        {
            if protocol != "udp" {
                continue;
            }
            if port_state == "open" {
                open += 1;
                if let Some(note) = udp_note(*port) {
                    notes.push(Observation::Fact {
                        address: address.clone(),
                        port: Some(*port),
                        protocol: "udp".to_owned(),
                        claim: format!("UDP {port} open: {note}"),
                        record: crate::evidence::EvidenceRecord::observed(
                            crate::evidence::Source::NmapXml,
                            crate::evidence::Confidence::High,
                            &format!("nmap -sU: {port}/udp open"),
                        ),
                    });
                }
            } else if port_state.contains("open") {
                maybe += 1;
            }
        }
    }
    observations.extend(notes);
    let (changed, _) = record(state, observations, None);
    Ok(StageEnd::Done(format!(
        "{open} UDP services answered, {maybe} open|filtered (no answer, so maybe open) ({changed} new facts)"
    )))
}

pub(crate) async fn services(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let stage = cx.stage;
    let settings = cx.settings.clone();
    let preset = cx.preset.clone();
    let limits = cx.limits;
    let privileged = cx.privileged;
    let out = |suffix: &str| cx.out(suffix);
    // The ports the port inventory of this task found open.
    let inventory = Found::load(&state.db_lock(), task.id, Stage::Ports, target);
    let hosts: Vec<(String, Vec<u16>)> = inventory
        .hosts
        .iter()
        .map(|(address, ports)| (address.clone(), ports.clone()))
        .take(MAX_HOSTS_PER_STAGE)
        .collect();
    if hosts.is_empty() {
        return Ok(StageEnd::Skipped("no open TCP ports to inspect".to_owned()));
    }
    let mut seen = Vec::new();
    let mut changed = 0;
    for (index, (address, ports)) in hosts.iter().enumerate() {
        let (command, notices) = services_command(
            &settings,
            &preset,
            &split_recon_flags(&task.extra_flags),
            address,
            ports,
            privileged,
            &out(&format!("_{index}.xml")),
        );
        if index == 0 {
            for notice in notices {
                state.notice(notice);
            }
        }
        // One scan per host: which host it is on, and how far nmap says
        // that scan is.
        let of_hosts = |seen: Progress| match hosts.len() {
            1 => seen,
            total => Progress {
                done: Some(index as u64),
                total: Some(total as u64),
                ..seen
            },
        };
        cx.report(of_hosts(Progress::default()));
        let outcome = cx.run_tool(&command, OutputKind::NmapXml, of_hosts).await;
        if outcome == RunOutcome::Stopped {
            remove_regular_file(&command.output);
            return Ok(StageEnd::ModeChanged);
        }
        if !matches!(outcome, RunOutcome::Exited(Some(0))) {
            remove_regular_file(&command.output);
            bail!(describe_failure(&command.program, &outcome, limits));
        }
        let observations = read_scan(&command.output)?;
        seen.extend(observations.iter().cloned());
        changed += record(state, observations, None).0;
    }
    // What the probes called a web or SSH server, on ports the inventory
    // found open: that is where the next stages go.
    let mut probed = Found::of(&seen, target);
    probed.hosts = inventory.hosts.clone();
    probed
        .checked(target)
        .save(&state.db_lock(), task.id, stage)?;
    Ok(StageEnd::Done(format!(
        "{} hosts inspected ({changed} new facts)",
        hosts.len()
    )))
}

pub(crate) async fn cves(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let same_mode = || cx.same_mode();
    if !state.cve_enabled() {
        return Ok(StageEnd::Skipped(
            "CVE lookups are disabled in config.toml".to_owned(),
        ));
    }
    // What this task's own scans found is looked up now and in full. The
    // rest of the target is known from terminal text or imports, which
    // anyone can write: looked up later, and only so much.
    let own = own_ports(state, task.id, target);
    let mut candidate_addrs: BTreeSet<String> = own.keys().cloned().collect();
    for host in hosts_in_target(&state.graph(), target) {
        candidate_addrs.insert(host.address);
    }
    let mut versioned_hosts = Vec::new();
    let mut backport_obs = Vec::new();
    {
        let graph = state.graph();
        for addr in &candidate_addrs {
            let Some(host) = graph.hosts.get(addr) else {
                continue;
            };
            let has_versions = host
                .ports
                .values()
                .any(|p| p.state == "open" && (p.product.is_some() || !p.cpes.is_empty()));
            if has_versions {
                versioned_hosts.push(addr.clone());
                for (port_key, port) in &host.ports {
                    if port.state != "open" {
                        continue;
                    }
                    if let Some(note) = crate::cve::backport_note_for(host, Some(port_key)) {
                        backport_obs.push(Observation::Fact {
                            address: addr.clone(),
                            port: Some(port.number),
                            protocol: port.protocol.clone(),
                            claim: format!("Distro backporting note: {note}"),
                            record: crate::evidence::EvidenceRecord::observed(
                                crate::evidence::Source::NmapXml,
                                crate::evidence::Confidence::High,
                                format!(
                                    "{} {} {}",
                                    port.product.as_deref().unwrap_or(""),
                                    port.version.as_deref().unwrap_or(""),
                                    port.extra_info.as_deref().unwrap_or("")
                                )
                                .trim(),
                            ),
                        });
                    }
                }
            }
        }
    }
    if versioned_hosts.is_empty() {
        return Ok(StageEnd::Skipped(
            "no service CPEs or product/version banners to query".to_owned(),
        ));
    }
    let (mut changed, _) = record(state, backport_obs, None);
    let mut added_total = 0usize;
    let own_hosts: Vec<(&String, &BTreeSet<String>)> = versioned_hosts
        .iter()
        .filter_map(|addr| Some((addr, own.get(addr)?)))
        .collect();
    for (index, (addr, ports)) in own_hosts.iter().copied().enumerate() {
        if !same_mode() {
            return Ok(StageEnd::ModeChanged);
        }
        cx.progress(index, own_hosts.len());
        let asked = crate::cve::Asked::Recon(ports.clone());
        if let Some((merged, _kev, _errs)) = state.ground_host_for(addr, asked).await {
            added_total += merged.added;
            changed += merged.added;
        }
    }
    for addr in versioned_hosts
        .iter()
        .filter(|addr| !own.contains_key(*addr))
    {
        state.request_grounding(addr, crate::cve::Asked::Text);
    }
    let total: usize = {
        let graph = state.graph();
        versioned_hosts
            .iter()
            .filter_map(|addr| graph.hosts.get(addr))
            .map(|h| h.advisories.len())
            .sum()
    };
    Ok(StageEnd::Done(format!(
        "{added_total} new CVEs, {total} in all ({changed} new facts)"
    )))
}

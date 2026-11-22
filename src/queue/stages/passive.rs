//! Stages that read this machine or ask public services: `lan`, `dns`, `asn`,
//! `subdomains`, `mail-dns` and `trace`.

use super::*;

pub(crate) async fn lan(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let targets = state.graph().target_ips();
    let tools = state.tools().clone();
    let local =
        tokio::task::spawn_blocking(move || crate::observer::observe_with(&tools, &targets))
            .await
            .context("local ARP/NDP sweep failed")?;
    if state.is_closing() {
        // Cut short with the session: not what the tables hold.
        return Ok(StageEnd::ModeChanged);
    }
    let neighbors = local.neighbors.len();
    let routes = local.routes.len();
    let changed = {
        let mut graph = state.graph();
        let before = graph.local.neighbors.len() + graph.local.routes.len();
        let diff = graph.local.neighbors != local.neighbors
            || graph.local.routes != local.routes
            || graph.local.interfaces != local.interfaces;
        graph.local = local;
        if diff {
            (neighbors + routes).saturating_sub(before).max(1)
        } else {
            0
        }
    };
    if changed > 0 {
        state.mark_dirty();
    }
    Ok(StageEnd::Done(format!(
        "{neighbors} neighbours, {routes} routes in ARP/NDP cache ({changed} new facts)"
    )))
}

pub(crate) async fn dns(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let stage = cx.stage;
    let same_mode = || cx.same_mode();
    if let Target::Network(net) = target {
        return Ok(StageEnd::Skipped(format!(
            "network range {net} does not have a single DNS target"
        )));
    }
    // The family the port scan takes for a name: IPv6 with `-6`.
    let ipv6 = split_recon_flags(&task.extra_flags).ipv6();
    let (observations, ips, summary) = match crate::osint::run_dns(target, ipv6).await {
        Ok(res) => res,
        Err(err) => return Ok(StageEnd::Skipped(format!("DNS lookup unavailable: {err}"))),
    };
    if !same_mode() {
        return Ok(StageEnd::ModeChanged);
    }
    let mut cnames = Vec::new();
    for obs in &observations {
        if let Observation::Fact { claim, .. } = obs {
            if let Some(cname) = claim.strip_prefix("CNAME record: ") {
                cnames.push(cname.to_owned());
            }
        }
    }
    let found = Found {
        primary: crate::osint::primary_address(&ips, ipv6),
        ips,
        cnames,
        ..Found::default()
    }
    .checked(target);
    found.save(&state.db_lock(), task.id, stage)?;
    let (changed, _) = record(state, observations, None);
    Ok(StageEnd::Done(format!("{summary} ({changed} new facts)")))
}

pub(crate) async fn asn(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let same_mode = || cx.same_mode();
    let ips = resolve_target_ips(state, task.id, target).await;
    if !same_mode() {
        return Ok(StageEnd::ModeChanged);
    }
    if ips.is_empty() {
        return Ok(StageEnd::Skipped(
            "no resolved IP address to query ASN".to_owned(),
        ));
    }
    if ips.iter().all(|ip| crate::osint::is_non_public_ip(*ip)) {
        return Ok(StageEnd::Skipped(
            "private, loopback, or reserved IP range has no public ASN".to_owned(),
        ));
    }
    let ip_strings: Vec<String> = ips.iter().map(ToString::to_string).collect();
    let (observations, summary) =
        match crate::osint::run_asn(&ip_strings, Some(state.geo_db())).await {
            Ok(res) => res,
            Err(err) => {
                return Ok(StageEnd::Skipped(format!(
                    "ASN/RDAP lookup unavailable: {err}"
                )))
            }
        };
    if observations.is_empty() {
        return Ok(StageEnd::Skipped(summary));
    }
    let (changed, _) = record(state, observations, None);
    Ok(StageEnd::Done(format!("{summary} ({changed} new facts)")))
}

pub(crate) async fn subdomains(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let same_mode = || cx.same_mode();
    let Target::Host(HostAddr::Name(domain)) = target else {
        return Ok(StageEnd::Skipped(
            "target is an IP or CIDR, not a domain name".to_owned(),
        ));
    };
    let dns_found = Found::load(&state.db_lock(), task.id, Stage::Dns, target);
    let primary_address = dns_found.primary.unwrap_or_else(|| domain.clone());
    // Decided as for mail-dns: any address of the name that is not public,
    // or a name only a local network knows.
    let internal = crate::osint::is_internal_target(domain, &dns_found.ips).await;
    let ran = crate::osint::run_subdomains(domain, &primary_address, internal).await;
    let (observations, summary) = match ran {
        Ok(res) => res,
        Err(err) => {
            return Ok(StageEnd::Skipped(format!(
                "crt.sh query unavailable: {err}"
            )))
        }
    };
    if !same_mode() {
        return Ok(StageEnd::ModeChanged);
    }
    let (changed, _) = record(state, observations, None);
    Ok(StageEnd::Done(format!("{summary} ({changed} new facts)")))
}

pub(crate) async fn mail_dns(cx: &Ctx<'_>) -> Result<StageEnd> {
    match crate::osint::build_http_client(Duration::from_secs(6)) {
        Ok(client) => mail_dns_with(cx, crate::osint::Resolver::system(client)).await,
        Err(err) => Ok(StageEnd::Skipped(format!("DNS lookups unavailable: {err}"))),
    }
}

/// The `mail-dns` stage, with `resolver` for its questions.
pub(crate) async fn mail_dns_with(
    cx: &Ctx<'_>,
    resolver: crate::osint::Resolver,
) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let same_mode = || cx.same_mode();
    let Target::Host(HostAddr::Name(domain)) = target else {
        return Ok(StageEnd::Skipped(
            "target is an IP or CIDR, not a domain name".to_owned(),
        ));
    };
    let dns_found = Found::load(&state.db_lock(), task.id, Stage::Dns, target);
    let primary_address = dns_found.primary.clone().unwrap_or_else(|| domain.clone());
    // The names the certificate logs gave, to see which really resolve.
    let ct_names: Vec<String> = state
        .graph()
        .hosts
        .values()
        .filter(|host| {
            host.facts
                .iter()
                .any(|fact| fact.record.source == crate::evidence::Source::CtLog)
        })
        .map(|host| host.address.clone())
        .collect();
    // An internal target's questions stay on this machine's resolvers.
    let internal = crate::osint::internal_target_addresses(domain, &dns_found.ips).await;
    // How many questions it will ask depends on the answers: said as it goes.
    let asked = |answered: usize| {
        cx.report(Progress {
            done: Some(answered as u64),
            note: Some(match answered {
                1 => "1 lookup so far".to_owned(),
                n => format!("{n} lookups so far"),
            }),
            ..Progress::default()
        });
    };
    let ran = while_same_mode(
        &same_mode,
        crate::maildns::run_on_counted(
            resolver,
            domain,
            &primary_address,
            &ct_names,
            internal.as_deref(),
            asked,
        ),
    )
    .await;
    let (observations, summary) = match ran {
        None => return Ok(StageEnd::ModeChanged),
        Some(Ok(res)) => res,
        Some(Err(err)) => return Ok(StageEnd::Skipped(format!("DNS lookups unavailable: {err}"))),
    };
    // Nothing answered: the summary says why.
    if observations.is_empty() {
        return Ok(StageEnd::Skipped(summary));
    }
    register_mail_dns(&mut state.vault(), &observations);
    let (changed, _) = record(state, observations, None);
    Ok(StageEnd::Done(format!("{summary} ({changed} new facts)")))
}

/// Puts what the `mail-dns` stage found into the vault, before it goes into
/// the graph. The facts quote the records whole, but the graph keeps a part
/// of a long one: the names in them are registered from the record as it
/// was found, so a fact never names one the vault does not know.
pub(crate) fn register_mail_dns(vault: &mut crate::vault::Vault, observations: &[Observation]) {
    for observation in observations {
        if let Observation::DnsSecurity { info, .. } = observation {
            vault.register_dns_security(info);
        }
    }
}

pub(crate) async fn trace(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let same_mode = || cx.same_mode();
    // The address the port scan went to, which comes first; for a name it
    // did not reach, the one it would scan (IPv4 unless `-6`).
    let ips = resolve_target_ips(state, task.id, target).await;
    let ipv6 = split_recon_flags(&task.extra_flags).ipv6();
    let Some(resolved_ip) = ips
        .iter()
        .find(|ip| ip.is_ipv6() == ipv6)
        .or(ips.first())
        .copied()
    else {
        return Ok(StageEnd::Skipped(
            "no target IP resolved for traceroute".to_owned(),
        ));
    };
    if !same_mode() {
        return Ok(StageEnd::ModeChanged);
    }
    let local_gateway = state
        .graph()
        .local
        .routes
        .iter()
        .filter_map(|r| {
            if r.destination == "default" || r.destination == "0.0.0.0/0" || r.destination == "::/0"
            {
                r.gateway.as_ref()
            } else {
                None
            }
        })
        .find(|gw| {
            gw.parse::<std::net::IpAddr>()
                .is_ok_and(|g| g.is_ipv4() == resolved_ip.is_ipv4())
        })
        .cloned();
    let ip_str = resolved_ip.to_string();
    let traced = while_same_mode(
        &same_mode,
        crate::osint::run_trace(state.tools(), &ip_str, local_gateway.as_deref()),
    )
    .await;
    let (observations, summary) = match traced {
        None => return Ok(StageEnd::ModeChanged),
        Some(Ok(res)) => res,
        Some(Err(err)) => return Ok(StageEnd::Skipped(format!("traceroute unavailable: {err}"))),
    };
    // No hop: the summary says so.
    if observations.is_empty() {
        return Ok(StageEnd::Skipped(summary));
    }
    let (changed, _) = record(state, observations, None);
    Ok(StageEnd::Done(format!("{summary} ({changed} new facts)")))
}

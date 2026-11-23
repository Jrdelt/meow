//! Stages on web and remote-login services: `headers`, `waf-cdn`, `tls-audit`,
//! `ssh-audit`, `js`, `crawl` and `dirs`.

use super::*;

pub(crate) async fn headers(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let stage = cx.stage;
    let same_mode = || cx.same_mode();
    let probed = load_probed(state, task.id, target);
    if probed.web.is_empty() {
        return Ok(StageEnd::Skipped(
            "no HTTP or HTTPS port is open".to_owned(),
        ));
    }
    let host_header = match target {
        Target::Host(HostAddr::Name(name)) => Some(name.as_str()),
        _ => None,
    };
    let mut observations = Vec::new();
    let mut waf = BTreeMap::new();
    let mut inspected = 0usize;
    let total = probed.web.len().min(MAX_URLS_PER_STAGE);
    for (index, (address, port, https)) in probed.web.iter().take(total).enumerate() {
        if !same_mode() {
            return Ok(StageEnd::ModeChanged);
        }
        cx.progress(index, total);
        let inspected_now = while_same_mode(
            &same_mode,
            crate::osint::inspect_web_endpoint(address, host_header, *port, *https),
        )
        .await;
        let Some(inspected_now) = inspected_now else {
            return Ok(StageEnd::ModeChanged);
        };
        if let Ok((obs, detected_waf, _summary)) = inspected_now {
            if let Some(detected) = detected_waf {
                waf.insert(address.clone(), detected);
            }
            inspected += 1;
            observations.extend(obs);
        }
    }
    let mut saved = probed.clone();
    saved.waf = waf;
    saved
        .checked(target)
        .save(&state.db_lock(), task.id, stage)?;
    if inspected == 0 && observations.is_empty() {
        return Ok(StageEnd::Skipped(
            "no HTTP response received from open web ports".to_owned(),
        ));
    }
    let (changed, _) = record(state, observations, None);
    Ok(StageEnd::Done(format!(
        "{inspected} web endpoints inspected ({changed} new facts)"
    )))
}

pub(crate) async fn waf_cdn(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let stage = cx.stage;
    let (dns_found, headers_found) = {
        let db = state.db_lock();
        (
            Found::load(&db, task.id, Stage::Dns, target),
            Found::load(&db, task.id, Stage::Headers, target),
        )
    };
    // Outside the block above: it takes the database lock itself, and that
    // lock is not re-entrant.
    let probed = load_probed(state, task.id, target);
    let mut target_hosts: BTreeSet<String> = probed.hosts.keys().cloned().collect();
    // Of a name's addresses, the one the scan goes to: the others were not
    // looked at, and a verdict on each made each a host.
    target_hosts.extend(dns_found.primary.iter().cloned());
    for host in hosts_in_target(&state.graph(), target) {
        target_hosts.insert(host.address);
    }
    if target_hosts.is_empty() && dns_found.cnames.is_empty() {
        return Ok(StageEnd::Skipped(
            "no resolved hosts or web endpoints to inspect".to_owned(),
        ));
    }
    let cname_waf = crate::osint::detect_waf_from_cnames(&dns_found.cnames);
    let mut observations = Vec::new();
    let mut waf_map = headers_found.waf.clone();
    for address in &target_hosts {
        let existing = waf_map
            .get(address)
            .cloned()
            .or_else(|| state.graph().host(address).and_then(|h| h.waf_cdn.clone()))
            .or_else(|| cname_waf.clone());
        if let Some(provider) = existing {
            waf_map.insert(address.clone(), provider.clone());
            let record = crate::evidence::EvidenceRecord::observed(
                crate::evidence::Source::WafCdn,
                crate::evidence::Confidence::High,
                &format!("{address} -> {provider}"),
            );
            observations.push(Observation::HostMeta {
                address: address.clone(),
                asn: None,
                bgp_prefix: None,
                country: None,
                ipv6_dns: None,
                waf_cdn: Some(provider.clone()),
                hops: Vec::new(),
                record: record.clone(),
            });
            observations.push(Observation::Fact {
                address: address.clone(),
                port: None,
                protocol: "ip".to_owned(),
                claim: format!("WAF/CDN active: {provider}"),
                record,
            });
        } else {
            observations.push(Observation::Fact {
                address: address.clone(),
                port: None,
                protocol: "ip".to_owned(),
                claim: "no blocking WAF/CDN signature detected in CNAMEs or HTTP headers"
                    .to_owned(),
                record: crate::evidence::EvidenceRecord::observed(
                    crate::evidence::Source::WafCdn,
                    crate::evidence::Confidence::Medium,
                    address,
                ),
            });
        }
    }
    let mut saved = probed;
    saved.waf = waf_map.clone();
    saved
        .checked(target)
        .save(&state.db_lock(), task.id, stage)?;
    let (changed, _) = record(state, observations, None);
    let summary = if waf_map.is_empty() {
        "no blocking WAF/CDN detected".to_owned()
    } else {
        let providers: BTreeSet<&str> = waf_map.values().map(String::as_str).collect();
        format!(
            "detected {}",
            providers.into_iter().collect::<Vec<_>>().join(", ")
        )
    };
    Ok(StageEnd::Done(format!("{summary} ({changed} new facts)")))
}

pub(crate) async fn tls_audit(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let same_mode = || cx.same_mode();
    let probed = load_probed(state, task.id, target);
    let mut tls_targets: Vec<(String, u16)> = Vec::new();
    for (addr, port, https) in &probed.web {
        if (*https || matches!(*port, 443 | 8443))
            && !tls_targets.iter().any(|(a, p)| a == addr && *p == *port)
        {
            tls_targets.push((addr.clone(), *port));
        }
    }
    for (addr, ports) in &probed.hosts {
        for &port in ports {
            if matches!(port, 443 | 8443)
                && !tls_targets.iter().any(|(a, p)| a == addr && *p == port)
            {
                tls_targets.push((addr.clone(), port));
            }
        }
    }
    if tls_targets.is_empty() {
        return Ok(StageEnd::Skipped(
            "no TLS/HTTPS port (443/8443) is open".to_owned(),
        ));
    }
    let host_header = match target {
        Target::Host(HostAddr::Name(name)) => Some(name.as_str()),
        _ => None,
    };
    let mut observations = Vec::new();
    let mut audited = 0usize;
    let total = tls_targets.len().min(MAX_URLS_PER_STAGE);
    for (index, (address, port)) in tls_targets.iter().take(total).enumerate() {
        if !same_mode() {
            return Ok(StageEnd::ModeChanged);
        }
        cx.progress(index, total);
        let Some(audit) = while_same_mode(
            &same_mode,
            crate::osint::run_tls_audit(state.tools(), address, host_header, *port),
        )
        .await
        else {
            return Ok(StageEnd::ModeChanged);
        };
        if let Ok((obs, _summary)) = audit {
            if !obs.is_empty() {
                audited += 1;
                observations.extend(obs);
            }
        }
    }
    if audited == 0 && observations.is_empty() {
        return Ok(StageEnd::Skipped(
            "TLS handshake did not complete on open HTTPS ports".to_owned(),
        ));
    }
    let (changed, _) = record(state, observations, None);
    Ok(StageEnd::Done(format!(
        "{audited} TLS endpoints audited ({changed} new facts)"
    )))
}

pub(crate) async fn ssh_audit(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let same_mode = || cx.same_mode();
    let probed = load_probed(state, task.id, target);
    let mut ssh_targets = probed.ssh.clone();
    for (addr, ports) in &probed.hosts {
        for &port in ports {
            if port == 22 && !ssh_targets.iter().any(|(a, p)| a == addr && *p == port) {
                ssh_targets.push((addr.clone(), port));
            }
        }
    }
    if ssh_targets.is_empty() {
        return Ok(StageEnd::Skipped("no open SSH port".to_owned()));
    }
    let mut observations = Vec::new();
    let mut audited = 0usize;
    let total = ssh_targets.len().min(MAX_HOSTS_PER_STAGE);
    for (index, (address, port)) in ssh_targets.iter().take(total).enumerate() {
        if !same_mode() {
            return Ok(StageEnd::ModeChanged);
        }
        cx.progress(index, total);
        let Some(audit) =
            while_same_mode(&same_mode, crate::osint::audit_ssh_port(address, *port)).await
        else {
            return Ok(StageEnd::ModeChanged);
        };
        if let Ok((obs, _summary)) = audit {
            if !obs.is_empty() {
                audited += 1;
                observations.extend(obs);
            }
        }
    }
    if audited == 0 && observations.is_empty() {
        return Ok(StageEnd::Skipped(
            "no SSH-2.0 KEXINIT received from open SSH ports".to_owned(),
        ));
    }
    let (changed, _) = record(state, observations, None);
    Ok(StageEnd::Done(format!(
        "{audited} SSH endpoints audited ({changed} new facts)"
    )))
}

pub(crate) async fn js(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let mode = cx.mode;
    let same_mode = || cx.same_mode();
    let probed = load_probed(state, task.id, target);
    if probed.web.is_empty() {
        return Ok(StageEnd::Skipped(
            "no HTTP or HTTPS port is open".to_owned(),
        ));
    }
    let host_header = match target {
        Target::Host(HostAddr::Name(name)) => Some(name.as_str()),
        _ => None,
    };
    let max_files = if mode == Mode::Aggressive { 40 } else { 15 };
    let (mut files, mut endpoints_found, mut keys_found) = (0usize, 0usize, 0usize);
    let mut observations = Vec::new();
    let total = probed.web.len().min(MAX_URLS_PER_STAGE);
    for (index, (address, port, https)) in probed.web.iter().take(total).enumerate() {
        if files >= max_files {
            break;
        }
        cx.progress(index, total);
        let paths: Vec<String> = {
            let graph = state.graph();
            graph
                .host(address)
                .and_then(|host| host.ports.get(&format!("{port}/tcp")))
                .map(|p| crate::webfp::script_paths(p, max_files - files))
                .unwrap_or_default()
        };
        if paths.is_empty() {
            continue;
        }
        let fetched = while_same_mode(
            &same_mode,
            crate::osint::fetch_scripts(
                address,
                host_header,
                *port,
                *https,
                &paths,
                2 * 1024 * 1024,
            ),
        )
        .await;
        let Some(fetched) = fetched else {
            return Ok(StageEnd::ModeChanged);
        };
        let Ok(scripts) = fetched else {
            continue;
        };
        let mut endpoints = Vec::new();
        let mut secrets = Vec::new();
        for (path, source) in &scripts {
            files += 1;
            // Read before the vault is taken: a script can be megabytes.
            let found = crate::webfp::extract_endpoints(source, 60);
            let keys = crate::webfp::find_secrets(source);
            let (facts, kept, named) =
                script_facts(&mut state.vault(), address, *port, path, &found, keys);
            observations.extend(facts);
            endpoints_found += found.len();
            endpoints.extend(named);
            keys_found += kept.len();
            secrets.extend(kept);
        }
        if !endpoints.is_empty() || !secrets.is_empty() {
            observations.push(Observation::WebMeta {
                address: address.clone(),
                port: *port,
                http: Box::new(crate::graph::HttpInfo {
                    scheme: if *https { "https" } else { "http" }.to_owned(),
                    js_endpoints: endpoints,
                    js_secrets: secrets,
                    ..crate::graph::HttpInfo::default()
                }),
                record: js_evidence("JavaScript files of the site"),
            });
        }
    }
    if files == 0 {
        return Ok(StageEnd::Skipped(
            "no JavaScript files of the site's own were found (by the page or the crawl)"
                .to_owned(),
        ));
    }
    let (changed, _) = record(state, observations, None);
    Ok(StageEnd::Done(format!(
        "{files} scripts read: {endpoints_found} endpoints, {keys_found} exposed keys ({changed} new facts)"
    )))
}

fn js_evidence(text: &str) -> crate::evidence::EvidenceRecord {
    crate::evidence::EvidenceRecord::observed(
        crate::evidence::Source::JsScan,
        crate::evidence::Confidence::Medium,
        text,
    )
}

/// The facts one script file of the site at `address:port` gives: the
/// `endpoints` it names and the `keys` found in it, then the keys and the
/// endpoints as the graph keeps them. Both go into the vault first. The
/// graph keeps 150 endpoints a port, but a fact names each file's first ones
/// whatever it keeps, and a fact goes to the model too: every endpoint's
/// host is registered. A key is kept only as its placeholder, also where an
/// endpoint names it (see [`crate::webfp::kept_endpoint`]).
pub(crate) fn script_facts(
    vault: &mut crate::vault::Vault,
    address: &str,
    port: u16,
    path: &str,
    endpoints: &[String],
    keys: Vec<(&'static str, String)>,
) -> (Vec<Observation>, Vec<crate::graph::JsSecret>, Vec<String>) {
    let registered: Vec<(String, String)> = keys
        .iter()
        .map(|(_, value)| {
            (
                value.clone(),
                vault.register(crate::vault::Kind::Sec, value),
            )
        })
        .collect();
    let mut kept: Vec<String> = Vec::new();
    for endpoint in endpoints {
        if let Some(endpoint) = crate::webfp::kept_endpoint(endpoint, &registered) {
            if !kept.contains(&endpoint) {
                kept.push(endpoint);
            }
        }
    }
    let endpoints = kept;
    for endpoint in &endpoints {
        vault.register_url(endpoint);
    }
    let fact = |claim: String, evidence: String| Observation::Fact {
        address: address.to_owned(),
        port: Some(port),
        protocol: "tcp".to_owned(),
        claim,
        record: js_evidence(&evidence),
    };
    let mut facts = Vec::new();
    if !endpoints.is_empty() {
        let shown: Vec<&str> = endpoints.iter().take(12).map(String::as_str).collect();
        let more = endpoints.len().saturating_sub(12);
        facts.push(fact(
            format!(
                "JavaScript {path} names {} endpoints: {}{}",
                endpoints.len(),
                shown.join(", "),
                if more > 0 {
                    format!(" (+{more} more)")
                } else {
                    String::new()
                }
            ),
            format!("GET {path}"),
        ));
    }
    let mut secrets = Vec::new();
    for ((kind, value), (_, token)) in keys.into_iter().zip(registered) {
        // No hint at the key in the fact: facts go to the model, which gets
        // a key by its placeholder only. The hint stays with the key, for
        // the map and the report.
        facts.push(fact(
            format!("exposed {kind} in {path}: kept in the vault as {token}"),
            format!("GET {path}: {kind} {token}"),
        ));
        secrets.push(crate::graph::JsSecret {
            kind: kind.to_owned(),
            preview: crate::webfp::preview(kind, &value),
            token,
            file: path.to_owned(),
        });
    }
    (facts, secrets, endpoints)
}

/// `412 results so far`, and which site it is on when there are several.
pub(crate) fn results_note(found: u64, site: usize, sites: usize) -> String {
    let results = match found {
        1 => "1 result so far".to_owned(),
        n => format!("{n} results so far"),
    };
    match sites {
        0 | 1 => results,
        _ => format!("site {} of {sites}, {results}", site + 1),
    }
}

pub(crate) async fn crawl_or_dirs(cx: &Ctx<'_>) -> Result<StageEnd> {
    let state = cx.state;
    let task = cx.task;
    let target = cx.target;
    let stage = cx.stage;
    let settings = cx.settings.clone();
    let mode = cx.mode;
    let preset = cx.preset.clone();
    let limits = cx.limits;
    let out = |suffix: &str| cx.out(suffix);
    // The web servers the service inventory of this task found, or
    // without one, those the port inventory named.
    let probed = load_probed(state, task.id, target);
    // What a crawl may add to: the addresses being crawled, and the
    // name the user asked for. Not a name a server gave itself.
    let mut names: Names = probed.hosts.keys().cloned().collect();
    if let Target::Host(HostAddr::Name(name)) = target {
        names.insert(name.to_ascii_lowercase());
    }
    let waf_found = {
        let db = state.db_lock();
        let mut w = Found::load(&db, task.id, Stage::WafCdn, target).waf;
        for (k, v) in Found::load(&db, task.id, Stage::Headers, target).waf {
            w.entry(k).or_insert(v);
        }
        w
    };
    let mut skipped_waf: Vec<String> = Vec::new();
    let urls: Vec<String> = probed
        .web
        .iter()
        .filter(|(address, _, _)| {
            if stage == Stage::Dirs && mode == Mode::Mild {
                if let Some(provider) = waf_found
                    .get(address)
                    .cloned()
                    .or_else(|| state.graph().host(address).and_then(|h| h.waf_cdn.clone()))
                {
                    skipped_waf.push(format!("{address} ({provider})"));
                    return false;
                }
            }
            true
        })
        .map(|(address, port, https)| {
            crate::endpoint::web_origin(if *https { "https" } else { "http" }, address, *port)
        })
        .take(MAX_URLS_PER_STAGE)
        .collect();
    if urls.is_empty() {
        if !skipped_waf.is_empty() {
            return Ok(StageEnd::Skipped(format!(
                "skipped directory brute-forcing in mild mode behind WAF/CDN: {}",
                skipped_waf.join(", ")
            )));
        }
        return Ok(StageEnd::Skipped(
            "no HTTP or HTTPS port is open".to_owned(),
        ));
    }
    let wordlist = match stage {
        Stage::Dirs => match find_wordlist(
            settings.wordlist_path.as_deref(),
            settings.wordlist_dir.as_deref(),
        ) {
            Some(path) => Some(path),
            None => {
                let own = settings
                    .wordlist_dir
                    .as_ref()
                    .map(|dir| format!("put a .txt wordlist in {}, or ", dir.display()))
                    .unwrap_or_default();
                return Ok(StageEnd::Skipped(format!(
                    "no wordlist found: run `meow tools`, {own}set recon.wordlist_path in config.toml"
                )));
            }
        },
        _ => None,
    };
    let mut changed = 0;
    let mut elsewhere = Names::new();
    // The results the tool wrote for the sites before this one.
    let mut found_before = 0u64;
    for (index, url) in urls.iter().enumerate() {
        let output = out(&format!("_{index}.jsonl"));
        let command = match &wordlist {
            Some(wordlist) => dirs_command(&settings, &preset, url, wordlist, &output),
            None => crawl_command(&settings, &preset, url, &output),
        };
        let found_here = std::sync::atomic::AtomicU64::new(0);
        let so_far = |seen: Progress| {
            let here = seen.done.unwrap_or(0);
            found_here.store(here, std::sync::atomic::Ordering::Relaxed);
            let found = found_before + here;
            Progress {
                done: Some(found),
                note: Some(results_note(found, index, urls.len())),
                ..Progress::default()
            }
        };
        cx.report(so_far(Progress::default()));
        let outcome = cx.run_tool(&command, OutputKind::JsonLines, &so_far).await;
        found_before += found_here.load(std::sync::atomic::Ordering::Relaxed);
        match outcome {
            RunOutcome::NotInstalled => {
                return Ok(StageEnd::Skipped(install_hint(&command.program)))
            }
            RunOutcome::Failed(reason) => bail!(reason),
            // JSON Lines stay valid when a run is cut short, so keep
            // whatever was written before a limit was hit.
            _ => {}
        }
        let mut url_added = 0usize;
        if std::fs::symlink_metadata(&command.output).is_ok() {
            match read_lines(&command.output) {
                Ok(observations) => {
                    let (added, dropped) = record(state, observations, Some(&names));
                    url_added = added;
                    changed += added;
                    elsewhere.extend(dropped);
                }
                // Said, not swallowed: the stage did not see what
                // its tool found.
                Err(error) => state.notice(format!(
                    "recon {}: the output of {} could not be read: {error:#}",
                    task.target, command.program
                )),
            }
        }
        if outcome == RunOutcome::Stopped {
            return Ok(StageEnd::ModeChanged);
        }
        if matches!(
            outcome,
            RunOutcome::TimedOut | RunOutcome::OutputCapExceeded | RunOutcome::Exited(None)
        ) || (matches!(outcome, RunOutcome::Exited(Some(code)) if code != 0) && url_added == 0)
        {
            state.notice(describe_failure(&command.program, &outcome, limits));
        }
    }
    let left_out = match elsewhere.len() {
        0 => String::new(),
        1 => "; links to 1 other site left out".to_owned(),
        n => format!("; links to {n} other sites left out"),
    };
    Ok(StageEnd::Done(format!(
        "{} sites covered ({changed} new facts{left_out})",
        urls.len()
    )))
}

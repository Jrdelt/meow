//! Route hops and latency: the `trace` stage.

use super::*;

// ---------------------------------------------------------------------------
// 4. Lightweight Traceroute (`trace` task)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceHop {
    pub hop: u8,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

impl TraceHop {
    pub fn formatted(&self) -> String {
        let label = self
            .label
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("({s})"))
            .unwrap_or_default();
        let rtt = match self.rtt_ms {
            Some(ms) => format!("{ms:.1} ms"),
            None => "—".to_owned(),
        };
        format!(
            "Hop {}: {:<18} {:<32} {}",
            self.hop, self.address, label, rtt
        )
        .trim_end()
        .to_owned()
    }
}

/// Parses structured traceroute hops (including RTT latency in `ms`, hostnames/labels,
/// and `* * *` ICMP-filtered hops) from `traceroute`, `tracepath`, or `tracert` output.
pub fn parse_traceroute_detailed(
    text: &str,
    target_ip: &str,
    local_gateway: Option<&str>,
    target_hostname: Option<&str>,
) -> Vec<TraceHop> {
    let mut hops: Vec<TraceHop> = Vec::new();
    let mut consecutive_stars = 0usize;

    let expanded = text.replace(" | Hop ", "\nHop ").replace(" Hop ", "\nHop ");

    for line in expanded.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("traceroute")
            || trimmed.starts_with("Tracing")
            || trimmed.starts_with("over a maximum")
            || trimmed.starts_with("Trace complete")
            || trimmed.starts_with("Resume:")
        {
            continue;
        }
        let normalized = trimmed
            .strip_prefix("Hop ")
            .or_else(|| trimmed.strip_prefix("hop "))
            .unwrap_or(trimmed);
        let paren_label = normalized.find('(').and_then(|start| {
            let rest = &normalized[start + 1..];
            let end = rest.find(')')?;
            let inside = rest[..end].trim();
            (inside.parse::<IpAddr>().is_err() && !inside.is_empty()).then(|| sanitize(inside, 80))
        });
        let tokens: Vec<&str> = normalized.split_whitespace().collect();
        let Some(first) = tokens.first() else {
            continue;
        };
        let hop_str = first.trim_end_matches(':');
        let Ok(hop_num) = hop_str.parse::<u8>() else {
            continue;
        };
        if hop_num == 0 {
            continue;
        }

        let mut found_ip: Option<String> = None;
        let mut found_host: Option<String> = paren_label;
        let mut found_rtt: Option<f64> = None;

        for (idx, &tok) in tokens.iter().enumerate().skip(1) {
            let lower = tok.to_ascii_lowercase();
            if lower == "ms" && idx > 1 {
                let prev = tokens[idx - 1].trim_start_matches('<');
                if let Ok(val) = prev.parse::<f64>() {
                    if val.is_finite() && val >= 0.0 {
                        found_rtt = Some((val * 10.0).round() / 10.0);
                    }
                }
                continue;
            }
            if let Some(ms_prefix) = lower.strip_suffix("ms") {
                let clean_num = ms_prefix.trim_start_matches('<');
                if let Ok(val) = clean_num.parse::<f64>() {
                    if val.is_finite() && val >= 0.0 {
                        found_rtt = Some((val * 10.0).round() / 10.0);
                        continue;
                    }
                }
            }
            let clean_tok = tok.trim_matches(['(', ')', '[', ']', ',']);
            if found_ip.is_none() {
                if let Ok(ip) = IpAddr::from_str(clean_tok) {
                    found_ip = Some(ip.to_canonical().to_string());
                    continue;
                }
            }
            if found_ip.is_none()
                && found_host.is_none()
                && clean_tok != "*"
                && clean_tok != "no"
                && clean_tok != "reply"
                && (clean_tok.contains('.') || clean_tok.contains('-'))
                && clean_tok.parse::<f64>().is_err()
            {
                found_host = Some(sanitize(clean_tok, 80));
            }
        }

        if let Some(ip) = found_ip {
            consecutive_stars = 0;
            if hops.iter().any(|h| h.address == ip) {
                continue;
            }
            let is_local_gw = local_gateway.is_some_and(|gw| gw == ip)
                || (hop_num == 1 && IpAddr::from_str(&ip).is_ok_and(is_non_public_ip));
            let label = if is_local_gw {
                Some(
                    found_host
                        .filter(|h| h != &ip)
                        .unwrap_or_else(|| "Local Router".to_owned()),
                )
            } else if ip == target_ip {
                target_hostname
                    .map(|h| sanitize(h, 80))
                    .or_else(|| found_host.filter(|h| h != &ip))
                    .or_else(|| Some("Target Host".to_owned()))
            } else if let Some(h) = found_host.filter(|h| h != &ip) {
                Some(h)
            } else if hop_num == 2 {
                Some("ISP Regional Node".to_owned())
            } else {
                Some("ISP Backbone / Transit".to_owned())
            };

            hops.push(TraceHop {
                hop: hop_num,
                address: ip.clone(),
                label,
                rtt_ms: found_rtt,
            });
            if ip == target_ip {
                break;
            }
        } else if trimmed.contains('*') || trimmed.contains("no reply") {
            consecutive_stars += 1;
            if consecutive_stars <= 2 {
                hops.push(TraceHop {
                    hop: hop_num,
                    address: "* * *".to_owned(),
                    label: Some("isp-transit / ICMP filtered".to_owned()),
                    rtt_ms: None,
                });
            }
        }
    }

    // Trim trailing `* * *` hops if the target never answered ICMP/UDP at the tail.
    while hops.last().is_some_and(|h| h.address == "* * *") && hops.len() > 1 {
        let prev_is_star = hops
            .get(hops.len().saturating_sub(2))
            .is_some_and(|h| h.address == "* * *");
        if prev_is_star {
            hops.pop();
        } else {
            break;
        }
    }

    hops
}

async fn measure_tcp_rtt_ms(ip: IpAddr) -> Option<f64> {
    for port in [80u16, 443, 22] {
        let addr = SocketAddr::new(ip, port);
        let start = tokio::time::Instant::now();
        if let Ok(Ok(_stream)) =
            tokio::time::timeout(Duration::from_millis(1500), TcpStream::connect(addr)).await
        {
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            return Some((ms * 10.0).round() / 10.0);
        }
    }
    None
}

/// How long the `trace` stage's tools may run in all. Each is told to fit
/// in it (see [`trace_commands`]); one that does not is stopped, and the
/// hops it printed by then are kept.
pub const TRACE_TIMEOUT: Duration = Duration::from_secs(50);

/// The programs that find the route to `ip`, in the order they are tried,
/// with their arguments: at most 15 hops and no name lookups. The ones that
/// probe one hop after another (BSD traceroute, `tracert`, `tracepath`)
/// wait for each silent hop, so their waits are short enough for 15 of
/// them to fit in [`TRACE_TIMEOUT`].
pub fn trace_commands(ip: &str) -> Vec<(&'static str, Vec<String>)> {
    #[cfg(unix)]
    let commands: [(&str, &[&str]); 2] = [
        // One probe a hop, 1 s for its answer: 15 s at most.
        ("traceroute", &["-n", "-q", "1", "-w", "1", "-m", "15"]),
        // Up to three tries of 1 s a hop: 45 s at most.
        ("tracepath", &["-n", "-m", "15"]),
    ];
    // Three probes a hop, 0.5 s each: 22.5 s at most.
    #[cfg(windows)]
    let commands: [(&str, &[&str]); 1] = [("tracert", &["-d", "-h", "15", "-w", "500"])];
    commands
        .iter()
        .map(|(program, args)| {
            let args = args.iter().map(|arg| (*arg).to_owned());
            (*program, args.chain([ip.to_owned()]).collect())
        })
        .collect()
}

/// Runs a lightweight traceroute (`traceroute`, `tracepath`, or `tracert`) to
/// `target_ip` for at most [`TRACE_TIMEOUT`], as one of the session's
/// `tools`: it ends with the session. Only what the tool reported is kept:
/// no observations when it gave no hop, and the summary says so.
pub async fn run_trace(
    tools: &Tracker,
    target_ip: &str,
    local_gateway: Option<&str>,
) -> Result<(Vec<Observation>, String)> {
    let Ok(ip) = IpAddr::from_str(target_ip) else {
        bail!("invalid IP address '{target_ip}' for traceroute");
    };
    let ip = ip.to_canonical();
    let installed: Vec<(std::path::PathBuf, Vec<String>)> = trace_commands(&ip.to_string())
        .into_iter()
        .filter_map(|(program, args)| Some((crate::tools::find_program(program)?, args)))
        .collect();
    trace_with(tools, ip, local_gateway, &installed, TRACE_TIMEOUT).await
}

/// [`run_trace`] with the `commands` that are installed, tried in order,
/// for at most `timeout` in all.
pub(super) async fn trace_with(
    tools: &Tracker,
    ip: IpAddr,
    local_gateway: Option<&str>,
    commands: &[(std::path::PathBuf, Vec<String>)],
    timeout: Duration,
) -> Result<(Vec<Observation>, String)> {
    let ip_str = ip.to_string();
    let answered = |hops: &[TraceHop]| hops.iter().any(|h| h.address != "* * *");

    let deadline = tokio::time::Instant::now() + timeout;
    let mut raw_out = String::new();
    let mut tool_ran = false;
    for (bin, args) in commands {
        let mut cmd = tokio::process::Command::new(bin);
        cmd.args(args);
        configure_osint_command(&mut cmd);
        let Ok((child, group)) = tools.spawn(&mut cmd) else {
            continue;
        };
        tool_ran = true;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(printed) = read_bounded(child, group, 128 * 1024, left).await else {
            continue;
        };
        raw_out = printed.text;
        // Out of time: no other tool gets to start.
        if printed.timed_out || answered(&parse_traceroute_detailed(&raw_out, &ip_str, None, None))
        {
            break;
        }
    }
    if !tool_ran {
        bail!("traceroute/tracepath is not installed");
    }

    let detailed = parse_traceroute_detailed(&raw_out, &ip_str, local_gateway, None);
    let Some(last) = detailed.iter().rev().find(|h| h.address != "* * *") else {
        return Ok((Vec::new(), "traceroute gave no hops".to_owned()));
    };
    let reached = last.address == ip_str;
    let hops: Vec<String> = detailed
        .iter()
        .filter(|h| h.address != "* * *" && h.address != ip_str)
        .map(|h| h.address.clone())
        .collect();
    let mut chain = hops.clone();
    let rtt = if reached {
        chain.push(ip_str.clone());
        last.rtt_ms
            .map(|ms| format!(" ({ms:.1} ms)"))
            .unwrap_or_default()
    } else {
        // Its round trip, if a connection to it can be timed, is said to
        // be that and nothing more.
        match measure_tcp_rtt_ms(ip).await {
            Some(ms) => format!(", target did not answer; TCP connect {ms:.1} ms"),
            None => ", target did not answer".to_owned(),
        }
    };
    let claim = format!(
        "route path ({} hops{rtt}): {}",
        last.hop,
        chain.join(" -> ")
    );
    let formatted_lines: Vec<String> = detailed.iter().map(TraceHop::formatted).collect();
    let ev = sanitize(&formatted_lines.join("\n"), 1200);
    let observations = vec![
        Observation::HostMeta {
            address: ip_str.clone(),
            asn: None,
            bgp_prefix: None,
            country: None,
            ipv6_dns: None,
            waf_cdn: None,
            hops: hops.clone(),
            record: EvidenceRecord::observed(Source::Traceroute, Confidence::Medium, &ev),
        },
        Observation::Fact {
            address: ip_str,
            port: None,
            protocol: "ip".to_owned(),
            claim,
            record: EvidenceRecord::observed(Source::Traceroute, Confidence::Medium, &ev),
        },
    ];
    let summary = format!("{} intermediate hops", hops.len());
    Ok((observations, summary))
}

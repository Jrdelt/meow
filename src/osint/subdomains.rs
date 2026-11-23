//! Subdomains from Certificate Transparency logs: the `subdomains` stage (`crt.sh`).

use super::*;

// ---------------------------------------------------------------------------
// 3. Certificate Transparency Subdomains (`subdomains` task)
// ---------------------------------------------------------------------------

/// Extracts the registrable root domain for Certificate Transparency queries
/// (e.g., `app.staging.example.co.uk` -> `example.co.uk`, `scanme.nmap.org` -> `nmap.org`).
pub fn root_domain(hostname: &str) -> Option<String> {
    let Some(HostAddr::Name(clean)) = HostAddr::parse(hostname) else {
        return None;
    };
    let labels: Vec<&str> = clean.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    const MULTI_PART_TLDS: &[&str] = &[
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
        "ne.jp", "or.jp", "com.br", "com.mx", "co.za", "co.in", "com.sg", "com.hk",
    ];
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if labels.len() >= 3 && MULTI_PART_TLDS.contains(&last_two.as_str()) {
        Some(format!("{}.{last_two}", labels[labels.len() - 3]))
    } else {
        Some(last_two)
    }
}

/// Parses a `crt.sh` JSON array, deduplicating `name_value` and `common_name`,
/// ignoring wildcards (`*.`), validating suffix match on `root`, and capping at `limit`.
pub fn parse_crtsh_json(json_text: &str, root: &str, limit: usize) -> Result<Vec<String>> {
    let root = root.trim().trim_end_matches('.').to_ascii_lowercase();
    let suffix = format!(".{root}");
    let entries: Value = serde_json::from_str(json_text).context("invalid crt.sh JSON")?;
    let Some(array) = entries.as_array() else {
        bail!("crt.sh response is not a JSON array");
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in array {
        for field in ["name_value", "common_name"] {
            let Some(val) = item.get(field).and_then(Value::as_str) else {
                continue;
            };
            for line in val.lines() {
                let candidate = line.trim().trim_end_matches('.').to_ascii_lowercase();
                if candidate.is_empty() || candidate.contains('*') {
                    continue;
                }
                let Some(HostAddr::Name(valid)) = HostAddr::parse(&candidate) else {
                    continue;
                };
                if valid != root && !valid.ends_with(&suffix) {
                    continue;
                }
                if seen.insert(valid.clone()) {
                    out.push(valid);
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// The certificate log asked about public names.
pub const CRT_SH: &str = "https://crt.sh/";

/// Queries `<crt_sh>?q=%25.<root_domain>&output=json` passively (the
/// public log is [`CRT_SH`]). `internal`: the target is internal (see
/// [`is_internal_target`]), and nothing about it is sent. What is found is
/// recorded on `primary_address`.
pub async fn run_subdomains_at(
    crt_sh: &str,
    domain: &str,
    primary_address: &str,
    internal: bool,
) -> Result<(Vec<Observation>, String)> {
    let Some(root) = root_domain(domain) else {
        bail!("'{domain}' has no registrable root domain");
    };
    // A public log knows only public names; an internal one is not sent.
    if internal || !may_ask_public_services(&root) {
        bail!("'{domain}' is an internal name; it is not sent to crt.sh");
    }
    let client = build_http_client(Duration::from_secs(10))?;
    let query = format!("%.{root}");
    let resp = client
        .get(crt_sh)
        .query(&[("q", query.as_str()), ("output", "json")])
        .send()
        .await
        .context("crt.sh request failed")?;
    if !resp.status().is_success() {
        bail!("crt.sh answered HTTP {}", resp.status());
    }
    let bytes = read_bytes_bounded(resp, MAX_CRTSH_BYTES).await?;
    let text = String::from_utf8_lossy(&bytes);
    let names = parse_crtsh_json(&text, &root, MAX_SUBDOMAINS)?;

    let mut observations = Vec::new();
    if !names.is_empty() {
        let preview: Vec<&str> = names.iter().take(10).map(String::as_str).collect();
        let more = if names.len() > 10 {
            format!(" (+{} more)", names.len() - 10)
        } else {
            String::new()
        };
        let claim = format!(
            "CT log subdomains for {root} ({}): {}{more}",
            names.len(),
            preview.join(", ")
        );
        observations.push(Observation::Fact {
            address: primary_address.to_owned(),
            port: None,
            protocol: "ip".to_owned(),
            claim,
            record: EvidenceRecord::observed(
                Source::CtLog,
                Confidence::Medium,
                &format!("crt.sh query %.{root} -> {} hostnames", names.len()),
            ),
        });
        // Surface up to 15 sibling hostnames as unverified/mentioned entries without scanning them.
        for sibling in names.iter().filter(|n| *n != domain).take(15) {
            observations.push(Observation::Fact {
                address: sibling.clone(),
                port: None,
                protocol: "ip".to_owned(),
                claim: format!("discovered in Certificate Transparency logs for {root}"),
                record: EvidenceRecord::observed(
                    Source::CtLog,
                    Confidence::Medium,
                    &format!("crt.sh name_value: {sibling}"),
                ),
            });
        }
    }
    let summary = format!("{} subdomains for {root}", names.len());
    Ok((observations, summary))
}

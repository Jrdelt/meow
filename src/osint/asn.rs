//! ASN, BGP prefix and provider: the `asn` stage (Team Cymru DNS, RDAP, offline GeoIP).

use super::*;

// ---------------------------------------------------------------------------
// 2. ASN (`asn` task) — Team Cymru DNS + RDAP + offline GeoDb fallback
// ---------------------------------------------------------------------------

/// Parses a Team Cymru origin TXT record:
/// `"63949 | 45.33.32.0/24 | US | arin | 2010-02-02"`
pub fn parse_cymru_origin(txt: &str) -> Option<(u32, Option<String>, Option<String>)> {
    let parts: Vec<&str> = txt
        .trim()
        .trim_matches('"')
        .split('|')
        .map(str::trim)
        .collect();
    if parts.is_empty() {
        return None;
    }
    // Sometimes multiple origin ASNs are space-separated ("63949 12345"); take the first.
    let asn_str = parts[0].split_whitespace().next()?.trim_start_matches("AS");
    let asn = asn_str.parse::<u32>().ok()?;
    let prefix = parts
        .get(1)
        .map(|s| sanitize(s, 64))
        .filter(|s| !s.is_empty());
    let country = parts
        .get(2)
        .map(|s| sanitize(s, 16))
        .filter(|s| !s.is_empty());
    Some((asn, prefix, country))
}

/// Parses a Team Cymru ASN description TXT record:
/// `"63949 | US | arin | 2012-07-20 | LINO-1 - Akamai Connected Cloud, US"`
pub fn parse_cymru_asn(txt: &str) -> Option<String> {
    let parts: Vec<&str> = txt
        .trim()
        .trim_matches('"')
        .split('|')
        .map(str::trim)
        .collect();
    let desc = parts.get(4).or_else(|| parts.last())?;
    let cleaned = sanitize(desc, 160);
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Parsed RDAP response fields: `(asn, org_name, bgp_prefix, country)`.
pub type RdapParsed = (Option<u32>, Option<String>, Option<String>, Option<String>);

/// Parses an RDAP IP network JSON response (`https://rdap.arin.net/registry/ip/<ip>`).
pub fn parse_rdap_response(json: &Value) -> Option<RdapParsed> {
    if !json.is_object() {
        return None;
    }
    let name = json
        .get("name")
        .and_then(Value::as_str)
        .map(|s| sanitize(s, 120))
        .filter(|s| !s.is_empty());
    let country = json
        .get("country")
        .and_then(Value::as_str)
        .map(|s| sanitize(s, 16))
        .filter(|s| !s.is_empty());

    let prefix = json
        .get("cidr0_cidrs")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|cidr| {
            let v4 = cidr.get("v4prefix").and_then(Value::as_str);
            let v6 = cidr.get("v6prefix").and_then(Value::as_str);
            let len = cidr.get("length").and_then(Value::as_u64)?;
            Some(format!("{}/{len}", v4.or(v6)?))
        });

    let asn = json
        .get("arin_originas0_originautnums")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_u64)
        .map(|n| n as u32);

    // Extract organization full name from `entities[*].vcardArray[1][*]` where `[0] == "fn"`.
    let mut org_fn: Option<String> = None;
    if let Some(entities) = json.get("entities").and_then(Value::as_array) {
        for ent in entities {
            if let Some(vcard) = ent
                .get("vcardArray")
                .and_then(Value::as_array)
                .and_then(|v| v.get(1))
                .and_then(Value::as_array)
            {
                for prop in vcard {
                    let Some(arr) = prop.as_array() else {
                        continue;
                    };
                    if arr.first().and_then(Value::as_str) == Some("fn") {
                        if let Some(val) = arr.get(3).and_then(Value::as_str) {
                            let clean_val = sanitize(val, 160);
                            if !clean_val.is_empty() {
                                org_fn = Some(clean_val);
                                break;
                            }
                        }
                    }
                }
            }
            if org_fn.is_some() {
                break;
            }
        }
    }

    let org = match (org_fn, name) {
        (Some(f), Some(n)) if !f.eq_ignore_ascii_case(&n) => Some(format!("{f} ({n})")),
        (Some(f), _) => Some(f),
        (None, Some(n)) => Some(n),
        (None, None) => None,
    };

    if asn.is_none() && org.is_none() && prefix.is_none() && country.is_none() {
        return None;
    }
    Some((asn, org, prefix, country))
}

fn is_allowed_rdap_redirect(url: &reqwest::Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let lower = host.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "rdap.arin.net"
            | "rdap.db.ripe.net"
            | "rdap.apnic.net"
            | "rdap.lacnic.net"
            | "rdap.afrinic.net"
            | "rdap.org"
    )
}

async fn query_rdap(client: &reqwest::Client, ip: IpAddr) -> Result<Value> {
    let mut url = format!("https://rdap.arin.net/registry/ip/{ip}");
    for _ in 0..4 {
        let resp = client
            .get(&url)
            .header("Accept", "application/rdap+json, application/json")
            .send()
            .await
            .context("RDAP request failed")?;
        if resp.status().is_redirection() {
            let Some(loc) = resp.headers().get(reqwest::header::LOCATION) else {
                bail!("RDAP redirect without Location header");
            };
            let loc_str = loc.to_str().context("invalid RDAP Location header")?;
            let parsed = reqwest::Url::parse(loc_str).context("invalid RDAP redirect URL")?;
            if !is_allowed_rdap_redirect(&parsed) {
                bail!("refusing untrusted RDAP redirect host");
            }
            url = parsed.to_string();
            continue;
        }
        if !resp.status().is_success() {
            bail!("RDAP HTTP {}", resp.status());
        }
        let bytes = read_bytes_bounded(resp, MAX_HTTP_BYTES).await?;
        return serde_json::from_slice(&bytes).context("invalid RDAP JSON");
    }
    bail!("too many RDAP redirects")
}

/// Runs the passive `asn` lookup for a list of target IP addresses.
pub async fn run_asn(ips: &[String], geo: Option<&GeoDb>) -> Result<(Vec<Observation>, String)> {
    let client = build_http_client(Duration::from_secs(6))?;
    let mut observations = Vec::new();
    let mut summaries = Vec::new();

    for ip_str in ips.iter().take(16) {
        let Ok(ip) = IpAddr::from_str(ip_str) else {
            continue;
        };
        if is_non_public_ip(ip) {
            continue;
        }

        let origin_qname = cymru_origin_name(ip);
        let (origin_txts, rdap_res) = tokio::join!(
            resolve_rr(&client, &origin_qname, 16),
            query_rdap(&client, ip)
        );

        let mut asn_num: Option<u32> = None;
        let mut prefix: Option<String> = None;
        let mut country: Option<String> = None;
        let mut cymru_org: Option<String> = None;
        let mut cymru_ev = String::new();

        if let Some(first_txt) = origin_txts.first() {
            if let Some((asn, pfx, cc)) = parse_cymru_origin(first_txt) {
                asn_num = Some(asn);
                prefix = pfx;
                country = cc;
                cymru_ev = first_txt.clone();
                let asn_qname = format!("AS{asn}.asn.cymru.com");
                let asn_txts = resolve_rr(&client, &asn_qname, 16).await;
                if let Some(desc_txt) = asn_txts.first() {
                    cymru_org = parse_cymru_asn(desc_txt);
                    cymru_ev = format!("{first_txt} / {desc_txt}");
                }
            }
        }

        let mut rdap_org: Option<String> = None;
        let mut rdap_ev = String::new();
        if let Ok(rdap_json) = rdap_res {
            if let Some((r_asn, r_org, r_pfx, r_cc)) = parse_rdap_response(&rdap_json) {
                if asn_num.is_none() {
                    asn_num = r_asn;
                }
                if prefix.is_none() {
                    prefix = r_pfx;
                }
                if country.is_none() {
                    country = r_cc;
                }
                rdap_org = r_org;
                rdap_ev = sanitize(&rdap_json.to_string(), 600);
            }
        }

        // Offline GeoDb country fallback/enrichment.
        if country.is_none() {
            if let Some(db) = geo {
                if let Ok(Some(place)) = db.lookup(ip) {
                    if let Some(cc) = place.country {
                        country = Some(sanitize(&cc, 16));
                    }
                }
            }
        }

        let org = cymru_org.clone().or_else(|| rdap_org.clone());
        let asn_label = match (asn_num, &org) {
            (Some(n), Some(o)) => Some(format!("AS{n} · {o}")),
            (Some(n), None) => Some(format!("AS{n}")),
            (None, Some(o)) => Some(o.clone()),
            (None, None) => None,
        };

        let Some(label) = asn_label else {
            continue;
        };

        let primary_source = if !cymru_ev.is_empty() {
            Source::AsnDns
        } else {
            Source::Rdap
        };
        let primary_ev = if !cymru_ev.is_empty() {
            cymru_ev.clone()
        } else if !rdap_ev.is_empty() {
            rdap_ev.clone()
        } else {
            label.clone()
        };

        let mut claim = format!("ASN: {label}");
        let mut meta_parts = Vec::new();
        if let Some(pfx) = &prefix {
            meta_parts.push(format!("prefix {pfx}"));
        }
        if let Some(cc) = &country {
            meta_parts.push(format!("country {cc}"));
        }
        if !meta_parts.is_empty() {
            claim.push_str(&format!(" ({})", meta_parts.join(", ")));
        }

        observations.push(Observation::Fact {
            address: ip_str.clone(),
            port: None,
            protocol: "ip".to_owned(),
            claim,
            record: EvidenceRecord::observed(primary_source, Confidence::High, &primary_ev),
        });

        if let Some(r_org) = &rdap_org {
            if !rdap_ev.is_empty() && primary_source != Source::Rdap {
                observations.push(Observation::Fact {
                    address: ip_str.clone(),
                    port: None,
                    protocol: "ip".to_owned(),
                    claim: format!("RDAP organization: {r_org}"),
                    record: EvidenceRecord::observed(Source::Rdap, Confidence::High, &rdap_ev),
                });
            }
        }

        let waf_hint = detect_waf_from_asn(&label);
        observations.push(Observation::HostMeta {
            address: ip_str.clone(),
            asn: Some(label.clone()),
            bgp_prefix: prefix,
            country,
            ipv6_dns: None,
            waf_cdn: waf_hint,
            hops: Vec::new(),
            record: EvidenceRecord::observed(primary_source, Confidence::High, &primary_ev),
        });
        summaries.push(label);
    }

    let summary = if summaries.is_empty() {
        "no public ASN found".to_owned()
    } else {
        summaries.join(", ")
    };
    Ok((observations, summary))
}

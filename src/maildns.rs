//! The `mail-dns` recon stage: how well a domain protects its mail and its
//! DNS, and what its DNS gives away.
//!
//! - SPF, DMARC and DKIM (common selectors): can someone send mail that
//!   looks like it comes from the domain?
//! - CAA: which certificate authorities may issue certificates for it.
//! - DNSSEC: are its answers signed (DS at the parent, DNSKEY in the zone)?
//! - SRV and well-known names (`_ldap`, `_kerberos`, `_sip`, autodiscover):
//!   directory, chat and mail services the domain publishes, which often
//!   reveal Active Directory or Microsoft 365.
//! - Wildcard DNS: whether made-up names resolve, and which names from the
//!   certificate logs only resolve through that wildcard.
//!
//! Everything is a DNS question asked the way the `dns` stage asks: this
//! machine's resolvers first, DNS-over-HTTPS only for public names. Nothing
//! is sent to the target's own servers.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{bail, Result};
use futures_util::future::join_all;

use crate::evidence::{Confidence, EvidenceRecord, Source};
use crate::graph::{DnsCheck, DnsSecurity, DnsService, Observation, SubdomainCheck};
use crate::osint::{build_http_client, resolve_rr, root_domain};

const A: u16 = 1;
const CNAME: u16 = 5;
const MX: u16 = 15;
const TXT: u16 = 16;
const AAAA: u16 = 28;
const SRV: u16 = 33;
const DS: u16 = 43;
const DNSKEY: u16 = 48;
const CAA: u16 = 257;

/// Questions asked at once: enough to be quick, few enough not to flood a
/// home router's resolver.
const PARALLEL: usize = 6;
/// Certificate-log names looked up for the wildcard check.
const MAX_SUBDOMAINS: usize = 15;

/// DKIM selectors mail providers commonly use. A domain can use any name,
/// so finding none is not proof there is no DKIM.
pub const DKIM_SELECTORS: &[&str] = &[
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "k3",
    "s1",
    "s2",
    "mail",
    "dkim",
    "smtp",
    "mx",
    "sig1",
    "fm1",
    "fm2",
    "fm3",
    "protonmail",
    "protonmail2",
    "protonmail3",
    "zoho",
    "mandrill",
    "everlytickey1",
    "key1",
];

/// SRV records that say which services a domain runs, and what each means.
pub const SRV_RECORDS: &[(&str, &str)] = &[
    (
        "_ldap._tcp",
        "LDAP directory (often Active Directory domain controllers)",
    ),
    (
        "_ldap._tcp.dc._msdcs",
        "Active Directory domain controllers",
    ),
    (
        "_kerberos._tcp",
        "Kerberos login service (Active Directory or a Kerberos realm)",
    ),
    (
        "_kerberos._udp",
        "Kerberos login service (Active Directory or a Kerberos realm)",
    ),
    ("_kpasswd._tcp", "Kerberos password change service"),
    ("_gc._tcp", "Active Directory global catalog"),
    ("_vlmcs._tcp", "Windows KMS activation server"),
    ("_sip._tls", "SIP calling (Skype for Business / Teams)"),
    ("_sip._tcp", "SIP calling"),
    (
        "_sipfederationtls._tcp",
        "Skype for Business / Teams federation",
    ),
    (
        "_autodiscover._tcp",
        "Exchange Autodiscover (mail client set-up)",
    ),
    ("_xmpp-client._tcp", "XMPP chat for users"),
    ("_xmpp-server._tcp", "XMPP chat between servers"),
    ("_submission._tcp", "mail submission for clients"),
    ("_imaps._tcp", "IMAP mail access"),
];

/// Well-known names that point at hosted services.
pub const WELL_KNOWN_NAMES: &[(&str, &str)] = &[
    ("autodiscover", "Exchange / Microsoft 365 Autodiscover"),
    ("lyncdiscover", "Skype for Business / Teams discovery"),
    (
        "enterpriseenrollment",
        "Intune device enrollment (Microsoft 365)",
    ),
    ("sip", "SIP calling"),
];

fn check(
    name: &str,
    status: &str,
    value: impl Into<String>,
    advice: impl Into<String>,
) -> DnsCheck {
    DnsCheck {
        name: name.to_owned(),
        status: status.to_owned(),
        value: value.into(),
        advice: advice.into(),
    }
}

fn unquote(record: &str) -> String {
    record.trim().trim_matches('"').trim().to_owned()
}

/// SPF: one `v=spf1` TXT record at the domain, ending in `-all`, within the
/// limit of 10 DNS lookups.
pub fn grade_spf(txt: &[String], receives_mail: bool) -> DnsCheck {
    let spf: Vec<String> = txt
        .iter()
        .map(|t| unquote(t))
        .filter(|t| t.to_ascii_lowercase().starts_with("v=spf1"))
        .collect();
    let Some(record) = spf.first() else {
        return if receives_mail {
            check(
                "SPF",
                "bad",
                "no SPF record",
                "Anyone can send mail as this domain. Publish a TXT record such as \"v=spf1 include:<your mail provider> -all\".",
            )
        } else {
            check(
                "SPF",
                "warn",
                "no SPF record (the domain has no MX either)",
                "A domain that sends no mail should say so: publish \"v=spf1 -all\".",
            )
        };
    };
    if spf.len() > 1 {
        return check(
            "SPF",
            "bad",
            format!("{} SPF records", spf.len()),
            "More than one SPF record is an error: receivers treat it as no SPF at all. Merge them into one.",
        );
    }
    let lower = record.to_ascii_lowercase();
    let terms: Vec<&str> = lower.split_whitespace().skip(1).collect();
    let lookups = terms
        .iter()
        .filter(|t| {
            let t = t.trim_start_matches(['+', '-', '~', '?']);
            t.starts_with("include:")
                || t.starts_with("exists:")
                || t.starts_with("redirect=")
                || t == "a"
                || t.starts_with("a:")
                || t.starts_with("a/")
                || t == "mx"
                || t.starts_with("mx:")
                || t.starts_with("mx/")
                || t.starts_with("ptr")
        })
        .count();
    let all = terms
        .iter()
        .rev()
        .find(|t| t.ends_with("all") && t.len() <= 4)
        .copied();
    let mut notes = Vec::new();
    let mut status = "ok";
    match all {
        Some("-all") => {}
        Some("~all") => {
            status = "warn";
            notes.push(
                "~all only marks forged mail as suspicious; -all rejects it once DMARC is in place",
            );
        }
        Some("?all") | Some("+all") | Some("all") => {
            status = "bad";
            notes.push("this ending lets any server send mail as the domain");
        }
        _ if lower.contains("redirect=") => {}
        _ => {
            status = "warn";
            notes.push("no \"all\" at the end: mail from other servers is not judged");
        }
    }
    if lookups > 10 {
        status = "bad";
        notes.push("more than 10 DNS lookups: receivers give up and the record fails (permerror)");
    }
    if terms.iter().any(|t| {
        t.trim_start_matches(['+', '-', '~', '?'])
            .starts_with("ptr")
    }) {
        if status == "ok" {
            status = "warn";
        }
        notes.push("the ptr mechanism is deprecated and slow");
    }
    check("SPF", status, record.clone(), notes.join("; "))
}

/// The value of `key` in a `k=v; k=v` record.
fn tag<'a>(record: &'a str, key: &str) -> Option<&'a str> {
    record.split(';').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        k.trim().eq_ignore_ascii_case(key).then_some(v.trim())
    })
}

/// DMARC: a `v=DMARC1` record at `_dmarc.<domain>` with `p=reject` (or
/// `quarantine`) for all mail, sending reports somewhere.
pub fn grade_dmarc(txt: &[String]) -> DnsCheck {
    let Some(record) = txt
        .iter()
        .map(|t| unquote(t))
        .find(|t| t.to_ascii_lowercase().starts_with("v=dmarc1"))
    else {
        return check(
            "DMARC",
            "bad",
            "no DMARC record",
            "Receivers are not told to reject mail that fails SPF and DKIM. Start with \"v=DMARC1; p=none; rua=mailto:<you>\", then move to p=reject.",
        );
    };
    let policy = tag(&record, "p").unwrap_or("").to_ascii_lowercase();
    let percent: u32 = tag(&record, "pct")
        .and_then(|p| p.parse().ok())
        .unwrap_or(100);
    let mut notes: Vec<String> = Vec::new();
    let mut status = match policy.as_str() {
        "reject" => "ok",
        "quarantine" => "ok",
        "none" => {
            notes.push("p=none only monitors: forged mail is still delivered".to_owned());
            "warn"
        }
        _ => {
            notes.push("no valid p= policy".to_owned());
            "bad"
        }
    };
    if percent < 100 && status == "ok" {
        status = "warn";
        notes.push(format!(
            "pct={percent}: the policy covers only part of the mail"
        ));
    }
    if tag(&record, "rua").is_none() {
        notes.push("no rua= address: nobody receives the aggregate reports".to_owned());
    }
    if let Some(sub) = tag(&record, "sp") {
        if sub.eq_ignore_ascii_case("none") && policy != "none" {
            notes.push("sp=none leaves subdomains unprotected".to_owned());
            if status == "ok" {
                status = "warn";
            }
        }
    }
    check("DMARC", status, record, notes.join("; "))
}

/// DKIM: keys found under the common selectors, and how strong they look.
pub fn grade_dkim(found: &[(String, String)], tried: usize) -> DnsCheck {
    if found.is_empty() {
        return check(
            "DKIM",
            "info",
            format!("none of {tried} common selectors answered"),
            "The domain may still sign mail with a selector of its own; a received message's DKIM-Signature header (s=) names it.",
        );
    }
    let mut weak = Vec::new();
    let mut revoked = Vec::new();
    for (selector, record) in found {
        let key = tag(record, "p").unwrap_or("");
        let rsa = tag(record, "k").is_none_or(|k| k.eq_ignore_ascii_case("rsa"));
        if key.is_empty() {
            revoked.push(selector.as_str());
        } else if rsa && key.len() < 300 {
            // A 1024-bit RSA key is about 216 base64 characters; 2048-bit about 392.
            weak.push(selector.as_str());
        }
    }
    let names: Vec<&str> = found.iter().map(|(s, _)| s.as_str()).collect();
    let mut notes = Vec::new();
    if !weak.is_empty() {
        notes.push(format!(
            "1024-bit or shorter RSA key on {}: use 2048-bit",
            weak.join(", ")
        ));
    }
    if !revoked.is_empty() {
        notes.push(format!("revoked (empty key) on {}", revoked.join(", ")));
    }
    let status = if weak.is_empty() { "ok" } else { "warn" };
    check(
        "DKIM",
        status,
        format!("selectors {}", names.join(", ")),
        notes.join("; "),
    )
}

/// CAA: which certificate authorities may issue for the domain.
pub fn grade_caa(records: &[String], at: &str) -> DnsCheck {
    if records.is_empty() {
        return check(
            "CAA",
            "warn",
            "no CAA record",
            "Any certificate authority may issue certificates for the domain. A record such as 0 issue \"letsencrypt.org\" limits it to the ones you use.",
        );
    }
    let mut issuers = BTreeSet::new();
    let mut report = false;
    for record in records {
        let mut parts = record.splitn(3, ' ');
        let (_flags, tag, value) = (
            parts.next(),
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
        );
        let value = value.trim().trim_matches('"');
        match tag.to_ascii_lowercase().as_str() {
            "issue" | "issuewild" => {
                issuers.insert(if value.is_empty() || value == ";" {
                    "nobody".to_owned()
                } else {
                    value.split(';').next().unwrap_or(value).trim().to_owned()
                });
            }
            "iodef" => report = true,
            _ => {}
        }
    }
    let list: Vec<String> = issuers.into_iter().collect();
    check(
        "CAA",
        "ok",
        format!(
            "at {at}: {}",
            if list.is_empty() {
                "records without issue tags".to_owned()
            } else {
                list.join(", ")
            }
        ),
        if report {
            ""
        } else {
            "No iodef: a refused request is not reported to you."
        },
    )
}

/// DNSSEC: a DS record at the parent and DNSKEY records in the zone.
pub fn grade_dnssec(ds: &[String], dnskey: &[String], zone: &str) -> DnsCheck {
    let algorithm = |record: &String, at: usize| {
        record
            .split_whitespace()
            .nth(at)
            .and_then(|a| a.parse::<u8>().ok())
    };
    let name = |alg: u8| match alg {
        5 | 7 => "RSA/SHA-1 (deprecated)",
        8 => "RSA/SHA-256",
        10 => "RSA/SHA-512",
        13 => "ECDSA P-256",
        14 => "ECDSA P-384",
        15 => "Ed25519",
        16 => "Ed448",
        1 | 3 | 6 | 12 => "a retired algorithm",
        _ => "an unknown algorithm",
    };
    let algorithms: BTreeSet<u8> = ds
        .iter()
        .filter_map(|r| algorithm(r, 1))
        .chain(dnskey.iter().filter_map(|r| algorithm(r, 2)))
        .collect();
    let named: Vec<&str> = algorithms.iter().map(|a| name(*a)).collect();
    let old = algorithms
        .iter()
        .any(|a| matches!(a, 1 | 3 | 5 | 6 | 7 | 12));
    match (ds.is_empty(), dnskey.is_empty()) {
        (false, _) => check(
            "DNSSEC",
            if old { "warn" } else { "ok" },
            format!("{zone} is signed ({})", named.join(", ")),
            if old { "Move to ECDSA P-256 (algorithm 13) or Ed25519 (15)." } else { "" },
        ),
        (true, false) => check(
            "DNSSEC",
            "warn",
            format!("{zone} publishes keys but has no DS record at its parent"),
            "Resolvers cannot check the signatures until the DS record is added at the registrar.",
        ),
        (true, true) => check(
            "DNSSEC",
            "warn",
            format!("{zone} is not signed"),
            "Answers for the domain can be forged on the way (cache poisoning). Turn on DNSSEC at the DNS host and add the DS record at the registrar.",
        ),
    }
}

/// Who handles the domain's mail, from its MX records.
pub fn mail_provider(mx: &[String]) -> Option<&'static str> {
    const PROVIDERS: &[(&str, &str)] = &[
        ("google.com", "Google Workspace"),
        ("googlemail.com", "Google Workspace"),
        ("outlook.com", "Microsoft 365"),
        ("protection.outlook.com", "Microsoft 365"),
        ("pphosted.com", "Proofpoint"),
        ("ppe-hosted.com", "Proofpoint"),
        ("mimecast.com", "Mimecast"),
        ("barracudanetworks.com", "Barracuda"),
        ("messagelabs.com", "Broadcom Email Security"),
        ("iphmx.com", "Cisco Secure Email"),
        ("protonmail.ch", "Proton Mail"),
        ("zoho.com", "Zoho Mail"),
        ("zoho.eu", "Zoho Mail"),
        ("messagingengine.com", "Fastmail"),
        ("mailgun.org", "Mailgun"),
        ("amazonaws.com", "Amazon SES"),
        ("icloud.com", "iCloud Mail"),
        ("yandex.net", "Yandex Mail"),
    ];
    mx.iter().find_map(|record| {
        let host = record
            .split_whitespace()
            .last()?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        PROVIDERS
            .iter()
            .find(|(suffix, _)| host == *suffix || host.ends_with(&format!(".{suffix}")))
            .map(|(_, name)| *name)
    })
}

/// A to F: two points for each check that is fine, one for a warning or
/// an unknown, none for a problem.
pub fn overall_grade(checks: &[DnsCheck]) -> String {
    let graded: Vec<&DnsCheck> = checks
        .iter()
        .filter(|c| matches!(c.name.as_str(), "SPF" | "DMARC" | "DKIM" | "CAA" | "DNSSEC"))
        .collect();
    if graded.is_empty() {
        return "?".to_owned();
    }
    let points: usize = graded
        .iter()
        .map(|c| match c.status.as_str() {
            "ok" => 2,
            "bad" => 0,
            _ => 1,
        })
        .sum();
    let score = points * 10 / (graded.len() * 2);
    // A missing DMARC or SPF caps the grade: mail can be forged.
    let forgeable = graded
        .iter()
        .any(|c| matches!(c.name.as_str(), "SPF" | "DMARC") && c.status == "bad");
    let grade = match score {
        9..=10 => "A",
        7..=8 => "B",
        5..=6 => "C",
        3..=4 => "D",
        _ => "F",
    };
    if forgeable && matches!(grade, "A" | "B") {
        "C".to_owned()
    } else {
        grade.to_owned()
    }
}

/// How a name from the certificate logs answers, given the wildcard's answer.
pub fn classify_subdomain(addresses: &[String], wildcard: &[String]) -> &'static str {
    if addresses.is_empty() {
        "gone"
    } else if !wildcard.is_empty() && addresses.iter().all(|a| wildcard.contains(a)) {
        "wildcard"
    } else {
        "resolves"
    }
}

/// A label nobody would choose, for the wildcard check.
fn random_label() -> String {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        bytes.copy_from_slice(&(nanos as u64).to_le_bytes());
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("meow-check-{hex}")
}

async fn addresses<R, Fut>(ask: &R, name: &str) -> Vec<String>
where
    R: Fn(String, u16) -> Fut,
    Fut: std::future::Future<Output = Vec<String>>,
{
    let (mut v4, v6) = tokio::join!(ask(name.to_owned(), A), ask(name.to_owned(), AAAA));
    v4.extend(v6);
    v4.sort();
    v4.dedup();
    v4
}

/// Runs `ask` on every item, `PARALLEL` at a time, keeping the order.
async fn in_batches<T, R, F, Fut>(items: Vec<T>, ask: F) -> Vec<R>
where
    F: Fn(T) -> Fut,
    Fut: std::future::Future<Output = R>,
{
    let mut out = Vec::with_capacity(items.len());
    let mut items = items.into_iter().peekable();
    while items.peek().is_some() {
        let batch: Vec<Fut> = items.by_ref().take(PARALLEL).map(&ask).collect();
        out.extend(join_all(batch).await);
    }
    out
}

fn fact(address: &str, claim: String, evidence: &str) -> Observation {
    Observation::Fact {
        address: address.to_owned(),
        port: None,
        protocol: "ip".to_owned(),
        claim,
        record: EvidenceRecord::observed(Source::Dns, Confidence::High, evidence),
    }
}

/// Runs the stage for `domain`, whose records are kept on `primary_address`
/// (the address it resolves to, or the name itself). `ct_names` are names
/// the certificate logs gave for the same domain.
pub async fn run(
    domain: &str,
    primary_address: &str,
    ct_names: &[String],
) -> Result<(Vec<Observation>, String)> {
    let client = build_http_client(Duration::from_secs(6))?;
    let client = &client;
    run_with(
        domain,
        primary_address,
        ct_names,
        |name: String, rrtype: u16| async move { resolve_rr(client, &name, rrtype).await },
    )
    .await
}

/// The stage with `ask(name, type)` as the resolver.
pub async fn run_with<R, Fut>(
    domain: &str,
    primary_address: &str,
    ct_names: &[String],
    ask: R,
) -> Result<(Vec<Observation>, String)>
where
    R: Fn(String, u16) -> Fut,
    Fut: std::future::Future<Output = Vec<String>>,
{
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if !domain.contains('.') {
        bail!("'{domain}' is not a domain name");
    }
    let zone = root_domain(&domain).unwrap_or_else(|| domain.clone());
    let ask = &ask;
    // Borrowed by the lookups that run side by side.
    let (in_domain, in_zone) = (domain.as_str(), zone.as_str());

    // Mail: SPF and MX at the name, DMARC at _dmarc (falling back to the
    // registrable domain, as receivers do).
    let dmarc_at = format!("_dmarc.{domain}");
    let dmarc_zone = format!("_dmarc.{zone}");
    let (txt, mx, mut dmarc) = tokio::join!(
        ask(domain.clone(), TXT),
        ask(domain.clone(), MX),
        ask(dmarc_at.clone(), TXT),
    );
    if dmarc.is_empty() && zone != domain {
        dmarc = ask(dmarc_zone.clone(), TXT).await;
    }
    let selectors: Vec<String> = DKIM_SELECTORS.iter().map(|s| (*s).to_owned()).collect();
    let mut dkim: Vec<(String, String)> = in_batches(selectors, |selector| async move {
        let name = format!("{selector}._domainkey.{in_domain}");
        let records = ask(name.clone(), TXT).await;
        records
            .into_iter()
            .map(|r| unquote(&r))
            .find(|r| r.to_ascii_lowercase().contains("p="))
            .map(|r| (selector, r))
    })
    .await
    .into_iter()
    .flatten()
    .collect();
    dkim.sort();

    // Certificates: CAA at the name, else at the registrable domain.
    let mut caa_at = domain.clone();
    let mut caa = ask(domain.clone(), CAA).await;
    if caa.is_empty() && zone != domain {
        caa = ask(zone.clone(), CAA).await;
        caa_at = zone.clone();
    }

    // DNSSEC of the zone.
    let (ds, dnskey) = tokio::join!(ask(zone.clone(), DS), ask(zone.clone(), DNSKEY));

    let mut checks = vec![
        grade_spf(&txt, !mx.is_empty()),
        grade_dmarc(&dmarc),
        grade_dkim(&dkim, DKIM_SELECTORS.len()),
        grade_caa(&caa, &caa_at),
        grade_dnssec(&ds, &dnskey, &zone),
    ];
    if let Some(provider) = mail_provider(&mx) {
        checks.push(check("Mail", "info", format!("handled by {provider}"), ""));
    } else if mx.is_empty() {
        checks.push(check(
            "Mail",
            "info",
            "no MX record: the domain receives no mail",
            "",
        ));
    }

    // Services the domain publishes.
    let owned = |list: &[(&str, &str)]| -> Vec<(String, String)> {
        list.iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    };
    let srv: Vec<DnsService> = in_batches(owned(SRV_RECORDS), |(record, meaning)| async move {
        let name = format!("{record}.{in_zone}");
        ask(name.clone(), SRV)
            .await
            .into_iter()
            .filter_map(|answer| {
                // priority weight port target
                let parts: Vec<&str> = answer.split_whitespace().collect();
                let (port, target) = (parts.get(2)?, parts.get(3)?);
                (*target != "." && !target.is_empty()).then(|| DnsService {
                    record: name.clone(),
                    target: format!("{}:{port}", target.trim_end_matches('.')),
                    meaning: meaning.clone(),
                })
            })
            .take(4)
            .collect::<Vec<_>>()
    })
    .await
    .into_iter()
    .flatten()
    .collect();
    let named: Vec<DnsService> =
        in_batches(owned(WELL_KNOWN_NAMES), |(label, meaning)| async move {
            let name = format!("{label}.{in_zone}");
            let cname = ask(name.clone(), CNAME).await;
            let target = match cname.first() {
                Some(alias) => alias.clone(),
                None => addresses(ask, &name).await.first().cloned()?,
            };
            Some(DnsService {
                record: name,
                target,
                meaning,
            })
        })
        .await
        .into_iter()
        .flatten()
        .collect();
    let mut services: Vec<DnsService> = srv.into_iter().chain(named).collect();
    services.sort_by(|a, b| a.record.cmp(&b.record));
    let directory = services.iter().any(|s| {
        s.record.starts_with("_ldap.")
            || s.record.starts_with("_kerberos.")
            || s.record.starts_with("_gc.")
    });
    if directory {
        checks.push(check(
            "Directory",
            "warn",
            "Active Directory / Kerberos records are in public DNS",
            "They name the domain controllers to anyone who asks. Keep _ldap, _kerberos and _gc records on internal DNS only.",
        ));
    }

    // Wildcard: do two made-up names resolve, and to the same thing?
    let (first, second) = (
        format!("{}.{domain}", random_label()),
        format!("{}.{domain}", random_label()),
    );
    let (made_up, made_up_too) = tokio::join!(addresses(ask, &first), addresses(ask, &second));
    let wildcard: Vec<String> = made_up
        .iter()
        .filter(|a| made_up_too.contains(a))
        .cloned()
        .collect();
    let names: Vec<String> = ct_names
        .iter()
        .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
        .filter(|n| *n != domain && n.ends_with(&format!(".{zone}")))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_SUBDOMAINS)
        .collect();
    let wildcard_ref = &wildcard;
    let mut subdomains: Vec<SubdomainCheck> = in_batches(names, |name| async move {
        let found = addresses(ask, &name).await;
        SubdomainCheck {
            status: classify_subdomain(&found, wildcard_ref).to_owned(),
            name,
            addresses: found,
        }
    })
    .await;
    subdomains.sort_by(|a, b| a.name.cmp(&b.name));

    let grade = overall_grade(&checks);
    let mut observations = Vec::new();
    for c in &checks {
        let advice = if c.advice.is_empty() {
            String::new()
        } else {
            format!(" ({})", c.advice)
        };
        observations.push(fact(
            primary_address,
            format!("{} for {domain}: {}{advice}", c.name, c.value),
            &format!("mail-dns {} {}", c.name, c.status),
        ));
    }
    for s in &services {
        observations.push(fact(
            primary_address,
            format!("{} -> {} ({})", s.record, s.target, s.meaning),
            &format!("{} IN SRV/CNAME {}", s.record, s.target),
        ));
    }
    if !wildcard.is_empty() {
        observations.push(fact(
            primary_address,
            format!(
                "wildcard DNS: any name under {domain} resolves to {}",
                wildcard.join(", ")
            ),
            &format!("{first} and {second} both resolved"),
        ));
    }
    // Say on each certificate-log name how it answers.
    for sub in &subdomains {
        let claim = match sub.status.as_str() {
            "wildcard" => {
                format!("DNS: only the wildcard *.{domain} answers for this name; it may not exist")
            }
            "gone" => "DNS: no address record now (seen only in certificate logs)".to_owned(),
            _ => format!("DNS: resolves to {}", sub.addresses.join(", ")),
        };
        observations.push(fact(
            &sub.name,
            claim,
            &format!("{} A/AAAA lookup", sub.name),
        ));
    }
    let summary = format!(
        "grade {grade}: {}{}{}",
        checks
            .iter()
            .filter(|c| c.name != "Mail")
            .map(|c| format!("{} {}", c.name, c.status))
            .collect::<Vec<_>>()
            .join(", "),
        if services.is_empty() {
            String::new()
        } else {
            format!("; {} services published", services.len())
        },
        if wildcard.is_empty() {
            String::new()
        } else {
            "; wildcard DNS".to_owned()
        },
    );
    observations.push(Observation::DnsSecurity {
        address: primary_address.to_owned(),
        info: Box::new(DnsSecurity {
            domain: domain.clone(),
            grade,
            checks,
            services,
            wildcard,
            subdomains,
        }),
        record: EvidenceRecord::observed(
            Source::Dns,
            Confidence::High,
            &format!("mail-dns {domain}"),
        ),
    });
    Ok((observations, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| (*i).to_owned()).collect()
    }

    #[test]
    fn spf_is_graded_by_its_ending_and_lookup_count() {
        assert_eq!(
            grade_spf(&s(&["v=spf1 include:_spf.google.com -all"]), true).status,
            "ok"
        );
        assert_eq!(
            grade_spf(&s(&["\"v=spf1 include:_spf.google.com ~all\""]), true).status,
            "warn"
        );
        assert_eq!(grade_spf(&s(&["v=spf1 +all"]), true).status, "bad");
        assert_eq!(
            grade_spf(&s(&["v=spf1 include:a.test"]), true).status,
            "warn"
        );
        assert_eq!(
            grade_spf(&s(&["v=spf1 -all", "v=spf1 ~all"]), true).status,
            "bad"
        );
        assert_eq!(
            grade_spf(&s(&["google-site-verification=abc"]), true).status,
            "bad"
        );
        assert_eq!(grade_spf(&[], false).status, "warn");
        let many = format!(
            "v=spf1 {} -all",
            (0..11)
                .map(|i| format!("include:s{i}.test"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let graded = grade_spf(&[many], true);
        assert_eq!(graded.status, "bad");
        assert!(
            graded.advice.contains("10 DNS lookups"),
            "{}",
            graded.advice
        );
        assert_eq!(
            grade_spf(&s(&["v=spf1 redirect=_spf.example.test"]), true).status,
            "ok"
        );
    }

    #[test]
    fn dmarc_is_graded_by_policy_coverage_and_reports() {
        assert_eq!(
            grade_dmarc(&s(&["v=DMARC1; p=reject; rua=mailto:d@x.test"])).status,
            "ok"
        );
        assert_eq!(
            grade_dmarc(&s(&["v=DMARC1; p=quarantine; rua=mailto:d@x.test"])).status,
            "ok"
        );
        let none = grade_dmarc(&s(&["v=DMARC1; p=none"]));
        assert_eq!(none.status, "warn");
        assert!(
            none.advice.contains("only monitors") && none.advice.contains("rua"),
            "{}",
            none.advice
        );
        assert_eq!(
            grade_dmarc(&s(&["v=DMARC1; p=reject; pct=20; rua=mailto:d@x.test"])).status,
            "warn"
        );
        assert_eq!(
            grade_dmarc(&s(&["v=DMARC1; p=reject; sp=none; rua=mailto:d@x.test"])).status,
            "warn"
        );
        assert_eq!(grade_dmarc(&[]).status, "bad");
        assert_eq!(grade_dmarc(&s(&["v=DMARC1; p=bogus"])).status, "bad");
    }

    #[test]
    fn dkim_keys_are_listed_and_short_ones_flagged() {
        let strong = format!("v=DKIM1; k=rsa; p={}", "A".repeat(392));
        let weak = format!("v=DKIM1; k=rsa; p={}", "A".repeat(216));
        let found = vec![
            ("google".to_owned(), strong.clone()),
            ("s1".to_owned(), weak),
        ];
        let graded = grade_dkim(&found, 24);
        assert_eq!(graded.status, "warn");
        assert!(
            graded.value.contains("google, s1") && graded.advice.contains("s1"),
            "{graded:?}"
        );
        assert_eq!(
            grade_dkim(&[("google".to_owned(), strong)], 24).status,
            "ok"
        );
        // Ed25519 keys are short and fine.
        assert_eq!(
            grade_dkim(
                &[("ed".to_owned(), "v=DKIM1; k=ed25519; p=abcd".to_owned())],
                24
            )
            .status,
            "ok"
        );
        assert_eq!(grade_dkim(&[], 24).status, "info");
    }

    #[test]
    fn caa_and_dnssec_are_read_from_their_records() {
        let caa = grade_caa(
            &s(&[
                "0 issue \"letsencrypt.org\"",
                "0 issuewild \";\"",
                "0 iodef \"mailto:x@y.test\"",
            ]),
            "example.test",
        );
        assert_eq!(caa.status, "ok");
        assert!(
            caa.value.contains("letsencrypt.org")
                && caa.value.contains("nobody")
                && caa.advice.is_empty(),
            "{caa:?}"
        );
        assert_eq!(grade_caa(&[], "example.test").status, "warn");

        assert_eq!(
            grade_dnssec(&s(&["2371 13 2"]), &s(&["257 3 13"]), "example.test").status,
            "ok"
        );
        assert!(grade_dnssec(&s(&["2371 13 2"]), &[], "example.test")
            .value
            .contains("ECDSA P-256"));
        assert_eq!(
            grade_dnssec(&s(&["1 7 1"]), &[], "example.test").status,
            "warn"
        );
        let orphan = grade_dnssec(&[], &s(&["256 3 8 AwEAAc..."]), "example.test");
        assert!(
            orphan.status == "warn" && orphan.value.contains("no DS"),
            "{orphan:?}"
        );
        assert!(grade_dnssec(&[], &[], "example.test")
            .value
            .contains("not signed"));
    }

    #[test]
    fn the_overall_grade_cannot_be_high_while_mail_can_be_forged() {
        let all = |status: &str| {
            ["SPF", "DMARC", "DKIM", "CAA", "DNSSEC"]
                .iter()
                .map(|n| check(n, status, "", ""))
                .collect::<Vec<_>>()
        };
        assert_eq!(overall_grade(&all("ok")), "A");
        assert_eq!(overall_grade(&all("warn")), "C");
        assert_eq!(overall_grade(&all("bad")), "F");
        let mut no_dmarc = all("ok");
        no_dmarc[1].status = "bad".to_owned();
        assert_eq!(overall_grade(&no_dmarc), "C");
        assert_eq!(overall_grade(&[check("Mail", "info", "", "")]), "?");
    }

    #[tokio::test]
    async fn a_domain_is_graded_its_services_listed_and_wildcard_names_told_apart() {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        let mut table: HashMap<(String, u16), Vec<String>> = HashMap::new();
        let mut put = |name: &str, rrtype: u16, answers: &[&str]| {
            table.insert((name.to_owned(), rrtype), s(answers));
        };
        put(
            "example.test",
            TXT,
            &[
                "v=spf1 include:_spf.google.com ~all",
                "google-site-verification=x",
            ],
        );
        put("example.test", MX, &["1 aspmx.l.google.com"]);
        put("_dmarc.example.test", TXT, &["v=DMARC1; p=none"]);
        let key = format!("v=DKIM1; k=rsa; p={}", "A".repeat(392));
        put("google._domainkey.example.test", TXT, &[key.as_str()]);
        put("example.test", DNSKEY, &["257 3 13"]);
        put(
            "_ldap._tcp.example.test",
            SRV,
            &["0 100 389 dc01.corp.example.test"],
        );
        put(
            "autodiscover.example.test",
            CNAME,
            &["autodiscover.outlook.com"],
        );
        put("www.example.test", A, &["198.51.100.7"]);
        put("old.example.test", A, &["203.0.113.50"]);
        let table = Arc::new(table);
        let asked = Arc::new(Mutex::new(Vec::<String>::new()));
        let (t, log) = (Arc::clone(&table), Arc::clone(&asked));
        let resolver = move |name: String, rrtype: u16| {
            let (t, log) = (Arc::clone(&t), Arc::clone(&log));
            async move {
                log.lock().unwrap().push(name.clone());
                // Every made-up name answers: a wildcard.
                if name.starts_with("meow-check-") && rrtype == A {
                    return s(&["203.0.113.50"]);
                }
                t.get(&(name, rrtype)).cloned().unwrap_or_default()
            }
        };
        let ct = s(&[
            "www.example.test",
            "old.example.test",
            "gone.example.test",
            "other.test",
            "example.test",
        ]);
        let (observations, summary) = run_with("example.test", "198.51.100.1", &ct, resolver)
            .await
            .unwrap();

        let info = observations
            .iter()
            .find_map(|o| match o {
                Observation::DnsSecurity { info, address, .. } if address == "198.51.100.1" => {
                    Some(info)
                }
                _ => None,
            })
            .expect("a DnsSecurity record");
        let status = |name: &str| {
            info.checks
                .iter()
                .find(|c| c.name == name)
                .map(|c| c.status.clone())
        };
        assert_eq!(status("SPF").as_deref(), Some("warn"));
        assert_eq!(status("DMARC").as_deref(), Some("warn"));
        assert_eq!(status("DKIM").as_deref(), Some("ok"));
        assert_eq!(status("CAA").as_deref(), Some("warn"));
        assert_eq!(status("DNSSEC").as_deref(), Some("warn"));
        assert_eq!(status("Directory").as_deref(), Some("warn"));
        assert!(info
            .checks
            .iter()
            .any(|c| c.name == "Mail" && c.value.contains("Google Workspace")));
        assert_eq!(info.grade, "C", "{summary}");
        assert!(info
            .services
            .iter()
            .any(|sv| sv.record == "_ldap._tcp.example.test"
                && sv.target == "dc01.corp.example.test:389"));
        assert!(info
            .services
            .iter()
            .any(|sv| sv.record == "autodiscover.example.test"
                && sv.target == "autodiscover.outlook.com"));
        assert_eq!(info.wildcard, ["203.0.113.50"]);
        let sub = |name: &str| {
            info.subdomains
                .iter()
                .find(|x| x.name == name)
                .map(|x| x.status.as_str())
        };
        assert_eq!(sub("www.example.test"), Some("resolves"));
        assert_eq!(sub("old.example.test"), Some("wildcard"));
        assert_eq!(sub("gone.example.test"), Some("gone"));
        assert_eq!(sub("other.test"), None);
        assert!(observations.iter().any(|o| matches!(o,
            Observation::Fact { address, claim, .. }
                if address == "old.example.test" && claim.contains("only the wildcard"))));
        // Nothing outside the domain was asked about.
        let asked = asked.lock().unwrap();
        assert!(
            asked
                .iter()
                .all(|n| n == "example.test" || n.ends_with(".example.test")),
            "{asked:?}"
        );
        assert!(
            summary.starts_with("grade C") && summary.contains("wildcard DNS"),
            "{summary}"
        );
    }

    #[test]
    fn mail_providers_and_wildcard_answers_are_recognised() {
        assert_eq!(
            mail_provider(&s(&["1 aspmx.l.google.com"])),
            Some("Google Workspace")
        );
        assert_eq!(
            mail_provider(&s(&["0 example-test.mail.protection.outlook.com"])),
            Some("Microsoft 365")
        );
        assert_eq!(mail_provider(&s(&["10 mx.example.test"])), None);
        // A suffix match, not a substring one.
        assert_eq!(mail_provider(&s(&["10 notgoogle.com.evil.test"])), None);

        let wildcard = s(&["203.0.113.9"]);
        assert_eq!(
            classify_subdomain(&s(&["203.0.113.9"]), &wildcard),
            "wildcard"
        );
        assert_eq!(
            classify_subdomain(&s(&["203.0.113.9", "198.51.100.4"]), &wildcard),
            "resolves"
        );
        assert_eq!(classify_subdomain(&[], &wildcard), "gone");
        assert_eq!(classify_subdomain(&s(&["203.0.113.9"]), &[]), "resolves");
        assert!(random_label() != random_label());
    }
}

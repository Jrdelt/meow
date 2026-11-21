//! Live CVE grounding at zero AI cost.
//!
//! * **Infrastructure (NVD v2.0 + CISA KEV):** every versioned CPE on an
//!   open port is looked up by `cpeName=` and again by `keywordSearch=`,
//!   because recent CVEs are often still unanalysed ("Deferred", "Awaiting
//!   Analysis") and carry no CPE configuration to match on.
//! * **Application packages (OSV.dev):** `POST /v1/querybatch` with
//!   `next_page_token` pagination.
//!
//! Requests carry only public software identifiers (CPE names, product and
//! package names, versions), never hosts or paths. Every match is stored as
//! a CVE of the host it was found on. Connecting has a 5 s timeout, so an offline
//! machine fails fast, while a reply may take as long as it keeps arriving;
//! NVD requests are paced to respect its rate limit.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cpe;
use crate::db::Db;
use crate::evidence::{Confidence, EvidenceRecord, Source};
use crate::graph::{Advisory, Fact, Host, Port};

pub const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const OSV_URL: &str = "https://api.osv.dev";
pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// NVD allows 5 requests per 30 s without a key and 50 with one.
pub const NVD_PACE_ANONYMOUS: Duration = Duration::from_millis(6500);
pub const NVD_PACE_WITH_KEY: Duration = Duration::from_millis(700);
/// Short, so an offline machine is not kept waiting.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a database may stay silent, before its first byte or between
/// two parts of a reply. NVD often takes half a minute to start answering a
/// keyword search, and a reply of megabytes may arrive slowly (a phone
/// hotspot, a VPN) as long as it keeps arriving.
const STALL_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(180);
const DAY: Duration = Duration::from_secs(24 * 3600);
const KEV_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const OSV_MAX_PAGES: usize = 5;
const OSV_MAX_DETAILS: usize = 25;
const MAX_REFERENCES: usize = 5;

/// `[cve]` section of `config.toml`.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct CveSettings {
    pub enabled: bool,
    pub nvd_api_key: Option<String>,
    /// Endpoints, overridable for mirrors and tests.
    pub nvd_url: String,
    pub osv_url: String,
    pub kev_url: String,
}

impl std::fmt::Debug for CveSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CveSettings")
            .field("enabled", &self.enabled)
            .field("nvd_api_key", &self.api_key().map(|_| "<redacted>"))
            .field("nvd_url", &self.nvd_url)
            .field("osv_url", &self.osv_url)
            .field("kev_url", &self.kev_url)
            .finish()
    }
}

impl Default for CveSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            nvd_api_key: None,
            nvd_url: NVD_URL.to_owned(),
            osv_url: OSV_URL.to_owned(),
            kev_url: KEV_URL.to_owned(),
        }
    }
}

impl CveSettings {
    fn api_key(&self) -> Option<&str> {
        self.nvd_api_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
    }

    pub fn nvd_pace(&self) -> Duration {
        if self.api_key().is_some() {
            NVD_PACE_WITH_KEY
        } else {
            NVD_PACE_ANONYMOUS
        }
    }
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/// Loose version ordering: digit runs compare numerically, pre-release
/// tags (`alpha`, `beta`, `rc`, `pre`, `dev`) sort before the release they
/// precede (`1.20.1-rc1` < `1.20.1`), patch suffixes sort after their base
/// (`8.2` < `8.2p1` < `8.10`, `1.1.1` < `1.1.1k`), trailing `.0` numeric
/// segments are equivalent (`1.0.0` == `1.0`), and distribution revision
/// suffixes (`2.4.52-1ubuntu4`) compare by their upstream version (`2.4.52`).
pub fn cmp_versions(a: &str, b: &str) -> Ordering {
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum VerToken {
        Pre(String),
        Num(u64),
        Patch(String),
    }

    fn is_prerelease_tag(tag: &str) -> bool {
        matches!(
            tag,
            "alpha" | "beta" | "rc" | "pre" | "dev" | "devel" | "preview"
        )
    }

    fn has_distro_tag(text: &str, tag: &str) -> bool {
        let bytes = text.as_bytes();
        let tbytes = tag.as_bytes();
        if bytes.len() <= tbytes.len() {
            return false;
        }
        for i in 0..=(bytes.len() - tbytes.len() - 1) {
            if &bytes[i..i + tbytes.len()] == tbytes {
                let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphabetic();
                let next_ok = bytes[i + tbytes.len()].is_ascii_digit();
                if prev_ok && next_ok {
                    return true;
                }
            }
        }
        false
    }

    fn strip_distro_revision(text: &str) -> &str {
        let Some((base, rev)) = text.split_once('-') else {
            return text;
        };
        if base.is_empty() {
            return text;
        }
        let lower = rev.to_ascii_lowercase();
        let is_distro = lower.starts_with(|c: char| c.is_ascii_digit())
            || lower.contains("ubuntu")
            || lower.contains("redhat")
            || lower.contains("centos")
            || lower.contains("amzn")
            || has_distro_tag(&lower, "deb")
            || has_distro_tag(&lower, "el")
            || has_distro_tag(&lower, "fc")
            || (lower.starts_with('r') && lower[1..].starts_with(|c: char| c.is_ascii_digit()));
        if is_distro {
            base
        } else {
            text
        }
    }

    fn tokens(text: &str) -> Vec<VerToken> {
        let mut out = Vec::new();
        let mut current = String::new();
        let mut digits = false;
        let mut preceded_by_dash = false;
        let mut token_after_dash = false;
        for ch in text.chars().chain(std::iter::once('.')) {
            let is_digit = ch.is_ascii_digit();
            let is_alpha = ch.is_ascii_alphabetic();
            let boundary = (!is_digit && !is_alpha) || is_digit != digits;
            if boundary && !current.is_empty() {
                if digits {
                    out.push(VerToken::Num(current.parse::<u64>().unwrap_or(u64::MAX)));
                } else {
                    let lower = current.to_ascii_lowercase();
                    if is_prerelease_tag(&lower)
                        || (token_after_dash && matches!(lower.as_str(), "a" | "b"))
                    {
                        out.push(VerToken::Pre(lower));
                    } else {
                        out.push(VerToken::Patch(lower));
                    }
                }
                current.clear();
                token_after_dash = false;
            }
            if is_digit || is_alpha {
                if current.is_empty() {
                    token_after_dash = preceded_by_dash;
                }
                digits = is_digit;
                current.push(ch);
                preceded_by_dash = false;
            } else {
                preceded_by_dash = matches!(ch, '-' | '_' | '~');
            }
        }
        out
    }

    // "v2.0" and "2.0" are the same version.
    fn unprefixed(text: &str) -> &str {
        text.strip_prefix(['v', 'V'])
            .filter(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
            .unwrap_or(text)
    }

    let a = tokens(strip_distro_revision(unprefixed(a.trim())));
    let b = tokens(strip_distro_revision(unprefixed(b.trim())));
    let len = a.len().max(b.len());
    for i in 0..len {
        let order = match (a.get(i), b.get(i)) {
            (Some(VerToken::Num(l)), Some(VerToken::Num(r))) => l.cmp(r),
            (Some(VerToken::Pre(l)), Some(VerToken::Pre(r))) => l.cmp(r),
            (Some(VerToken::Patch(l)), Some(VerToken::Patch(r))) => l.cmp(r),
            (Some(VerToken::Pre(_)), _) => Ordering::Less,
            (_, Some(VerToken::Pre(_))) => Ordering::Greater,
            (Some(VerToken::Num(0)), Some(VerToken::Patch(_))) => Ordering::Less,
            (Some(VerToken::Patch(_)), Some(VerToken::Num(0))) => Ordering::Greater,
            (Some(VerToken::Num(_)), Some(VerToken::Patch(_))) => Ordering::Greater,
            (Some(VerToken::Patch(_)), Some(VerToken::Num(_))) => Ordering::Less,
            (Some(VerToken::Num(0)), None) | (None, Some(VerToken::Num(0))) => Ordering::Equal,
            (Some(VerToken::Num(_) | VerToken::Patch(_)), None) => Ordering::Greater,
            (None, Some(VerToken::Num(_) | VerToken::Patch(_))) => Ordering::Less,
            (None, None) => Ordering::Equal,
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    Ordering::Equal
}

/// A version range of one product, from an NVD CPE match or a CNA
/// `affected` block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    pub product: String,
    pub exact: Option<String>,
    pub start_including: Option<String>,
    pub start_excluding: Option<String>,
    pub end_including: Option<String>,
    pub end_excluding: Option<String>,
    /// Operating systems (`vendor product`) the record ties this range to:
    /// "OpenSSH as packaged for Red Hat Enterprise Linux". Empty when the
    /// range applies wherever the product runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_on: Vec<String>,
}

/// The operating system family a host or a platform name belongs to, when
/// that can be told at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Windows,
    Linux,
    Mac,
}

const LINUX_WORDS: &[&str] = &[
    "linux",
    "ubuntu",
    "debian",
    "redhat",
    "red hat",
    "fedora",
    "centos",
    "suse",
    "raspbian",
    "alpine",
    "canonical",
];

fn family_of(text: &str) -> Option<Family> {
    let text = text.to_ascii_lowercase();
    if text.contains("windows") || text.contains("microsoft") {
        Some(Family::Windows)
    } else if text.contains("macos") || text.contains("mac_os") || text.contains("mac os") {
        Some(Family::Mac)
    } else if LINUX_WORDS.iter().any(|word| text.contains(word)) {
        Some(Family::Linux)
    } else {
        None
    }
}

/// The family a host belongs to, from an OS scan or from what its services
/// say about themselves (`OpenSSH for_Windows_9.5`, `Ubuntu 3ubuntu13`).
pub fn host_family(host: &Host) -> Option<Family> {
    if let Some(family) = host.os.as_deref().and_then(family_of) {
        return Some(family);
    }
    host.ports.values().find_map(|port| {
        [&port.product, &port.version, &port.extra_info]
            .into_iter()
            .flatten()
            .find_map(|text| family_of(text))
    })
}

fn normalize_product(name: &str) -> String {
    name.to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_owned()
}

impl VersionRange {
    /// Whether this range is about `product` at all.
    fn names(&self, product: &str) -> bool {
        let wanted = normalize_product(product);
        let mine = normalize_product(&self.product);
        mine == wanted
            || mine.ends_with(&format!("_{wanted}"))
            || wanted.ends_with(&format!("_{mine}"))
    }

    /// False only when the range is tied to operating systems and the host
    /// is known to run a different one.
    fn runs_on(&self, family: Option<Family>) -> bool {
        let Some(family) = family else {
            return true;
        };
        self.only_on.is_empty()
            || self
                .only_on
                .iter()
                .any(|platform| family_of(platform).is_none_or(|theirs| theirs == family))
    }

    fn covers(&self, product: &str, version: &str) -> bool {
        if !self.names(product) {
            return false;
        }
        if let Some(exact) = &self.exact {
            return cmp_versions(version, exact) == Ordering::Equal;
        }
        let above = |bound: &Option<String>, inclusive: bool| match bound {
            None => true,
            Some(bound) => match cmp_versions(version, bound) {
                Ordering::Greater => true,
                Ordering::Equal => inclusive,
                Ordering::Less => false,
            },
        };
        let below = |bound: &Option<String>, inclusive: bool| match bound {
            None => true,
            Some(bound) => match cmp_versions(version, bound) {
                Ordering::Less => true,
                Ordering::Equal => inclusive,
                Ordering::Greater => false,
            },
        };
        above(&self.start_including, true)
            && above(&self.start_excluding, false)
            && below(&self.end_including, true)
            && below(&self.end_excluding, false)
    }
}

// ---------------------------------------------------------------------------
// NVD
// ---------------------------------------------------------------------------

/// The parts of an NVD CVE record that grounding uses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NvdCve {
    pub id: String,
    pub description: String,
    /// `Analyzed`, `Deferred`, `Awaiting Analysis`, ...
    pub status: String,
    pub cvss: Option<f64>,
    pub severity: Option<String>,
    /// NVD itself marks the CVE as listed in CISA KEV.
    pub kev: bool,
    pub references: Vec<String>,
    /// Empty when the record has no applicability data at all.
    pub ranges: Vec<VersionRange>,
}

fn text_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty() && !matches!(*v, "*" | "-" | "n/a" | "unspecified"))
        .map(str::to_owned)
}

/// The operating systems a configuration node names as a mere platform:
/// every entry is an `o` CPE that is not itself vulnerable.
fn platform_node(node: &Value) -> Option<Vec<String>> {
    let matches = node.get("cpeMatch").and_then(Value::as_array)?;
    let mut names = Vec::new();
    for matched in matches {
        if matched.get("vulnerable").and_then(Value::as_bool) != Some(false) {
            return None;
        }
        let parts = matched
            .get("criteria")
            .and_then(Value::as_str)
            .and_then(cpe::parts)?;
        if parts.part != 'o' {
            return None;
        }
        let name = format!("{} {}", parts.vendor, parts.product);
        if !names.contains(&name) {
            names.push(name);
        }
    }
    (!names.is_empty()).then_some(names)
}

fn ranges_from_configurations(cve: &Value, out: &mut Vec<VersionRange>) {
    for configuration in cve
        .get("configurations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let nodes: Vec<&Value> = configuration
            .get("nodes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .collect();
        // "A running on B": the vulnerable product only counts on B.
        let only_on: Vec<String> =
            if configuration.get("operator").and_then(Value::as_str) == Some("AND") {
                nodes
                    .iter()
                    .filter_map(|node| platform_node(node))
                    .flatten()
                    .collect()
            } else {
                Vec::new()
            };
        for matched in nodes
            .iter()
            .filter_map(|n| n.get("cpeMatch").and_then(Value::as_array))
            .flatten()
        {
            if matched.get("vulnerable").and_then(Value::as_bool) == Some(false) {
                continue;
            }
            let Some(parts) = matched
                .get("criteria")
                .and_then(Value::as_str)
                .and_then(cpe::parts)
            else {
                continue;
            };
            out.push(VersionRange {
                product: parts.product,
                exact: parts.version,
                start_including: text_field(matched, "versionStartIncluding"),
                start_excluding: text_field(matched, "versionStartExcluding"),
                end_including: text_field(matched, "versionEndIncluding"),
                end_excluding: text_field(matched, "versionEndExcluding"),
                only_on: only_on.clone(),
            });
        }
    }
}

/// CNA-provided `affected` blocks (CVE record format 5), which exist even
/// when NVD has not analysed the CVE.
fn ranges_from_affected(cve: &Value, out: &mut Vec<VersionRange>) {
    let blocks = [
        cve.get("affected"),
        cve.pointer("/cna/affected"),
        cve.pointer("/containers/cna/affected"),
    ];
    for affected in blocks
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .flatten()
    {
        let Some(product) = text_field(affected, "product") else {
            continue;
        };
        for version in affected
            .get("versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if version
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|s| s != "affected")
            {
                continue;
            }
            let start = text_field(version, "version").filter(|v| v != "0");
            let end_excluding = text_field(version, "lessThan");
            let end_including = text_field(version, "lessThanOrEqual");
            let bounded = end_excluding.is_some() || end_including.is_some();
            out.push(VersionRange {
                product: product.clone(),
                exact: if bounded { None } else { start.clone() },
                start_including: if bounded { start } else { None },
                start_excluding: None,
                end_including,
                end_excluding,
                only_on: Vec::new(),
            });
        }
    }
}

/// Reduces an NVD API 2.0 response to [`NvdCve`]s.
pub fn parse_nvd(body: &Value) -> Vec<NvdCve> {
    let mut out = Vec::new();
    for item in body
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let cve = item.get("cve").unwrap_or(item);
        let Some(id) = text_field(cve, "id") else {
            continue;
        };
        let description = cve
            .get("descriptions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|d| d.get("lang").and_then(Value::as_str) == Some("en"))
            .and_then(|d| text_field(d, "value"))
            .unwrap_or_default();
        let metric = [
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ]
        .iter()
        .find_map(|key| cve.pointer(&format!("/metrics/{key}/0")));
        let cvss = metric
            .and_then(|m| m.pointer("/cvssData/baseScore"))
            .and_then(Value::as_f64);
        let severity = metric.and_then(|m| {
            text_field(m.get("cvssData").unwrap_or(&Value::Null), "baseSeverity")
                .or_else(|| text_field(m, "baseSeverity"))
        });
        let references = cve
            .get("references")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|r| text_field(r, "url"))
            .take(MAX_REFERENCES)
            .collect();
        let mut ranges = Vec::new();
        ranges_from_configurations(cve, &mut ranges);
        ranges_from_affected(cve, &mut ranges);
        out.push(NvdCve {
            id,
            description,
            status: text_field(cve, "vulnStatus").unwrap_or_default(),
            cvss,
            severity,
            kev: cve.get("cisaExploitAdd").is_some(),
            references,
            ranges,
        });
    }
    out
}

/// How a CVE record bears on one product at one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relevance {
    pub confidence: Confidence,
    /// The first release the record says is no longer affected.
    pub fixed_in: Option<String>,
    /// The last release the record says is affected, when it names no fix.
    pub last_affected: Option<String>,
}

impl NvdCve {
    /// Whether this record really concerns `product` at `version` on a host
    /// of `family`, and how sure that is. `None` means it does not apply.
    ///
    /// `matched_by_nvd` is set for `cpeName` lookups, where NVD compared the
    /// version itself. NVD also returns records that only name the product
    /// as the platform another product runs on; those are dropped here.
    pub fn relevance(
        &self,
        product: &str,
        version: &str,
        family: Option<Family>,
        matched_by_nvd: bool,
    ) -> Option<Relevance> {
        if self.ranges.is_empty() {
            if matched_by_nvd {
                return Some(Relevance {
                    confidence: Confidence::Medium,
                    fixed_in: None,
                    last_affected: None,
                });
            }
            // No applicability data: accept only an explicit mention of both.
            let text = self.description.to_ascii_lowercase();
            let product = product.to_ascii_lowercase().replace('_', " ");
            let mentions_version = text
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
                .any(|word| word.trim_matches('.') == version.to_ascii_lowercase());
            return (text.contains(&product) && mentions_version).then_some(Relevance {
                confidence: Confidence::Low,
                fixed_in: None,
                last_affected: None,
            });
        }
        let named: Vec<&VersionRange> = self.ranges.iter().filter(|r| r.names(product)).collect();
        let mut covering: Vec<&VersionRange> = named
            .iter()
            .copied()
            .filter(|r| r.covers(product, version))
            .collect();
        if covering.is_empty() && matched_by_nvd {
            // NVD's own version comparison wins over the one made here.
            covering = named;
        }
        covering.retain(|r| r.runs_on(family));
        if covering.is_empty() {
            return None;
        }
        let newest = |pick: fn(&VersionRange) -> &Option<String>| {
            covering
                .iter()
                .filter_map(|r| pick(r).clone())
                .max_by(|a, b| cmp_versions(a, b))
        };
        Some(Relevance {
            confidence: Confidence::Medium,
            fixed_in: newest(|r| &r.end_excluding),
            last_affected: newest(|r| &r.end_including),
        })
    }

    /// [`NvdCve::relevance`] for a keyword hit on a host of unknown family.
    pub fn applies_to(&self, product: &str, version: &str) -> Option<Confidence> {
        self.relevance(product, version, None, false)
            .map(|found| found.confidence)
    }
}

// ---------------------------------------------------------------------------
// Planning: which lookups a host needs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    /// `pkg:npm/lodash@4.17.20`; when set, name/ecosystem/version are unused.
    pub purl: Option<String>,
    pub name: String,
    pub ecosystem: String,
    pub version: String,
    /// False when the package was only guessed from a file name.
    pub declared: bool,
}

impl Package {
    pub fn label(&self) -> String {
        match &self.purl {
            Some(purl) => purl.clone(),
            None => format!("{}@{} ({})", self.name, self.version, self.ecosystem),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Cpe {
        cpe: String,
        port: String,
    },
    Keyword {
        product: String,
        version: String,
        port: String,
    },
    Package {
        package: Package,
        port: Option<String>,
    },
}

static PURL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"pkg:[a-z][a-z0-9.+-]*/[^\s"'@,;)]+@[^\s"',;)?#]+"#).expect("valid regex")
});
static JS_LIBRARY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^([a-z][a-z0-9]*(?:[-.][a-z][a-z0-9]*)*)[-.@]v?(\d+(?:\.\d+){1,3})(?:[.-]min)?\.js$",
    )
    .expect("valid regex")
});

/// Front-end libraries whose file names reliably identify an npm package.
const KNOWN_JS: &[&str] = &[
    "jquery",
    "jquery-ui",
    "bootstrap",
    "angular",
    "vue",
    "react",
    "react-dom",
    "lodash",
    "underscore",
    "moment",
    "handlebars",
    "backbone",
    "ember",
    "knockout",
    "d3",
    "axios",
    "dompurify",
    "tinymce",
    "ckeditor",
    "swagger-ui",
    "select2",
    "datatables",
    "mustache",
    "prototype",
    "dojo",
];

fn first_token(text: &str) -> Option<String> {
    let token = text.split_whitespace().next()?;
    token
        .chars()
        .next()?
        .is_ascii_digit()
        .then(|| token.to_owned())
}

const MAX_LOOKUPS_PER_HOST: usize = 64;

fn is_safe_keyword_token(s: &str, allow_spaces: bool) -> bool {
    let trimmed = s.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 80
        && !trimmed.starts_with('-')
        && !trimmed.contains("://")
        && trimmed.chars().any(|c| c.is_ascii_alphanumeric())
        && trimmed.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '_' | '+' | '-' | '~')
                || (allow_spaces && c == ' ')
        })
}

/// Decides which lookups a host's evidence justifies. Only open ports and
/// software with a known version are looked up: a product without a
/// version would match thousands of unrelated CVEs.
pub fn plan(host: &Host) -> Vec<Lookup> {
    plan_split(host, |_| true).0
}

/// [`plan`] in two parts: the lookups for the open ports `own` accepts and
/// the operator's notes, then those for the host's other open ports, within
/// the same limit.
pub fn plan_split(host: &Host, own: impl Fn(&Port) -> bool) -> (Vec<Lookup>, Vec<Lookup>) {
    let mut out: Vec<Lookup> = Vec::new();
    for port in host.open_ports().filter(|port| own(port)) {
        plan_port(port, &mut out);
    }
    // Package URLs the operator wrote into notes.
    for fact in &host.facts {
        if fact.record.source != Source::ManualNote {
            continue;
        }
        for found in PURL.find_iter(&fact.claim) {
            push_lookup(
                &mut out,
                Lookup::Package {
                    package: Package {
                        purl: Some(found.as_str().to_owned()),
                        name: String::new(),
                        ecosystem: String::new(),
                        version: String::new(),
                        declared: true,
                    },
                    port: None,
                },
            );
        }
    }
    let first = out.len();
    for port in host.open_ports().filter(|port| !own(port)) {
        plan_port(port, &mut out);
    }
    let rest = out.split_off(first);
    (out, rest)
}

fn push_lookup(out: &mut Vec<Lookup>, lookup: Lookup) {
    if out.len() < MAX_LOOKUPS_PER_HOST && !out.contains(&lookup) {
        out.push(lookup);
    }
}

/// The lookups one open port justifies.
fn plan_port(port: &Port, out: &mut Vec<Lookup>) {
    let key = port.key();
    let mut keyworded = false;
    for name in &port.cpes {
        let Some(parts) = cpe::parts(name) else {
            continue;
        };
        let Some(reported) = parts.version else {
            continue;
        };
        // Nmap reports Windows OpenSSH as version `for_windows_9.5`,
        // which no database entry is written against.
        let version = cpe::clean_version(&reported);
        let cpe = (version != reported)
            .then(|| cpe::with_version(name, &version))
            .flatten()
            .unwrap_or_else(|| name.clone());
        push_lookup(
            out,
            Lookup::Cpe {
                cpe,
                port: key.clone(),
            },
        );
        let product = parts.product.replace('_', " ");
        if is_safe_keyword_token(&product, true) && is_safe_keyword_token(&version, false) {
            push_lookup(
                out,
                Lookup::Keyword {
                    product,
                    version,
                    port: key.clone(),
                },
            );
            if parts.part == 'a' {
                keyworded = true;
            }
        }
    }
    if !keyworded {
        if let (Some(product), Some(version)) =
            (&port.product, port.version.as_deref().and_then(first_token))
        {
            if is_safe_keyword_token(product, true) && is_safe_keyword_token(&version, false) {
                push_lookup(
                    out,
                    Lookup::Keyword {
                        product: product.clone(),
                        version,
                        port: key.clone(),
                    },
                );
            }
        }
    }
    for (path, _) in port.paths.walk() {
        let file = path.rsplit('/').next().unwrap_or("");
        let Some(found) = JS_LIBRARY.captures(file) else {
            continue;
        };
        let name = found[1].to_ascii_lowercase().replace('.', "-");
        if KNOWN_JS.contains(&name.as_str()) {
            push_lookup(
                out,
                Lookup::Package {
                    package: Package {
                        purl: None,
                        name,
                        ecosystem: "npm".to_owned(),
                        version: found[2].to_owned(),
                        declared: false,
                    },
                    port: Some(key.clone()),
                },
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Grounding {
    pub advisories: Vec<Advisory>,
    /// Host-level facts (for example "CVE-x is listed in CISA KEV").
    pub facts: Vec<Fact>,
    pub lookups: usize,
    /// True when pagination caps, detail caps, or detail fetch errors left
    /// the lookup incomplete so stale advisories should not be pruned.
    pub partial: bool,
    /// One line per lookup that failed.
    pub errors: Vec<String>,
}

pub struct CveClient {
    http: reqwest::Client,
    local_http: reqwest::Client,
    settings: CveSettings,
    db: Arc<Mutex<Db>>,
    nvd_pace: Duration,
    /// Serialises NVD requests and remembers when the last one was sent.
    nvd_gate: tokio::sync::Mutex<Option<Instant>>,
}

/// The most that is read of one answer, by what real answers need: a page
/// of 200 NVD records, the whole KEV catalog, an OSV answer or record.
const NVD_MAX_BYTES: usize = 16 * 1024 * 1024;
const KEV_MAX_BYTES: usize = 8 * 1024 * 1024;
const OSV_MAX_BYTES: usize = 4 * 1024 * 1024;
/// An OSV record larger than this is used and not kept in the cache.
const OSV_CACHE_MAX: usize = 256 * 1024;
/// Real answers are mostly text: far more than this many bytes for each
/// value they hold. One made of nothing but tiny values costs about ninety
/// times its size in memory once it is read into a tree.
const MIN_BYTES_PER_VALUE: usize = 8;
const NVD_PAGE_SIZE: usize = 200;
const NVD_MAX_PAGES: usize = 5;

fn cache_key(kind: &str, value: &str) -> String {
    format!("{kind}:{}", value.to_ascii_lowercase())
}

/// Roughly how many values a JSON text holds: the commas, colons and
/// opening brackets outside its strings.
fn value_count(json: &[u8]) -> usize {
    let (mut count, mut in_string, mut escaped) = (0usize, false, false);
    for byte in json {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b',' | b':' | b'[' | b'{' => count += 1,
                _ => {}
            }
        }
    }
    count
}

/// Reads one answer of at most `max` bytes as JSON. A request error is
/// reported without its address: a mirror's address may hold a key.
async fn read_json_bounded(
    mut response: reqwest::Response,
    label: &str,
    max: usize,
) -> Result<Value> {
    let too_large = || anyhow!("{label} answered with more than {} MB", max / (1024 * 1024));
    if response
        .content_length()
        .is_some_and(|len| len > max as u64)
    {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("failed reading {label} response"))?
    {
        if bytes.len() + chunk.len() > max {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    if value_count(&bytes).saturating_mul(MIN_BYTES_PER_VALUE) > bytes.len().max(64 * 1024) {
        bail!("{label} sent an answer that is almost all structure and no content; not read");
    }
    serde_json::from_slice(&bytes).with_context(|| format!("{label} sent invalid JSON"))
}

fn validate_osv_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || matches!(id, "." | "..")
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("refusing invalid OSV vulnerability id '{id}'");
    }
    Ok(())
}

fn extract_osv_versions(details: &Value, package: &Package) -> (Option<String>, Option<String>) {
    let Some(affected) = details.get("affected").and_then(Value::as_array) else {
        return (None, None);
    };
    let (purl_base, purl_ver) = match package.purl.as_deref() {
        Some(purl) => {
            let core = purl.split(['?', '#']).next().unwrap_or(purl);
            match core.rsplit_once('@') {
                Some((base, ver)) => (Some(base), Some(ver)),
                None => (Some(core), None),
            }
        }
        None => (None, None),
    };
    let target_ver = if !package.version.is_empty() {
        Some(package.version.as_str())
    } else {
        purl_ver
    };

    let mut fixed_candidates: Vec<String> = Vec::new();
    let mut last_candidates: Vec<String> = Vec::new();

    for entry in affected {
        if let Some(pkg) = entry.get("package") {
            let matches_pkg = if let Some(base) = purl_base {
                text_field(pkg, "purl")
                    .is_some_and(|p| p.eq_ignore_ascii_case(base) || base.starts_with(&p))
                    || text_field(pkg, "name").is_some_and(|n| {
                        base.to_ascii_lowercase()
                            .ends_with(&format!("/{}", n.to_ascii_lowercase()))
                    })
            } else {
                let name_ok =
                    text_field(pkg, "name").is_none_or(|n| n.eq_ignore_ascii_case(&package.name));
                let eco_ok = package.ecosystem.is_empty()
                    || text_field(pkg, "ecosystem")
                        .is_none_or(|e| e.eq_ignore_ascii_case(&package.ecosystem));
                name_ok && eco_ok
            };
            if !matches_pkg {
                continue;
            }
        }
        for range in entry
            .get("ranges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(kind) = text_field(range, "type") else {
                continue;
            };
            if !matches!(kind.as_str(), "SEMVER" | "ECOSYSTEM") {
                continue;
            }
            let mut intro: Option<String> = None;
            for event in range
                .get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(i) = text_field(event, "introduced") {
                    intro = Some(i);
                } else if let Some(fixed) = text_field(event, "fixed") {
                    let covers = match target_ver {
                        Some(ver) => {
                            let after_intro = intro
                                .as_deref()
                                .is_none_or(|i| i == "0" || cmp_versions(ver, i) != Ordering::Less);
                            after_intro && cmp_versions(ver, &fixed) == Ordering::Less
                        }
                        None => true,
                    };
                    if covers {
                        fixed_candidates.push(fixed);
                    }
                    intro = None;
                } else if let Some(last) = text_field(event, "last_affected") {
                    let covers = match target_ver {
                        Some(ver) => {
                            let after_intro = intro
                                .as_deref()
                                .is_none_or(|i| i == "0" || cmp_versions(ver, i) != Ordering::Less);
                            after_intro && cmp_versions(ver, &last) != Ordering::Greater
                        }
                        None => true,
                    };
                    if covers {
                        last_candidates.push(last);
                    }
                    intro = None;
                }
            }
        }
    }

    let fixed_in = fixed_candidates
        .into_iter()
        .min_by(|a, b| cmp_versions(a, b));
    let last_affected = last_candidates
        .into_iter()
        .max_by(|a, b| cmp_versions(a, b));
    (fixed_in, last_affected)
}

impl CveClient {
    pub fn new(settings: CveSettings, db: Arc<Mutex<Db>>) -> Result<Self> {
        crate::ai::validate_cloud_url(&settings.nvd_url).context("invalid cve.nvd_url")?;
        crate::ai::validate_cloud_url(&settings.osv_url).context("invalid cve.osv_url")?;
        crate::ai::validate_cloud_url(&settings.kev_url).context("invalid cve.kev_url")?;
        let build = |local: bool| {
            let mut builder = reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .read_timeout(STALL_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .user_agent("security-audit-client");
            if local {
                builder = builder
                    .no_proxy()
                    .resolve("localhost", std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
            }
            builder.build().context("cannot create the HTTP client")
        };
        let nvd_pace = settings.nvd_pace();
        Ok(Self {
            http: build(false)?,
            local_http: build(true)?,
            settings,
            db,
            nvd_pace,
            nvd_gate: tokio::sync::Mutex::new(None),
        })
    }

    fn client(&self, url: &str) -> &reqwest::Client {
        if crate::ai::is_loopback_url(url) {
            &self.local_http
        } else {
            &self.http
        }
    }

    /// Overrides the NVD pacing interval (tests).
    pub fn with_nvd_pace(mut self, pace: Duration) -> Self {
        self.nvd_pace = pace;
        self
    }

    /// Seconds the NVD lookups for `lookups` will take at the current pace,
    /// ignoring cached answers.
    pub fn estimate(&self, lookups: &[Lookup]) -> Duration {
        let nvd = lookups
            .iter()
            .filter(|l| !matches!(l, Lookup::Package { .. }))
            .count();
        self.nvd_pace * nvd as u32
    }

    fn cached(&self, key: &str, ttl: Duration) -> Option<String> {
        self.db
            .lock()
            .ok()?
            .cache_get(key, Some(ttl))
            .ok()
            .flatten()
    }

    fn stale(&self, key: &str) -> Option<String> {
        self.db.lock().ok()?.cache_get(key, None).ok().flatten()
    }

    fn store(&self, key: &str, body: &str) {
        if let Ok(db) = self.db.lock() {
            let _ = db.cache_put(key, body);
        }
    }

    async fn nvd_query_paged(&self, param: &str, value: &str) -> Result<(Vec<NvdCve>, bool)> {
        crate::ai::validate_cloud_url(&self.settings.nvd_url)?;
        // `nvd2`: answers cached before platform conditions were kept are
        // not reused.
        let key = cache_key(&format!("nvd2:{param}"), value);
        if let Some(found) = self
            .cached(&key, DAY)
            .and_then(|body| serde_json::from_str::<Vec<NvdCve>>(&body).ok())
        {
            let maybe_truncated = found.len() >= NVD_PAGE_SIZE * NVD_MAX_PAGES;
            return Ok((found, maybe_truncated));
        }
        let mut found: Vec<NvdCve> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut start_index = 0usize;
        let mut truncated = true;
        for _ in 0..NVD_MAX_PAGES {
            let body = {
                let mut last = self.nvd_gate.lock().await;
                if let Some(sent) = *last {
                    tokio::time::sleep(self.nvd_pace.saturating_sub(sent.elapsed())).await;
                }
                let mut request = self
                    .client(&self.settings.nvd_url)
                    .get(&self.settings.nvd_url)
                    .query(&[(param, value), ("resultsPerPage", "200")]);
                if start_index > 0 {
                    let start = start_index.to_string();
                    request = request.query(&[("startIndex", start.as_str())]);
                }
                if param == "cpeName" {
                    // Leave out records that name the product only as the
                    // platform something else runs on.
                    request = request.query(&[("isVulnerable", "")]);
                }
                if let Some(api_key) = self.settings.api_key() {
                    if crate::ai::is_loopback_url(&self.settings.nvd_url) {
                        if let Some(why) = crate::ai::not_own_server(&self.settings.nvd_url) {
                            bail!("refusing to send the NVD API key to a loopback address: {why}");
                        }
                    }
                    let mut val = reqwest::header::HeaderValue::from_str(api_key)
                        .context("invalid characters in NVD API key")?;
                    val.set_sensitive(true);
                    request = request.header("apiKey", val);
                }
                let response = request.send().await;
                *last = Some(Instant::now());
                let response = response
                    .map_err(reqwest::Error::without_url)
                    .context("NVD request failed")?;
                if !response.status().is_success() {
                    bail!("NVD answered HTTP {}", response.status());
                }
                read_json_bounded(response, "NVD", NVD_MAX_BYTES).await?
            };
            let page_items = body
                .get("vulnerabilities")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            let total = body
                .get("totalResults")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            // A page holds the 200 records that were asked for. More than
            // that is not NVD answering, and is not read further.
            if page_items > NVD_PAGE_SIZE {
                bail!("NVD answered with {page_items} records on a page of {NVD_PAGE_SIZE}");
            }
            for cve in parse_nvd(&body) {
                if seen.insert(cve.id.clone()) {
                    found.push(cve);
                }
            }
            start_index += page_items;
            if page_items < NVD_PAGE_SIZE || start_index >= total {
                truncated = false;
                break;
            }
        }
        self.store(&key, &serde_json::to_string(&found)?);
        Ok((found, truncated))
    }

    pub async fn nvd_by_cpe(&self, cpe23: &str) -> Result<Vec<NvdCve>> {
        self.nvd_query_paged("cpeName", cpe23).await.map(|(v, _)| v)
    }

    pub async fn nvd_by_keyword(&self, product: &str, version: &str) -> Result<Vec<NvdCve>> {
        self.nvd_query_paged("keywordSearch", &format!("{product} {version}"))
            .await
            .map(|(v, _)| v)
    }

    /// CVE ids in the CISA KEV catalog, from a local copy refreshed every
    /// seven days. A stale copy is used when the download fails.
    pub async fn kev(&self) -> Result<BTreeSet<String>> {
        const KEY: &str = "cisa_kev";
        let parse = |body: &str| serde_json::from_str::<BTreeSet<String>>(body).ok();
        if let Some(found) = self.cached(KEY, KEV_TTL).as_deref().and_then(parse) {
            return Ok(found);
        }
        let fetched: Result<Value> = async {
            crate::ai::validate_cloud_url(&self.settings.kev_url)?;
            let response = self
                .client(&self.settings.kev_url)
                .get(&self.settings.kev_url)
                .send()
                .await
                .map_err(reqwest::Error::without_url)?;
            if !response.status().is_success() {
                bail!("HTTP {}", response.status());
            }
            read_json_bounded(response, "CISA KEV", KEV_MAX_BYTES).await
        }
        .await;
        match fetched {
            Ok(body) => {
                let ids: BTreeSet<String> = body
                    .get("vulnerabilities")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|v| text_field(v, "cveID"))
                    .collect();
                self.store(KEY, &serde_json::to_string(&ids)?);
                Ok(ids)
            }
            Err(error) => match self.stale(KEY).as_deref().and_then(parse) {
                Some(found) => Ok(found),
                None => Err(error.context(
                    "cannot download the CISA KEV catalog, so known-exploited flags are missing",
                )),
            },
        }
    }

    async fn osv_batch_paged(&self, packages: &[Package]) -> Result<(Vec<(usize, String)>, bool)> {
        crate::ai::validate_cloud_url(&self.settings.osv_url)?;
        let url = format!(
            "{}/v1/querybatch",
            self.settings.osv_url.trim_end_matches('/')
        );
        let query = |package: &Package, token: Option<&str>| {
            let mut query = match &package.purl {
                Some(purl) => json!({ "package": { "purl": purl } }),
                None => json!({
                    "package": { "name": package.name, "ecosystem": package.ecosystem },
                    "version": package.version,
                }),
            };
            if let Some(token) = token {
                query["page_token"] = json!(token);
            }
            query
        };
        let mut pending: Vec<(usize, Option<String>)> =
            (0..packages.len()).map(|i| (i, None)).collect();
        let mut found = Vec::new();
        for _ in 0..OSV_MAX_PAGES {
            if pending.is_empty() {
                break;
            }
            let queries: Vec<Value> = pending
                .iter()
                .map(|(i, t)| query(&packages[*i], t.as_deref()))
                .collect();
            let response = self
                .client(&url)
                .post(&url)
                .json(&json!({ "queries": queries }))
                .send()
                .await
                .map_err(reqwest::Error::without_url)
                .context("OSV request failed")?;
            if !response.status().is_success() {
                bail!("OSV answered HTTP {}", response.status());
            }
            let body: Value = read_json_bounded(response, "OSV", OSV_MAX_BYTES).await?;
            let results = body
                .get("results")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut next = Vec::new();
            for ((index, _), result) in pending.iter().zip(&results) {
                for vuln in result
                    .get("vulns")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(id) = text_field(vuln, "id") {
                        found.push((*index, id));
                    }
                }
                if let Some(token) = text_field(result, "next_page_token") {
                    next.push((*index, Some(token)));
                }
            }
            pending = next;
        }
        Ok((found, !pending.is_empty()))
    }

    /// Queries OSV for several packages at once, following
    /// `next_page_token`. Returns `(package index, vulnerability id)` pairs.
    pub async fn osv_batch(&self, packages: &[Package]) -> Result<Vec<(usize, String)>> {
        self.osv_batch_paged(packages).await.map(|(found, _)| found)
    }

    /// Full OSV record for one id (cached for a day).
    pub async fn osv_details(&self, id: &str) -> Result<Value> {
        validate_osv_id(id)?;
        crate::ai::validate_cloud_url(&self.settings.osv_url)?;
        let key = cache_key("osv", id);
        if let Some(found) = self
            .cached(&key, DAY)
            .and_then(|body| serde_json::from_str(&body).ok())
        {
            return Ok(found);
        }
        let url = format!(
            "{}/v1/vulns/{id}",
            self.settings.osv_url.trim_end_matches('/')
        );
        let response = self
            .client(&url)
            .get(&url)
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("OSV request failed")?;
        if !response.status().is_success() {
            bail!("OSV answered HTTP {} for {id}", response.status());
        }
        let body: Value = read_json_bounded(response, "OSV", OSV_MAX_BYTES).await?;
        // A record is a few kilobytes. One far larger is used this once and
        // not kept: the cache does not grow by megabytes per advisory.
        let text = body.to_string();
        if text.len() <= OSV_CACHE_MAX {
            self.store(&key, &text);
        }
        Ok(body)
    }

    /// Runs every lookup [`plan`] produces for `host`. Never fails as a
    /// whole: problems are reported per lookup in [`Grounding::errors`], and
    /// after two consecutive failures NVD lookups stop so an offline or
    /// rate-limited session is not kept waiting.
    pub async fn ground(&self, host: &Host) -> Grounding {
        self.ground_lookups(host, plan(host)).await
    }

    /// [`Self::ground`] with only `lookups`, a part of what [`plan`] gave.
    pub async fn ground_lookups(&self, host: &Host, lookups: Vec<Lookup>) -> Grounding {
        let mut grounding = Grounding {
            lookups: lookups.len(),
            ..Grounding::default()
        };
        if lookups.is_empty() {
            return grounding;
        }
        let kev = match self.kev().await {
            Ok(ids) => ids,
            Err(error) => {
                grounding.errors.push(format!("{error:#}"));
                BTreeSet::new()
            }
        };

        let family = host_family(host);
        let mut packages: Vec<(Package, Option<String>)> = Vec::new();
        // One slow answer is not an outage: the next lookup is still tried.
        // After a second failure NVD is skipped; OSV is only skipped when
        // transport itself failed (not when NVD returned HTTP 429/5xx).
        let mut nvd_failures = 0usize;
        let mut transport_failures = 0usize;
        let mut nvd_stopped = false;
        let mut network_offline = false;
        for lookup in &lookups {
            let (query, product, version, port) = match lookup {
                Lookup::Package { package, port } => {
                    packages.push((package.clone(), port.clone()));
                    continue;
                }
                Lookup::Cpe { cpe, port } => {
                    let Some(parts) = cpe::parts(cpe) else {
                        continue;
                    };
                    (
                        format!("cpeName={cpe}"),
                        parts.product,
                        parts.version.unwrap_or_default(),
                        port,
                    )
                }
                Lookup::Keyword {
                    product,
                    version,
                    port,
                } => (
                    format!("keywordSearch={product} {version}"),
                    product.clone(),
                    version.clone(),
                    port,
                ),
            };
            if nvd_stopped {
                grounding.partial = true;
                continue;
            }
            let matched_by_nvd = matches!(lookup, Lookup::Cpe { .. });
            let result = match lookup {
                Lookup::Cpe { cpe, .. } => self.nvd_query_paged("cpeName", cpe).await,
                _ => {
                    self.nvd_query_paged("keywordSearch", &format!("{product} {version}"))
                        .await
                }
            };
            let (found, truncated) = match result {
                Ok(pair) => pair,
                Err(error) => {
                    let msg = format!("{error:#}");
                    let is_http_status = msg.contains("NVD answered HTTP ");
                    grounding.errors.push(format!("{query}: {msg}"));
                    nvd_failures += 1;
                    nvd_stopped = nvd_failures >= 2;
                    if !is_http_status {
                        transport_failures += 1;
                        network_offline = transport_failures >= 2;
                    }
                    continue;
                }
            };
            if truncated {
                grounding.partial = true;
            }
            for cve in found {
                // NVD matched cpeName itself, but also returns records that
                // name the product only as a platform, or only on another
                // operating system; keyword hits are checked in full.
                let Some(relevance) = cve.relevance(&product, &version, family, matched_by_nvd)
                else {
                    continue;
                };
                let backport = backport_note_for(host, Some(port));
                let evidence = json!({
                    "query": query,
                    "id": cve.id,
                    "vulnStatus": cve.status,
                    "cvss": cve.cvss,
                    "distro_backport_note": backport,
                })
                .to_string();
                push_advisory(
                    &mut grounding,
                    Advisory {
                        kev: cve.kev || kev.contains(&cve.id),
                        id: cve.id,
                        title: cve.description,
                        severity: cve.severity,
                        cvss: cve.cvss,
                        matched: query.clone(),
                        port: Some(port.clone()),
                        references: cve.references,
                        fixed_in: relevance.fixed_in,
                        last_affected: relevance.last_affected,
                        record: EvidenceRecord::observed(
                            Source::NvdApi,
                            relevance.confidence,
                            &evidence,
                        ),
                    },
                );
            }
        }

        if !packages.is_empty() {
            if network_offline {
                grounding.partial = true;
            } else {
                let list: Vec<Package> = packages.iter().map(|(p, _)| p.clone()).collect();
                match self.osv_batch_paged(&list).await {
                    Ok((hits, page_truncated)) => {
                        if page_truncated || hits.len() > OSV_MAX_DETAILS {
                            grounding.partial = true;
                        }
                        for (index, id) in hits.into_iter().take(OSV_MAX_DETAILS) {
                            let (package, port) = &packages[index];
                            let details = match self.osv_details(&id).await {
                                Ok(details) => details,
                                Err(_) => {
                                    grounding.partial = true;
                                    Value::Null
                                }
                            };
                            let (fixed_in, last_affected) = extract_osv_versions(&details, package);
                            let aliases: Vec<String> = details
                                .get("aliases")
                                .and_then(Value::as_array)
                                .into_iter()
                                .flatten()
                                .filter_map(|a| a.as_str().map(str::to_owned))
                                .collect();
                            let title = text_field(&details, "summary")
                                .or_else(|| text_field(&details, "details"))
                                .unwrap_or_else(|| format!("{id} affects {}", package.label()));
                            let confidence = if package.declared {
                                Confidence::Medium
                            } else {
                                Confidence::Low
                            };
                            let evidence =
                                json!({ "query": package.label(), "id": id, "aliases": aliases })
                                    .to_string();
                            push_advisory(
                                &mut grounding,
                                Advisory {
                                    kev: kev.contains(&id)
                                        || aliases.iter().any(|a| kev.contains(a)),
                                    id,
                                    title,
                                    severity: details
                                        .pointer("/database_specific/severity")
                                        .and_then(Value::as_str)
                                        .map(str::to_owned),
                                    cvss: None,
                                    matched: package.label(),
                                    fixed_in,
                                    last_affected,
                                    port: port.clone(),
                                    references: details
                                        .get("references")
                                        .and_then(Value::as_array)
                                        .into_iter()
                                        .flatten()
                                        .filter_map(|r| text_field(r, "url"))
                                        .take(MAX_REFERENCES)
                                        .collect(),
                                    record: EvidenceRecord::observed(
                                        Source::OsvApi,
                                        confidence,
                                        &evidence,
                                    ),
                                },
                            );
                        }
                    }
                    Err(error) => grounding.errors.push(format!("OSV: {error:#}")),
                }
            }
        }

        for advisory in grounding.advisories.iter().filter(|a| a.kev) {
            grounding.facts.push(Fact {
                claim: format!(
                    "{} is listed in the CISA Known Exploited Vulnerabilities catalog",
                    advisory.id
                ),
                record: EvidenceRecord::observed(Source::CisaKev, Confidence::High, &advisory.id),
            });
        }
        grounding
    }
}

impl Lookup {
    /// What is asked: the same software asked about for two hosts is one
    /// question, answered the second time from the cache.
    fn question(&self) -> String {
        match self {
            Lookup::Cpe { cpe, .. } => format!("cpe {cpe}"),
            Lookup::Keyword {
                product, version, ..
            } => format!("keyword {product} {version}"),
            Lookup::Package { package, .. } => format!("package {}", package.label()),
        }
    }
}

/// Who asked for a host's CVE lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asked {
    /// The operator: looked up first, as many as needed.
    Operator,
    /// A recon task, for the open ports its own scans reported (`22/tcp`):
    /// those first, as many as needed. The host's other ports are known
    /// from text, and are looked up as text is.
    Recon(BTreeSet<String>),
    /// Terminal text or an imported file, which anyone can write: looked up
    /// after the rest, and only so many new questions per session.
    Text,
}

impl Asked {
    /// Who asked, when two did: the operator before a recon task before
    /// text; two recon tasks for the ports of both.
    fn and(self, other: Asked) -> Asked {
        match (self, other) {
            (Asked::Operator, _) | (_, Asked::Operator) => Asked::Operator,
            (Asked::Recon(mut ports), Asked::Recon(more)) => {
                ports.extend(more);
                Asked::Recon(ports)
            }
            (Asked::Recon(ports), Asked::Text) | (Asked::Text, Asked::Recon(ports)) => {
                Asked::Recon(ports)
            }
            (Asked::Text, Asked::Text) => Asked::Text,
        }
    }
}

/// New questions terminal text and imports may ask in one session. NVD
/// answers one every 6.5 s without a key: about half an hour of lookups.
pub const TEXT_QUESTIONS: usize = 256;
/// Hosts waiting for their lookups in each queue, at most (a graph holds
/// 4096): text cannot hold up what the operator asks for.
const MAX_WAITING: usize = 4096;

/// The hosts waiting for CVE lookups: those the operator or a recon task
/// asked for first, each host once, and what text may still ask.
#[derive(Debug)]
pub struct GroundQueue {
    first: std::collections::VecDeque<String>,
    later: std::collections::VecDeque<String>,
    /// Each waiting host, and who asked for it.
    waiting: std::collections::HashMap<String, Asked>,
    /// Questions text asked this session, and how many more it may ask.
    asked: std::collections::HashSet<String>,
    left: usize,
}

impl GroundQueue {
    pub fn new(text_questions: usize) -> Self {
        Self {
            first: std::collections::VecDeque::new(),
            later: std::collections::VecDeque::new(),
            waiting: std::collections::HashMap::new(),
            asked: std::collections::HashSet::new(),
            left: text_questions,
        }
    }

    /// Queues `address`; false when it waits already or its queue is full.
    /// The operator or a recon task asking for a host that text queued
    /// moves it forward.
    pub fn push(&mut self, address: &str, asked: Asked) -> bool {
        let first = asked != Asked::Text;
        let queue = if first { &self.first } else { &self.later };
        if queue.len() >= MAX_WAITING {
            return false;
        }
        if let Some(waits) = self.waiting.get_mut(address) {
            let moves = first && *waits == Asked::Text;
            *waits = std::mem::replace(waits, Asked::Text).and(asked);
            if moves {
                if let Some(at) = self.later.iter().position(|a| a == address) {
                    self.later.remove(at);
                }
                self.first.push_back(address.to_owned());
            }
            return moves;
        }
        self.waiting.insert(address.to_owned(), asked);
        if first {
            self.first.push_back(address.to_owned());
        } else {
            self.later.push_back(address.to_owned());
        }
        true
    }

    /// The next host to look up, the operator's and recon's first.
    pub fn pop(&mut self) -> Option<(String, Asked)> {
        let address = match self.first.pop_front() {
            Some(address) => address,
            None => self.later.pop_front()?,
        };
        let asked = self.waiting.remove(&address).unwrap_or(Asked::Text);
        Some((address, asked))
    }

    /// The lookups text may make for a host: questions already asked this
    /// session (answered from the cache), and new ones while any are left.
    /// Also says whether any were left out.
    pub fn allow(&mut self, lookups: Vec<Lookup>) -> (Vec<Lookup>, bool) {
        let mut cut = false;
        let mut kept = Vec::with_capacity(lookups.len());
        for lookup in lookups {
            let question = lookup.question();
            if !self.asked.contains(&question) {
                if self.left == 0 {
                    cut = true;
                    continue;
                }
                self.left -= 1;
                self.asked.insert(question);
            }
            kept.push(lookup);
        }
        (kept, cut)
    }
}

/// What grounding a whole graph added.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GraphGrounding {
    pub hosts: usize,
    pub lookups: usize,
    pub new_advisories: usize,
    pub kev: usize,
    /// Earlier matches the databases no longer return.
    pub dropped: usize,
    pub errors: Vec<String>,
}

/// What merging one host's lookups into the graph changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Merged {
    pub added: usize,
    pub kev: usize,
    /// Earlier matches the databases no longer return for this host.
    pub dropped: usize,
}

/// Merges one host's grounding into the graph. After a lookup that reached
/// every source without truncation, earlier matches it did not return are
/// removed.
pub fn merge(graph: &mut crate::graph::Graph, address: &str, grounding: &Grounding) -> Merged {
    let mut merged = Merged::default();
    let known: BTreeSet<String> = graph
        .hosts
        .get(address)
        .map(|host| host.advisories.iter().map(|a| a.id.clone()).collect())
        .unwrap_or_default();
    for advisory in &grounding.advisories {
        if graph.add_advisory(address, advisory.clone()) && !known.contains(&advisory.id) {
            merged.added += 1;
            merged.kev += usize::from(advisory.kev);
        }
    }
    for fact in &grounding.facts {
        graph.add_host_fact(address, fact.clone());
    }
    if grounding.lookups > 0 && grounding.errors.is_empty() && !grounding.partial {
        let current: BTreeSet<String> = grounding.advisories.iter().map(|a| a.id.clone()).collect();
        merged.dropped = graph.drop_stale_advisories(address, &current);
    }
    merged
}

/// One piece of software on a host and what to do about its CVEs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixItem {
    /// `Apache httpd 2.4.34`
    pub software: String,
    pub port: Option<String>,
    pub advisories: usize,
    pub kev: usize,
    /// `2.4.69 or later`
    pub target: String,
    /// The whole instruction, as one sentence.
    pub action: String,
}

impl FixItem {
    /// What the update answers: `3 CVEs, 1 known exploited`.
    pub fn counts(&self) -> String {
        let noun = if self.advisories == 1 { "CVE" } else { "CVEs" };
        match self.kev {
            0 => format!("{} {noun}", self.advisories),
            kev => format!("{} {noun}, {kev} known exploited", self.advisories),
        }
    }
}

/// The rating of a CVE as a word (`Critical`, `High`, `Medium`, `Low`):
/// the database's own, or else the one its CVSS score falls in.
pub fn severity_word(advisory: &Advisory) -> Option<String> {
    let named = advisory
        .severity
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(word) = named {
        let known = match word.to_ascii_uppercase().as_str() {
            "CRITICAL" => "Critical",
            "HIGH" => "High",
            "MEDIUM" | "MODERATE" => "Medium",
            "LOW" => "Low",
            "NONE" => "None",
            _ => return Some(word.to_owned()),
        };
        return Some(known.to_owned());
    }
    let score = advisory.cvss?;
    Some(
        match score {
            s if s >= 9.0 => "Critical",
            s if s >= 7.0 => "High",
            s if s >= 4.0 => "Medium",
            s if s > 0.0 => "Low",
            _ => "None",
        }
        .to_owned(),
    )
}

/// `High 7.7`, `Critical`, `5.3`: the rating and the CVSS score, or
/// `unrated`.
pub fn severity_label(advisory: &Advisory) -> String {
    match (severity_word(advisory), advisory.cvss) {
        (Some(word), Some(score)) => format!("{word} {score:.1}"),
        (Some(word), None) => word,
        (None, Some(score)) => format!("{score:.1}"),
        (None, None) => "unrated".to_owned(),
    }
}

/// The CVSS score, or one that stands for the rating word when there is none.
fn score(advisory: &Advisory) -> f64 {
    advisory
        .cvss
        .unwrap_or_else(|| match severity_word(advisory).as_deref() {
            Some("Critical") => 9.0,
            Some("High") => 7.0,
            Some("Medium") => 4.0,
            Some("Low") => 0.1,
            _ => 0.0,
        })
}

/// Known exploited, or rated critical or high: drawn red on the map.
pub fn is_serious(advisory: &Advisory) -> bool {
    advisory.kev
        || matches!(
            severity_word(advisory).as_deref(),
            Some("Critical" | "High")
        )
}

/// Most urgent first: known exploited, then by score, then by ID.
pub fn cmp_urgency(a: &Advisory, b: &Advisory) -> Ordering {
    b.kev
        .cmp(&a.kev)
        .then(score(b).total_cmp(&score(a)))
        .then(a.id.cmp(&b.id))
}

/// Why the version of a service on this host may say little: its
/// distribution backports security fixes without changing the version.
pub fn backport_note_for(host: &Host, port_key: Option<&str>) -> Option<&'static str> {
    if let Some(p) = port_key.and_then(|key| host.ports.get(key)) {
        for field in [
            p.version.as_deref(),
            p.extra_info.as_deref(),
            p.http.as_ref().and_then(|h| h.server.as_deref()),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(note) = crate::osint::distro_backport_note(field) {
                return Some(note);
            }
        }
    }
    host.os
        .as_deref()
        .and_then(crate::osint::distro_backport_note)
}

/// The CVEs found from one piece of software on a host.
#[derive(Debug, Clone, PartialEq)]
pub struct CveGroup<'a> {
    /// `nginx 1.18.0`, `jquery@3.4.1 (npm)`
    pub software: String,
    /// The port the software was seen on, if any.
    pub port: Option<String>,
    /// Most urgent first.
    pub cves: Vec<&'a Advisory>,
}

impl CveGroup<'_> {
    fn newest(&self, pick: fn(&Advisory) -> &Option<String>) -> Option<String> {
        self.cves
            .iter()
            .filter_map(|a| pick(a).clone())
            .max_by(|a, b| cmp_versions(a, b))
    }

    /// The first release that has none of them: `fixed in 1.20.1`, or
    /// `affected up to 1.21.0` when no fix past that is named.
    pub fn fix(&self) -> Option<String> {
        match (
            self.newest(|a| &a.fixed_in),
            self.newest(|a| &a.last_affected),
        ) {
            (Some(fixed), Some(last)) if cmp_versions(&last, &fixed) != Ordering::Less => {
                Some(format!("affected up to {last}"))
            }
            (Some(fixed), _) => Some(format!("fixed in {fixed}")),
            (None, Some(last)) => Some(format!("affected up to {last}")),
            (None, None) => None,
        }
    }

    /// What to update to: `1.20.1 or later`.
    pub fn target(&self) -> String {
        match (
            self.newest(|a| &a.fixed_in),
            self.newest(|a| &a.last_affected),
        ) {
            (Some(fixed), Some(last)) if cmp_versions(&last, &fixed) != Ordering::Less => {
                format!("a release newer than {last}")
            }
            (Some(fixed), _) => format!("{fixed} or later"),
            (None, Some(last)) => format!("a release newer than {last}"),
            (None, None) => "its newest release".to_owned(),
        }
    }

    pub fn kev(&self) -> usize {
        self.cves.iter().filter(|a| a.kev).count()
    }

    /// `nginx 1.18.0 · 443/tcp · fixed in 1.20.1`
    pub fn heading(&self) -> String {
        let mut parts = vec![self.software.clone()];
        parts.extend(self.port.clone());
        parts.extend(self.fix());
        parts.join(" \u{b7} ")
    }
}

/// The name and version of the software a CVE was found from.
fn software_of(host: &Host, advisory: &Advisory) -> String {
    let seen = advisory
        .port
        .as_ref()
        .and_then(|key| host.ports.get(key))
        .and_then(|port| {
            let product = port.product.as_deref()?;
            Some(match port.version.as_deref() {
                Some(version) => format!("{product} {version}"),
                None => product.to_owned(),
            })
        });
    if let Some(cpe) = advisory.matched.strip_prefix("cpeName=") {
        seen.or_else(|| {
            let parts = cpe::parts(cpe)?;
            Some(format!("{} {}", parts.product, parts.version?).replace('_', " "))
        })
        .unwrap_or_else(|| cpe.to_owned())
    } else if let Some(words) = advisory.matched.strip_prefix("keywordSearch=") {
        seen.unwrap_or_else(|| words.to_owned())
    } else {
        advisory.matched.clone()
    }
}

/// A host's CVEs grouped by the software and version they were found
/// from, the most urgent group first and the most urgent CVE first in each.
pub fn by_software(host: &Host) -> Vec<CveGroup<'_>> {
    let mut groups: Vec<CveGroup> = Vec::new();
    for advisory in &host.advisories {
        let software = software_of(host, advisory);
        match groups
            .iter_mut()
            .find(|g| g.software == software && g.port == advisory.port)
        {
            Some(group) => group.cves.push(advisory),
            None => groups.push(CveGroup {
                software,
                port: advisory.port.clone(),
                cves: vec![advisory],
            }),
        }
    }
    for group in &mut groups {
        group.cves.sort_by(|a, b| cmp_urgency(a, b));
    }
    groups.sort_by(|a, b| {
        cmp_urgency(a.cves[0], b.cves[0])
            .then(b.cves.len().cmp(&a.cves.len()))
            .then(a.software.cmp(&b.software))
    });
    groups
}

/// Groups a host's CVEs by the software they were found from: one update
/// usually answers all of them. In the order of [`by_software`], with the
/// same software on several ports as one update: `nginx 1.18.0` on 80/tcp
/// and 443/tcp is one program to update, to the release that fixes all.
pub fn fix_plan(host: &Host) -> Vec<FixItem> {
    let mut merged: Vec<CveGroup> = Vec::new();
    for group in by_software(host) {
        match merged.iter_mut().find(|m| m.software == group.software) {
            Some(first) => {
                first.port = match (first.port.take(), group.port) {
                    (Some(ports), Some(port)) => Some(format!("{ports}, {port}")),
                    // Seen without a port too: closing ports would not do.
                    _ => None,
                };
                first.cves.extend(group.cves);
            }
            None => merged.push(group),
        }
    }
    for group in &mut merged {
        if let Some(ports) = &group.port {
            let mut list: Vec<&str> = ports.split(", ").collect();
            list.sort_by_key(|port| {
                let number = port.split('/').next().and_then(|n| n.parse::<u32>().ok());
                (number.unwrap_or(u32::MAX), port.to_string())
            });
            list.dedup();
            group.port = Some(list.join(", "));
        }
    }
    merged
        .into_iter()
        .map(|group| {
            let target = group.target();
            let close = group
                .port
                .as_ref()
                .map(|port| format!(", or close {port} if the service is not needed"))
                .unwrap_or_default();
            FixItem {
                action: format!("Update {} to {target}{close}.", group.software),
                advisories: group.cves.len(),
                kev: group.kev(),
                software: group.software,
                port: group.port,
                target,
            }
        })
        .collect()
}

/// Grounds every host that has something to look up and merges the results
/// into the graph. Stops at the first host whose lookups fail, so an
/// offline machine is not kept waiting host after host.
pub async fn ground_graph(client: &CveClient, graph: &mut crate::graph::Graph) -> GraphGrounding {
    let mut summary = GraphGrounding::default();
    let addresses: Vec<String> = graph
        .hosts
        .values()
        .filter(|host| !plan(host).is_empty())
        .map(|host| host.address.clone())
        .collect();
    for address in addresses {
        let Some(host) = graph.hosts.get(&address).cloned() else {
            continue;
        };
        let grounding = client.ground(&host).await;
        summary.hosts += 1;
        summary.lookups += grounding.lookups;
        let merged = merge(graph, &address, &grounding);
        summary.new_advisories += merged.added;
        summary.kev += merged.kev;
        summary.dropped += merged.dropped;
        if !grounding.errors.is_empty() {
            summary.errors = grounding.errors;
            break;
        }
    }
    summary
}

/// Keeps one advisory per id, preferring the more confident match.
fn push_advisory(grounding: &mut Grounding, advisory: Advisory) {
    match grounding
        .advisories
        .iter_mut()
        .find(|a| a.id == advisory.id)
    {
        Some(existing) => {
            existing.kev |= advisory.kev;
            if advisory.record.confidence > existing.record.confidence {
                *existing = advisory;
            }
        }
        None => grounding.advisories.push(advisory),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Graph, Observation};
    use axum::extract::{Path, Query, State};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    #[test]
    fn versions_order_naturally() {
        use Ordering::*;
        for (a, b, expected) in [
            ("1.18.0", "1.18.0", Equal),
            ("1.9", "1.10", Less),
            ("8.2", "8.2p1", Less),
            ("8.2.0", "8.2p1", Less),
            ("8.2p1", "8.10", Less),
            ("1.1.1", "1.1.1k", Less),
            ("2.4.41", "2.4.9", Greater),
            ("1.0.0", "1.0", Equal),
            ("1.20.1-rc1", "1.20.1", Less),
            ("1.20.1-alpha", "1.20.1-beta", Less),
            ("1.2.3-beta", "1.2.3-rc", Less),
            ("2.4.52-1ubuntu4", "2.4.52", Equal),
            ("8.2p1-4ubuntu0.5", "8.2p1", Equal),
            ("v2.0", "2.0", Equal),
            ("10", "9.99.99", Greater),
        ] {
            assert_eq!(cmp_versions(a, b), expected, "{a} vs {b}");
            assert_eq!(cmp_versions(b, a), expected.reverse(), "{b} vs {a}");
        }
        assert!(validate_osv_id(".").is_err());
        assert!(validate_osv_id("..").is_err());
    }

    #[test]
    fn version_ranges_respect_every_bound() {
        let range = VersionRange {
            product: "nginx".into(),
            start_including: Some("1.0.0".into()),
            end_excluding: Some("1.20.1".into()),
            ..VersionRange::default()
        };
        assert!(range.covers("nginx", "1.18.0"));
        assert!(range.covers("NGINX", "1.0.0"));
        assert!(!range.covers("nginx", "1.20.1"));
        assert!(!range.covers("nginx", "0.9"));
        assert!(!range.covers("apache", "1.18.0"));
        let exact = VersionRange {
            product: "http_server".into(),
            exact: Some("2.4.49".into()),
            ..VersionRange::default()
        };
        assert!(exact.covers("http server", "2.4.49"));
        assert!(exact.covers("apache http server", "2.4.49"));
        assert!(!exact.covers("http server", "2.4.50"));
        let any = VersionRange {
            product: "openssh".into(),
            ..VersionRange::default()
        };
        assert!(any.covers("openssh", "3.1"));
    }

    fn nvd_body() -> Value {
        json!({ "vulnerabilities": [
            { "cve": {
                "id": "CVE-2021-23017", "vulnStatus": "Analyzed",
                "cisaExploitAdd": "2022-01-01",
                "descriptions": [
                    { "lang": "es", "value": "otro" },
                    { "lang": "en", "value": "A security issue in nginx resolver was identified." }
                ],
                "metrics": { "cvssMetricV31": [ { "cvssData": { "baseScore": 7.7, "baseSeverity": "HIGH" } } ] },
                "references": [ { "url": "https://example.test/advisory" } ],
                "configurations": [ { "nodes": [ { "cpeMatch": [
                    { "vulnerable": true, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                      "versionStartIncluding": "0.6.18", "versionEndExcluding": "1.20.1" },
                    { "vulnerable": false, "criteria": "cpe:2.3:o:fedora:fedora:33:*:*:*:*:*:*:*" }
                ] } ] } ]
            } },
            { "cve": {
                "id": "CVE-2026-1111", "vulnStatus": "Deferred",
                "descriptions": [ { "lang": "en", "value": "Heap overflow in the mp4 module." } ],
                "affected": [ { "vendor": "F5", "product": "nginx", "versions": [
                    { "version": "1.17.0", "lessThanOrEqual": "1.19.9", "status": "affected" },
                    { "version": "1.21.0", "status": "unaffected" }
                ] } ]
            } },
            { "cve": {
                "id": "CVE-2026-2222", "vulnStatus": "Awaiting Analysis",
                "descriptions": [ { "lang": "en", "value": "nginx 1.18.0 mishandles chunked bodies." } ],
                "metrics": { "cvssMetricV2": [ { "cvssData": { "baseScore": 5.0 }, "baseSeverity": "MEDIUM" } ] }
            } },
            { "cve": {
                "id": "CVE-2026-3333", "vulnStatus": "Awaiting Analysis",
                "descriptions": [ { "lang": "en", "value": "A plugin for nginx-ui 2.0 allows XSS; unrelated to 1.18.0x." } ]
            } },
            { "cve": {
                "id": "CVE-2019-9999", "vulnStatus": "Analyzed",
                "descriptions": [ { "lang": "en", "value": "Old nginx bug." } ],
                "configurations": [ { "nodes": [ { "cpeMatch": [
                    { "vulnerable": true, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "versionEndIncluding": "1.16.0" }
                ] } ] } ]
            } }
        ] })
    }

    #[test]
    fn nvd_records_are_reduced_and_matched() {
        let cves = parse_nvd(&nvd_body());
        assert_eq!(cves.len(), 5);
        let first = &cves[0];
        assert_eq!(
            first.description,
            "A security issue in nginx resolver was identified."
        );
        assert_eq!(
            (first.cvss, first.severity.as_deref(), first.kev),
            (Some(7.7), Some("HIGH"), true)
        );
        assert_eq!(first.ranges.len(), 1, "non-vulnerable matches are ignored");
        assert_eq!(cves[2].severity.as_deref(), Some("MEDIUM"));

        let verdicts: Vec<_> = cves
            .iter()
            .map(|c| c.applies_to("nginx", "1.18.0"))
            .collect();
        assert_eq!(
            verdicts,
            [
                Some(Confidence::Medium), // NVD configuration range
                Some(Confidence::Medium), // Deferred: CNA affected block
                Some(Confidence::Low),    // unanalysed: description names product and version
                None, // unanalysed: different product, version only as a substring
                None, // analysed: version out of range
            ]
        );
        assert_eq!(cves[1].applies_to("nginx", "1.21.0"), None);
        assert!(parse_nvd(&json!({ "nope": 1 })).is_empty());
    }

    fn sample_host() -> Host {
        let mut graph = Graph::default();
        let record = || EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x");
        let port = |number: u16,
                    product: Option<&str>,
                    version: Option<&str>,
                    cpes: &[&str],
                    state: &str| {
            Observation::Port {
                address: "10.0.0.5".into(),
                port: number,
                protocol: "tcp".into(),
                state: state.into(),
                service: Some("http".into()),
                product: product.map(Into::into),
                version: version.map(Into::into),
                extra_info: None,
                cpes: cpes.iter().map(|c| c.to_string()).collect(),
                record: record(),
            }
        };
        graph.apply(port(
            80,
            Some("nginx"),
            Some("1.18.0"),
            &[
                "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
            ],
            "open",
        ));
        graph.apply(port(
            8080,
            Some("Jetty"),
            Some("9.4.31.v20200723 (extra)"),
            &[],
            "open",
        ));
        graph.apply(port(9000, Some("mystery"), None, &[], "open"));
        graph.apply(port(
            21,
            Some("vsftpd"),
            Some("2.3.4"),
            &["cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*"],
            "filtered",
        ));
        for path in [
            "/static/jquery-3.4.1.min.js",
            "/static/app-1.2.3.js",
            "/js/Bootstrap.bundle.4.3.1.js",
        ] {
            graph.apply(Observation::Path {
                address: "10.0.0.5".into(),
                port: 80,
                scheme: "http".into(),
                path: path.into(),
                status: Some(200),
                record: EvidenceRecord::observed(Source::KatanaJsonl, Confidence::High, "x"),
            });
        }
        graph.apply(Observation::Note {
            address: Some("10.0.0.5".into()),
            text: "package.json shows pkg:npm/lodash@4.17.20, check it".into(),
            record: EvidenceRecord::observed(Source::ManualNote, Confidence::Medium, "x"),
        });
        graph.hosts.remove("10.0.0.5").unwrap()
    }

    #[test]
    fn lookups_need_an_open_port_and_a_version() {
        let lookups = plan(&sample_host());
        let shown: Vec<String> = lookups
            .iter()
            .map(|l| match l {
                Lookup::Cpe { cpe, port } => format!("cpe {cpe} @{port}"),
                Lookup::Keyword {
                    product,
                    version,
                    port,
                } => format!("kw {product} {version} @{port}"),
                Lookup::Package { package, port } => format!("pkg {} @{port:?}", package.label()),
            })
            .collect();
        assert_eq!(
            shown,
            [
                "cpe cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:* @80/tcp",
                "kw nginx 1.18.0 @80/tcp",
                "pkg jquery@3.4.1 (npm) @Some(\"80/tcp\")",
                "kw Jetty 9.4.31.v20200723 @8080/tcp",
                "pkg pkg:npm/lodash@4.17.20 @None",
            ]
        );
    }

    #[test]
    fn pacing_follows_the_api_key() {
        let mut settings = CveSettings::default();
        assert_eq!(settings.nvd_pace(), Duration::from_millis(6500));
        settings.nvd_api_key = Some("  ".into());
        assert_eq!(settings.nvd_pace(), Duration::from_millis(6500));
        settings.nvd_api_key = Some("key".into());
        assert_eq!(settings.nvd_pace(), Duration::from_millis(700));
        assert!(
            settings.enabled
                && settings
                    .nvd_url
                    .starts_with("https://services.nvd.nist.gov/")
        );
    }

    #[derive(Default)]
    struct Mock {
        nvd: AtomicUsize,
        kev: AtomicUsize,
        osv_batch: AtomicUsize,
        osv_detail: AtomicUsize,
        api_keys: Mutex<Vec<Option<String>>>,
        queries: Mutex<Vec<String>>,
    }

    #[tokio::test]
    async fn oversized_or_padded_answers_are_refused_and_a_page_is_at_most_200_records() {
        use axum::routing::get;
        let app = Router::new()
            // More records on a page than were asked for.
            .route(
                "/many/nvd",
                get(|| async {
                    let items: Vec<Value> = (0..5_000)
                        .map(|i| json!({ "cve": { "id": format!("CVE-2026-{i:07}"),
                            "descriptions": [{ "lang": "en", "value": "a real-looking description of the issue" }] } }))
                        .collect();
                    Json(json!({ "totalResults": 5_000, "vulnerabilities": items }))
                }),
            )
            // 8 MB of nothing but structure.
            .route(
                "/padded/nvd",
                get(|| async {
                    let junk = vec![json!({ "": 0 }); 1_000_000];
                    Json(json!({ "totalResults": 0, "vulnerabilities": [], "x": junk }))
                }),
            )
            // More than the NVD limit.
            .route(
                "/huge/nvd",
                get(|| async { format!("{{\"x\":\"{}\"}}", "a".repeat(NVD_MAX_BYTES + 10)) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        for (path, expected) in [
            ("many", "5000 records on a page of 200"),
            ("padded", "almost all structure"),
            ("huge", "more than 16 MB"),
        ] {
            let started = std::time::Instant::now();
            let error = client(&format!("{base}/{path}"), None)
                .nvd_by_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
                .await
                .unwrap_err();
            let error = format!("{error:#}");
            assert!(error.contains(expected), "{path}: {error}");
            assert!(started.elapsed() < Duration::from_secs(20), "{path}");
        }
        assert_eq!(value_count(br#"{"a":[1,2,{"b":"x,y:[{"}]}"#), 7);
    }

    async fn mock_server() -> (String, Arc<Mock>) {
        let mock = Arc::new(Mock::default());
        let app = Router::new()
            .route(
                "/nvd",
                get(
                    |State(mock): State<Arc<Mock>>,
                     headers: axum::http::HeaderMap,
                     Query(query): Query<HashMap<String, String>>| async move {
                        mock.nvd.fetch_add(1, AtomicOrdering::SeqCst);
                        mock.api_keys
                            .lock()
                            .unwrap()
                            .push(headers.get("apiKey").map(|v| v.to_str().unwrap().to_owned()));
                        let mut shown: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
                        shown.sort();
                        mock.queries.lock().unwrap().push(shown.join("&"));
                        if query.get("keywordSearch").is_some_and(|k| k.starts_with("Jetty")) {
                            return Json(json!({ "vulnerabilities": [] }));
                        }
                        Json(nvd_body())
                    },
                ),
            )
            .route(
                "/kev",
                get(|State(mock): State<Arc<Mock>>| async move {
                    mock.kev.fetch_add(1, AtomicOrdering::SeqCst);
                    Json(json!({ "vulnerabilities": [ { "cveID": "CVE-2026-1111" }, { "cveID": "CVE-2020-8203" } ] }))
                }),
            )
            .route(
                "/osv/v1/querybatch",
                post(|State(mock): State<Arc<Mock>>, Json(body): Json<Value>| async move {
                    mock.osv_batch.fetch_add(1, AtomicOrdering::SeqCst);
                    let results: Vec<Value> = body["queries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|q| {
                            mock.queries.lock().unwrap().push(q.to_string());
                            let jquery = q["package"]["name"] == "jquery";
                            match (jquery, q.get("page_token").and_then(Value::as_str)) {
                                (true, None) => json!({ "vulns": [ { "id": "GHSA-jquery-1" } ], "next_page_token": "p2" }),
                                (true, Some("p2")) => json!({ "vulns": [ { "id": "GHSA-jquery-2" } ] }),
                                (false, _) if q["package"]["purl"] == "pkg:npm/lodash@4.17.20" => {
                                    json!({ "vulns": [ { "id": "GHSA-lodash-1" } ] })
                                }
                                _ => json!({}),
                            }
                        })
                        .collect();
                    Json(json!({ "results": results }))
                }),
            )
            .route(
                "/osv/v1/vulns/{id}",
                get(|State(mock): State<Arc<Mock>>, Path(id): Path<String>| async move {
                    mock.osv_detail.fetch_add(1, AtomicOrdering::SeqCst);
                    let aliases = if id == "GHSA-lodash-1" { json!(["CVE-2020-8203"]) } else { json!([]) };
                    Json(json!({
                        "id": id, "summary": format!("summary of {id}"), "aliases": aliases,
                        "database_specific": { "severity": "HIGH" },
                        "references": [ { "type": "WEB", "url": "https://example.test/osv" } ]
                    }))
                }),
            )
            .with_state(Arc::clone(&mock));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, mock)
    }

    fn client(base: &str, api_key: Option<&str>) -> CveClient {
        let settings = CveSettings {
            enabled: true,
            nvd_api_key: api_key.map(Into::into),
            nvd_url: format!("{base}/nvd"),
            osv_url: format!("{base}/osv"),
            kev_url: format!("{base}/kev"),
        };
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        CveClient::new(settings, db)
            .unwrap()
            .with_nvd_pace(Duration::from_millis(120))
    }

    #[tokio::test]
    async fn grounding_finds_cves_from_versions_and_packages() {
        let (base, mock) = mock_server().await;
        let client = client(&base, Some("secret-key"));
        let host = sample_host();
        let grounding = client.ground(&host).await;
        assert_eq!(grounding.errors, Vec::<String>::new());
        assert_eq!(grounding.lookups, 5);

        let ids: Vec<&str> = grounding.advisories.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "CVE-2021-23017",
                "CVE-2026-1111",
                "CVE-2026-2222",
                "CVE-2026-3333",
                "CVE-2019-9999",
                "GHSA-jquery-1",
                "GHSA-lodash-1",
                "GHSA-jquery-2",
            ],
            "cpeName results are trusted as matched by NVD; keyword results add nothing new here"
        );
        let by_id = |id: &str| grounding.advisories.iter().find(|a| a.id == id).unwrap();
        assert!(by_id("CVE-2021-23017").kev, "flagged by NVD itself");
        assert!(
            by_id("CVE-2026-1111").kev,
            "cross-tagged from the KEV catalog"
        );
        assert!(by_id("GHSA-lodash-1").kev, "KEV match through a CVE alias");
        assert!(!by_id("CVE-2026-2222").kev);
        assert_eq!(by_id("CVE-2021-23017").port.as_deref(), Some("80/tcp"));
        assert_eq!(by_id("CVE-2021-23017").record.source, Source::NvdApi);
        assert!(by_id("CVE-2021-23017")
            .record
            .evidence
            .contains("cpeName=cpe:2.3:a:nginx:nginx:1.18.0"));
        let jquery = by_id("GHSA-jquery-2");
        assert_eq!(jquery.record.source, Source::OsvApi);
        assert_eq!(
            jquery.record.confidence,
            Confidence::Low,
            "guessed from a file name"
        );
        assert_eq!(jquery.matched, "jquery@3.4.1 (npm)");
        assert_eq!(jquery.title, "summary of GHSA-jquery-2");
        assert_eq!(by_id("GHSA-lodash-1").record.confidence, Confidence::Medium);
        assert_eq!(grounding.facts.len(), 3);
        assert!(grounding
            .facts
            .iter()
            .all(|f| f.record.source == Source::CisaKev));

        // One NVD request per lookup, each carrying the API key, and only
        // public identifiers ever left the machine.
        assert_eq!(mock.nvd.load(AtomicOrdering::SeqCst), 3);
        assert!(mock
            .api_keys
            .lock()
            .unwrap()
            .iter()
            .all(|k| k.as_deref() == Some("secret-key")));
        assert_eq!(
            mock.osv_batch.load(AtomicOrdering::SeqCst),
            2,
            "second page followed"
        );
        let sent = mock.queries.lock().unwrap().join("\n");
        assert!(
            sent.contains(
                "cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*&isVulnerable=&resultsPerPage=200"
            ),
            "{sent}"
        );
        assert!(sent.contains("keywordSearch=nginx 1.18.0"), "{sent}");
        assert!(sent.contains("\"page_token\":\"p2\""), "{sent}");
        assert!(
            !sent.contains("10.0.0.5"),
            "a host address was sent: {sent}"
        );

        // A second run is answered from the cache.
        let again = client.ground(&host).await;
        assert_eq!(again.advisories.len(), 8);
        assert_eq!(mock.nvd.load(AtomicOrdering::SeqCst), 3);
        assert_eq!(mock.kev.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(mock.osv_detail.load(AtomicOrdering::SeqCst), 3);
    }

    /// Records shaped like the ones NVD returns for an old web server and
    /// for an SSH server packaged by one Linux vendor.
    fn conditional_body() -> Value {
        json!({ "vulnerabilities": [
            { "cve": {
                "id": "CVE-2026-4001", "vulnStatus": "Analyzed",
                "descriptions": [ { "lang": "en", "value": "A panel is unsafe when httpd serves it." } ],
                "configurations": [ { "operator": "AND", "nodes": [
                    { "cpeMatch": [ { "vulnerable": true, "criteria": "cpe:2.3:a:panel_project:panel:4.3:*:*:*:*:*:*:*" } ] },
                    { "cpeMatch": [ { "vulnerable": false, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" } ] }
                ] } ]
            } },
            { "cve": {
                "id": "CVE-2026-4002", "vulnStatus": "Analyzed",
                "descriptions": [ { "lang": "en", "value": "Vendor packages of the SSH server were tampered with." } ],
                "configurations": [ { "operator": "AND", "nodes": [
                    { "cpeMatch": [ { "vulnerable": false, "criteria": "cpe:2.3:o:redhat:enterprise_linux:5.0:*:*:*:*:*:*:*" } ] },
                    { "cpeMatch": [ { "vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*" } ] }
                ] } ]
            } },
            { "cve": {
                "id": "CVE-2026-4003", "vulnStatus": "Analyzed",
                "descriptions": [ { "lang": "en", "value": "Request smuggling in httpd." } ],
                "configurations": [ { "nodes": [ { "cpeMatch": [
                    { "vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                      "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.60" }
                ] } ] } ]
            } },
            { "cve": {
                "id": "CVE-2026-4004", "vulnStatus": "Analyzed",
                "descriptions": [ { "lang": "en", "value": "Overflow in a httpd module." } ],
                "configurations": [ { "nodes": [ { "cpeMatch": [
                    { "vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                      "versionEndIncluding": "2.4.68" }
                ] } ] } ]
            } }
        ] })
    }

    #[test]
    fn platform_only_and_other_system_matches_are_dropped() {
        let cves = parse_nvd(&conditional_body());
        let by = |id: &str| cves.iter().find(|c| c.id == id).unwrap();

        // The web server is only what the vulnerable panel runs on.
        let panel = by("CVE-2026-4001");
        assert_eq!(panel.relevance("http_server", "2.4.34", None, true), None);

        // Tied to one Linux vendor: not on a Windows host, still shown
        // where the system is unknown or is that family.
        let packaged = by("CVE-2026-4002");
        assert_eq!(packaged.ranges[0].only_on, ["redhat enterprise_linux"]);
        assert_eq!(
            packaged.relevance("openssh", "9.5", Some(Family::Windows), true),
            None
        );
        for family in [None, Some(Family::Linux)] {
            assert!(packaged.relevance("openssh", "9.5", family, true).is_some());
        }

        // A plain match says which release ends it.
        let fixed = by("CVE-2026-4003")
            .relevance("http_server", "2.4.34", Some(Family::Windows), true)
            .unwrap();
        assert_eq!(fixed.fixed_in.as_deref(), Some("2.4.60"));
        let open = by("CVE-2026-4004")
            .relevance("http_server", "2.4.34", None, false)
            .unwrap();
        assert_eq!(
            (open.fixed_in.as_deref(), open.last_affected.as_deref()),
            (None, Some("2.4.68"))
        );
    }

    #[test]
    fn decorated_versions_are_looked_up_by_their_number() {
        let mut graph = Graph::default();
        graph.apply(Observation::Port {
            address: "192.0.2.7".into(),
            port: 22,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("ssh".into()),
            product: Some("OpenSSH".into()),
            version: Some("for_Windows_9.5".into()),
            extra_info: Some("protocol 2.0".into()),
            cpes: vec!["cpe:/a:openbsd:openssh:for_windows_9.5".into()],
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
        });
        let host = graph.hosts["192.0.2.7"].clone();
        assert_eq!(host_family(&host), Some(Family::Windows));
        assert_eq!(
            plan(&host),
            [
                Lookup::Cpe {
                    cpe: "cpe:2.3:a:openbsd:openssh:9.5:*:*:*:*:*:*:*".into(),
                    port: "22/tcp".into(),
                },
                Lookup::Keyword {
                    product: "openssh".into(),
                    version: "9.5".into(),
                    port: "22/tcp".into(),
                },
            ]
        );
    }

    fn matched(
        id: &str,
        kev: bool,
        fixed_in: Option<&str>,
        last_affected: Option<&str>,
    ) -> Advisory {
        Advisory {
            id: id.into(),
            title: format!("about {id}"),
            severity: None,
            cvss: None,
            kev,
            matched: "cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*".into(),
            port: Some("80/tcp".into()),
            references: Vec::new(),
            fixed_in: fixed_in.map(Into::into),
            last_affected: last_affected.map(Into::into),
            record: EvidenceRecord::observed(Source::NvdApi, Confidence::Medium, "x"),
        }
    }

    #[test]
    fn one_update_answers_a_whole_group_of_advisories() {
        let mut host = sample_host();
        host.advisories = vec![
            matched("CVE-2026-5001", true, Some("1.20.1"), None),
            matched("CVE-2026-5002", false, Some("1.19.4"), None),
            matched("CVE-2026-5003", false, None, Some("1.19.9")),
            matched("CVE-2026-5004", false, None, None),
        ];
        host.advisories[3].matched = "jquery@3.4.1 (npm)".into();
        let plan = fix_plan(&host);
        assert_eq!(plan.len(), 2);
        assert_eq!(
            (plan[0].software.as_str(), plan[0].advisories, plan[0].kev),
            ("nginx 1.18.0", 3, 1)
        );
        assert_eq!(
            plan[0].action,
            "Update nginx 1.18.0 to 1.20.1 or later, or close 80/tcp if the service is not needed."
        );
        assert_eq!(plan[1].software, "jquery@3.4.1 (npm)");
        assert_eq!(plan[1].target, "its newest release");

        assert_eq!(plan[0].counts(), "3 CVEs, 1 known exploited");
        assert_eq!(plan[1].counts(), "1 CVE");

        // No release is named as fixed past the last affected one.
        host.advisories[2].last_affected = Some("1.21.0".into());
        assert_eq!(fix_plan(&host)[0].target, "a release newer than 1.21.0");
    }

    #[test]
    fn one_program_on_two_ports_is_one_update_to_the_release_that_fixes_all() {
        let mut host = sample_host();
        host.advisories = vec![
            Advisory {
                port: Some("443/tcp".into()),
                cvss: Some(7.5),
                ..matched("CVE-2023-44487", true, Some("1.25.3"), None)
            },
            matched("CVE-2021-23017", false, Some("1.20.1"), None),
            matched("CVE-2019-20372", false, Some("1.17.7"), None),
        ];
        let plan = fix_plan(&host);
        assert_eq!(plan.len(), 1, "{plan:?}");
        assert_eq!(plan[0].target, "1.25.3 or later");
        assert_eq!(plan[0].port.as_deref(), Some("80/tcp, 443/tcp"));
        assert_eq!((plan[0].advisories, plan[0].kev), (3, 1));
        assert_eq!(
            plan[0].action,
            "Update nginx 1.18.0 to 1.25.3 or later, or close 80/tcp, 443/tcp if the service \
             is not needed."
        );
    }

    #[test]
    fn what_to_update_follows_the_order_of_the_cve_groups() {
        // nginx has more CVEs, but Jetty has the most urgent one: both
        // lists put Jetty first.
        let mut host = sample_host();
        let jetty = Advisory {
            matched: "keywordSearch=jetty 9.4.31".into(),
            port: Some("8080/tcp".into()),
            cvss: Some(9.8),
            ..matched("CVE-2026-7001", true, Some("9.4.41"), None)
        };
        host.advisories = vec![
            Advisory {
                cvss: Some(7.7),
                ..matched("CVE-2026-5001", true, Some("1.20.1"), None)
            },
            matched("CVE-2026-5002", false, Some("1.19.4"), None),
            matched("CVE-2026-5003", false, None, None),
            jetty,
        ];
        let groups: Vec<String> = by_software(&host)
            .into_iter()
            .map(|group| group.software)
            .collect();
        let plan: Vec<String> = fix_plan(&host)
            .into_iter()
            .map(|fix| fix.software)
            .collect();
        assert_eq!(groups, ["Jetty 9.4.31.v20200723 (extra)", "nginx 1.18.0"]);
        assert_eq!(plan, groups);
    }

    #[test]
    fn cves_are_grouped_by_software_and_known_exploited_come_first() {
        let mut host = sample_host();
        let scored = |id: &str, kev: bool, severity: Option<&str>, cvss: Option<f64>| Advisory {
            severity: severity.map(Into::into),
            cvss,
            ..matched(id, kev, None, None)
        };
        host.advisories = vec![
            scored("CVE-2026-6001", false, Some("CRITICAL"), Some(9.8)),
            Advisory {
                fixed_in: Some("1.20.1".into()),
                ..scored("CVE-2021-23017", true, Some("HIGH"), Some(7.7))
            },
            scored("CVE-2026-6002", false, Some("MODERATE"), None),
            Advisory {
                matched: "jquery@3.4.1 (npm)".into(),
                port: None,
                ..scored("GHSA-0001", false, None, Some(4.2))
            },
        ];
        let groups = by_software(&host);
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].heading(),
            "nginx 1.18.0 \u{b7} 80/tcp \u{b7} fixed in 1.20.1"
        );
        let ids: Vec<&str> = groups[0].cves.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["CVE-2021-23017", "CVE-2026-6001", "CVE-2026-6002"]);
        assert_eq!(groups[0].kev(), 1);
        assert_eq!(groups[1].heading(), "jquery@3.4.1 (npm)");

        let labels: Vec<String> = groups[0].cves.iter().map(|a| severity_label(a)).collect();
        assert_eq!(labels, ["High 7.7", "Critical 9.8", "Medium"]);
        assert_eq!(severity_label(groups[1].cves[0]), "Medium 4.2");
        assert_eq!(
            severity_label(&matched("CVE-1", false, None, None)),
            "unrated"
        );
        let serious: Vec<bool> = groups[0].cves.iter().map(|a| is_serious(a)).collect();
        assert_eq!(serious, [true, true, false]);
        assert!(!is_serious(groups[1].cves[0]));
    }

    #[test]
    fn a_complete_lookup_removes_matches_it_no_longer_returns() {
        let mut graph = Graph::default();
        graph.hosts.insert("10.0.0.5".into(), sample_host());
        for id in ["CVE-2026-5001", "CVE-2026-5002", "CVE-2026-5003"] {
            graph.add_advisory("10.0.0.5", matched(id, false, None, None));
        }
        let mut grounding = Grounding {
            advisories: vec![
                matched("CVE-2026-5001", false, Some("1.20.1"), None),
                matched("CVE-2026-5009", true, None, None),
            ],
            lookups: 2,
            ..Grounding::default()
        };

        // An incomplete lookup proves nothing about what is missing.
        grounding.errors.push("NVD answered HTTP 503".into());
        let partial = merge(&mut graph.clone(), "10.0.0.5", &grounding);
        assert_eq!((partial.added, partial.dropped), (1, 0));

        grounding.errors.clear();
        let merged = merge(&mut graph, "10.0.0.5", &grounding);
        assert_eq!(
            merged,
            Merged {
                added: 1,
                kev: 1,
                dropped: 2
            }
        );
        let host = &graph.hosts["10.0.0.5"];
        let ids: Vec<&str> = host.advisories.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["CVE-2026-5001", "CVE-2026-5009"]);
        assert_eq!(
            host.advisories[0].fixed_in.as_deref(),
            Some("1.20.1"),
            "a known match learns its fixed release"
        );
    }

    #[tokio::test]
    async fn keyword_hits_are_filtered_by_version() {
        let (base, _mock) = mock_server().await;
        let client = client(&base, None);
        let mut host = sample_host();
        // No CPE: only the keyword search runs for this port.
        host.ports.get_mut("80/tcp").unwrap().cpes.clear();
        host.ports.get_mut("80/tcp").unwrap().paths = Default::default();
        host.facts.clear();
        let grounding = client.ground(&host).await;
        let found: Vec<_> = grounding
            .advisories
            .iter()
            .map(|a| (a.id.as_str(), a.record.confidence))
            .collect();
        assert_eq!(
            found,
            [
                ("CVE-2021-23017", Confidence::Medium),
                ("CVE-2026-1111", Confidence::Medium),
                ("CVE-2026-2222", Confidence::Low),
            ]
        );
    }

    #[tokio::test]
    async fn nvd_requests_are_paced() {
        let (base, mock) = mock_server().await;
        let client = client(&base, None);
        let started = Instant::now();
        for version in ["1.0", "2.0", "3.0"] {
            client.nvd_by_keyword("nginx", version).await.unwrap();
        }
        assert!(
            started.elapsed() >= Duration::from_millis(240),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(mock.nvd.load(AtomicOrdering::SeqCst), 3);
        assert!(mock.api_keys.lock().unwrap().iter().all(Option::is_none));
        assert_eq!(
            client.estimate(&plan(&sample_host())),
            Duration::from_millis(120 * 3)
        );
    }

    #[tokio::test]
    async fn offline_fails_fast_and_gives_up_after_two_lookups() {
        // A port nothing listens on: connection refused immediately.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let client = client(&base, None);
        let started = Instant::now();
        let grounding = client.ground(&sample_host()).await;
        assert!(started.elapsed() < Duration::from_secs(8));
        assert!(grounding.advisories.is_empty());
        // The catalog, then two lookups: one slow answer is not an outage,
        // two failures in a row are, and the rest is not tried.
        assert_eq!(grounding.errors.len(), 3, "{:?}", grounding.errors);
        assert!(grounding.errors[0].contains("CISA KEV"));
        assert!(grounding.errors[1].starts_with("cpeName="));
        assert!(grounding.lookups > 2, "there was more to try");
    }

    #[tokio::test]
    async fn stale_kev_copy_is_used_when_the_download_fails() {
        let (base, mock) = mock_server().await;
        let good = client(&base, None);
        assert_eq!(good.kev().await.unwrap().len(), 2);
        // Age the cached copy beyond seven days, then break the URL.
        good.db
            .lock()
            .unwrap()
            .conn()
            .execute(
                "UPDATE cve_cache SET fetched_utc = '2020-01-01T00:00:00Z' WHERE key = 'cisa_kev'",
                [],
            )
            .unwrap();
        let broken = CveClient {
            settings: CveSettings {
                kev_url: format!("{base}/missing"),
                ..good.settings.clone()
            },
            ..good
        };
        let ids = broken.kev().await.unwrap();
        assert!(ids.contains("CVE-2026-1111"));
        assert_eq!(mock.kev.load(AtomicOrdering::SeqCst), 1);
    }

    #[tokio::test]
    async fn purl_only_from_manual_notes_osv_id_validation_and_os_cpe_fallback() {
        let mut graph = Graph::default();
        // Port with an OS CPE that has a version AND a product/version on the port:
        // the `:o:` CPE must not suppress the port's own product keyword lookup.
        graph.apply(Observation::Port {
            address: "192.0.2.50".into(),
            port: 80,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("http".into()),
            product: Some("nginx".into()),
            version: Some("1.18.0".into()),
            extra_info: None,
            cpes: vec!["cpe:2.3:o:linux:linux_kernel:5.4:*:*:*:*:*:*:*".into()],
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
        });
        // A PURL inside a scraped HTTP header or banner fact must NOT trigger an OSV lookup.
        graph.apply(Observation::Http {
            address: "192.0.2.50".into(),
            port: 80,
            scheme: "http".into(),
            server: Some("banner pkg:npm/evil-canary@1.0.0".into()),
            location: None,
            record: EvidenceRecord::observed(Source::HttpHeader, Confidence::Medium, "x"),
        });
        let host = &graph.hosts["192.0.2.50"];
        let lookups = plan(host);
        assert!(
            lookups.iter().any(|l| matches!(
                l,
                Lookup::Keyword {
                    product,
                    version,
                    ..
                } if product == "nginx" && version == "1.18.0"
            )),
            "OS CPE must not suppress port.product keyword lookup: {lookups:?}"
        );
        assert!(
            !lookups.iter().any(|l| matches!(l, Lookup::Package { .. })),
            "non-ManualNote facts must not produce PURL lookups: {lookups:?}"
        );

        let (base, _mock) = mock_server().await;
        let client = client(&base, None);
        for bad_id in [
            "",
            "../etc/passwd",
            "GHSA-1234/../../x",
            "CVE-2024-1?foo=bar",
        ] {
            assert!(
                client.osv_details(bad_id).await.is_err(),
                "osv_details should reject {bad_id:?}"
            );
        }
    }

    #[tokio::test]
    async fn nvd_query_follows_start_index_pagination() {
        let app = Router::new().route(
            "/nvd",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                let start = query
                    .get("startIndex")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                let items: Vec<Value> = if start == 0 {
                    (0..200)
                        .map(|i| {
                            json!({ "cve": {
                                "id": format!("CVE-2025-{i:04}"),
                                "vulnStatus": "Analyzed",
                                "descriptions": [{ "lang": "en", "value": "page 1" }]
                            }})
                        })
                        .collect()
                } else {
                    vec![json!({ "cve": {
                        "id": "CVE-2025-9999",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{ "lang": "en", "value": "page 2" }]
                    }})]
                };
                Json(json!({
                    "totalResults": 201,
                    "vulnerabilities": items,
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = client(&base, Some("k")).with_nvd_pace(Duration::from_millis(1));
        let found = client
            .nvd_by_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
            .await
            .unwrap();
        assert_eq!(found.len(), 201);
        assert_eq!(found.last().unwrap().id, "CVE-2025-9999");
    }

    #[test]
    fn settings_debug_redacts_api_key_and_devel_versions_stay_distinct() {
        let settings = CveSettings {
            nvd_api_key: Some("super-secret-nvd-key".into()),
            ..CveSettings::default()
        };
        let rendered = format!("{settings:?}");
        assert!(!rendered.contains("super-secret-nvd-key"));
        assert!(rendered.contains("<redacted>"));

        assert_eq!(cmp_versions("1.2.3-devel", "1.2.3"), Ordering::Less);
        assert_ne!(cmp_versions("1.2.3-debug", "1.2.3"), Ordering::Equal);
        assert_eq!(cmp_versions("2.4.52-deb11u3", "2.4.52"), Ordering::Equal);
        assert_eq!(cmp_versions("2.4.52-el8_4", "2.4.52"), Ordering::Equal);
    }

    #[tokio::test]
    async fn nvd_rate_limit_does_not_skip_osv_and_osv_extracts_fixed_in() {
        let app = Router::new()
            .route(
                "/kev",
                get(|| async { Json(json!({ "vulnerabilities": [] })) }),
            )
            .route(
                "/nvd",
                get(|| async { axum::http::StatusCode::TOO_MANY_REQUESTS }),
            )
            .route(
                "/osv/v1/querybatch",
                axum::routing::post(|| async {
                    Json(json!({
                        "results": [
                            { "vulns": [{ "id": "GHSA-jq-fixed" }] },
                            { "vulns": [] }
                        ]
                    }))
                }),
            )
            .route(
                "/osv/v1/vulns/{id}",
                get(|| async {
                    Json(json!({
                        "id": "GHSA-jq-fixed",
                        "summary": "jQuery XSS",
                        "affected": [{
                            "package": { "name": "jquery", "ecosystem": "npm" },
                            "ranges": [{
                                "type": "SEMVER",
                                "events": [
                                    { "introduced": "1.0.0" },
                                    { "fixed": "3.5.0" }
                                ]
                            }]
                        }]
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let c = client(&base, None).with_nvd_pace(Duration::from_millis(1));
        let grounding = c.ground(&sample_host()).await;
        assert!(
            grounding
                .advisories
                .iter()
                .any(|a| a.id == "GHSA-jq-fixed" && a.fixed_in.as_deref() == Some("3.5.0")),
            "OSV should still run and extract fixed_in when NVD returns 429: {grounding:?}"
        );

        // Partial grounding with no explicit errors must not drop stale advisories.
        let mut graph = Graph::default();
        graph.hosts.insert("10.0.0.5".into(), sample_host());
        graph.add_advisory("10.0.0.5", matched("CVE-2026-8888", false, None, None));
        let partial_grounding = Grounding {
            lookups: 1,
            partial: true,
            ..Grounding::default()
        };
        let res = merge(&mut graph, "10.0.0.5", &partial_grounding);
        assert_eq!(res.dropped, 0);
        assert!(graph.hosts["10.0.0.5"]
            .advisories
            .iter()
            .any(|a| a.id == "CVE-2026-8888"));
    }

    #[test]
    fn plan_caps_lookups_and_rejects_unsafe_keyword_tokens() {
        let mut graph = Graph::default();
        for port in 1..=90u16 {
            graph.apply(Observation::Port {
                address: "10.0.0.9".into(),
                port,
                protocol: "tcp".into(),
                state: "open".into(),
                service: Some("http".into()),
                product: Some(format!("svc{port}")),
                version: Some(format!("1.0.{port}")),
                extra_info: None,
                cpes: Vec::new(),
                record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
            });
        }
        graph.apply(Observation::Port {
            address: "10.0.0.9".into(),
            port: 9000,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("http".into()),
            product: Some("https://evil.example/exfil".into()),
            version: Some("1.0.0".into()),
            extra_info: None,
            cpes: Vec::new(),
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
        });
        let host = graph.hosts.remove("10.0.0.9").unwrap();
        let lookups = plan(&host);
        assert_eq!(lookups.len(), MAX_LOOKUPS_PER_HOST);
        assert!(!lookups.iter().any(|l| matches!(
            l,
            Lookup::Keyword { product, .. } if product.contains("://")
        )));
        assert!(!is_safe_keyword_token("https://evil.example", true));
        assert!(!is_safe_keyword_token("-flag", true));
        assert!(is_safe_keyword_token("Apache httpd", true));
        assert!(is_safe_keyword_token("9.4.31.v20200723", false));
    }

    #[test]
    fn the_operator_is_looked_up_first_and_text_only_so_much() {
        let mut queue = GroundQueue::new(3);
        assert!(queue.push("198.51.100.1", Asked::Text));
        assert!(queue.push("198.51.100.2", Asked::Text));
        assert!(!queue.push("198.51.100.1", Asked::Text), "each host once");
        assert!(queue.push("192.0.2.10", Asked::Operator));
        // Asked for by the operator too, a host text queued moves forward.
        assert!(queue.push("198.51.100.2", Asked::Operator));
        assert_eq!(
            [queue.pop(), queue.pop(), queue.pop(), queue.pop()],
            [
                Some(("192.0.2.10".to_owned(), Asked::Operator)),
                Some(("198.51.100.2".to_owned(), Asked::Operator)),
                Some(("198.51.100.1".to_owned(), Asked::Text)),
                None
            ]
        );
        assert!(
            queue.push("198.51.100.1", Asked::Text),
            "queued again once done"
        );

        // The same software on many hosts is one question; new questions
        // stop at the limit.
        let keyword = |product: &str| Lookup::Keyword {
            product: product.to_owned(),
            version: "1.0".to_owned(),
            port: "80/tcp".to_owned(),
        };
        let (kept, cut) = queue.allow(vec![keyword("a"), keyword("b")]);
        assert_eq!((kept.len(), cut), (2, false));
        let (kept, cut) = queue.allow(vec![keyword("a"), keyword("b"), keyword("c")]);
        assert_eq!((kept.len(), cut), (3, false));
        let (kept, cut) = queue.allow(vec![keyword("d"), keyword("a")]);
        assert_eq!((kept, cut), (vec![keyword("a")], true));
    }

    #[test]
    fn a_recon_task_goes_first_for_its_own_ports_only() {
        let ports = |keys: &[&str]| -> BTreeSet<String> {
            keys.iter().map(|key| (*key).to_owned()).collect()
        };
        let mut queue = GroundQueue::new(3);
        assert!(queue.push("198.51.100.1", Asked::Text));
        assert!(queue.push("198.51.100.2", Asked::Text));
        assert!(queue.push("198.51.100.3", Asked::Recon(ports(&["22/tcp"]))));
        // A recon task asking for a host text queued moves it forward; two
        // tasks ask for the ports of both.
        assert!(queue.push("198.51.100.2", Asked::Recon(ports(&["80/tcp"]))));
        assert!(!queue.push("198.51.100.3", Asked::Recon(ports(&["53/udp"]))));
        assert!(!queue.push("198.51.100.3", Asked::Text));
        assert_eq!(
            [queue.pop(), queue.pop(), queue.pop(), queue.pop()],
            [
                Some((
                    "198.51.100.3".to_owned(),
                    Asked::Recon(ports(&["22/tcp", "53/udp"]))
                )),
                Some(("198.51.100.2".to_owned(), Asked::Recon(ports(&["80/tcp"])))),
                Some(("198.51.100.1".to_owned(), Asked::Text)),
                None
            ]
        );
        assert!(queue.push("198.51.100.4", Asked::Recon(ports(&["22/tcp"]))));
        assert!(!queue.push("198.51.100.4", Asked::Operator));
        assert_eq!(
            queue.pop(),
            Some(("198.51.100.4".to_owned(), Asked::Operator))
        );

        // Text calls 70 ports of a host open; the scan found one. Its
        // lookup comes first, whatever text says.
        let mut graph = Graph::default();
        for port in (1..=70u16).chain([9000]) {
            graph.apply(Observation::Port {
                address: "198.51.100.5".into(),
                port,
                protocol: "tcp".into(),
                state: "open".into(),
                service: None,
                product: Some(if port == 9000 {
                    "OpenSSH".into()
                } else {
                    format!("Prod{port}")
                }),
                version: Some("1.0".into()),
                extra_info: None,
                cpes: Vec::new(),
                record: EvidenceRecord::observed(Source::PtyRegex, Confidence::Medium, "x"),
            });
        }
        let host = graph.hosts.remove("198.51.100.5").unwrap();
        let openssh = |lookups: &[Lookup]| {
            lookups.iter().any(
                |lookup| matches!(lookup, Lookup::Keyword { product, .. } if product == "OpenSSH"),
            )
        };
        assert!(!openssh(&plan(&host)), "the limit was reached before it");
        let (own, rest) = plan_split(&host, |port| port.key() == "9000/tcp");
        assert_eq!(own.len(), 1);
        assert!(openssh(&own));
        assert_eq!(rest.len(), MAX_LOOKUPS_PER_HOST - 1);
        assert!(!openssh(&rest));
    }

    #[test]
    fn hosts_waiting_for_lookups_are_bounded() {
        let mut queue = GroundQueue::new(TEXT_QUESTIONS);
        for n in 0..MAX_WAITING {
            assert!(queue.push(&format!("host{n}.example"), Asked::Text));
        }
        assert!(!queue.push("one-more.example", Asked::Text));
        // Text filling its queue does not hold up the operator.
        assert!(queue.push("one-more.example", Asked::Operator));
        assert_eq!(queue.pop().unwrap().0, "one-more.example");
        for n in 0..MAX_WAITING {
            assert!(queue.push(&format!("asked{n}.example"), Asked::Operator));
        }
        assert!(!queue.push("one-more.example", Asked::Operator));
        assert_eq!(queue.waiting.len(), 2 * MAX_WAITING);
    }
}

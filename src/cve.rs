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
//! an `UnverifiedHypothesis`. Connecting has a 5 s timeout, so an offline
//! machine fails fast, while a reply may take as long as it keeps arriving;
//! NVD requests are paced to respect its rate limit.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cpe;
use crate::db::Db;
use crate::evidence::{Confidence, EvidenceRecord, Source};
use crate::graph::{Advisory, Fact, Host};

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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct CveSettings {
    pub enabled: bool,
    pub nvd_api_key: Option<String>,
    /// Endpoints, overridable for mirrors and tests.
    pub nvd_url: String,
    pub osv_url: String,
    pub kev_url: String,
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

/// Loose version ordering: digit runs compare numerically, letter runs
/// alphabetically, and a longer version sorts after its own prefix
/// (`8.2` < `8.2p1` < `8.10`).
pub fn cmp_versions(a: &str, b: &str) -> Ordering {
    fn tokens(text: &str) -> Vec<Result<u64, String>> {
        let mut out = Vec::new();
        let mut current = String::new();
        let mut digits = false;
        for ch in text.chars().chain(std::iter::once('.')) {
            let is_digit = ch.is_ascii_digit();
            let is_alpha = ch.is_ascii_alphabetic();
            let boundary = (!is_digit && !is_alpha) || is_digit != digits;
            if boundary && !current.is_empty() {
                out.push(if digits {
                    Ok(current.parse::<u64>().unwrap_or(u64::MAX))
                } else {
                    Err(current.to_ascii_lowercase())
                });
                current.clear();
            }
            if is_digit || is_alpha {
                digits = is_digit;
                current.push(ch);
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
    let (a, b) = (tokens(unprefixed(a)), tokens(unprefixed(b)));
    for (left, right) in a.iter().zip(&b) {
        let order = match (left, right) {
            (Ok(l), Ok(r)) => l.cmp(r),
            (Err(l), Err(r)) => l.cmp(r),
            (Ok(_), Err(_)) => Ordering::Greater,
            (Err(_), Ok(_)) => Ordering::Less,
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    a.len().cmp(&b.len())
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
    fn covers(&self, product: &str, version: &str) -> bool {
        let wanted = normalize_product(product);
        let mine = normalize_product(&self.product);
        if mine != wanted
            && !mine.ends_with(&format!("_{wanted}"))
            && !wanted.ends_with(&format!("_{mine}"))
        {
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

fn ranges_from_configurations(cve: &Value, out: &mut Vec<VersionRange>) {
    let nodes = cve
        .get("configurations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| c.get("nodes").and_then(Value::as_array))
        .flatten();
    for matched in nodes
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
        });
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

impl NvdCve {
    /// Whether a keyword hit really concerns `product` at `version`, and how
    /// sure that is. `None` means it does not apply.
    pub fn applies_to(&self, product: &str, version: &str) -> Option<Confidence> {
        if !self.ranges.is_empty() {
            return self
                .ranges
                .iter()
                .any(|range| range.covers(product, version))
                .then_some(Confidence::Medium);
        }
        // No applicability data: accept only an explicit mention of both.
        let text = self.description.to_ascii_lowercase();
        let product = product.to_ascii_lowercase().replace('_', " ");
        let mentions_version = text
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
            .any(|word| word.trim_matches('.') == version.to_ascii_lowercase());
        (text.contains(&product) && mentions_version).then_some(Confidence::Low)
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

/// Decides which lookups a host's evidence justifies. Only open ports and
/// software with a known version are looked up: a product without a
/// version would match thousands of unrelated CVEs.
pub fn plan(host: &Host) -> Vec<Lookup> {
    let mut out: Vec<Lookup> = Vec::new();
    let mut push = |lookup: Lookup| {
        if !out.contains(&lookup) {
            out.push(lookup);
        }
    };
    for port in host.open_ports() {
        let key = port.key();
        let mut keyworded = false;
        for name in &port.cpes {
            let Some(parts) = cpe::parts(name) else {
                continue;
            };
            let Some(version) = parts.version else {
                continue;
            };
            push(Lookup::Cpe {
                cpe: name.clone(),
                port: key.clone(),
            });
            push(Lookup::Keyword {
                product: parts.product.replace('_', " "),
                version,
                port: key.clone(),
            });
            keyworded = true;
        }
        if !keyworded {
            if let (Some(product), Some(version)) =
                (&port.product, port.version.as_deref().and_then(first_token))
            {
                push(Lookup::Keyword {
                    product: product.clone(),
                    version,
                    port: key.clone(),
                });
            }
        }
        for (path, _) in port.paths.walk() {
            let file = path.rsplit('/').next().unwrap_or("");
            let Some(found) = JS_LIBRARY.captures(file) else {
                continue;
            };
            let name = found[1].to_ascii_lowercase().replace('.', "-");
            if KNOWN_JS.contains(&name.as_str()) {
                push(Lookup::Package {
                    package: Package {
                        purl: None,
                        name,
                        ecosystem: "npm".to_owned(),
                        version: found[2].to_owned(),
                        declared: false,
                    },
                    port: Some(key.clone()),
                });
            }
        }
    }
    // Package URLs the operator wrote into notes.
    for fact in &host.facts {
        for found in PURL.find_iter(&fact.claim) {
            push(Lookup::Package {
                package: Package {
                    purl: Some(found.as_str().to_owned()),
                    name: String::new(),
                    ecosystem: String::new(),
                    version: String::new(),
                    declared: true,
                },
                port: None,
            });
        }
    }
    out
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
    /// One line per lookup that failed.
    pub errors: Vec<String>,
}

pub struct CveClient {
    http: reqwest::Client,
    settings: CveSettings,
    db: Arc<Mutex<Db>>,
    nvd_pace: Duration,
    /// Serialises NVD requests and remembers when the last one was sent.
    nvd_gate: tokio::sync::Mutex<Option<Instant>>,
}

fn cache_key(kind: &str, value: &str) -> String {
    format!("{kind}:{}", value.to_ascii_lowercase())
}

impl CveClient {
    pub fn new(settings: CveSettings, db: Arc<Mutex<Db>>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(STALL_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent("security-audit-client")
            .build()
            .context("cannot create the HTTP client")?;
        let nvd_pace = settings.nvd_pace();
        Ok(Self {
            http,
            settings,
            db,
            nvd_pace,
            nvd_gate: tokio::sync::Mutex::new(None),
        })
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

    async fn nvd_query(&self, param: &str, value: &str) -> Result<Vec<NvdCve>> {
        let key = cache_key(&format!("nvd:{param}"), value);
        if let Some(found) = self
            .cached(&key, DAY)
            .and_then(|body| serde_json::from_str(&body).ok())
        {
            return Ok(found);
        }
        let body = {
            let mut last = self.nvd_gate.lock().await;
            if let Some(sent) = *last {
                tokio::time::sleep(self.nvd_pace.saturating_sub(sent.elapsed())).await;
            }
            let mut request = self
                .http
                .get(&self.settings.nvd_url)
                .query(&[(param, value), ("resultsPerPage", "200")]);
            if let Some(api_key) = self.settings.api_key() {
                request = request.header("apiKey", api_key);
            }
            let response = request.send().await;
            *last = Some(Instant::now());
            let response = response.context("NVD request failed")?;
            if !response.status().is_success() {
                bail!("NVD answered HTTP {}", response.status());
            }
            response
                .json::<Value>()
                .await
                .context("NVD sent invalid JSON")?
        };
        let found = parse_nvd(&body);
        self.store(&key, &serde_json::to_string(&found)?);
        Ok(found)
    }

    pub async fn nvd_by_cpe(&self, cpe23: &str) -> Result<Vec<NvdCve>> {
        self.nvd_query("cpeName", cpe23).await
    }

    pub async fn nvd_by_keyword(&self, product: &str, version: &str) -> Result<Vec<NvdCve>> {
        self.nvd_query("keywordSearch", &format!("{product} {version}"))
            .await
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
            let response = self.http.get(&self.settings.kev_url).send().await?;
            if !response.status().is_success() {
                bail!("HTTP {}", response.status());
            }
            Ok(response.json::<Value>().await?)
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

    /// Queries OSV for several packages at once, following
    /// `next_page_token`. Returns `(package index, vulnerability id)` pairs.
    pub async fn osv_batch(&self, packages: &[Package]) -> Result<Vec<(usize, String)>> {
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
                .http
                .post(&url)
                .json(&json!({ "queries": queries }))
                .send()
                .await
                .context("OSV request failed")?;
            if !response.status().is_success() {
                bail!("OSV answered HTTP {}", response.status());
            }
            let body: Value = response.json().await.context("OSV sent invalid JSON")?;
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
        Ok(found)
    }

    /// Full OSV record for one id (cached for a day).
    pub async fn osv_details(&self, id: &str) -> Result<Value> {
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
            .http
            .get(&url)
            .send()
            .await
            .context("OSV request failed")?;
        if !response.status().is_success() {
            bail!("OSV answered HTTP {} for {id}", response.status());
        }
        let body: Value = response.json().await.context("OSV sent invalid JSON")?;
        self.store(&key, &body.to_string());
        Ok(body)
    }

    /// Runs every lookup [`plan`] produces for `host`. Never fails as a
    /// whole: problems are reported per lookup in [`Grounding::errors`], and
    /// after the first network failure the remaining lookups are skipped so
    /// an offline machine is not kept waiting.
    pub async fn ground(&self, host: &Host) -> Grounding {
        let lookups = plan(host);
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

        let mut packages: Vec<(Package, Option<String>)> = Vec::new();
        // One slow answer is not an outage: the next lookup is still tried.
        // After a second failure the rest is skipped.
        let mut failures = 0;
        let mut offline = false;
        for lookup in &lookups {
            let (query, product, version, port) = match lookup {
                Lookup::Package { package, port } => {
                    packages.push((package.clone(), port.clone()));
                    continue;
                }
                Lookup::Cpe { cpe, port } => (format!("cpeName={cpe}"), None, None, port),
                Lookup::Keyword {
                    product,
                    version,
                    port,
                } => (
                    format!("keywordSearch={product} {version}"),
                    Some(product.as_str()),
                    Some(version.as_str()),
                    port,
                ),
            };
            if offline {
                continue;
            }
            let result = match (lookup, product, version) {
                (Lookup::Cpe { cpe, .. }, _, _) => self.nvd_by_cpe(cpe).await,
                (_, Some(product), Some(version)) => self.nvd_by_keyword(product, version).await,
                _ => continue,
            };
            let found = match result {
                Ok(found) => found,
                Err(error) => {
                    grounding.errors.push(format!("{query}: {error:#}"));
                    failures += 1;
                    offline = failures >= 2;
                    continue;
                }
            };
            for cve in found {
                // NVD already matched cpeName server-side; keyword hits are
                // checked against the version ranges here.
                let confidence = match (product, version) {
                    (Some(product), Some(version)) => match cve.applies_to(product, version) {
                        Some(confidence) => confidence,
                        None => continue,
                    },
                    _ => Confidence::Medium,
                };
                let evidence = json!({
                    "query": query, "id": cve.id, "vulnStatus": cve.status, "cvss": cve.cvss,
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
                        record: EvidenceRecord::hypothesis(Source::NvdApi, confidence, &evidence),
                    },
                );
            }
        }

        if !packages.is_empty() && !offline {
            let list: Vec<Package> = packages.iter().map(|(p, _)| p.clone()).collect();
            match self.osv_batch(&list).await {
                Ok(hits) => {
                    for (index, id) in hits.into_iter().take(OSV_MAX_DETAILS) {
                        let (package, port) = &packages[index];
                        let details = self.osv_details(&id).await.unwrap_or(Value::Null);
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
                                kev: kev.contains(&id) || aliases.iter().any(|a| kev.contains(a)),
                                id,
                                title,
                                severity: details
                                    .pointer("/database_specific/severity")
                                    .and_then(Value::as_str)
                                    .map(str::to_owned),
                                cvss: None,
                                matched: package.label(),
                                port: port.clone(),
                                references: details
                                    .get("references")
                                    .and_then(Value::as_array)
                                    .into_iter()
                                    .flatten()
                                    .filter_map(|r| text_field(r, "url"))
                                    .take(MAX_REFERENCES)
                                    .collect(),
                                record: EvidenceRecord::hypothesis(
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

/// What grounding a whole graph added.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GraphGrounding {
    pub hosts: usize,
    pub lookups: usize,
    pub new_advisories: usize,
    pub kev: usize,
    pub errors: Vec<String>,
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
        for advisory in grounding.advisories {
            let kev = advisory.kev;
            let known = host.advisories.iter().any(|a| a.id == advisory.id);
            if graph.add_advisory(&address, advisory) && !known {
                summary.new_advisories += 1;
                summary.kev += usize::from(kev);
            }
        }
        for fact in grounding.facts {
            graph.add_host_fact(&address, fact);
        }
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
    use crate::evidence::VerificationStatus;
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
            ("8.2p1", "8.10", Less),
            ("2.4.41", "2.4.9", Greater),
            ("1.0.0", "1.0", Greater),
            ("1.2.3-beta", "1.2.3-rc", Less),
            ("v2.0", "2.0", Equal),
            ("10", "9.99.99", Greater),
        ] {
            assert_eq!(cmp_versions(a, b), expected, "{a} vs {b}");
            assert_eq!(cmp_versions(b, a), expected.reverse(), "{b} vs {a}");
        }
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
    async fn grounding_attaches_only_unverified_hypotheses() {
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
        for advisory in &grounding.advisories {
            assert_eq!(
                advisory.record.verification_status,
                VerificationStatus::UnverifiedHypothesis
            );
        }
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
            sent.contains("cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*&resultsPerPage=200"),
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
}

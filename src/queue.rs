//! The background recon queue.
//!
//! `meow recon <target>` queues one task of four stages that run strictly
//! one at a time: port inventory (`nmap`), service inventory (`nmap -sV` on
//! the open ports only), web crawl (`katana`) and directory inventory
//! (`feroxbuster`). Each tool runs with `stdin` closed, in its own process
//! group (a Job Object on Windows), under a wall-clock timeout and an output
//! size cap, and writes a structured file to `<workspace>/tmp/` that is
//! parsed and then deleted. Stage status is kept in `state.db` so an
//! interrupted task can be resumed when the session is reopened.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Semaphore};

use crate::coordinator::State;
use crate::db::Db;
use crate::endpoint::{HostAddr, Target};
use crate::graph::{Graph, Host, Observation};
use crate::mode::Mode;
use crate::parsers;
use crate::timeutil::now_rfc3339;

const MAX_HOSTS_PER_STAGE: usize = 64;
const MAX_URLS_PER_STAGE: usize = 32;
const CAP_POLL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Lan,
    Dns,
    Asn,
    Subdomains,
    Trace,
    Ports,
    Services,
    Headers,
    #[serde(rename = "waf-cdn", alias = "waf_cdn")]
    WafCdn,
    #[serde(rename = "tls-audit", alias = "tls_audit")]
    TlsAudit,
    #[serde(rename = "ssh-audit", alias = "ssh_audit")]
    SshAudit,
    Cves,
    Crawl,
    Dirs,
}

pub const STAGES: [Stage; 14] = [
    Stage::Lan,
    Stage::Dns,
    Stage::Asn,
    Stage::Subdomains,
    Stage::Trace,
    Stage::Ports,
    Stage::Services,
    Stage::Headers,
    Stage::WafCdn,
    Stage::TlsAudit,
    Stage::SshAudit,
    Stage::Cves,
    Stage::Crawl,
    Stage::Dirs,
];

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Lan => "lan",
            Stage::Dns => "dns",
            Stage::Asn => "asn",
            Stage::Subdomains => "subdomains",
            Stage::Trace => "trace",
            Stage::Ports => "ports",
            Stage::Services => "services",
            Stage::Headers => "headers",
            Stage::WafCdn => "waf-cdn",
            Stage::TlsAudit => "tls-audit",
            Stage::SshAudit => "ssh-audit",
            Stage::Cves => "cves",
            Stage::Crawl => "crawl",
            Stage::Dirs => "dirs",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "waf_cdn" => Some(Stage::WafCdn),
            "tls_audit" => Some(Stage::TlsAudit),
            "ssh_audit" => Some(Stage::SshAudit),
            _ => STAGES.into_iter().find(|stage| stage.as_str() == text),
        }
    }
}

// ---------------------------------------------------------------------------
// Settings and presets
// ---------------------------------------------------------------------------

/// Tool flags for one mode. `None` means "use the built-in default".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PresetOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nmap_ports: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nmap_services: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub katana_depth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ferox_rate_limit: Option<u32>,
}

impl PresetOverride {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    pub nmap_ports: Vec<String>,
    pub nmap_services: Vec<String>,
    pub katana_depth: u32,
    /// Requests per second for feroxbuster; `None` uses `--auto-tune`.
    pub ferox_rate_limit: Option<u32>,
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

impl Preset {
    /// Built-in flags for a mode. `light` never runs tools.
    pub fn builtin(mode: Mode) -> Self {
        let scripts = "ssl-cert,http-server-header,http-title";
        match mode {
            Mode::Aggressive => Self {
                nmap_ports: strings(&["-sS", "-T4", "-p-", "-O"]),
                nmap_services: strings(&["-sV", "--version-all", "-T4", "--script", scripts]),
                katana_depth: 4,
                ferox_rate_limit: None,
            },
            _ => Self {
                nmap_ports: strings(&["-sS", "-T3", "--top-ports", "1000"]),
                nmap_services: strings(&[
                    "-sV",
                    "--version-intensity",
                    "5",
                    "-T3",
                    "--script",
                    scripts,
                ]),
                katana_depth: 2,
                ferox_rate_limit: Some(20),
            },
        }
    }

    fn apply(mut self, over: &PresetOverride) -> Self {
        if let Some(flags) = &over.nmap_ports {
            self.nmap_ports = flags.clone();
        }
        if let Some(flags) = &over.nmap_services {
            self.nmap_services = flags.clone();
        }
        if let Some(depth) = over.katana_depth {
            self.katana_depth = depth;
        }
        if over.ferox_rate_limit.is_some() {
            self.ferox_rate_limit = over.ferox_rate_limit;
        }
        self
    }
}

/// `[recon]` section of `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ReconSettings {
    /// Wall-clock limit for each tool run.
    pub stage_timeout_secs: u64,
    /// A tool whose output file grows past this is stopped.
    pub output_cap_mb: u64,
    /// Wordlist for feroxbuster; standard system paths are tried otherwise.
    pub wordlist_path: Option<String>,
    /// Program names or paths of the tools.
    pub nmap: String,
    pub katana: String,
    pub feroxbuster: String,
    pub mild: PresetOverride,
    pub aggressive: PresetOverride,
    /// `~/.meow/wordlists`: any `.txt` file put there is used when no
    /// wordlist is configured and none is installed system-wide.
    #[serde(skip)]
    pub wordlist_dir: Option<PathBuf>,
}

impl Default for ReconSettings {
    fn default() -> Self {
        Self {
            stage_timeout_secs: 1800,
            output_cap_mb: 50,
            wordlist_path: None,
            nmap: "nmap".to_owned(),
            katana: "katana".to_owned(),
            feroxbuster: "feroxbuster".to_owned(),
            mild: PresetOverride::default(),
            aggressive: PresetOverride::default(),
            wordlist_dir: None,
        }
    }
}

impl ReconSettings {
    /// Flags for `mode`: built-in, then `config.toml`, then `profile.toml`.
    pub fn preset(&self, mode: Mode, profile: &PresetOverride) -> Preset {
        let from_config = match mode {
            Mode::Aggressive => &self.aggressive,
            _ => &self.mild,
        };
        Preset::builtin(mode).apply(from_config).apply(profile)
    }

    fn limits(&self) -> RunLimits {
        RunLimits {
            timeout: Duration::from_secs(self.stage_timeout_secs.max(1)),
            cap_bytes: self.output_cap_mb.max(1).saturating_mul(1024 * 1024),
        }
    }
}

const MAX_WORDLIST_BYTES: u64 = 50 * 1024 * 1024;

const STANDARD_WORDLISTS: &[&str] = &[
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/local/share/seclists/Discovery/Web-Content/common.txt",
    "/home/linuxbrew/.linuxbrew/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/homebrew/share/meow/wordlists/common.txt",
    "/usr/local/share/meow/wordlists/common.txt",
    "/home/linuxbrew/.linuxbrew/share/meow/wordlists/common.txt",
];

fn usable_wordlist(path: &Path, allow_symlink: bool) -> bool {
    if path.as_os_str().to_string_lossy().starts_with('-') {
        return false;
    }
    if !allow_symlink {
        let Ok(link_meta) = std::fs::symlink_metadata(path) else {
            return false;
        };
        if link_meta.file_type().is_symlink() {
            return false;
        }
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && meta.len() > 0 && meta.len() <= MAX_WORDLIST_BYTES
}

/// The configured wordlist if it exists, else the first standard one found,
/// else the first `.txt` file (by name) in `own_dir`.
pub fn find_wordlist(configured: Option<&str>, own_dir: Option<&Path>) -> Option<PathBuf> {
    let system_paths: &[&str] = if cfg!(unix) { STANDARD_WORDLISTS } else { &[] };
    let found = configured
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .into_iter()
        .map(|p| (PathBuf::from(p), false))
        .chain(system_paths.iter().map(|p| (PathBuf::from(p), true)))
        .find(|(path, allow_symlink)| usable_wordlist(path, *allow_symlink))
        // Tools run in a folder of their own: a relative path would not
        // name the same file there.
        .map(|(path, _)| std::path::absolute(&path).unwrap_or(path));
    found.or_else(|| {
        let mut own: Vec<PathBuf> = std::fs::read_dir(own_dir?)
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension().is_some_and(|e| e == "txt") && usable_wordlist(path, false)
            })
            .collect();
        own.sort();
        own.into_iter()
            .next()
            .map(|path| std::path::absolute(&path).unwrap_or(path))
    })
}

/// How to get a missing tool, said where the stage is skipped.
fn install_hint(program: &str) -> String {
    format!("{program} is not installed (run `meow tools` to install it)")
}

// ---------------------------------------------------------------------------
// Command builders
// ---------------------------------------------------------------------------

/// True when the process may send raw packets (root / elevated).
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // SAFETY: IsUserAnAdmin takes no arguments.
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
    }
}

const HIGH_RATE_FLAGS: &[&str] = &["-T4", "-T5", "-A"];
const MAX_NMAP_FLAGS: usize = 32;
const SAFE_SERVICE_SCRIPTS: &[&str] = &[
    "ssl-cert",
    "http-server-header",
    "http-title",
    "ssh-hostkey",
    "banner",
];

/// nmap script categories an operator may ask for. Whatever is chosen,
/// scripts that are also in [`SCRIPT_NEVER`] do not run.
pub const SCRIPT_CATEGORIES: &[&str] = &["default", "safe", "vuln", "discovery", "version"];
/// Categories that log in, guess passwords, crash or exploit services, send
/// data to third parties or reach beyond the target.
const SCRIPT_NEVER: &str =
    "intrusive or external or brute or dos or exploit or fuzzer or malware or broadcast";

fn is_operator_script_list(val: &str) -> bool {
    !val.is_empty()
        && val
            .split(',')
            .all(|item| SCRIPT_CATEGORIES.contains(&item) || SAFE_SERVICE_SCRIPTS.contains(&item))
}

/// The operator's flags, sorted into the stage each belongs to: port
/// choice, up check, timing and OS detection run in the port stage; version
/// detection and scripts in the service stage, on the open ports only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconFlags {
    pub ports: Vec<String>,
    pub versions: Vec<String>,
    /// Script categories and built-in script names.
    pub scripts: Vec<String>,
    /// Host-discovery, DNS, and address-family flags needed by both nmap stages.
    pub shared: Vec<String>,
}

pub fn split_recon_flags(flags: &[String]) -> ReconFlags {
    let mut out = ReconFlags::default();
    let add_scripts = |out: &mut ReconFlags, list: &str| {
        for item in list.split(',') {
            if !out.scripts.iter().any(|known| known == item) {
                out.scripts.push(item.to_owned());
            }
        }
    };
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "-sC" => add_scripts(&mut out, "default"),
            // -A is -O -sV -sC (and a traceroute, left out).
            "-A" => {
                out.ports.push("-O".to_owned());
                add_scripts(&mut out, "default");
            }
            "--script" => {
                if let Some(list) = flags.next() {
                    add_scripts(&mut out, list);
                }
            }
            "-sV" => {} // the service stage always runs version detection
            "--version-light" | "--version-all" => out.versions.push(flag.clone()),
            "--version-intensity" => {
                out.versions.push(flag.clone());
                out.versions.extend(flags.next().cloned());
            }
            other => {
                if let Some(list) = other.strip_prefix("--script=") {
                    add_scripts(&mut out, list);
                } else if other.starts_with("--version-intensity=") {
                    out.versions.push(flag.clone());
                } else if is_scan_technique_flag(other)
                    && other[2..].contains('V')
                    && other.len() > 3
                {
                    // -sSV: the scan type stays here, V is the service stage's.
                    out.ports.push(other.replacen('V', "", 1));
                } else {
                    if is_host_probe_flag(other)
                        || matches!(other, "-n" | "-R" | "--system-dns" | "-4" | "-6")
                    {
                        out.shared.push(flag.clone());
                    }
                    out.ports.push(flag.clone());
                }
            }
        }
    }
    out
}

/// The nmap `--script` expression for the built-in scripts plus the
/// operator's choice, with the never-run categories excluded. Anything that
/// is neither a known category nor a built-in script is left out, whatever
/// the caller checked: a script file or expression never reaches nmap.
fn script_expression(builtin: &[&str], chosen: &[String]) -> String {
    let mut names: Vec<String> = builtin.iter().map(|name| (*name).to_owned()).collect();
    let mut categories = Vec::new();
    for item in chosen {
        if SCRIPT_CATEGORIES.contains(&item.as_str()) {
            categories.push(item.as_str());
        } else if SAFE_SERVICE_SCRIPTS.contains(&item.as_str()) && !names.contains(item) {
            names.push(item.clone());
        }
    }
    let mut parts = names;
    if !categories.is_empty() {
        parts.push(format!(
            "(({}) and not ({SCRIPT_NEVER}))",
            categories.join(" or ")
        ));
    }
    parts.join(" or ")
}

/// Which of `flags` are high-rate (`-T4`, `-T5`, "-A").
pub fn high_rate_flags(flags: &[String]) -> Vec<&str> {
    flags
        .iter()
        .map(String::as_str)
        .filter(|flag| HIGH_RATE_FLAGS.contains(flag))
        .collect()
}

fn is_port_spec(val: &str) -> bool {
    if val.is_empty() || val.len() > 256 {
        return false;
    }
    if val == "-" {
        return true;
    }
    if val.starts_with('-') {
        return false;
    }
    val.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b',' | b'-' | b':' | b'_'))
}

fn is_uint_in(val: &str, min: u32, max: u32) -> bool {
    !val.is_empty()
        && val.bytes().all(|b| b.is_ascii_digit())
        && val.parse::<u32>().is_ok_and(|n| (min..=max).contains(&n))
}

fn is_nmap_duration(val: &str) -> bool {
    let digits = val
        .strip_suffix("ms")
        .or_else(|| val.strip_suffix(['s', 'm', 'h']))
        .unwrap_or(val);
    !digits.is_empty()
        && digits.len() <= 12
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits.parse::<u64>().is_ok()
}

fn is_exclude_list(val: &str) -> bool {
    !val.is_empty()
        && val.len() <= 512
        && val.split(',').all(|item| {
            !item.is_empty()
                && (item.parse::<ipnetwork::IpNetwork>().is_ok() || HostAddr::parse(item).is_some())
        })
}

fn is_safe_service_script_list(val: &str) -> bool {
    !val.is_empty()
        && val
            .split(',')
            .all(|script| SAFE_SERVICE_SCRIPTS.contains(&script))
}

fn is_scan_technique_flag(flag: &str) -> bool {
    if matches!(flag, "-sn" | "-sP" | "-sO") {
        return true;
    }
    if !flag.starts_with("-s") || flag.starts_with("--") || !(3..=5).contains(&flag.len()) {
        return false;
    }
    let mut seen = 0u32;
    for c in flag[2..].chars() {
        if !matches!(
            c,
            'S' | 'T' | 'U' | 'A' | 'W' | 'M' | 'N' | 'F' | 'X' | 'Y' | 'Z' | 'V'
        ) {
            return false;
        }
        let bit = 1u32 << (c as u8 - b'A');
        if seen & bit != 0 {
            return false;
        }
        seen |= bit;
    }
    true
}

fn is_host_probe_flag(flag: &str) -> bool {
    if matches!(flag, "-Pn" | "-P0" | "-PE" | "-PP" | "-PM") {
        return true;
    }
    for prefix in ["-PS", "-PA", "-PU", "-PY"] {
        if flag == prefix {
            return true;
        }
        if let Some(ports) = flag.strip_prefix(prefix) {
            return !ports.starts_with('-') && is_port_spec(ports);
        }
    }
    false
}

/// `operator`: flags typed on `meow recon`, which may also choose script
/// categories (`-sC`, `-A`, `--script default`); presets from
/// `config.toml` may not.
fn validate_flags_inner(
    flags: &[String],
    allow_service_scripts: bool,
    operator: bool,
) -> Result<()> {
    if flags.len() > MAX_NMAP_FLAGS {
        bail!("too many nmap flags (at most {MAX_NMAP_FLAGS} allowed)");
    }
    let mut i = 0;
    while i < flags.len() {
        let arg = flags[i].as_str();
        if arg.is_empty() || arg.chars().any(|c| c.is_control()) {
            bail!("invalid nmap flag {arg:?}");
        }
        if !arg.starts_with('-') || arg == "-" || arg == "--" {
            bail!("unexpected nmap argument '{arg}': only safe nmap option flags are allowed");
        }

        if matches!(
            arg,
            "-O" | "-F"
                | "-r"
                | "-n"
                | "-R"
                | "-4"
                | "-6"
                | "-v"
                | "-vv"
                | "-d"
                | "-dd"
                | "-p-"
                | "--open"
                | "--reason"
                | "--system-dns"
                | "--osscan-limit"
                | "--osscan-guess"
                | "--fuzzy"
                | "--version-light"
                | "--version-all"
                | "--defeat-rst-ratelimit"
                | "--defeat-icmp-ratelimit"
                | "-T0"
                | "-T1"
                | "-T2"
                | "-T3"
                | "-T4"
                | "-T5"
        ) || (operator && matches!(arg, "-sC" | "-A"))
            || is_scan_technique_flag(arg)
            || is_host_probe_flag(arg)
        {
            i += 1;
            continue;
        }

        if let Some(inline) = arg.strip_prefix("-p") {
            if !arg.starts_with("--") {
                if inline.is_empty() {
                    let Some(val) = flags.get(i + 1).map(String::as_str) else {
                        bail!("nmap flag '-p' requires a port range");
                    };
                    if !is_port_spec(val) {
                        bail!("invalid port specification '{val}' for '-p'");
                    }
                    i += 2;
                    continue;
                } else if !inline.starts_with(|c: char| c.is_ascii_digit()) {
                    // nmap reads `-po`, `-pri` or `-pro` as shortened long
                    // options (--port-ratio, --privileged, --proxies), not
                    // as ports: the next value would become a scan target.
                    bail!(
                        "write the port list after a space: '-p {inline}' (attached to '-p' it must start with a digit)"
                    );
                } else if is_port_spec(inline) {
                    i += 1;
                    continue;
                } else {
                    bail!("invalid port specification '{inline}' in '{arg}'");
                }
            }
        }
        if arg == "-T" {
            let Some(val) = flags.get(i + 1).map(String::as_str) else {
                bail!("nmap flag '-T' requires a timing template (0-5)");
            };
            if !is_uint_in(val, 0, 5) {
                bail!("invalid timing template '{val}' for '-T' (expected 0-5)");
            }
            i += 2;
            continue;
        }

        if arg.starts_with("--") {
            let (name, inline_val) = match arg.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (arg, None),
            };
            let take_val = |i: &mut usize| -> Result<&str> {
                if let Some(v) = inline_val {
                    *i += 1;
                    Ok(v)
                } else if let Some(v) = flags.get(*i + 1).map(String::as_str) {
                    if v.is_empty() || v.chars().any(|c| c.is_control()) {
                        bail!("invalid value for nmap flag '{name}'");
                    }
                    *i += 2;
                    Ok(v)
                } else {
                    bail!("nmap flag '{name}' requires a value");
                }
            };

            match name {
                "--ports" | "--exclude-ports" => {
                    let val = take_val(&mut i)?;
                    if !is_port_spec(val) || val == "-" {
                        bail!("invalid port specification '{val}' for '{name}'");
                    }
                    continue;
                }
                "--top-ports" => {
                    let val = take_val(&mut i)?;
                    if !is_uint_in(val, 1, 65535) {
                        bail!("invalid value '{val}' for '--top-ports' (expected 1..65535)");
                    }
                    continue;
                }
                "--version-intensity" => {
                    let val = take_val(&mut i)?;
                    if !is_uint_in(val, 0, 9) {
                        bail!("invalid value '{val}' for '--version-intensity' (expected 0..9)");
                    }
                    continue;
                }
                "--max-retries" => {
                    let val = take_val(&mut i)?;
                    if !is_uint_in(val, 0, 30) {
                        bail!("invalid value '{val}' for '--max-retries' (expected 0..30)");
                    }
                    continue;
                }
                "--min-rate" | "--max-rate" => {
                    let val = take_val(&mut i)?;
                    if !is_uint_in(val, 1, 1_000_000) {
                        bail!("invalid value '{val}' for '{name}'");
                    }
                    continue;
                }
                "--min-parallelism"
                | "--max-parallelism"
                | "--min-hostgroup"
                | "--max-hostgroup" => {
                    let val = take_val(&mut i)?;
                    if !is_uint_in(val, 1, 10_000) {
                        bail!("invalid value '{val}' for '{name}'");
                    }
                    continue;
                }
                "--host-timeout"
                | "--scan-delay"
                | "--max-scan-delay"
                | "--min-rtt-timeout"
                | "--max-rtt-timeout"
                | "--initial-rtt-timeout" => {
                    let val = take_val(&mut i)?;
                    if !is_nmap_duration(val) {
                        bail!("invalid duration '{val}' for '{name}'");
                    }
                    continue;
                }
                "--exclude" => {
                    let val = take_val(&mut i)?;
                    if !is_exclude_list(val) {
                        bail!("invalid target list '{val}' for '--exclude'");
                    }
                    continue;
                }
                "--script" if allow_service_scripts => {
                    let val = take_val(&mut i)?;
                    if !is_safe_service_script_list(val) {
                        bail!(
                            "nmap '--script' in service presets may only name built-in header/TLS scripts ({})",
                            SAFE_SERVICE_SCRIPTS.join(", ")
                        );
                    }
                    continue;
                }
                "--script" if operator => {
                    let val = take_val(&mut i)?;
                    if !is_operator_script_list(val) {
                        bail!(
                            "nmap '--script' takes script categories ({}) or built-in scripts ({}); \
                             scripts that are intrusive, brute-force, denial-of-service, exploits, \
                             external or broadcast never run. For anything else run nmap yourself \
                             and import the result with `meow add`",
                            SCRIPT_CATEGORIES.join(", "),
                            SAFE_SERVICE_SCRIPTS.join(", ")
                        );
                    }
                    continue;
                }
                _ => bail!(
                    "nmap flag '{name}' is not allowed in recon (scripts, file outputs, and target files are refused)"
                ),
            }
        }

        bail!(
            "nmap flag '{arg}' is not allowed in recon (scripts, file outputs, and target files are refused)"
        );
    }
    Ok(())
}

/// Validates extra operator `nmap` flags passed to `meow recon <target> -- ...`.
pub fn validate_nmap_flags(flags: &[String]) -> Result<()> {
    validate_flags_inner(flags, false, true)
}

/// Validates `nmap_ports` and `nmap_services` preset lists from `config.toml`
/// and `profile.toml`.
pub fn validate_preset_nmap_flags(ports: &[String], services: &[String]) -> Result<()> {
    validate_flags_inner(ports, false, false).context("invalid recon nmap_ports preset")?;
    validate_flags_inner(services, true, false).context("invalid recon nmap_services preset")?;
    Ok(())
}

/// Adapts nmap flags to an unprivileged process: `-sS` (raw SYN scan)
/// becomes `-sT` (connect scan) and `-O` (OS detection) is removed, since
/// both need raw sockets. Returns the flags and a notice for each change.
pub fn adapt_for_privilege(flags: Vec<String>, privileged: bool) -> (Vec<String>, Vec<String>) {
    if privileged {
        return (flags, Vec::new());
    }
    let is_raw_tcp = |c: char| matches!(c, 'S' | 'A' | 'W' | 'M' | 'N' | 'F' | 'X' | 'Y' | 'Z');
    let to_connect = |chars: &str| -> String {
        let mut out = String::new();
        for c in chars.chars() {
            let mapped = if is_raw_tcp(c) { 'T' } else { c };
            if !out.contains(mapped) {
                out.push(mapped);
            }
        }
        out
    };
    let mut out = Vec::with_capacity(flags.len());
    let mut notices = Vec::new();
    for flag in flags {
        if flag == "-O" {
            notices.push(
                "not running as root: removed -O (OS detection needs raw sockets)".to_owned(),
            );
        } else if flag == "-sO" {
            notices.push(
                "not running as root: left out -sO (IP protocol scan needs raw sockets)".to_owned(),
            );
        } else if is_scan_technique_flag(&flag) && flag[2..].contains('U') {
            // A UDP scan needs raw sockets: nmap would refuse the whole run.
            let without_u: String = flag[2..].chars().filter(|&c| c != 'U').collect();
            let rest = to_connect(&without_u);
            notices.push(format!(
                "not running as root: left out the UDP scan in {flag} (it needs root; scan UDP \
                 with `sudo nmap -sU -oX udp.xml <target>` and import it with `meow add udp.xml`)"
            ));
            if !rest.is_empty() {
                out.push(format!("-s{rest}"));
            }
        } else if flag.starts_with("-s")
            && !flag.starts_with("--")
            && flag[2..].chars().any(is_raw_tcp)
        {
            let replaced = format!("-s{}", to_connect(&flag[2..]));
            notices.push(format!(
                "not running as root: {flag} replaced with {replaced} (connect scan)"
            ));
            out.push(replaced);
        } else {
            out.push(flag);
        }
    }
    (out, notices)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCommand {
    pub program: String,
    pub args: Vec<String>,
    pub output: PathBuf,
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// How many hosts nmap itself found up (`<hosts up="N" ...>` in its XML).
fn nmap_hosts_up(xml: &str) -> Option<u64> {
    let at = xml.find("<hosts ")?;
    let rest = &xml[at..];
    let value = rest.split("up=\"").nth(1)?.split('"').next()?;
    value.parse().ok()
}

/// Said when nothing answered nmap's host discovery: nmap then scans no
/// ports at all, so a host that is on but ignores those probes looks absent.
fn discovery_hint(flags: &[String]) -> String {
    if flags.iter().any(|flag| flag == "-Pn" || flag == "-P0") {
        return "; nothing answered, even scanning without the up check".to_owned();
    }
    "; nothing answered nmap's up check (ping and probes to ports 80 and 443), so no ports \
     were scanned. If the host is on, run again with `-- -Pn` to scan it anyway, or with \
     other probes such as `-- -PS22,445,3389`"
        .to_owned()
}

/// Flags that say which ports to scan.
fn chooses_ports(flag: &str) -> bool {
    flag == "-F"
        || flag.starts_with("--ports")
        || flag.starts_with("--top-ports")
        || flag.starts_with("--port-ratio")
        || (flag.starts_with("-p") && !flag.starts_with("--"))
}

/// The preset's flags without its own choice of ports (`--top-ports 1000`,
/// `-p-`, `-F`). nmap applies `--top-ports` within any `-p` range, so an
/// operator's `-p-` next to the preset's `--top-ports 1000` would still
/// scan only 1,000 ports.
fn without_port_choice(flags: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(flags.len());
    let mut flags = flags.into_iter();
    while let Some(flag) = flags.next() {
        if !chooses_ports(&flag) {
            out.push(flag);
            continue;
        }
        // `-p 80`, `--ports 80`, `--top-ports 1000`, `--port-ratio 0.1` take
        // their value as the next argument; `-p-`, `-p80`, `--top-ports=1000` do not.
        if matches!(
            flag.as_str(),
            "-p" | "--ports" | "--top-ports" | "--port-ratio"
        ) {
            flags.next();
        }
    }
    out
}

/// Stage 1: port inventory.
pub fn ports_command(
    settings: &ReconSettings,
    preset: &Preset,
    target: &Target,
    extra: &[String],
    privileged: bool,
    output: &Path,
) -> (ToolCommand, Vec<String>) {
    // Ports the operator names replace the preset's choice of ports.
    let mut flags = if extra.iter().any(|flag| chooses_ports(flag)) {
        without_port_choice(preset.nmap_ports.clone())
    } else {
        preset.nmap_ports.clone()
    };
    flags.extend(extra.iter().cloned());
    let (mut args, notices) = adapt_for_privilege(flags, privileged);
    let ipv6 = match target {
        Target::Host(host) => host.ip().is_some_and(|ip| ip.is_ipv6()),
        Target::Network(network) => network.is_ipv6(),
    };
    if ipv6 && !args.iter().any(|a| a == "-6") {
        args.push("-6".to_owned());
    }
    args.extend([
        "-oX".to_owned(),
        path_arg(output),
        "--".to_owned(),
        target.to_string(),
    ]);
    (
        ToolCommand {
            program: settings.nmap.clone(),
            args,
            output: output.to_path_buf(),
        },
        notices,
    )
}

/// Stage 2: service inventory, only on the ports stage 1 found open.
pub fn services_command(
    settings: &ReconSettings,
    preset: &Preset,
    extra: &ReconFlags,
    address: &str,
    ports: &[u16],
    privileged: bool,
    output: &Path,
) -> (ToolCommand, Vec<String>) {
    let mut flags = preset.nmap_services.clone();
    if !extra.scripts.is_empty() {
        // One --script with everything: the built-in scripts stay.
        let mut builtin: Vec<String> = Vec::new();
        let mut index = 0;
        while index < flags.len() {
            if flags[index] == "--script" && index + 1 < flags.len() {
                let list = flags.remove(index + 1);
                flags.remove(index);
                builtin.extend(list.split(',').filter(|s| !s.is_empty()).map(str::to_owned));
            } else if let Some(list) = flags[index].strip_prefix("--script=") {
                let list = list.to_owned();
                flags.remove(index);
                builtin.extend(list.split(',').filter(|s| !s.is_empty()).map(str::to_owned));
            } else {
                index += 1;
            }
        }
        let builtin_refs: Vec<&str> = builtin.iter().map(String::as_str).collect();
        flags.push("--script".to_owned());
        flags.push(script_expression(&builtin_refs, &extra.scripts));
    }
    flags.extend(extra.versions.iter().cloned());
    for shared in &extra.shared {
        if !flags.contains(shared) {
            flags.push(shared.clone());
        }
    }
    let (mut args, notices) = adapt_for_privilege(flags, privileged);
    let ipv6 = HostAddr::parse(address)
        .and_then(|h| h.ip())
        .is_some_and(|ip| ip.is_ipv6());
    if ipv6 && !args.iter().any(|a| a == "-6") {
        args.push("-6".to_owned());
    }
    let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
    args.extend([
        "-p".to_owned(),
        ports.join(","),
        "-oX".to_owned(),
        path_arg(output),
        "--".to_owned(),
        address.to_owned(),
    ]);
    (
        ToolCommand {
            program: settings.nmap.clone(),
            args,
            output: output.to_path_buf(),
        },
        notices,
    )
}

/// Stage 3: web link and JavaScript route crawl.
pub fn crawl_command(
    settings: &ReconSettings,
    preset: &Preset,
    url: &str,
    output: &Path,
) -> ToolCommand {
    let depth = preset.katana_depth.to_string();
    ToolCommand {
        program: settings.katana.clone(),
        args: strings(&[
            "-u",
            url,
            "-jsonl",
            "-silent",
            "-nc",
            "-jc",
            // Stay on the host being crawled. The default scope is the root
            // domain, which an IP address does not have, so links to other
            // sites (and to `localhost`) would be followed.
            "-fs",
            "fqdn",
            "-ct",
            "5m",
            "-d",
            &depth,
            "-o",
            &path_arg(output),
        ]),
        output: output.to_path_buf(),
    }
}

/// Stage 4: directory and endpoint inventory. `--rate-limit` (with
/// `--scan-limit 1` and `--auto-bail`) and `--auto-tune` exclude each other.
pub fn dirs_command(
    settings: &ReconSettings,
    preset: &Preset,
    url: &str,
    wordlist: &Path,
    output: &Path,
) -> ToolCommand {
    let mut args = strings(&["-u", url, "--quiet", "--no-state"]);
    match preset.ferox_rate_limit {
        Some(rate) => args.extend(strings(&[
            "--rate-limit",
            &rate.to_string(),
            "--scan-limit",
            "1",
            "--auto-bail",
            "--time-limit",
            "10m",
        ])),
        None => args.extend(strings(&["--auto-tune", "--time-limit", "15m"])),
    }
    args.extend(strings(&[
        "--json",
        "-o",
        &path_arg(output),
        "-w",
        &path_arg(wordlist),
    ]));
    ToolCommand {
        program: settings.feroxbuster.clone(),
        args,
        output: output.to_path_buf(),
    }
}

// ---------------------------------------------------------------------------
// Running one tool
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    pub timeout: Duration,
    pub cap_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// The tool exited by itself with this code (`None`: killed by a signal).
    Exited(Option<i32>),
    TimedOut,
    OutputCapExceeded,
    NotInstalled,
    Failed(String),
    /// Stopped by meow because it may no longer run (the mode changed).
    Stopped,
}

/// Kills the whole process group when dropped, so a cancelled stage or a
/// closing session never leaves scanners running.
#[cfg(unix)]
struct GroupGuard(Option<u32>);

#[cfg(unix)]
impl GroupGuard {
    fn kill_all(&self) {
        if let Some(pid) = self.0 {
            // SAFETY: plain syscall; the child was started as the leader of
            // its own process group, so this cannot signal our own group.
            unsafe {
                libc::killpg(pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

#[cfg(unix)]
impl Drop for GroupGuard {
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// A Job Object with kill-on-close: closing the handle ends every process
/// the tool started.
#[cfg(windows)]
struct GroupGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
// SAFETY: a job handle may be used and closed from any thread.
unsafe impl Send for GroupGuard {}

#[cfg(windows)]
impl GroupGuard {
    fn attach(process: std::os::windows::io::RawHandle) -> Option<Self> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        // SAFETY: all pointers are valid for the duration of each call and
        // the structure is plain data that may be zero-initialised.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) != 0;
            if !configured || AssignProcessToJobObject(job, process as _) == 0 {
                CloseHandle(job);
                return None;
            }
            Some(Self(job))
        }
    }

    fn kill_all(&self) {
        // SAFETY: self.0 is a valid Job Object handle owned by this guard.
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0, 1);
        }
    }
}

#[cfg(windows)]
impl Drop for GroupGuard {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this guard and closed exactly once.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Environment variables that hold credentials by their names: API keys
/// and tokens are no business of a scanner.
fn is_secret_variable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL"]
        .iter()
        .any(|word| upper.contains(word))
}

/// Runs one tool to completion, or stops it at the time or size limit.
///
/// The tool runs in an empty private folder made for this run, not where
/// the session was started: feroxbuster, nmap and katana all read settings
/// or data files from their working directory, and that directory may be
/// one the user did not write (a cloned repository). Variables that look
/// like credentials are not passed on.
pub async fn run_tool(command: &ToolCommand, limits: RunLimits) -> RunOutcome {
    run_tool_while(command, limits, || true).await
}

/// [`run_tool`], stopping the tool (and everything it started) as soon as
/// `may_run` says no. It is asked before the start and every [`CAP_POLL`].
pub async fn run_tool_while(
    command: &ToolCommand,
    limits: RunLimits,
    may_run: impl Fn() -> bool,
) -> RunOutcome {
    if !may_run() {
        return RunOutcome::Stopped;
    }
    // Whatever already sits where the output goes is never written through.
    match std::fs::symlink_metadata(&command.output) {
        Ok(meta) if meta.file_type().is_file() => {
            let _ = std::fs::remove_file(&command.output);
        }
        Ok(_) => {
            return RunOutcome::Failed(format!(
                "{} exists and is not a regular file; refusing to write {}'s output there",
                command.output.display(),
                command.program
            ))
        }
        Err(_) => {}
    }
    let scratch = command.output.parent().and_then(|dir| {
        let mut builder = tempfile::Builder::new();
        builder.prefix("run-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        builder.tempdir_in(dir).ok()
    });
    let Some(scratch) = scratch else {
        return RunOutcome::Failed(format!(
            "cannot make a private folder to run {} in",
            command.program
        ));
    };
    // A configured relative path names a program where meow was started;
    // bare names resolve strictly through absolute `PATH` entries (never a
    // relative `PATH` entry or Windows's parent working directory).
    let program_candidate = if Path::new(&command.program).components().count() > 1
        && Path::new(&command.program).is_relative()
    {
        std::path::absolute(&command.program)
            .ok()
            .and_then(|p| p.to_str().map(str::to_owned))
            .unwrap_or_else(|| command.program.clone())
    } else {
        command.program.clone()
    };
    let Some(program) = crate::tools::find_program(&program_candidate) else {
        return RunOutcome::NotInstalled;
    };
    let mut process = tokio::process::Command::new(program);
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(is_secret_variable) {
            process.env_remove(&name);
        }
    }
    process
        .current_dir(scratch.path())
        .args(&command.args)
        // No terminal input: a tool that asks a question gets EOF instead of
        // hanging the queue.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    process.process_group(0);

    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RunOutcome::NotInstalled
        }
        Err(error) => {
            return RunOutcome::Failed(format!("cannot start {}: {error}", command.program))
        }
    };
    #[cfg(unix)]
    let _group = GroupGuard(child.id());
    #[cfg(windows)]
    let _group = child.raw_handle().and_then(GroupGuard::attach);

    let deadline = tokio::time::sleep(limits.timeout);
    tokio::pin!(deadline);
    let mut poll = tokio::time::interval(CAP_POLL);
    let outcome = loop {
        tokio::select! {
            status = child.wait() => break match status {
                Ok(status) => RunOutcome::Exited(status.code()),
                Err(error) => RunOutcome::Failed(error.to_string()),
            },
            () = &mut deadline => break RunOutcome::TimedOut,
            _ = poll.tick() => {
                if !may_run() {
                    break RunOutcome::Stopped;
                }
                let size = tokio::fs::metadata(&command.output).await.map(|m| m.len()).unwrap_or(0);
                if size > limits.cap_bytes {
                    break RunOutcome::OutputCapExceeded;
                }
            }
        }
    };
    if !matches!(outcome, RunOutcome::Exited(_)) {
        #[cfg(unix)]
        _group.kill_all();
        #[cfg(windows)]
        if let Some(group) = &_group {
            group.kill_all();
        }
        let _ = child.kill().await;
    }
    outcome
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageRow {
    pub stage: Stage,
    /// `pending`, `running`, `interrupted`, `done`, `skipped` or `failed`.
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRow {
    pub id: i64,
    pub target: String,
    pub mode: Mode,
    pub extra_flags: Vec<String>,
    pub created_utc: String,
    pub stages: Vec<StageRow>,
}

impl TaskRow {
    /// Still has work to do (now or after a resume).
    pub fn unfinished(&self) -> bool {
        self.stages
            .iter()
            .any(|s| matches!(s.status.as_str(), "pending" | "running" | "interrupted"))
    }

    /// `recon 10.0.0.0/24: services interrupted`
    pub fn describe(&self) -> String {
        let current = self
            .stages
            .iter()
            .find(|s| matches!(s.status.as_str(), "running" | "interrupted" | "pending"));
        match current {
            Some(stage) => format!(
                "recon {}: {} {}",
                self.target,
                stage.stage.as_str(),
                stage.status
            ),
            None => format!("recon {}: finished", self.target),
        }
    }
}

fn map_task_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskRow> {
    let mode: String = row.get(2)?;
    let flags: String = row.get(3)?;
    Ok(TaskRow {
        id: row.get(0)?,
        target: row.get(1)?,
        mode: Mode::parse(&mode).unwrap_or(Mode::Light),
        extra_flags: serde_json::from_str(&flags).unwrap_or_default(),
        created_utc: row.get(4)?,
        stages: Vec::new(),
    })
}

fn attach_stages_range(conn: &rusqlite::Connection, rows: &mut [TaskRow]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let min_id = rows.iter().map(|r| r.id).min().unwrap_or(0);
    let max_id = rows.iter().map(|r| r.id).max().unwrap_or(0);
    let index_by_id: std::collections::HashMap<i64, usize> = rows
        .iter()
        .enumerate()
        .map(|(idx, r)| (r.id, idx))
        .collect();
    let mut stmt = conn.prepare(
        "SELECT task_id, stage, status, detail FROM task_stages
         WHERE task_id BETWEEN ?1 AND ?2 ORDER BY task_id, position",
    )?;
    let iter = stmt.query_map(params![min_id, max_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    for item in iter {
        let (task_id, stage, status, detail) = item?;
        if let (Some(&idx), Some(stage)) = (index_by_id.get(&task_id), Stage::parse(&stage)) {
            rows[idx].stages.push(StageRow {
                stage,
                status,
                detail,
            });
        }
    }
    Ok(())
}

pub fn enqueue(db: &Db, target: &str, mode: Mode, extra_flags: &[String]) -> Result<i64> {
    validate_nmap_flags(extra_flags)?;
    let conn = db.conn();
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO tasks (target, mode, extra_flags, created_utc) VALUES (?1, ?2, ?3, ?4)",
        params![
            target,
            mode.as_str(),
            serde_json::to_string(extra_flags)?,
            now_rfc3339()
        ],
    )?;
    let id = tx.last_insert_rowid();
    for (position, stage) in STAGES.iter().enumerate() {
        tx.execute(
            "INSERT INTO task_stages (task_id, stage, position, status) VALUES (?1, ?2, ?3, 'pending')",
            params![id, stage.as_str(), position as i64],
        )?;
    }
    tx.commit()?;
    Ok(id)
}

pub fn set_stage(db: &Db, task: i64, stage: Stage, status: &str, detail: &str) -> Result<()> {
    let now = now_rfc3339();
    let (started, finished) = match status {
        "running" => (Some(now), None),
        "pending" => (None, None),
        _ => (None, Some(now)),
    };
    db.conn().execute(
        "UPDATE task_stages SET status = ?3, detail = ?4,
                started_utc = COALESCE(?5, started_utc), finished_utc = ?6
         WHERE task_id = ?1 AND stage = ?2",
        params![task, stage.as_str(), status, detail, started, finished],
    )?;
    Ok(())
}

/// The most recent tasks, newest first.
pub fn tasks(db: &Db, limit: usize) -> Result<Vec<TaskRow>> {
    let conn = db.conn();
    let mut statement = conn.prepare(
        "SELECT id, target, mode, extra_flags, created_utc FROM tasks ORDER BY id DESC LIMIT ?1",
    )?;
    let mut rows: Vec<TaskRow> = statement
        .query_map([limit as i64], map_task_row)?
        .collect::<rusqlite::Result<_>>()?;
    attach_stages_range(conn, &mut rows)?;
    Ok(rows)
}

pub fn task(db: &Db, id: i64) -> Result<Option<TaskRow>> {
    let conn = db.conn();
    let mut statement =
        conn.prepare("SELECT id, target, mode, extra_flags, created_utc FROM tasks WHERE id = ?1")?;
    let mut rows: Vec<TaskRow> = statement
        .query_map([id], map_task_row)?
        .collect::<rusqlite::Result<_>>()?;
    attach_stages_range(conn, &mut rows)?;
    Ok(rows.into_iter().next())
}

/// Tasks with pending or interrupted stages, oldest first.
pub fn unfinished(db: &Db) -> Result<Vec<TaskRow>> {
    let conn = db.conn();
    let mut statement = conn.prepare(
        "SELECT id, target, mode, extra_flags, created_utc FROM tasks
         WHERE id IN (
             SELECT DISTINCT task_id FROM task_stages
             WHERE status IN ('pending', 'running', 'interrupted')
         )
         ORDER BY id ASC",
    )?;
    let mut rows: Vec<TaskRow> = statement
        .query_map([], map_task_row)?
        .collect::<rusqlite::Result<_>>()?;
    if !rows.is_empty() {
        let index_by_id: std::collections::HashMap<i64, usize> = rows
            .iter()
            .enumerate()
            .map(|(idx, r)| (r.id, idx))
            .collect();
        let mut stmt = conn.prepare(
            "SELECT task_id, stage, status, detail FROM task_stages
             WHERE task_id IN (
                 SELECT DISTINCT task_id FROM task_stages
                 WHERE status IN ('pending', 'running', 'interrupted')
             )
             ORDER BY task_id ASC, position ASC",
        )?;
        let iter = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for item in iter {
            let (task_id, stage, status, detail) = item?;
            if let (Some(&idx), Some(stage)) = (index_by_id.get(&task_id), Stage::parse(&stage)) {
                rows[idx].stages.push(StageRow {
                    stage,
                    status,
                    detail,
                });
            }
        }
    }
    Ok(rows)
}

/// A stage still marked `running` belongs to a session that ended (or
/// crashed) while it ran. Returns how many were marked `interrupted`.
pub fn mark_running_interrupted(db: &Db) -> Result<usize> {
    Ok(db.conn().execute(
        "UPDATE task_stages SET status = 'interrupted', detail = 'the session ended while this stage was running'
         WHERE status = 'running'",
        [],
    )?)
}

/// The operator declined to resume: the remaining stages are skipped.
pub fn decline(db: &Db, task: i64) -> Result<()> {
    db.conn().execute(
        "UPDATE task_stages SET status = 'skipped', detail = 'not resumed', finished_utc = ?2
         WHERE task_id = ?1 AND status IN ('pending', 'interrupted', 'running')",
        params![task, now_rfc3339()],
    )?;
    Ok(())
}

/// Number of unfinished tasks in a workspace's `state.db`, without creating
/// or migrating it (used by the workspace listing).
pub fn count_unfinished(state_db: &Path) -> usize {
    if crate::db::refuse_sqlite_symlinks(state_db).is_err() || !state_db.is_file() {
        return 0;
    }
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    rusqlite::Connection::open_with_flags(state_db, flags)
        .and_then(|conn| {
            let _ = conn.busy_timeout(crate::db::BUSY_TIMEOUT);
            crate::db::harden_connection(&conn)?;
            conn.query_row(
                "SELECT COUNT(DISTINCT task_id) FROM task_stages
                 WHERE status IN ('pending', 'running', 'interrupted')",
                [],
                |row| row.get::<_, i64>(0),
            )
        })
        .map(|count| count.max(0) as usize)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

enum StageEnd {
    Done(String),
    Skipped(String),
    /// The mode changed while the stage ran: its tool was stopped and no
    /// other was started. What it had found by then is kept.
    ModeChanged,
}

/// The mode a task runs in: the gentler of the one it was queued in and the
/// one the session is in now. Switching the session down governs work that
/// is already queued; switching it up does not turn an earlier request into
/// a more active one.
fn running_mode(state: &State, task: &TaskRow) -> Mode {
    task.mode.min(state.mode())
}

/// The hosts of the graph a target names, for looking up what is known
/// about them. Never for deciding where a tool is sent: see [`Found`].
fn hosts_in_target(graph: &Graph, target: &Target) -> Vec<Host> {
    match target {
        Target::Host(HostAddr::Name(name)) => graph.host(name).cloned().into_iter().collect(),
        _ => graph
            .hosts
            .values()
            .filter(|host| Found::belongs(&host.address, target))
            .cloned()
            .collect(),
    }
}

/// What a stage's own tool reported, kept with the task for the stages
/// after it. They work from this alone and never from what the graph
/// holds: the graph also learns from text shown in the terminal, and a line
/// of text can call any port open and give any name to any address. The
/// service stage probes the ports the port inventory found, and the crawl
/// and directory stages visit what the scanner itself called a web server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Found {
    /// How many hosts answered.
    pub up: usize,
    /// Addresses with their open TCP ports.
    pub hosts: BTreeMap<String, Vec<u16>>,
    /// Open ports the scanner called HTTP or HTTPS: (address, port, https).
    pub web: Vec<(String, u16, bool)>,
    /// Open ports the scanner called SSH: (address, port).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh: Vec<(String, u16)>,
    /// Resolved IP addresses from the `dns` stage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
    /// CNAME targets from the `dns` stage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cnames: Vec<String>,
    /// Detected WAF/CDN per host from `headers` / `waf-cdn`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub waf: BTreeMap<String, String>,
}

/// The most hosts and web ports kept for one task.
const MAX_FOUND: usize = 4096;

impl Found {
    /// Whether a tool may be sent to `address` for `target`. For a range
    /// or an address: inside it (matching IPv6 zone IDs when present). For a
    /// name: the scanner resolved it, so any IP address it reported.
    fn belongs(address: &str, target: &Target) -> bool {
        match (HostAddr::parse(address), target) {
            (Some(HostAddr::Ip { .. }), Target::Host(HostAddr::Name(_))) => true,
            (
                Some(HostAddr::Ip { addr, zone }),
                Target::Host(HostAddr::Ip {
                    addr: t_addr,
                    zone: t_zone,
                }),
            ) => {
                addr == *t_addr
                    && match (&zone, t_zone) {
                        (Some(a), Some(b)) => a == b,
                        (Some(_), None) => false,
                        _ => true,
                    }
            }
            (Some(HostAddr::Ip { addr, zone: None }), Target::Network(net)) => net.contains(addr),
            _ => false,
        }
    }

    /// Reads it out of a scanner's own output.
    fn of(observations: &[Observation], target: &Target) -> Self {
        let mut found = Found::default();
        let mut up = BTreeSet::new();
        let canonical = |address: &str| {
            HostAddr::parse(address)
                .map(|addr| addr.canonical())
                .filter(|addr| Self::belongs(addr, target))
        };
        for observation in observations {
            match observation {
                Observation::Host { address, .. } => {
                    up.extend(canonical(address));
                }
                Observation::Port {
                    address,
                    port,
                    protocol,
                    state,
                    service,
                    ..
                } if protocol == "tcp" && state == "open" => {
                    let Some(address) = canonical(address) else {
                        continue;
                    };
                    let ports = found.hosts.entry(address.clone()).or_default();
                    if !ports.contains(port) {
                        ports.push(*port);
                    }
                    let service = service.as_deref().unwrap_or("");
                    if service.contains("http") {
                        let https = service.contains("https") || service.starts_with("ssl/");
                        found.web.push((address.clone(), *port, https));
                    }
                    if service.contains("ssh") {
                        found.ssh.push((address, *port));
                    }
                }
                Observation::Http {
                    address,
                    port,
                    scheme,
                    ..
                } => {
                    if let Some(address) = canonical(address) {
                        found.web.push((address, *port, scheme == "https"));
                    }
                }
                _ => {}
            }
        }
        found.up = up.len();
        found.checked(target)
    }

    /// Drops whatever a tool may not be sent to. Applied to what was just
    /// parsed and again to what is read back from the database, which is
    /// only as trustworthy as the workspace folder.
    fn checked(mut self, target: &Target) -> Self {
        self.hosts
            .retain(|address, ports| Self::belongs(address, target) && !ports.is_empty());
        while self.hosts.len() > MAX_FOUND {
            self.hosts.pop_last();
        }
        for ports in self.hosts.values_mut() {
            ports.sort_unstable();
            ports.dedup();
        }
        // A web port is one of the open ports; said twice, once as HTTPS,
        // it is HTTPS.
        let mut web: Vec<(String, u16, bool)> = Vec::new();
        for (address, port, https) in std::mem::take(&mut self.web) {
            if !self
                .hosts
                .get(&address)
                .is_some_and(|ports| ports.contains(&port))
            {
                continue;
            }
            match web.iter().position(|(a, p, _)| *a == address && *p == port) {
                Some(known) => web[known].2 |= https,
                None if web.len() < MAX_FOUND => web.push((address, port, https)),
                None => {}
            }
        }
        self.web = web;
        let mut ssh: Vec<(String, u16)> = Vec::new();
        for (address, port) in std::mem::take(&mut self.ssh) {
            if !self
                .hosts
                .get(&address)
                .is_some_and(|ports| ports.contains(&port))
            {
                continue;
            }
            if !ssh.iter().any(|(a, p)| *a == address && *p == port) && ssh.len() < MAX_FOUND {
                ssh.push((address, port));
            }
        }
        self.ssh = ssh;
        self.ips.retain(|ip| Self::belongs(ip, target));
        self.ips.sort_unstable();
        self.ips.dedup();
        self.ips.truncate(MAX_FOUND);
        self.cnames.retain(|c| HostAddr::parse(c).is_some());
        self.cnames.sort_unstable();
        self.cnames.dedup();
        self.cnames.truncate(MAX_FOUND);
        self.waf
            .retain(|addr, w| Self::belongs(addr, target) && !w.is_empty());
        self
    }

    fn load(db: &Db, task: i64, stage: Stage, target: &Target) -> Self {
        db.conn()
            .query_row(
                "SELECT found FROM task_stages WHERE task_id = ?1 AND stage = ?2",
                params![task, stage.as_str()],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|json| serde_json::from_str::<Found>(&json).ok())
            .unwrap_or_default()
            .checked(target)
    }

    fn save(&self, db: &Db, task: i64, stage: Stage) -> Result<()> {
        db.conn().execute(
            "UPDATE task_stages SET found = ?3 WHERE task_id = ?1 AND stage = ?2",
            params![task, stage.as_str(), serde_json::to_string(self)?],
        )?;
        Ok(())
    }

    fn open_ports(&self) -> usize {
        self.hosts.values().map(Vec::len).sum()
    }
}

type Names = BTreeSet<String>;

fn remove_regular_file(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file()) {
        let _ = std::fs::remove_file(path);
    }
}

/// Reads a scanner's XML output (and `<hosts up="N"/>` count), then deletes
/// the file. A stage knows what its tool writes: the format is never guessed
/// from the content, part of which the scanned server chose.
fn read_scan_with_up(output: &Path) -> Result<(Option<u64>, Vec<Observation>)> {
    crate::workspace::refuse_file_symlink(output)?;
    let parsed = parsers::read_capped(output).and_then(|xml| {
        let up = nmap_hosts_up(&xml);
        let observations = parsers::nmap::parse(&xml)
            .with_context(|| format!("cannot parse {}", output.display()))?;
        Ok((up, observations))
    });
    remove_regular_file(output);
    parsed
}

fn read_scan(output: &Path) -> Result<Vec<Observation>> {
    read_scan_with_up(output).map(|(_, observations)| observations)
}

/// Reads a crawler's JSON Lines output (keeping valid complete lines when a
/// run was cut short at the output cap), then deletes the file.
fn read_lines(output: &Path) -> Result<Vec<Observation>> {
    crate::workspace::refuse_file_symlink(output)?;
    let parsed = parsers::read_prefix_capped(output).map(|text| parsers::jsonl::parse(&text).0);
    remove_regular_file(output);
    parsed
}

/// Records observations in the graph. With `only` set, those about any
/// other host are dropped: a crawler reports the links a page makes to
/// other sites, which says nothing about those sites. Returns the facts
/// changed and the other hosts that were left out.
fn record(state: &State, observations: Vec<Observation>, only: Option<&Names>) -> (usize, Names) {
    let mut dropped = Names::new();
    let kept: Vec<_> = observations
        .into_iter()
        .filter(|observation| {
            let Some(names) = only else { return true };
            let address = observation.address().unwrap_or("").to_ascii_lowercase();
            let keep = names.contains(&address);
            if !keep && !address.is_empty() {
                dropped.insert(address);
            }
            keep
        })
        .collect();
    let changed = state.graph().apply_all(kept);
    if changed > 0 {
        state.mark_dirty();
    }
    (changed, dropped)
}

fn describe_failure(program: &str, outcome: &RunOutcome, limits: RunLimits) -> String {
    match outcome {
        RunOutcome::Exited(Some(code)) => format!("{program} exited with code {code}"),
        RunOutcome::Exited(None) => format!("{program} was killed by a signal"),
        RunOutcome::TimedOut => format!("{program} timed out after {} s", limits.timeout.as_secs()),
        RunOutcome::OutputCapExceeded => format!(
            "{program} exceeded the {} MB output cap",
            limits.cap_bytes / (1024 * 1024)
        ),
        RunOutcome::NotInstalled => format!("{program} is not installed"),
        RunOutcome::Failed(reason) => reason.clone(),
        RunOutcome::Stopped => format!("{program} was stopped: the mode changed"),
    }
}

fn load_probed(state: &State, task_id: i64, target: &Target) -> Found {
    let db = state.db_lock();
    let mut services = Found::load(&db, task_id, Stage::Services, target);
    let ports = Found::load(&db, task_id, Stage::Ports, target);
    if services.hosts.is_empty() {
        return ports;
    }
    for (addr, port, https) in ports.web {
        if let Some(pos) = services
            .web
            .iter()
            .position(|(a, p, _)| *a == addr && *p == port)
        {
            services.web[pos].2 |= https;
        } else {
            services.web.push((addr, port, https));
        }
    }
    for (addr, port) in ports.ssh {
        if !services.ssh.iter().any(|(a, p)| *a == addr && *p == port) {
            services.ssh.push((addr, port));
        }
    }
    services.checked(target)
}

async fn resolve_target_ips(state: &State, task_id: i64, target: &Target) -> Vec<std::net::IpAddr> {
    let mut ips: Vec<std::net::IpAddr> = Vec::new();
    let dns_found = Found::load(&state.db_lock(), task_id, Stage::Dns, target);
    for ip_str in &dns_found.ips {
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    match target {
        Target::Host(HostAddr::Ip { addr, .. }) => {
            if !ips.contains(addr) {
                ips.push(*addr);
            }
        }
        Target::Host(HostAddr::Name(name)) if ips.is_empty() => {
            if let Ok(Ok(addrs)) = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((name.as_str(), 0)),
            )
            .await
            {
                for sa in addrs.take(4) {
                    if !ips.contains(&sa.ip()) {
                        ips.push(sa.ip());
                    }
                }
            }
        }
        Target::Network(_) => {
            for host in hosts_in_target(&state.graph(), target) {
                if let Ok(ip) = host.address.parse::<std::net::IpAddr>() {
                    if !ips.contains(&ip) && ips.len() < 8 {
                        ips.push(ip);
                    }
                }
            }
        }
        _ => {}
    }
    ips
}

async fn run_stage(
    state: &Arc<State>,
    task: &TaskRow,
    target: &Target,
    stage: Stage,
) -> Result<StageEnd> {
    let settings = state.config.recon.clone();
    let mode = running_mode(state, task);
    // Asked before every tool and while one runs.
    let same_mode = || running_mode(state, task) == mode;
    let preset = settings.preset(mode, &state.profile_recon());
    validate_preset_nmap_flags(&preset.nmap_ports, &preset.nmap_services)?;
    // A stored task is only as trustworthy as the workspace's database, so
    // its flags are checked before every stage, not only when it is queued.
    validate_nmap_flags(&task.extra_flags)?;
    let limits = settings.limits();
    let tmp = state.workspace_dir().join("tmp");
    let privileged = is_privileged();
    let out = |suffix: &str| tmp.join(format!("{}_{}{suffix}", stage_file(stage), task.id));

    match stage {
        Stage::Lan => {
            let targets = state.graph().target_ips();
            let local = tokio::task::spawn_blocking(move || crate::observer::observe(&targets))
                .await
                .context("local ARP/NDP sweep failed")?;
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
            state.mark_dirty();
            Ok(StageEnd::Done(format!(
                "{neighbors} neighbours, {routes} routes in ARP/NDP cache ({changed} new facts)"
            )))
        }
        Stage::Dns => {
            if let Target::Network(net) = target {
                return Ok(StageEnd::Skipped(format!(
                    "network range {net} does not have a single DNS target"
                )));
            }
            let (observations, ips, summary) = match crate::osint::run_dns(target).await {
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
                ips,
                cnames,
                ..Found::default()
            }
            .checked(target);
            found.save(&state.db_lock(), task.id, stage)?;
            let (changed, _) = record(state, observations, None);
            Ok(StageEnd::Done(format!("{summary} ({changed} new facts)")))
        }
        Stage::Asn => {
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
        Stage::Subdomains => {
            let Target::Host(HostAddr::Name(domain)) = target else {
                return Ok(StageEnd::Skipped(
                    "target is an IP or CIDR, not a domain name".to_owned(),
                ));
            };
            let dns_found = Found::load(&state.db_lock(), task.id, Stage::Dns, target);
            let primary_address = dns_found
                .ips
                .first()
                .cloned()
                .unwrap_or_else(|| domain.clone());
            let (observations, summary) =
                match crate::osint::run_subdomains(domain, &primary_address).await {
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
        Stage::Trace => {
            let Some(resolved_ip) = resolve_target_ips(state, task.id, target)
                .await
                .into_iter()
                .next()
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
                .find(|r| r.destination == "default" || r.destination == "0.0.0.0/0")
                .and_then(|r| r.gateway.clone());
            let ip_str = resolved_ip.to_string();
            let (observations, summary) =
                match crate::osint::run_trace(&ip_str, local_gateway.as_deref()).await {
                    Ok(res) => res,
                    Err(err) => {
                        return Ok(StageEnd::Skipped(format!("traceroute unavailable: {err}")))
                    }
                };
            if observations.is_empty() {
                return Ok(StageEnd::Skipped(
                    "no intermediate traceroute hops observed".to_owned(),
                ));
            }
            let (changed, _) = record(state, observations, None);
            Ok(StageEnd::Done(format!("{summary} ({changed} new facts)")))
        }
        Stage::Ports => {
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
            let outcome = run_tool_while(&command, limits, same_mode).await;
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
        Stage::Services => {
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
                let outcome = run_tool_while(&command, limits, same_mode).await;
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
        Stage::Headers => {
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
            for (address, port, https) in probed.web.iter().take(MAX_URLS_PER_STAGE) {
                if !same_mode() {
                    return Ok(StageEnd::ModeChanged);
                }
                if let Ok((obs, detected_waf, _summary)) =
                    crate::osint::inspect_web_endpoint(address, host_header, *port, *https).await
                {
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
        Stage::WafCdn => {
            let (dns_found, headers_found, probed) = {
                let db = state.db_lock();
                (
                    Found::load(&db, task.id, Stage::Dns, target),
                    Found::load(&db, task.id, Stage::Headers, target),
                    load_probed(state, task.id, target),
                )
            };
            let mut target_hosts: BTreeSet<String> = probed.hosts.keys().cloned().collect();
            for ip in &dns_found.ips {
                target_hosts.insert(ip.clone());
            }
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
        Stage::TlsAudit => {
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
            for (address, port) in tls_targets.iter().take(MAX_URLS_PER_STAGE) {
                if !same_mode() {
                    return Ok(StageEnd::ModeChanged);
                }
                if let Ok((obs, _summary)) =
                    crate::osint::run_tls_audit(address, host_header, *port).await
                {
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
        Stage::SshAudit => {
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
            for (address, port) in ssh_targets.iter().take(MAX_HOSTS_PER_STAGE) {
                if !same_mode() {
                    return Ok(StageEnd::ModeChanged);
                }
                if let Ok((obs, _summary)) = crate::osint::audit_ssh_port(address, *port).await {
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
        Stage::Cves => {
            if !state.cve_enabled() {
                return Ok(StageEnd::Skipped(
                    "CVE lookups are disabled in config.toml".to_owned(),
                ));
            }
            let probed = load_probed(state, task.id, target);
            let mut candidate_addrs: BTreeSet<String> = probed.hosts.keys().cloned().collect();
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
                            if let Some(note) =
                                crate::checklist::backport_note_for(host, Some(port_key))
                            {
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
            for addr in &versioned_hosts {
                if !same_mode() {
                    return Ok(StageEnd::ModeChanged);
                }
                if let Some((merged, _kev, _errs)) = state.ground_host(addr).await {
                    added_total += merged.added;
                    changed += merged.added;
                }
            }
            let to_verify: usize = {
                let graph = state.graph();
                versioned_hosts
                    .iter()
                    .filter_map(|addr| graph.hosts.get(addr))
                    .map(|h| {
                        h.advisories
                            .iter()
                            .filter(|a| {
                                a.record.verification_status
                                    == crate::evidence::VerificationStatus::UnverifiedHypothesis
                            })
                            .count()
                    })
                    .sum()
            };
            Ok(StageEnd::Done(format!(
                "{added_total} new advisories, {to_verify} hypotheses to verify ({changed} new facts)"
            )))
        }
        Stage::Crawl | Stage::Dirs => {
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
            let urls: Vec<String> =
                probed
                    .web
                    .iter()
                    .filter(|(address, _, _)| {
                        if stage == Stage::Dirs && mode == Mode::Mild {
                            if let Some(provider) = waf_found.get(address).cloned().or_else(|| {
                                state.graph().host(address).and_then(|h| h.waf_cdn.clone())
                            }) {
                                skipped_waf.push(format!("{address} ({provider})"));
                                return false;
                            }
                        }
                        true
                    })
                    .map(|(address, port, https)| {
                        crate::endpoint::web_origin(
                            if *https { "https" } else { "http" },
                            address,
                            *port,
                        )
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
            for (index, url) in urls.iter().enumerate() {
                let output = out(&format!("_{index}.jsonl"));
                let command = match &wordlist {
                    Some(wordlist) => dirs_command(&settings, &preset, url, wordlist, &output),
                    None => crawl_command(&settings, &preset, url, &output),
                };
                let outcome = run_tool_while(&command, limits, same_mode).await;
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
                ) || (matches!(outcome, RunOutcome::Exited(Some(code)) if code != 0)
                    && url_added == 0)
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
    }
}

fn stage_file(stage: Stage) -> &'static str {
    match stage {
        Stage::Lan => "lan",
        Stage::Dns => "dns",
        Stage::Asn => "asn",
        Stage::Subdomains => "subdomains",
        Stage::Trace => "trace",
        Stage::Ports => "nmap_ports",
        Stage::Services => "nmap_svc",
        Stage::Headers => "headers",
        Stage::WafCdn => "waf_cdn",
        Stage::TlsAudit => "tls_audit",
        Stage::SshAudit => "ssh_audit",
        Stage::Cves => "cves",
        Stage::Crawl => "katana",
        Stage::Dirs => "ferox",
    }
}

async fn run_task(state: &Arc<State>, id: i64) -> Result<()> {
    let Some(task_row) = task(&state.db_lock(), id)? else {
        return Ok(());
    };
    let target = Target::parse(&task_row.target)
        .with_context(|| format!("invalid target '{}'", task_row.target))?;
    let update = |stage: Stage, status: &str, detail: &str| {
        let result = set_stage(&state.db_lock(), id, stage, status, detail);
        state.touch();
        result
    };
    // Checked again here: a task is only as trustworthy as the database.
    if let Err(reason) = target.check_size() {
        update(Stage::Ports, "failed", &reason)?;
        for stage in STAGES {
            if stage != Stage::Ports {
                update(stage, "skipped", "the port inventory failed")?;
            }
        }
        state.notice(format!("recon {} refused: {reason}", task_row.target));
        return Ok(());
    }

    for stage in STAGES {
        let current_status = {
            let db = state.db_lock();
            db.conn()
                .query_row(
                    "SELECT status FROM task_stages WHERE task_id = ?1 AND stage = ?2",
                    params![id, stage.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .ok()
        };
        if !current_status
            .as_deref()
            .is_some_and(|s| matches!(s, "pending" | "interrupted" | "running"))
        {
            continue;
        }
        let end = loop {
            // Light mode sends no packets: stop here and keep the rest for
            // later. A task stored as light (meow queues none) never runs.
            if running_mode(state, &task_row) == Mode::Light {
                update(stage, "interrupted", "paused: the session is in light mode")?;
                state.notice(format!(
                    "recon {} paused: light mode sends no packets",
                    task_row.target
                ));
                return Ok(());
            }
            update(stage, "running", "")?;
            state.notice(format!(
                "recon {}: {} started",
                task_row.target,
                stage.as_str()
            ));
            match run_stage(state, &task_row, &target, stage).await {
                // Start the stage again with what the mode is now.
                Ok(StageEnd::ModeChanged) => state.notice(format!(
                    "recon {}: {} stopped, the mode changed",
                    task_row.target,
                    stage.as_str()
                )),
                end => break end,
            }
        };
        match end {
            Ok(StageEnd::ModeChanged) => {}
            Ok(StageEnd::Done(detail)) => {
                update(stage, "done", &detail)?;
                state.notice(format!(
                    "recon {}: {} done, {detail}",
                    task_row.target,
                    stage.as_str()
                ));
            }
            Ok(StageEnd::Skipped(reason)) => {
                update(stage, "skipped", &reason)?;
                state.notice(format!(
                    "recon {}: {} skipped, {reason}",
                    task_row.target,
                    stage.as_str()
                ));
            }
            Err(error) => {
                let reason = format!("{error:#}");
                update(stage, "failed", &reason)?;
                state.notice(format!(
                    "recon {}: {} failed, {reason}",
                    task_row.target,
                    stage.as_str()
                ));
                if stage == Stage::Ports {
                    // Nothing to build on: the later stages cannot run.
                    if let Some(pos) = STAGES.iter().position(|s| *s == Stage::Ports) {
                        for later in &STAGES[pos + 1..] {
                            update(*later, "skipped", "the port inventory failed")?;
                        }
                    }
                    return Ok(());
                }
            }
        }
    }
    let addresses: Vec<String> = hosts_in_target(&state.graph(), &target)
        .into_iter()
        .map(|host| host.address)
        .collect();
    for address in addresses {
        state.request_grounding(&address);
    }
    Ok(())
}

/// Runs queued tasks strictly one at a time.
pub async fn worker(state: Arc<State>, mut queue: mpsc::UnboundedReceiver<i64>) {
    let one_at_a_time = Semaphore::new(1);
    while let Some(id) = queue.recv().await {
        let Ok(_permit) = one_at_a_time.acquire().await else {
            break;
        };
        if let Err(error) = run_task(&state, id).await {
            state.notice(format!("recon task {id} failed: {error:#}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(command: &ToolCommand) -> String {
        command.args.join(" ")
    }

    fn target(text: &str) -> Target {
        Target::parse(text).unwrap()
    }

    #[test]
    fn unprivileged_scans_fall_back_to_connect_and_drop_os_detection() {
        let flags = strings(&[
            "-sS", "-T4", "-p-", "-O", "--script", "ssl-cert", "-sV", "-sSV",
        ]);
        let (root, notices) = adapt_for_privilege(flags.clone(), true);
        assert_eq!(root, flags);
        assert!(notices.is_empty());

        let (user, notices) = adapt_for_privilege(flags, false);
        assert_eq!(
            user,
            strings(&["-sT", "-T4", "-p-", "--script", "ssl-cert", "-sV", "-sTV"])
        );
        assert_eq!(notices.len(), 3);
        assert!(notices[0].contains("-sS replaced with -sT"));
        assert!(notices[1].contains("removed -O"));

        // UDP needs root: left out, with a way to do it by hand.
        let (user, notices) = adapt_for_privilege(strings(&["-sU", "-sSU", "-T3"]), false);
        assert_eq!(user, strings(&["-sT", "-T3"]));
        assert_eq!(notices.len(), 2);
        assert!(
            notices[0].contains("left out the UDP scan in -sU"),
            "{notices:?}"
        );
        assert!(notices[0].contains("meow add udp.xml"), "{notices:?}");
        let (root, notices) = adapt_for_privilege(strings(&["-sU"]), true);
        assert_eq!((root, notices.len()), (strings(&["-sU"]), 0));
    }

    #[test]
    fn a_silent_target_says_how_to_scan_it_anyway() {
        let down = r#"<nmaprun><runstats><finished/><hosts up="0" down="1" total="1"/></runstats></nmaprun>"#;
        let up =
            r#"<nmaprun><host/><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>"#;
        assert_eq!(nmap_hosts_up(down), Some(0));
        assert_eq!(nmap_hosts_up(up), Some(1));
        assert_eq!(nmap_hosts_up("<nmaprun>"), None);
        assert!(discovery_hint(&[]).contains("run again with `-- -Pn`"));
        assert!(discovery_hint(&strings(&["-Pn"])).contains("even scanning without the up check"));
    }

    #[test]
    fn port_stage_command_is_built_from_preset_extra_flags_and_target() {
        let settings = ReconSettings::default();
        let mild = settings.preset(Mode::Mild, &PresetOverride::default());
        let out = Path::new("/w/tmp/nmap_ports_7.xml");

        let (command, notices) =
            ports_command(&settings, &mild, &target("10.0.0.0/24"), &[], true, out);
        assert_eq!(command.program, "nmap");
        assert_eq!(
            args(&command),
            "-sS -T3 --top-ports 1000 -oX /w/tmp/nmap_ports_7.xml -- 10.0.0.0/24"
        );
        assert!(notices.is_empty());

        // Ports the operator names replace the preset's --top-ports, which
        // nmap would otherwise apply within them (verified with nmap 7.94:
        // `--top-ports 1000 -p-` scans 1000 ports, `-p-` alone 65535).
        let extra = strings(&["-p", "80,443", "-O"]);
        let (command, notices) =
            ports_command(&settings, &mild, &target("10.0.0.5"), &extra, false, out);
        assert_eq!(
            args(&command),
            "-sT -T3 -p 80,443 -oX /w/tmp/nmap_ports_7.xml -- 10.0.0.5"
        );
        assert_eq!(notices.len(), 2);
        for (extra, expected) in [
            (vec!["-p-"], "-sS -T3 -p-"),
            (vec!["-p1-10000"], "-sS -T3 -p1-10000"),
            (vec!["--top-ports", "100"], "-sS -T3 --top-ports 100"),
            (vec!["-F"], "-sS -T3 -F"),
            (vec!["-Pn"], "-sS -T3 --top-ports 1000 -Pn"),
        ] {
            let (command, _) = ports_command(
                &settings,
                &mild,
                &target("10.0.0.5"),
                &strings(&extra),
                true,
                out,
            );
            assert_eq!(
                args(&command),
                format!("{expected} -oX /w/tmp/nmap_ports_7.xml -- 10.0.0.5"),
                "{extra:?}"
            );
        }

        let aggressive = settings.preset(Mode::Aggressive, &PresetOverride::default());
        let (command, _) = ports_command(
            &settings,
            &aggressive,
            &target("2001:db8::/64"),
            &[],
            true,
            out,
        );
        assert_eq!(
            args(&command),
            "-sS -T4 -p- -O -6 -oX /w/tmp/nmap_ports_7.xml -- 2001:db8::/64"
        );
    }

    #[test]
    fn service_stage_probes_only_the_open_ports() {
        let settings = ReconSettings::default();
        let mild = settings.preset(Mode::Mild, &PresetOverride::default());
        let (command, _) = services_command(
            &settings,
            &mild,
            &ReconFlags::default(),
            "10.0.0.5",
            &[22, 443, 8080],
            false,
            Path::new("/t/svc.xml"),
        );
        assert_eq!(
            args(&command),
            "-sV --version-intensity 5 -T3 --script ssl-cert,http-server-header,http-title \
             -p 22,443,8080 -oX /t/svc.xml -- 10.0.0.5"
        );
        let (command, _) = services_command(
            &settings,
            &mild,
            &ReconFlags::default(),
            "2001:db8::a",
            &[80],
            true,
            Path::new("/t/svc.xml"),
        );
        assert!(args(&command).contains("-6 -p 80 -oX /t/svc.xml -- 2001:db8::a"));
    }

    #[test]
    fn only_known_categories_and_built_in_scripts_reach_the_script_expression() {
        let chosen = strings(&[
            "vuln",
            "banner",
            "/tmp/evil.nse",
            "http-shellshock",
            "default or exploit",
        ]);
        assert_eq!(
            script_expression(&["ssl-cert"], &chosen),
            format!("ssl-cert or banner or ((vuln) and not ({SCRIPT_NEVER}))")
        );
    }

    #[test]
    fn os_detection_versions_and_scripts_go_to_the_stage_they_belong_to() {
        let flags = split_recon_flags(&strings(&[
            "-A",
            "-p-",
            "-Pn",
            "--script",
            "vuln,default",
            "--version-all",
            "-sSV",
        ]));
        assert_eq!(flags.ports, strings(&["-O", "-p-", "-Pn", "-sS"]));
        assert_eq!(flags.versions, strings(&["--version-all"]));
        assert_eq!(flags.scripts, strings(&["default", "vuln"]));
        assert_eq!(flags.shared, strings(&["-Pn"]));

        let settings = ReconSettings::default();
        let mild = settings.preset(Mode::Mild, &PresetOverride::default());
        let (command, _) = services_command(
            &settings,
            &mild,
            &flags,
            "10.0.0.5",
            &[22, 445],
            true,
            Path::new("/t/svc.xml"),
        );
        // One --script: the built-in scripts, then the chosen categories
        // with the never-run ones excluded (nmap --script-help checked:
        // 0 of the selected scripts are intrusive, external, brute, dos,
        // exploit, fuzzer, malware or broadcast). `-Pn` carries over from
        // Stage 1 so hosts that ignore discovery probes still get inspected.
        assert_eq!(
            command.args,
            strings(&[
                "-sV",
                "--version-intensity",
                "5",
                "-T3",
                "--script",
                "ssl-cert or http-server-header or http-title or ((default or vuln) and not \
                 (intrusive or external or brute or dos or exploit or fuzzer or malware or broadcast))",
                "--version-all",
                "-Pn",
                "-p",
                "22,445",
                "-oX",
                "/t/svc.xml",
                "--",
                "10.0.0.5",
            ])
        );
        // -sC alone, and --script= spelled inline.
        assert_eq!(
            split_recon_flags(&strings(&["-sC"])).scripts,
            strings(&["default"])
        );
        assert_eq!(
            split_recon_flags(&strings(&["--script=safe,ssh-hostkey"])).scripts,
            strings(&["safe", "ssh-hostkey"])
        );
        // --ports replaces the preset's --top-ports choice.
        let (port_cmd, _) = ports_command(
            &settings,
            &mild,
            &target("10.0.0.5"),
            &strings(&["--ports", "80,443"]),
            true,
            Path::new("/t/ports.xml"),
        );
        assert!(!args(&port_cmd).contains("--top-ports"));
    }

    #[test]
    fn nmap_flag_allowlist_permits_tuning_and_blocks_scripts_files_and_targets() {
        for allowed in [
            &[][..],
            &["-Pn", "-p", "22,80,443", "-T4", "--open"],
            &["-p-", "-sU", "--top-ports=100", "--max-retries", "2"],
            &["-p80-90", "-PS22,443", "-PA", "-n", "--reason"],
            &["-p", "T:80,U:53", "-p", "http,ssh"],
            &[
                "--min-rate",
                "100",
                "--max-rate=500",
                "--host-timeout",
                "5m",
                "--scan-delay=200ms",
                "--exclude",
                "192.0.2.1,198.51.100.0/24,10.0.0.0/8",
            ],
            &["-T", "3", "--exclude-ports=9100,515"],
            // OS detection, versions and scripts by category.
            &["-A"],
            &["-sC", "-O", "--version-all"],
            &["--script", "default,vuln,safe,discovery,version"],
            &["--script=ssh-hostkey,banner"],
        ] {
            validate_nmap_flags(&strings(allowed))
                .unwrap_or_else(|e| panic!("rejected safe flags {allowed:?}: {e:#}"));
        }

        for mode in [Mode::Mild, Mode::Aggressive] {
            let preset = Preset::builtin(mode);
            validate_preset_nmap_flags(&preset.nmap_ports, &preset.nmap_services).unwrap();
        }

        for blocked in [
            &["--script=/tmp/evil.nse"][..],
            &["--script", "intrusive"],
            &["--script", "default,brute"],
            &["--script", "all"],
            &["--script", "*"],
            &["--script", "vuln and intrusive"],
            &["--script", "smb-vuln-ms17-010"],
            &["--script-args", "foo=bar"],
            &["--script-args-file=/etc/passwd"],
            &["-sSC"],
            &["-sVV"],
            &["-oN", "/tmp/out.txt"],
            &["-oX", "/tmp/out.xml"],
            &["-oG", "-"],
            &["-oA", "/tmp/base"],
            &["--append-output"],
            &["--resume", "/tmp/scan.gnmap"],
            &["--datadir", "/tmp"],
            &["--servicedb", "/tmp/services"],
            &["--stylesheet", "https://example.invalid/x.xsl"],
            &["-iL", "/etc/hosts"],
            &["-iR", "50"],
            &["--excludefile", "/etc/hosts"],
            &["--proxies", "http://192.0.2.9:8080"],
            &["-D", "192.0.2.2"],
            &["-S", "192.0.2.2"],
            &["-e", "en0"],
            &["192.0.2.99"],
            &["--", "192.0.2.99"],
            &["-"],
            &[""],
            &["-p"],
            &["-p", "-oN"],
            &["--top-ports"],
            &["--top-ports=0"],
            &["--top-ports=70000"],
            &["--exclude", "-iL"],
            &["-p", "80\n443"],
            // nmap would read these as --port-ratio, --packet-trace,
            // --privileged and --proxies, taking the next value with them.
            &["-po", "-p", "2130706434"],
            &["-po"],
            &["-pa"],
            &["-packet-trace"],
            &["-pri"],
            &["-privileged"],
            &["-pro", "-p", "http"],
            &["-proxies"],
            &["-pT:80"],
            &["-phttp"],
        ] {
            assert!(
                validate_nmap_flags(&strings(blocked)).is_err(),
                "accepted unsafe flags {blocked:?}"
            );
        }

        let too_many: Vec<String> = vec!["-n".to_owned(); MAX_NMAP_FLAGS + 1];
        assert!(validate_nmap_flags(&too_many).is_err());

        // Service presets may name only the known safe built-in NSE scripts,
        // never arbitrary script names or file paths.
        assert!(validate_preset_nmap_flags(
            &strings(&["-sS"]),
            &strings(&["-sV", "--script", "/tmp/evil.nse"])
        )
        .is_err());
        assert!(validate_preset_nmap_flags(
            &strings(&["-sS"]),
            &strings(&["-sV", "--script=vuln"])
        )
        .is_err());
        assert!(validate_preset_nmap_flags(
            &strings(&["--script", "ssl-cert"]),
            &strings(&["-sV"])
        )
        .is_err());

        // `enqueue` enforces the same gate at persistence time.
        let db = Db::open_in_memory().unwrap();
        assert!(enqueue(
            &db,
            "192.0.2.10",
            Mode::Mild,
            &strings(&["--script=/tmp/evil.nse"])
        )
        .is_err());
    }

    #[test]
    fn web_stage_commands_match_the_mode_rules() {
        let settings = ReconSettings::default();
        let none = PresetOverride::default();
        let mild = settings.preset(Mode::Mild, &none);
        let aggressive = settings.preset(Mode::Aggressive, &none);
        let out = Path::new("/t/out.jsonl");
        let url = "https://app.lab.local:8443";

        assert_eq!(
            args(&crawl_command(&settings, &mild, url, out)),
            "-u https://app.lab.local:8443 -jsonl -silent -nc -jc -fs fqdn -ct 5m -d 2 -o /t/out.jsonl"
        );
        assert!(args(&crawl_command(&settings, &aggressive, url, out)).contains(" -d 4 "));

        let wordlist = Path::new("/usr/share/wordlists/common.txt");
        assert_eq!(
            args(&dirs_command(&settings, &mild, url, wordlist, out)),
            "-u https://app.lab.local:8443 --quiet --no-state --rate-limit 20 --scan-limit 1 --auto-bail \
             --time-limit 10m --json -o /t/out.jsonl -w /usr/share/wordlists/common.txt"
        );
        let fast = args(&dirs_command(&settings, &aggressive, url, wordlist, out));
        assert_eq!(
            fast,
            "-u https://app.lab.local:8443 --quiet --no-state --auto-tune --time-limit 15m \
             --json -o /t/out.jsonl -w /usr/share/wordlists/common.txt"
        );
        assert!(!fast.contains("--rate-limit") && !fast.contains("--auto-bail"));
    }

    #[test]
    fn presets_layer_builtin_config_and_profile() {
        let mut settings = ReconSettings::default();
        settings.mild.nmap_ports = Some(strings(&["-sT", "--top-ports", "100"]));
        settings.mild.katana_depth = Some(3);
        let profile = PresetOverride {
            katana_depth: Some(1),
            ferox_rate_limit: Some(5),
            ..PresetOverride::default()
        };
        let preset = settings.preset(Mode::Mild, &profile);
        assert_eq!(preset.nmap_ports, strings(&["-sT", "--top-ports", "100"]));
        assert_eq!(preset.katana_depth, 1, "profile.toml wins over config.toml");
        assert_eq!(preset.ferox_rate_limit, Some(5));
        assert_eq!(
            preset.nmap_services,
            Preset::builtin(Mode::Mild).nmap_services
        );
        // The aggressive preset is untouched by the mild overrides.
        assert_eq!(
            settings.preset(Mode::Aggressive, &PresetOverride::default()),
            Preset::builtin(Mode::Aggressive)
        );

        let parsed: ReconSettings = toml::from_str(
            "stage_timeout_secs = 60\nwordlist_path = \"/w.txt\"\nnmap = \"/opt/nmap\"\n\
             [aggressive]\nnmap_ports = [\"-sS\", \"-T5\"]\n",
        )
        .unwrap();
        assert_eq!(parsed.stage_timeout_secs, 60);
        assert_eq!(parsed.output_cap_mb, 50);
        assert_eq!(parsed.nmap, "/opt/nmap");
        assert_eq!(parsed.aggressive.nmap_ports, Some(strings(&["-sS", "-T5"])));
        assert_eq!(
            high_rate_flags(&strings(&["-sS", "-T5", "-A", "-T3"])),
            ["-T5", "-A"]
        );
    }

    #[test]
    fn wordlist_is_only_used_if_it_exists() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("words.txt");
        std::fs::write(&list, "admin\n").unwrap();
        assert_eq!(
            find_wordlist(Some(list.to_str().unwrap()), None),
            Some(list)
        );
        let missing = dir.path().join("missing.txt");
        let found = find_wordlist(Some(missing.to_str().unwrap()), None);
        assert!(found.is_none_or(|path| STANDARD_WORDLISTS.contains(&path.to_str().unwrap())));

        // Without a configured or system wordlist, the user's own folder is
        // read: the first .txt file by name, nothing else.
        let own = dir.path().join("own");
        std::fs::create_dir(&own).unwrap();
        std::fs::write(own.join("notes.md"), "x").unwrap();
        std::fs::write(own.join("b.txt"), "x").unwrap();
        std::fs::write(own.join("a.txt"), "x").unwrap();
        let installed = STANDARD_WORDLISTS.iter().any(|p| Path::new(p).is_file());
        if !installed {
            assert_eq!(find_wordlist(None, Some(&own)), Some(own.join("a.txt")));
            assert_eq!(find_wordlist(None, Some(&dir.path().join("none"))), None);
        }
    }

    #[test]
    fn task_rows_track_stage_status() {
        let db = Db::open_in_memory().unwrap();
        let id = enqueue(&db, "10.0.0.0/24", Mode::Mild, &strings(&["-p", "80"])).unwrap();
        let row = task(&db, id).unwrap().unwrap();
        assert_eq!(row.target, "10.0.0.0/24");
        assert_eq!(row.mode, Mode::Mild);
        assert_eq!(row.extra_flags, ["-p", "80"]);
        let statuses = |db: &Db| -> Vec<String> {
            task(db, id)
                .unwrap()
                .unwrap()
                .stages
                .iter()
                .map(|s| s.status.clone())
                .collect()
        };
        assert_eq!(statuses(&db), ["pending"; STAGES.len()]);
        assert_eq!(row.describe(), "recon 10.0.0.0/24: lan pending");

        for s in [
            Stage::Lan,
            Stage::Dns,
            Stage::Asn,
            Stage::Subdomains,
            Stage::Trace,
            Stage::Ports,
        ] {
            set_stage(&db, id, s, "done", "ok").unwrap();
        }
        set_stage(&db, id, Stage::Services, "running", "").unwrap();
        assert_eq!(unfinished(&db).unwrap().len(), 1);

        // The session dies here; on reopen the running stage is interrupted.
        assert_eq!(mark_running_interrupted(&db).unwrap(), 1);
        let after = statuses(&db);
        assert_eq!(&after[..6], &["done"; 6]);
        assert_eq!(after[6], "interrupted");
        assert_eq!(&after[7..], &["pending"; 7]);
        let row = task(&db, id).unwrap().unwrap();
        assert!(row.unfinished());
        assert_eq!(row.describe(), "recon 10.0.0.0/24: services interrupted");

        decline(&db, id).unwrap();
        let declined = statuses(&db);
        assert_eq!(&declined[..6], &["done"; 6]);
        assert_eq!(&declined[6..], &["skipped"; 8]);
        assert!(unfinished(&db).unwrap().is_empty());
        assert_eq!(
            task(&db, id).unwrap().unwrap().describe(),
            "recon 10.0.0.0/24: finished"
        );
        assert_eq!(task(&db, 999).unwrap(), None);
    }

    #[test]
    fn a_stage_reads_its_tools_output_as_what_that_tool_writes() {
        // A scanned server puts the marker of another format into a header.
        // Guessed from the content this file was "XML", failed to parse, and
        // the stage reported nothing found.
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("ferox_1_0.jsonl");
        std::fs::write(
            &output,
            "{\"type\":\"response\",\"url\":\"http://10.0.0.5/admin\",\"status\":403,\"headers\":{\"x-a\":\"<nmaprun\"}}\n\
             {\"type\":\"response\",\"url\":\"http://10.0.0.5/login\",\"status\":200}\n",
        )
        .unwrap();
        assert_eq!(
            parsers::detect(&std::fs::read_to_string(&output).unwrap()),
            parsers::Format::NmapXml,
            "what guessing makes of it"
        );
        let observations = read_lines(&output).unwrap();
        assert_eq!(observations.len(), 2, "{observations:?}");
        assert!(!output.exists(), "read once, then deleted");
        // A scanner's output that is not XML is an error with the file's name.
        let output = dir.path().join("nmap_ports_1.xml");
        std::fs::write(&output, "not xml").unwrap();
        let error = format!("{:#}", read_scan(&output).unwrap_err());
        assert!(error.contains("nmap_ports_1.xml"), "{error}");
        assert!(!output.exists());
    }

    #[test]
    fn what_a_scan_found_is_taken_from_its_own_output_only() {
        let observations = parsers::nmap::parse(
            r#"<nmaprun>
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="25"><state state="filtered"/><service name="smtp"/></port>
<port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
</ports></host>
<host><status state="up"/><address addr="10.0.9.9" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
</ports></host>
<host><status state="up"/><address addr="10.0.0.7" addrtype="ipv4"/><ports></ports></host>
</nmaprun>"#,
        )
        .unwrap();
        let range = target("10.0.0.0/24");
        let found = Found::of(&observations, &range);
        assert_eq!(found.up, 2, "the host outside the range is not counted");
        assert_eq!(
            found.hosts,
            BTreeMap::from([("10.0.0.5".to_owned(), vec![22, 80, 443])])
        );
        assert_eq!(
            found.web,
            [
                ("10.0.0.5".to_owned(), 443, true),
                ("10.0.0.5".to_owned(), 80, false)
            ]
        );
        assert_eq!(found.open_ports(), 3);
        // For a name the scanner resolved, every address it reported.
        let named = Found::of(&observations, &target("app.example.org"));
        assert_eq!(named.hosts.len(), 2);
        // Read back from a database, the same checks apply again.
        let planted: Found = serde_json::from_str(
            r#"{"hosts":{"10.0.0.5":[443,443,22],"192.0.2.1":[80],"x":[1],"10.0.0.6":[]},
                "web":[["10.0.0.5",443,false],["10.0.0.5",443,true],["10.0.0.5",8443,true],["192.0.2.1",80,false]]}"#,
        )
        .unwrap();
        let checked = planted.checked(&range);
        assert_eq!(
            checked.hosts,
            BTreeMap::from([("10.0.0.5".to_owned(), vec![22, 443])])
        );
        assert_eq!(checked.web, [("10.0.0.5".to_owned(), 443, true)]);
        assert_eq!(Found::default().checked(&range), Found::default());
    }

    #[test]
    fn unfinished_tasks_are_counted_without_touching_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        assert_eq!(count_unfinished(&path), 0);
        assert!(!path.exists(), "counting must not create the file");
        {
            let db = Db::open(&path).unwrap();
            let first = enqueue(&db, "10.0.0.5", Mode::Mild, &[]).unwrap();
            enqueue(&db, "10.0.0.6", Mode::Mild, &[]).unwrap();
            decline(&db, first).unwrap();
        }
        assert_eq!(count_unfinished(&path), 1);
    }

    #[test]
    fn a_database_someone_else_prepared_cannot_run_its_own_statements() {
        let dir = tempfile::tempdir().unwrap();

        // A file in which the table that is counted is a view that never
        // finishes: the count comes back at once, as nothing.
        let endless = dir.path().join("endless.db");
        rusqlite::Connection::open(&endless)
            .unwrap()
            .execute_batch(
                "CREATE VIEW task_stages AS
                 WITH RECURSIVE forever(task_id, status) AS (
                     SELECT 1, 'pending' UNION ALL SELECT task_id + 1, 'pending' FROM forever
                 ) SELECT task_id, status FROM forever;",
            )
            .unwrap();
        let started = std::time::Instant::now();
        assert_eq!(count_unfinished(&endless), 0);
        assert!(started.elapsed() < Duration::from_secs(5));

        // A real database with a trigger added behind meow's back: queueing
        // a task does not run it, and deleting a task still removes its
        // stages (the schema's own rule).
        let path = dir.path().join("state.db");
        drop(Db::open(&path).unwrap());
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE planted (note TEXT);
                 CREATE TRIGGER on_task AFTER INSERT ON tasks BEGIN
                     INSERT INTO planted VALUES ('ran');
                     UPDATE tasks SET extra_flags = '[\"--script\",\"/tmp/x.nse\"]';
                 END;",
            )
            .unwrap();
        let db = Db::open(&path).unwrap();
        let id = enqueue(&db, "10.0.0.5", Mode::Mild, &[]).unwrap();
        let planted: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM planted", [], |row| row.get(0))
            .unwrap();
        assert_eq!(planted, 0, "the trigger did not run");
        assert!(task(&db, id).unwrap().unwrap().extra_flags.is_empty());
        assert_eq!(count_unfinished(&path), 1);
        db.conn()
            .execute("DELETE FROM tasks WHERE id = ?1", [id])
            .unwrap();
        let stages: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM task_stages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stages, 0, "stages still go with their task");
        // The schema cannot be rewritten through meow's own connection.
        assert!(db
            .conn()
            .execute_batch("PRAGMA writable_schema = ON; DELETE FROM sqlite_schema;")
            .is_err());
    }

    #[cfg(unix)]
    mod tools {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn script(dir: &Path, name: &str, body: &str) -> String {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path.to_string_lossy().into_owned()
        }

        fn command(program: String, output: &Path) -> ToolCommand {
            ToolCommand {
                program,
                args: vec![output.to_string_lossy().into_owned()],
                output: output.to_path_buf(),
            }
        }

        const GENEROUS: RunLimits = RunLimits {
            timeout: Duration::from_secs(20),
            cap_bytes: 1024 * 1024,
        };

        #[tokio::test]
        async fn a_tool_runs_in_its_own_empty_folder_without_credentials() {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("out");
            std::env::set_var("MEOW_TEST_SCANNER_API_KEY", "sk-not-for-scanners");
            std::env::set_var("MEOW_TEST_SCANNER_PLAIN", "kept");
            let tool = script(
                dir.path(),
                "tool",
                "{ pwd; ls -A | wc -l; stat -c %a . 2>/dev/null || stat -f %Lp .; env; } > \"$1\"",
            );
            let outcome = run_tool(&command(tool, &out), GENEROUS).await;
            assert_eq!(outcome, RunOutcome::Exited(Some(0)));
            let text = std::fs::read_to_string(&out).unwrap();
            let mut lines = text.lines();
            let ran_in = PathBuf::from(lines.next().unwrap());
            // Not where the session was started, but a fresh folder beside
            // the output: empty, private, and gone afterwards.
            assert_ne!(ran_in, std::env::current_dir().unwrap());
            assert_eq!(
                ran_in.parent().unwrap().canonicalize().unwrap(),
                dir.path().canonicalize().unwrap()
            );
            assert!(ran_in
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("run-"));
            assert_eq!(lines.next().unwrap().trim(), "0", "the folder is empty");
            assert_eq!(lines.next().unwrap().trim(), "700");
            assert!(!ran_in.exists());
            assert!(!text.contains("sk-not-for-scanners"), "{text}");
            assert!(text.contains("MEOW_TEST_SCANNER_PLAIN=kept"));
            for (name, secret) in [
                ("ANTHROPIC_API_KEY", true),
                ("OPENROUTER_API_KEY", true),
                ("GITHUB_TOKEN", true),
                ("aws_secret_access_key", true),
                ("DB_PASSWORD", true),
                ("PATH", false),
                ("HOME", false),
                ("HTTPS_PROXY", false),
                ("SSH_AUTH_SOCK", false),
            ] {
                assert_eq!(is_secret_variable(name), secret, "{name}");
            }

            // A link (or anything but a file) where the output goes is not
            // written through, and the tool is not started.
            let outside = dir.path().join("outside.txt");
            std::fs::write(&outside, "keep me").unwrap();
            let linked = dir.path().join("linked-out");
            std::os::unix::fs::symlink(&outside, &linked).unwrap();
            let marker = dir.path().join("started");
            let tool = script(
                dir.path(),
                "tool2",
                &format!("touch '{}'; echo scan > \"$1\"", marker.display()),
            );
            let outcome = run_tool(&command(tool, &linked), GENEROUS).await;
            assert!(
                matches!(&outcome, RunOutcome::Failed(why) if why.contains("not a regular file")),
                "{outcome:?}"
            );
            assert!(!marker.exists());
            assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep me");
        }

        #[tokio::test]
        async fn a_tool_runs_with_stdin_closed_and_its_exit_code_is_reported() {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("out");
            // `read` returns at once on a closed stdin; an interactive prompt
            // would otherwise wait forever.
            let ok = script(
                dir.path(),
                "ok",
                "read answer; echo \"answer=[$answer]\" > \"$1\"; exit 0",
            );
            assert_eq!(
                run_tool(&command(ok, &out), GENEROUS).await,
                RunOutcome::Exited(Some(0))
            );
            assert_eq!(std::fs::read_to_string(&out).unwrap(), "answer=[]\n");

            let bad = script(dir.path(), "bad", "exit 3");
            assert_eq!(
                run_tool(&command(bad, &out), GENEROUS).await,
                RunOutcome::Exited(Some(3))
            );
            let missing = command(dir.path().join("nope").to_string_lossy().into_owned(), &out);
            assert_eq!(run_tool(&missing, GENEROUS).await, RunOutcome::NotInstalled);
        }

        fn alive(pid: &str) -> bool {
            if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
                return !status.lines().any(|line| {
                    line.strip_prefix("State:")
                        .is_some_and(|s| s.trim_start().starts_with('Z'))
                });
            }
            if Path::new(&format!("/proc/{pid}")).exists() {
                return true;
            }
            std::process::Command::new("kill")
                .args(["-0", pid])
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        }

        async fn wait_gone(pid: &str) {
            for _ in 0..100 {
                if !alive(pid) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("process {pid} is still running");
        }

        #[tokio::test]
        async fn a_runaway_tool_is_stopped_at_the_timeout_with_its_children() {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("out");
            let pids = dir.path().join("pids");
            // The tool starts a child of its own; both must die.
            let body = format!("sleep 300 &\necho \"$$ $!\" > {}\nwait", pids.display());
            let slow = script(dir.path(), "slow", &body);
            let limits = RunLimits {
                timeout: Duration::from_millis(600),
                cap_bytes: 1024 * 1024,
            };
            let started = std::time::Instant::now();
            assert_eq!(
                run_tool(&command(slow, &out), limits).await,
                RunOutcome::TimedOut
            );
            assert!(started.elapsed() < Duration::from_secs(10));
            let recorded = std::fs::read_to_string(&pids).unwrap();
            for pid in recorded.split_whitespace() {
                wait_gone(pid).await;
            }
        }

        #[tokio::test]
        async fn a_tool_that_floods_its_output_is_stopped_at_the_cap() {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("out");
            let flood = script(
                dir.path(),
                "flood",
                "while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx >> \"$1\"; done",
            );
            let limits = RunLimits {
                timeout: Duration::from_secs(30),
                cap_bytes: 64 * 1024,
            };
            assert_eq!(
                run_tool(&command(flood, &out), limits).await,
                RunOutcome::OutputCapExceeded
            );
            let size = std::fs::metadata(&out).unwrap().len();
            assert!(size > 64 * 1024 && size < 64 * 1024 * 1024, "{size}");
        }

        #[tokio::test]
        async fn dropping_a_running_tool_kills_its_process_group() {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("out");
            let pids = dir.path().join("pids");
            let body = format!("sleep 300 &\necho \"$$ $!\" > {}\nwait", pids.display());
            let slow = script(dir.path(), "slow", &body);
            let command = command(slow, &out);
            // Cancel the run (as a closing session does) once it has started.
            let cancelled =
                tokio::time::timeout(Duration::from_millis(600), run_tool(&command, GENEROUS))
                    .await;
            assert!(cancelled.is_err());
            let recorded = std::fs::read_to_string(&pids).unwrap();
            for pid in recorded.split_whitespace() {
                wait_gone(pid).await;
            }
        }

        #[tokio::test]
        async fn parent_traversal_program_and_symlinked_stage_output_are_refused() {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("out");
            let parent_prog = command("../bin/sh".to_owned(), &out);
            assert_eq!(
                run_tool(&parent_prog, GENEROUS).await,
                RunOutcome::NotInstalled
            );

            let victim = dir.path().join("victim.jsonl");
            std::fs::write(&victim, "{\"url\":\"http://10.0.0.5/secret\"}\n").unwrap();
            let link = dir.path().join("ferox_9_0.jsonl");
            std::os::unix::fs::symlink(&victim, &link).unwrap();
            assert!(read_lines(&link).is_err());
            assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
            assert!(victim.exists());
        }
    }

    #[test]
    fn zoned_ipv6_found_and_inline_preset_scripts_are_handled_cleanly() {
        let observations = parsers::nmap::parse(
            r#"<nmaprun>
<host><status state="up"/><address addr="fe80::1%eth0" addrtype="ipv6"/><ports>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http"/></port>
</ports></host>
<host><status state="up"/><address addr="fe80::1%eth1" addrtype="ipv6"/><ports>
<port protocol="tcp" portid="8443"><state state="open"/><service name="https"/></port>
</ports></host>
</nmaprun>"#,
        )
        .unwrap();
        let found = Found::of(&observations, &target("fe80::1%eth0"));
        assert_eq!(found.up, 1);
        assert_eq!(
            found.hosts,
            BTreeMap::from([("fe80::1%eth0".to_owned(), vec![8080])])
        );
        assert_eq!(found.web, [("fe80::1%eth0".to_owned(), 8080, false)]);

        let settings = ReconSettings::default();
        let mut preset = settings.preset(Mode::Mild, &PresetOverride::default());
        preset.nmap_services = strings(&["-sV", "--script=ssl-cert,banner"]);
        let extra = split_recon_flags(&strings(&["--script", "safe"]));
        let (cmd, _) = services_command(
            &settings,
            &preset,
            &extra,
            "fe80::1%eth0",
            &[8080],
            true,
            Path::new("/t/svc.xml"),
        );
        assert_eq!(
            cmd.args
                .iter()
                .filter(|arg| *arg == "--script" || arg.starts_with("--script="))
                .count(),
            1,
            "{:?}",
            cmd.args
        );
        assert!(args(&cmd).contains("ssl-cert or banner"));
        assert!(args(&cmd).contains(" -6 "));
    }
}

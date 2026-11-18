//! The background recon queue.
//!
//! `meow recon <target>` queues one task of 17 sequential stages (`lan`, `dns`,
//! `asn`, `subdomains`, `mail-dns`, `trace`, `ports`, `udp`, `services`, `headers`,
//! `waf-cdn`, `tls-audit`, `ssh-audit`, `cves`, `crawl`, `js`, `dirs`) that run strictly one at
//! a time. External tools (`nmap`, `katana`, `feroxbuster`, `traceroute`,
//! `openssl`) run with `stdin` closed, under a wall-clock timeout and an output
//! size cap, and write structured files to `<workspace>/tmp/` that are parsed
//! and then deleted. Stage status is kept in `state.db` so an interrupted task
//! can be resumed when the session is reopened.

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
    #[serde(rename = "mail-dns", alias = "mail_dns")]
    MailDns,
    Trace,
    Ports,
    Udp,
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
    Js,
    Dirs,
}

pub const STAGES: [Stage; 17] = [
    Stage::Lan,
    Stage::Dns,
    Stage::Asn,
    Stage::Subdomains,
    Stage::MailDns,
    Stage::Trace,
    Stage::Ports,
    Stage::Udp,
    Stage::Services,
    Stage::Headers,
    Stage::WafCdn,
    Stage::TlsAudit,
    Stage::SshAudit,
    Stage::Cves,
    Stage::Crawl,
    Stage::Js,
    Stage::Dirs,
];

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Lan => "lan",
            Stage::Dns => "dns",
            Stage::Asn => "asn",
            Stage::Subdomains => "subdomains",
            Stage::MailDns => "mail-dns",
            Stage::Trace => "trace",
            Stage::Ports => "ports",
            Stage::Udp => "udp",
            Stage::Services => "services",
            Stage::Headers => "headers",
            Stage::WafCdn => "waf-cdn",
            Stage::TlsAudit => "tls-audit",
            Stage::SshAudit => "ssh-audit",
            Stage::Cves => "cves",
            Stage::Crawl => "crawl",
            Stage::Js => "js",
            Stage::Dirs => "dirs",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "waf_cdn" => Some(Stage::WafCdn),
            "mail_dns" => Some(Stage::MailDns),
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
    /// Stages to leave out (`["udp", "js"]`): they are marked skipped.
    pub skip: Vec<String>,
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
            skip: Vec::new(),
            mild: PresetOverride::default(),
            aggressive: PresetOverride::default(),
            wordlist_dir: None,
        }
    }
}

impl ReconSettings {
    /// Whether `config.toml` turns `stage` off. Unknown names are ignored.
    pub fn skips(&self, stage: Stage) -> bool {
        self.skip
            .iter()
            .any(|name| Stage::parse(&name.trim().to_ascii_lowercase()) == Some(stage))
    }

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

mod commands;
mod runner;
mod stages;

pub use commands::*;
pub use runner::*;

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
            (Some(HostAddr::Ip { addr, zone }), Target::Host(HostAddr::Name(name))) => {
                zone.is_none() && crate::osint::is_allowed_resolved_ip_for_name(name, addr)
            }
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
                for sa in addrs
                    .filter(|sa| crate::osint::is_allowed_resolved_ip_for_name(name, sa.ip()))
                    .take(4)
                {
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

/// Runs `work` while the mode stays what it was; `None` once it changed.
/// The work is then dropped, which ends the programs it started and closes
/// its connections: a switch to light mode stops a traceroute or a TLS or
/// SSH handshake in progress, not only the next one.
async fn while_same_mode<T>(
    same_mode: &impl Fn() -> bool,
    work: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::pin!(work);
    let mut poll = tokio::time::interval(CAP_POLL);
    loop {
        tokio::select! {
            done = &mut work => return Some(done),
            _ = poll.tick() => {
                if !same_mode() {
                    return None;
                }
            }
        }
    }
}

async fn run_stage(
    state: &Arc<State>,
    task: &TaskRow,
    target: &Target,
    stage: Stage,
) -> Result<StageEnd> {
    let cx = stages::Ctx::new(state, task, target, stage)?;
    match stage {
        Stage::Lan => stages::lan(&cx).await,
        Stage::Dns => stages::dns(&cx).await,
        Stage::Asn => stages::asn(&cx).await,
        Stage::Subdomains => stages::subdomains(&cx).await,
        Stage::MailDns => stages::mail_dns(&cx).await,
        Stage::Trace => stages::trace(&cx).await,
        Stage::Ports => stages::ports(&cx).await,
        Stage::Udp => stages::udp(&cx).await,
        Stage::Services => stages::services(&cx).await,
        Stage::Headers => stages::headers(&cx).await,
        Stage::WafCdn => stages::waf_cdn(&cx).await,
        Stage::TlsAudit => stages::tls_audit(&cx).await,
        Stage::SshAudit => stages::ssh_audit(&cx).await,
        Stage::Cves => stages::cves(&cx).await,
        Stage::Js => stages::js(&cx).await,
        Stage::Crawl | Stage::Dirs => stages::crawl_or_dirs(&cx).await,
    }
}

fn stage_file(stage: Stage) -> &'static str {
    match stage {
        Stage::Lan => "lan",
        Stage::Dns => "dns",
        Stage::Asn => "asn",
        Stage::Subdomains => "subdomains",
        Stage::MailDns => "mail_dns",
        Stage::Trace => "trace",
        Stage::Ports => "nmap_ports",
        Stage::Udp => "nmap_udp",
        Stage::Services => "nmap_svc",
        Stage::Headers => "headers",
        Stage::WafCdn => "waf_cdn",
        Stage::TlsAudit => "tls_audit",
        Stage::SshAudit => "ssh_audit",
        Stage::Cves => "cves",
        Stage::Crawl => "katana",
        Stage::Js => "js",
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
        if state.config.recon.skips(stage) {
            update(stage, "skipped", "turned off in config.toml (recon.skip)")?;
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
mod tests;

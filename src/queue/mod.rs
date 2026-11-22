//! The background recon queue.
//!
//! `meow recon <target>` queues one task of 17 sequential stages (`lan`, `dns`,
//! `asn`, `subdomains`, `mail-dns`, `ports`, `trace`, `udp`, `services`, `headers`,
//! `waf-cdn`, `tls-audit`, `ssh-audit`, `cves`, `crawl`, `js`, `dirs`) that run strictly one at
//! a time. External tools (`nmap`, `katana`, `feroxbuster`, `traceroute`,
//! `openssl`) run with `stdin` closed, under a wall-clock timeout and an output
//! size cap, and write structured files to `<workspace>/tmp/` that are parsed
//! and then deleted. Stage status is kept in `state.db`. A recon belongs to
//! the session that queued it: when that session ends, the running stage is
//! stopped, the stages after it are left out, and nothing of it runs later.

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
    Stage::Ports,
    // After the port inventory: the route to the address it scanned.
    Stage::Trace,
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
mod progress;
mod runner;
mod stages;

pub use commands::*;
pub use runner::*;

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// How far a running stage is, as far as it can tell. Kept in memory only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Progress {
    /// 0 to 100, when the tool itself reports one (nmap, for the scan
    /// named in `note`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    /// Items handled so far (endpoints, hosts, results).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub done: Option<u64>,
    /// Items in all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// Seconds the tool expects to need still.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_s: Option<u64>,
    /// A few plain words, such as `SYN Stealth Scan` or `412 results so far`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The longest note a stage's progress carries.
pub const PROGRESS_NOTE_MAX: usize = 80;
/// The longest time left that is believed: a week.
const MAX_ETA_SECS: u64 = 7 * 24 * 3600;

impl Progress {
    /// `done` of `total` items.
    pub fn items(done: usize, total: usize) -> Self {
        Self {
            done: Some(done as u64),
            total: Some(total as u64),
            ..Self::default()
        }
    }

    /// Within bounds and as plain text, whoever made it: part of it comes
    /// from a tool's output file.
    pub fn checked(mut self) -> Self {
        self.percent = self.percent.map(|percent| percent.min(100));
        self.eta_s = self.eta_s.map(|secs| secs.min(MAX_ETA_SECS));
        self.note = self
            .note
            .map(|note| crate::evidence::sanitize(&note, PROGRESS_NOTE_MAX))
            .filter(|note| !note.is_empty());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageRow {
    pub stage: Stage,
    /// `pending`, `running`, `interrupted`, `done`, `skipped` or `failed`.
    pub status: String,
    pub detail: String,
    /// When the stage last started and ended (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_utc: Option<String>,
    /// Only while the stage runs in a live session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
}

/// A stage's status in the words shown to the user.
pub fn status_word(status: &str) -> &str {
    match status {
        "pending" => "waiting",
        "interrupted" => "stopped",
        other => other,
    }
}

/// What a stage says once the session it ran in is gone. It is not run
/// again.
pub const CLOSED_DETAIL: &str = "stopped: the session was closed";
/// ... and of one that light mode stopped: it goes on in mild or aggressive,
/// in the same session.
pub const LIGHT_DETAIL: &str = "stopped: the session is in light mode";
/// What meow 0.2.3 and earlier said of the same stage.
const CLOSED_DETAIL_BEFORE: &str = "the session ended while this stage was running";
/// How the reason starts for a stage whose turn never came because its
/// session ended. The map and the HUD tell such a stage from one that was
/// turned off by it.
pub const NOT_RUN: &str = "not run: ";
/// ... when the session was closed in order,
pub const NOT_RUN_CLOSED: &str = "not run: the session was closed";
/// ... and when it was found gone at the next start.
pub const NOT_RUN_ENDED: &str = "not run: the session ended";

impl StageRow {
    /// Has work to do in the session that queued it: waiting, running, or
    /// stopped by light mode.
    pub fn live(&self) -> bool {
        match self.status.as_str() {
            "pending" | "running" => true,
            "interrupted" => self.detail != CLOSED_DETAIL,
            _ => false,
        }
    }

    /// Left out because the session ended before its turn.
    pub fn not_run(&self) -> bool {
        self.status == "skipped" && self.detail.starts_with(NOT_RUN)
    }
}

/// Shows `tasks` as the end of their session leaves them: the stage that
/// had started stopped, the ones that had not started left out. For a view
/// of a session that is gone; nothing is stored.
pub fn show_ended(tasks: &mut [TaskRow]) {
    for stage in tasks.iter_mut().flat_map(|task| &mut task.stages) {
        // A stage meow 0.2.3 had stopped and kept for a resume is one this
        // version stopped, as `end_session` stores it.
        let stopped_before = stage.status == "interrupted" && stage.detail == CLOSED_DETAIL_BEFORE;
        // So is one that light mode stopped after it had started.
        let started = stage.live() && stage.started_utc.is_some();
        if stage.status == "running" || stopped_before || started {
            stage.status = "interrupted".to_owned();
            stage.detail = CLOSED_DETAIL.to_owned();
        } else if stage.live() {
            stage.status = "skipped".to_owned();
            stage.detail = NOT_RUN_CLOSED.to_owned();
        }
        stage.progress = None;
    }
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
    /// Still has work to do in the session that queued it.
    pub fn unfinished(&self) -> bool {
        self.stages.iter().any(StageRow::live)
    }

    /// Stages that are over and were not left out by the session's end:
    /// the `8` of `8/17`.
    pub fn stages_over(&self) -> usize {
        self.stages
            .iter()
            .filter(|s| matches!(s.status.as_str(), "done" | "skipped" | "failed") && !s.not_run())
            .count()
    }

    /// What is said once, at the next start, of a recon that the end of a
    /// session cut short. `own`: the session's files are the user's own; of
    /// a scan that may have been put there by someone else, only that it
    /// was dropped.
    pub fn left_line(&self, own: bool) -> String {
        let target = crate::evidence::sanitize(&self.target, 120);
        // Only a target that is one is offered as a command to run.
        let again = Target::parse(&self.target)
            .filter(|_| own)
            .map(|target| format!(" \u{b7} `meow recon {target}`"));
        let Some(again) = again else {
            return format!("Dropped a scan queued in these files: recon {target}");
        };
        // Which stages are left: the HUD and the map show them.
        let stopped = self.stages.iter().find(|s| s.status == "interrupted");
        let not_run = self.stages.iter().filter(|s| s.not_run()).count();
        let what = match stopped {
            Some(stage) => format!("cut short at {}", stage.stage.as_str()),
            None if not_run == self.stages.len() => "not run".to_owned(),
            None => "not finished".to_owned(),
        };
        format!("Recon {target} {what}{again}")
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

/// The columns [`read_stage`] reads, in its order.
const STAGE_COLUMNS: &str = "task_id, stage, status, detail, started_utc, finished_utc";

/// One row of `task_stages`: the task it belongs to and the stage, if it
/// is one this version knows.
fn read_stage(row: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, Option<StageRow>)> {
    let name: String = row.get(1)?;
    let Some(stage) = Stage::parse(&name) else {
        return Ok((row.get(0)?, None));
    };
    Ok((
        row.get(0)?,
        Some(StageRow {
            stage,
            status: row.get(2)?,
            detail: row.get(3)?,
            started_utc: row.get(4)?,
            finished_utc: row.get(5)?,
            progress: None,
        }),
    ))
}

/// Gives each of `rows` its stages from what `stages` selects.
fn attach_stages(
    rows: &mut [TaskRow],
    mut stages: rusqlite::Statement<'_>,
    params: impl rusqlite::Params,
) -> Result<()> {
    let index_by_id: std::collections::HashMap<i64, usize> = rows
        .iter()
        .enumerate()
        .map(|(idx, r)| (r.id, idx))
        .collect();
    for item in stages.query_map(params, read_stage)? {
        if let (task_id, Some(stage)) = item? {
            if let Some(&idx) = index_by_id.get(&task_id) {
                rows[idx].stages.push(stage);
            }
        }
    }
    Ok(())
}

fn attach_stages_range(conn: &rusqlite::Connection, rows: &mut [TaskRow]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let min_id = rows.iter().map(|r| r.id).min().unwrap_or(0);
    let max_id = rows.iter().map(|r| r.id).max().unwrap_or(0);
    let stages = conn.prepare(&format!(
        "SELECT {STAGE_COLUMNS} FROM task_stages
         WHERE task_id BETWEEN ?1 AND ?2 ORDER BY task_id, position"
    ))?;
    attach_stages(rows, stages, params![min_id, max_id])
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

/// Stages that still have work to do in the session that queued them
/// ([`StageRow::live`]), as SQL.
const LIVE_STAGE: &str = "(status IN ('pending', 'running')
     OR (status = 'interrupted' AND detail <> 'stopped: the session was closed'))";

/// Tasks with work still to do, oldest first.
pub fn unfinished(db: &Db) -> Result<Vec<TaskRow>> {
    let conn = db.conn();
    let live = format!("SELECT DISTINCT task_id FROM task_stages WHERE {LIVE_STAGE}");
    let mut statement = conn.prepare(&format!(
        "SELECT id, target, mode, extra_flags, created_utc FROM tasks
         WHERE id IN ({live}) ORDER BY id ASC"
    ))?;
    let mut rows: Vec<TaskRow> = statement
        .query_map([], map_task_row)?
        .collect::<rusqlite::Result<_>>()?;
    if !rows.is_empty() {
        let stages = conn.prepare(&format!(
            "SELECT {STAGE_COLUMNS} FROM task_stages
             WHERE task_id IN ({live}) ORDER BY task_id ASC, position ASC"
        ))?;
        attach_stages(&mut rows, stages, [])?;
    }
    Ok(rows)
}

/// The most unfinished tasks [`shown`] returns.
const SHOWN_UNFINISHED: usize = 100;

/// The tasks a session shows, newest first: every task above `floor` (the
/// session's own) that still has work to do, and the newest of all the
/// others up to `limit` in all. Tasks run oldest first, so the one that is
/// running is the first to fall out of a list of the newest alone. Of more
/// unfinished tasks than [`SHOWN_UNFINISHED`], the ones that run first.
pub fn shown(db: &Db, floor: i64, limit: usize) -> Result<Vec<TaskRow>> {
    let mut rows: Vec<TaskRow> = unfinished(db)?
        .into_iter()
        .filter(|task| task.id > floor)
        .take(SHOWN_UNFINISHED)
        .collect();
    if rows.len() < limit {
        for task in tasks(db, limit)? {
            if rows.len() >= limit {
                break;
            }
            if !rows.iter().any(|row| row.id == task.id) {
                rows.push(task);
            }
        }
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.id));
    Ok(rows)
}

/// The newest task's number, or 0: what a session finds when it starts is
/// at or below it and is never run.
pub fn newest_id(db: &Db) -> Result<i64> {
    Ok(db
        .conn()
        .query_row("SELECT COALESCE(MAX(id), 0) FROM tasks", [], |row| {
            row.get(0)
        })?)
}

/// How a session ended, for what becomes of its recons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// In order: the terminal was closed, the shell left, a signal.
    Closed,
    /// Without a word (killed, a crash): found by the next session as it
    /// starts.
    Lost,
}

/// The recons that the end of a session cut short, kept in `meta` until
/// the user has been told of them at the next start.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Left {
    /// The newest of them, oldest first: at most [`LEFT_MAX`].
    ids: Vec<i64>,
    /// How many more there were.
    more: usize,
}

const LEFT_KEY: &str = "recon_left";
/// The most recons that are told one by one.
pub const LEFT_MAX: usize = 5;
/// The most that "and N more" says.
const LEFT_COUNTED: usize = 9999;

impl Left {
    fn load(conn: &rusqlite::Connection) -> Self {
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [LEFT_KEY], |row| {
            row.get::<_, String>(0)
        })
        .ok()
        // A workspace's database may not be meow's own: a short list or none.
        .filter(|text| text.len() <= 64 * LEFT_MAX)
        .and_then(|text| serde_json::from_str::<Left>(&text).ok())
        .unwrap_or_default()
    }

    fn add(&mut self, ids: &[i64]) {
        self.ids.extend(ids);
        let over = self.ids.len().saturating_sub(LEFT_MAX);
        self.ids.drain(..over);
        self.more = self.more.saturating_add(over);
    }
}

/// A session is over, and so are its recons: the stage that was running,
/// or that light mode stopped after it had started, was stopped with it,
/// and every stage that had not started is left out. Finished stages keep
/// their status and results. Nothing is kept waiting for a later session.
/// Returns how many recons this cut short; said again, it changes nothing.
pub fn end_session(db: &Db, end: SessionEnd) -> Result<usize> {
    let now = now_rfc3339();
    let (not_run, stopped_at) = match end {
        SessionEnd::Closed => (NOT_RUN_CLOSED, Some(now.clone())),
        // When its tool went is not known: no end time is made up.
        SessionEnd::Lost => (NOT_RUN_ENDED, None),
    };
    // Taken for writing from the start: a helper that reads the database
    // at this moment is waited for, not run into.
    let tx =
        rusqlite::Transaction::new_unchecked(db.conn(), rusqlite::TransactionBehavior::Immediate)?;
    let cut: Vec<i64> = tx
        .prepare(&format!(
            "SELECT DISTINCT task_id FROM task_stages WHERE {LIVE_STAGE} ORDER BY task_id"
        ))?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if cut.is_empty() {
        return Ok(0);
    }
    // A recon an earlier version kept for a resume: the stage it had
    // stopped is one this version stopped.
    tx.execute(
        "UPDATE task_stages SET detail = ?1 WHERE status = 'interrupted' AND detail = ?2",
        params![CLOSED_DETAIL, CLOSED_DETAIL_BEFORE],
    )?;
    // A stage that light mode stopped after it had started ran: it is cut
    // short, with the times it ran from and to.
    tx.execute(
        &format!(
            "UPDATE task_stages SET status = 'interrupted', detail = ?1,
                    finished_utc = COALESCE(finished_utc, ?2)
             WHERE status <> 'running' AND started_utc IS NOT NULL AND {LIVE_STAGE}"
        ),
        params![CLOSED_DETAIL, stopped_at],
    )?;
    // The rest never started.
    tx.execute(
        &format!(
            "UPDATE task_stages SET status = 'skipped', detail = ?1,
                    finished_utc = COALESCE(finished_utc, ?2)
             WHERE status <> 'running' AND {LIVE_STAGE}"
        ),
        params![not_run, now],
    )?;
    tx.execute(
        "UPDATE task_stages SET status = 'interrupted', detail = ?1, finished_utc = ?2
         WHERE status = 'running'",
        params![CLOSED_DETAIL, stopped_at],
    )?;
    let mut left = Left::load(&tx);
    left.add(&cut);
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![LEFT_KEY, serde_json::to_string(&left)?],
    )?;
    tx.commit()?;
    Ok(cut.len())
}

/// The recons that the end of an earlier session cut short and the user
/// has not been told of: the newest of them, oldest first, and how many
/// more there were. Each is returned once.
pub fn take_left(db: &Db) -> Result<(Vec<TaskRow>, usize)> {
    if db.get_meta(LEFT_KEY)?.is_none() {
        return Ok((Vec::new(), 0));
    }
    let conn = db.conn();
    let Left { mut ids, more } = Left::load(conn);
    conn.execute("DELETE FROM meta WHERE key = ?1", [LEFT_KEY])?;
    ids.truncate(LEFT_MAX);
    ids.dedup();
    let mut rows = Vec::new();
    for id in ids {
        rows.extend(task(db, id)?);
    }
    Ok((rows, more.min(LEFT_COUNTED)))
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
                &format!("SELECT COUNT(DISTINCT task_id) FROM task_stages WHERE {LIVE_STAGE}"),
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
    /// Open UDP ports: (address, port).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp: Vec<(String, u16)>,
    /// Resolved IP addresses from the `dns` stage, in the system's order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
    /// Of `ips`, the one the port scan goes to (see
    /// [`crate::osint::primary_address`]): where the stages record what
    /// they find about the name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<String>,
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
                Observation::Port {
                    address,
                    port,
                    protocol,
                    state,
                    ..
                } if protocol == "udp" && state == "open" => {
                    found
                        .udp
                        .extend(canonical(address).map(|address| (address, *port)));
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
        self.udp
            .retain(|(address, _)| Self::belongs(address, target));
        self.udp.sort_unstable();
        self.udp.dedup();
        self.udp.truncate(MAX_FOUND);
        // In the order found: the first of a family is the one scanned.
        let mut ips: Vec<String> = Vec::new();
        for ip in std::mem::take(&mut self.ips) {
            if Self::belongs(&ip, target) && !ips.contains(&ip) && ips.len() < MAX_FOUND {
                ips.push(ip);
            }
        }
        self.ips = ips;
        self.primary = self.primary.take().filter(|ip| self.ips.contains(ip));
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

/// Removes what a tool left in the workspace's `tmp/` when meow was killed
/// while it ran: the private folder it ran in and its unfinished output.
/// For the start of a session, before any tool runs. Only entries of `tmp`
/// itself with those names go, and no link is followed. Returns how many.
pub fn clear_tool_leftovers(tmp: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(tmp) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        // The entry's own kind: a link is neither a folder nor a file here.
        let (Some(name), Ok(kind)) = (name.to_str(), entry.file_type()) else {
            continue;
        };
        let gone = if kind.is_dir() && name.starts_with(runner::RUN_DIR_PREFIX) {
            std::fs::remove_dir_all(entry.path()).is_ok()
        } else if kind.is_file() && is_stage_output(name) {
            std::fs::remove_file(entry.path()).is_ok()
        } else {
            false
        };
        removed += usize::from(gone);
    }
    removed
}

/// `nmap_svc_12_0.xml`: a stage's file name, `_` and the task's number.
fn is_stage_output(name: &str) -> bool {
    STAGES.iter().any(|stage| {
        name.strip_prefix(stage_file(*stage))
            .and_then(|rest| rest.strip_prefix('_'))
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
    })
}

/// Reads a scanner's XML output (and `<hosts up="N"/>` count), then deletes
/// the file. A stage knows what its tool writes: the format is never guessed
/// from the content, part of which the scanned server chose.
fn read_scan_with_up(output: &Path) -> Result<(Option<u64>, Vec<Observation>)> {
    crate::workspace::refuse_file_symlink(output)?;
    let parsed = parsers::read_capped(output).and_then(|xml| {
        let up = nmap_hosts_up(&xml);
        // This session's own scanner wrote it.
        let observations = parsers::nmap::parse(&xml, true)
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
    let (changed, full) = {
        let mut graph = state.graph();
        (graph.apply_all(kept), graph.is_full())
    };
    if changed > 0 {
        state.mark_dirty();
    }
    state.notice_if_full(full);
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

/// The most ports per host whose CVE lookups a task asks for as its own.
const MAX_OWN_PORTS: usize = 256;

/// The open ports this task's own scans reported, per host (`22/tcp`).
/// Their CVE lookups go first and are not limited; any other host or port
/// of the target is known from terminal text or imports, and is looked up
/// as they are.
fn own_ports(state: &State, task_id: i64, target: &Target) -> BTreeMap<String, BTreeSet<String>> {
    let probed = load_probed(state, task_id, target);
    let udp = Found::load(&state.db_lock(), task_id, Stage::Udp, target).udp;
    let tcp = probed
        .hosts
        .iter()
        .flat_map(|(address, ports)| ports.iter().map(move |port| (address, *port, "tcp")));
    let udp = udp.iter().map(|(address, port)| (address, *port, "udp"));
    let mut own: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (address, port, protocol) in tcp.chain(udp) {
        let ports = own.entry(address.clone()).or_default();
        if ports.len() < MAX_OWN_PORTS {
            ports.insert(crate::graph::port_key(port, protocol));
        }
    }
    own
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
    // For a name, the addresses the port inventory scanned come first: the
    // scanner resolved the name as the system does.
    let scanned = match target {
        Target::Host(HostAddr::Name(_)) => {
            Found::load(&state.db_lock(), task_id, Stage::Ports, target)
                .hosts
                .into_keys()
                .collect()
        }
        _ => Vec::new(),
    };
    // Then the address the scan goes to, then the name's other addresses.
    let dns_found = Found::load(&state.db_lock(), task_id, Stage::Dns, target);
    for ip_str in scanned
        .iter()
        .chain(&dns_found.primary)
        .chain(&dns_found.ips)
    {
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
    // Only what this session queued: a recon that was in the database when
    // the session started is over, whatever its rows say.
    if !state.owns_recon(id) {
        return Ok(());
    }
    let Some(task_row) = task(&state.db_lock(), id)? else {
        return Ok(());
    };
    let target = Target::parse(&task_row.target)
        .with_context(|| format!("invalid target '{}'", task_row.target))?;
    let update = |stage: Stage, status: &str, detail: &str| {
        let result = set_stage(&state.db_lock(), id, stage, status, detail);
        // How far the stage was belongs to the run that just began or ended.
        state.clear_progress(id, stage);
        state.notice_tool_fault();
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
        // The session is over: what has not started is left out with it.
        if state.is_closing() {
            return Ok(());
        }
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
                update(stage, "interrupted", LIGHT_DETAIL)?;
                state.notice(format!(
                    "recon {} paused: light mode sends no packets to hosts",
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
            let end = run_stage(state, &task_row, &target, stage).await;
            if state.is_closing() {
                // Its tool was stopped with the session, so whatever it
                // says now is not its result. The stage is left as running:
                // the session marks it stopped as it ends (`end_session`),
                // which is also what puts this recon on the list the next
                // start tells the user of.
                return Ok(());
            }
            match end {
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
                    // Nothing to build on: the later stages cannot run,
                    // but for the route, which needs no inventory.
                    if let Some(pos) = STAGES.iter().position(|s| *s == Stage::Ports) {
                        for later in &STAGES[pos + 1..] {
                            if *later != Stage::Trace {
                                update(*later, "skipped", "the port inventory failed")?;
                            }
                        }
                    }
                }
            }
        }
    }
    // The stages after `cves` may have found more to look up. Only what
    // this task found: text and imports asked for the rest themselves.
    for (address, ports) in own_ports(state, id, &target) {
        state.request_grounding(&address, crate::cve::Asked::Recon(ports));
    }
    Ok(())
}

/// Runs queued tasks strictly one at a time.
pub async fn worker(state: Arc<State>, mut queue: mpsc::UnboundedReceiver<i64>) {
    let one_at_a_time = Semaphore::new(1);
    while let Some(id) = queue.recv().await {
        if state.is_closing() {
            break;
        }
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

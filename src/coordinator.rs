//! The session coordinator.
//!
//! `meow <name>` is the single owner of a live workspace: the PTY shell, the
//! in-memory graph, the SQLite writer, the background queue and a loopback
//! HTTP/WebSocket server on `127.0.0.1:8765+`. Helper subcommands, the HUD
//! and the browser map find it through `runtime.json` (`0600`, removed when
//! the session ends) and must present its random 256-bit token.
//!
//! Defences on the loopback server:
//! * every request needs the token (`Authorization: Bearer`, or `?token=`
//!   for the browser page and WebSocket);
//! * the `Host` header must name the loopback address (DNS rebinding);
//! * a request carrying an `Origin` header must come from the coordinator's
//!   own origin, which blocks cross-site WebSocket hijacking.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Request, State as AxumState};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};

use crate::ai::{self, AiEngine, Tier};
use crate::cve::{self, CveClient};
use crate::db::Db;
use crate::endpoint::Target;
use crate::evidence::{Confidence, EvidenceRecord, Source};
use crate::geoip::{self, GeoDb};
use crate::graph::{Graph, Host, LocalNet, Observation};
use crate::location::Place;
use crate::location::{self, Location};
use crate::mode::Mode;
use crate::observer;
use crate::parsers::text::TextParser;
use crate::procs::Tracker;
use crate::pty::LineSink;
use crate::queue;
use crate::tiles::{MapView, Picture};
use crate::timeutil::now_rfc3339;
use crate::topology::Topology;
use crate::vault::Vault;
use crate::webui;
use crate::workspace::{write_private_atomic, Config, GitWatch, Workspace};

pub const FIRST_PORT: u16 = 8765;
const PORT_ATTEMPTS: u16 = 100;
/// Connections the server holds at once before one has shown the session
/// token. Each takes a file descriptor of the session's own process, which
/// also needs them for the terminal, the database and the scanners.
const MAX_CONNECTIONS: usize = 64;
/// Open WebSocket sessions held at once (separate from HTTP head slots).
const MAX_WS_CONNECTIONS: usize = 32;
/// How long a client may take to send a whole request head, on a new
/// connection and between requests on one it keeps open.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum time allowed for an HTTP request body + handler to complete.
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// Pause after a failed accept (out of descriptors) before trying again.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);
/// `runtime.json` is about 110 bytes.
const RUNTIME_MAX: u64 = 4096;
const MAX_NOTICES: usize = 100;
const TAP_QUEUE: usize = 4096;
const SAVE_DEBOUNCE: Duration = Duration::from_millis(750);
const OBSERVE_EVERY: Duration = Duration::from_secs(30);
/// How often a running session checks that git keeps out of `./meow`.
const GIT_GUARD_EVERY: Duration = Duration::from_secs(2);
/// How often the location is checked against the network, and how long
/// after a failed lookup it is tried again.
const LOCATE_EVERY: Duration = Duration::from_secs(30);
const LOCATE_RETRY: Duration = Duration::from_secs(15 * 60);
const WS_MIN_INTERVAL: Duration = Duration::from_millis(400);
/// How often, at most, the progress of a running stage is pushed.
const PROGRESS_EVERY: Duration = Duration::from_secs(1);
/// How many recon tasks the state carries.
const SHOWN_TASKS: usize = 20;
/// How often the session looks whether its guard still runs.
#[cfg(unix)]
const GUARD_CHECK_EVERY: Duration = Duration::from_secs(2);
const BODY_LIMIT: usize = 64 * 1024 * 1024;
/// Leaving a session waits at most this long for the tap's last lines, for
/// the background tasks to stop, and for a lock the final save needs.
const STOP_STEP: Duration = Duration::from_secs(1);
/// ... and at most this long for the whole cleanup: a stuck task must never
/// keep the user from their own shell.
const STOP_LIMIT: Duration = Duration::from_secs(5);

/// Contents of `runtime.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub pid: u32,
    pub port: u16,
    pub token: String,
}

impl RuntimeInfo {
    /// Reads `runtime.json`. Helpers and the listing read it before anything
    /// else in a workspace, so a link, a pipe or a huge file in its place is
    /// "no session" and never read through.
    pub fn read(path: &Path) -> Option<Self> {
        let text = crate::workspace::read_bounded(path, RUNTIME_MAX).ok()?;
        let info: Self = serde_json::from_str(&text).ok()?;
        let valid_token = !info.token.is_empty()
            && info
                .token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
        (info.pid != 0 && info.port != 0 && valid_token).then_some(info)
    }

    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// Removes `runtime.json` when the session ends, however it ends.
struct RuntimeFile(PathBuf);

impl Drop for RuntimeFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        // The page `meow map` gave the browser holds the same token.
        if let Some(workspace) = self.0.parent() {
            let _ = std::fs::remove_file(workspace.join("tmp").join(webui::OPENER_FILE));
        }
    }
}

/// 256 random bits as 64 hex characters.
pub fn new_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no secure random source: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = std::hint::black_box(a.as_bytes());
    let b = std::hint::black_box(b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff = std::hint::black_box(diff | (x ^ y));
    }
    std::hint::black_box(diff) == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    pub at: String,
    pub text: String,
}

/// A request to the coordinator, from a helper subcommand, the HUD or the
/// browser map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Cheap liveness check.
    Ping,
    /// Returns the full state snapshot.
    State,
    SetMode {
        mode: Mode,
    },
    /// Operator note (the HUD's catch-up box), for a host or the workspace.
    Note {
        address: Option<String>,
        text: String,
    },
    /// Parsed facts from `meow add`.
    Observations {
        items: Vec<Observation>,
        /// Run CVE lookups for the affected hosts afterwards.
        ground: bool,
    },
    /// Queues an authorized asset and service inventory (`meow recon`).
    Recon {
        target: String,
        /// Extra nmap flags, given after `--`.
        flags: Vec<String>,
    },
    /// Starts an AI request for a host (`[L]`, `[C]` or `[R]`).
    Ai {
        tier: Tier,
        address: String,
    },
    /// Starts estimating where this machine is (the map sends it when it
    /// opens); does nothing once started.
    Locate,
    /// Puts the device selected on the map on the round map (`None`: back
    /// to this machine). A public address is looked up in the location
    /// database on this disk; nothing is sent anywhere with it.
    LocateHost {
        #[serde(default)]
        address: Option<String>,
    },
    /// "Check now" on a host's status card: one TCP connection attempt to
    /// each of a few of its known open ports. Refused in light mode.
    CheckHost {
        address: String,
    },
}

/// Where the device selected on the map is, for the round map.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TargetLocation {
    pub address: String,
    /// `looking`, `found` (from the database), `local` (on your network:
    /// your own estimate), `unknown`, `no_database` or `name_only`.
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place: Option<Place>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub map: Option<Box<MapView>>,
    /// Why there is no place or no map.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The database's credit, when the place came from it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit_url: Option<&'static str>,
}

/// The ports a "Check now" tries at most, and how long it waits for each.
const CHECK_MAX_PORTS: usize = 6;
const CHECK_TIMEOUT: Duration = Duration::from_secs(3);
/// Tried when no open TCP port is known yet.
const CHECK_DEFAULT_PORTS: [u16; 3] = [443, 80, 22];

/// The answer of one port to a "Check now".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortCheck {
    pub port: u16,
    /// `open` (it accepted), `closed` (it refused) or `no answer`.
    pub state: String,
    /// How long the connection took, when it was accepted.
    pub ms: Option<f64>,
}

/// The last "Check now" of one host, or the one that is running.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostCheck {
    pub at: String,
    /// `checking`, `up` (a port accepted or refused: the host answered),
    /// or `down` (nothing answered in time).
    pub status: String,
    pub ports: Vec<PortCheck>,
}

/// The AI request that is running, or the last one that finished.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AiStatus {
    pub running: bool,
    pub tier: Option<Tier>,
    pub address: Option<String>,
    /// The reply so far (it grows while the request streams in).
    pub text: String,
    pub error: Option<String>,
    /// One line about the finished request: tier, model, cost, file.
    pub summary: Option<String>,
}

/// Everything the coordinator owns, shared between its tasks.
pub struct State {
    pub session: String,
    pub port: u16,
    pub token: String,
    /// Served in the map page and sent with every state push to it, never
    /// taken from a client: how the page knows its own session.
    page_key: String,
    pub config: Config,
    workspace: Mutex<Workspace>,
    graph: Mutex<Graph>,
    pub db: Arc<Mutex<Db>>,
    notices: Mutex<VecDeque<Notice>>,
    /// Bumped on every visible change; WebSocket clients and the saver watch it.
    revision: watch::Sender<u64>,
    dirty: AtomicBool,
    /// Hosts waiting for CVE lookups, and the task that runs them.
    grounds: Mutex<cve::GroundQueue>,
    ground_wake: tokio::sync::Notify,
    /// Lookups text asked for were left out, and the user was told.
    ground_cut_noticed: AtomicBool,
    recon_queue: mpsc::UnboundedSender<i64>,
    /// The newest task the database held when this session started.
    recon_floor: i64,
    /// How far each running stage is, by task and stage. Never stored: a
    /// stage that is not running has none.
    progress: Mutex<std::collections::HashMap<(i64, queue::Stage), Reported>>,
    progress_wake: tokio::sync::Notify,
    /// Bumped when only the progress changed: WebSocket clients then get
    /// that alone, not the whole state again.
    progress_revision: watch::Sender<u64>,
    /// Bumped when only the AI reply grew: WebSocket clients then get the
    /// reply alone, not the whole state again.
    ai_revision: watch::Sender<u64>,
    /// Every program recon starts, so that none outlives the session.
    tools: Tracker,
    cve: Option<CveClient>,
    vault: Mutex<Vault>,
    ai: AiEngine,
    ai_status: Mutex<AiStatus>,
    /// Where this machine is estimated to be; `None` until the map asks.
    location: Mutex<Option<Location>>,
    locating: AtomicBool,
    /// The "graph is full" notice was shown.
    full_noticed: AtomicBool,
    /// See [`State::files_doubtful`].
    files_doubtful: AtomicBool,
    /// The git [`git_guard`] runs, killed when the session ends.
    git_calls: Tracker,
    /// What [`git_guard`] and [`State::check_git`] know of git.
    git_watch: Mutex<GitWatch>,
    /// The location map's pictures, served to the page from memory.
    pictures: Mutex<Vec<Picture>>,
    /// The location database on this disk (`~/.meow/geo`).
    geo: GeoDb,
    /// The selected device on the round map, its pictures, and the places
    /// already looked up.
    target: Mutex<Option<TargetLocation>>,
    target_pictures: Mutex<Vec<Picture>>,
    target_places: Mutex<std::collections::HashMap<String, Option<Place>>>,
    target_generation: std::sync::atomic::AtomicU64,
    /// The last "Check now" of each host, by address.
    checks: Mutex<std::collections::HashMap<String, HostCheck>>,
    ws_slots: Arc<tokio::sync::Semaphore>,
    /// The last state made for the sockets, and the asks for one it
    /// answers ([`state_message`]).
    state_made: tokio::sync::Mutex<(u64, Option<Utf8Bytes>)>,
    state_asks: std::sync::atomic::AtomicU64,
    /// The coordinator's runtime, for work started from any thread.
    handle: tokio::runtime::Handle,
}

/// Removes the evidence record of every node in a port's path tree.
fn drop_path_evidence(node: &mut Value) {
    if let Some(object) = node.as_object_mut() {
        object.remove("record");
        if let Some(children) = object.get_mut("children").and_then(Value::as_object_mut) {
            for child in children.values_mut() {
                drop_path_evidence(child);
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock must not take the whole session down.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// [`lock`] for leaving the session: gives up at `deadline`, since a task
/// the runtime had to leave behind may hold the lock for good.
fn lock_until<T>(mutex: &Mutex<T>, deadline: Instant) -> Option<MutexGuard<'_, T>> {
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(TryLockError::WouldBlock) => return None,
        }
    }
}

impl State {
    pub fn graph(&self) -> MutexGuard<'_, Graph> {
        lock(&self.graph)
    }

    /// The Privacy Vault: where a key found during recon is kept, so only
    /// its placeholder goes anywhere else.
    pub fn vault(&self) -> MutexGuard<'_, Vault> {
        lock(&self.vault)
    }

    pub fn mode(&self) -> Mode {
        lock(&self.workspace).profile.mode
    }

    pub fn workspace_dir(&self) -> PathBuf {
        lock(&self.workspace).dir.clone()
    }

    pub fn db_lock(&self) -> MutexGuard<'_, Db> {
        lock(&self.db)
    }

    /// Tool flag overrides from this workspace's `profile.toml`.
    pub fn profile_recon(&self) -> crate::queue::PresetOverride {
        lock(&self.workspace).profile.recon.clone()
    }

    /// The programs this session started and still runs.
    pub fn tools(&self) -> &Tracker {
        &self.tools
    }

    /// The session is ending: its scanners were stopped and nothing new
    /// starts.
    pub fn is_closing(&self) -> bool {
        self.tools.is_closed()
    }

    /// Records how far a running stage is. Shown at the next progress
    /// push, which follows at once or, after another one, within about a
    /// second.
    pub fn set_progress(&self, task: i64, stage: queue::Stage, progress: queue::Progress) {
        let progress = progress.checked();
        let changed = {
            let mut known = lock(&self.progress);
            if progress == queue::Progress::default() {
                known.remove(&(task, stage)).is_some()
            } else if known
                .get(&(task, stage))
                .is_some_and(|said| said.progress == progress)
            {
                false
            } else {
                let at = Instant::now();
                known.insert((task, stage), Reported { progress, at });
                true
            }
        };
        if changed {
            self.progress_wake.notify_one();
        }
    }

    /// Forgets how far a stage was: it ended, or starts again.
    pub fn clear_progress(&self, task: i64, stage: queue::Stage) {
        lock(&self.progress).remove(&(task, stage));
    }

    /// Says once what happened to the guard that would stop scans after a
    /// hard end of meow: it was started again, or it is gone.
    pub fn notice_tool_fault(&self) {
        if let Some(fault) = self.tools.take_fault() {
            self.notice(fault);
        }
    }

    /// A recon this session queued. Whatever the database held when the
    /// session started belongs to a session that is over, and never runs.
    pub fn owns_recon(&self, task: i64) -> bool {
        task > self.recon_floor
    }

    /// This session's recons that still have work to do, oldest first.
    pub fn unfinished_recons(&self) -> Result<Vec<queue::TaskRow>> {
        let mut unfinished = queue::unfinished(&self.db_lock())?;
        unfinished.retain(|task| self.owns_recon(task.id));
        Ok(unfinished)
    }

    /// Puts this session's unfinished recons back on the queue (light mode
    /// had stopped them); returns how many.
    pub fn resume_unfinished(&self) -> Result<usize> {
        let unfinished = self.unfinished_recons()?;
        for task in &unfinished {
            let _ = self.recon_queue.send(task.id);
        }
        Ok(unfinished.len())
    }

    fn graph_path(&self) -> PathBuf {
        lock(&self.workspace).graph_path()
    }

    /// Records that something visible changed.
    pub fn touch(&self) {
        self.revision.send_modify(|rev| *rev += 1);
    }

    /// Records that the graph changed and must be saved.
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::SeqCst);
        self.touch();
    }

    /// Adds a line to the notice log shown in the HUD.
    pub fn notice(&self, text: impl Into<String>) {
        let text = crate::evidence::sanitize(&text.into(), 300);
        if text.is_empty() {
            return;
        }
        let mut notices = lock(&self.notices);
        if notices.len() >= MAX_NOTICES {
            notices.pop_front();
        }
        notices.push_back(Notice {
            at: now_rfc3339(),
            text,
        });
        drop(notices);
        self.touch();
    }

    /// Puts back what a pull changed to let git take in session files,
    /// and says what git would still take in (see [`GitWatch`]).
    fn watch_git(&self, watch: &mut GitWatch) {
        let dir = lock(&self.workspace).dir.clone();
        for note in watch.check(&dir) {
            self.notice(note);
        }
        if watch.files_doubtful() {
            self.files_doubtful.store(true, Ordering::SeqCst);
        }
    }

    /// Checks git once more, as the timer does: for the end of the
    /// session, so that a pull just before it is seen too. Skipped while
    /// a check runs.
    pub fn check_git(&self) {
        if let Ok(mut watch) = self.git_watch.try_lock() {
            self.watch_git(&mut watch);
        }
    }

    /// Whether git may have put files in the session while it ran
    /// ([`GitWatch::files_doubtful`]): they are then not taken as the
    /// user's own.
    pub fn files_doubtful(&self) -> bool {
        self.files_doubtful.load(Ordering::SeqCst)
    }

    fn save_if_dirty(&self) {
        if !self.dirty.load(Ordering::SeqCst) {
            return;
        }
        let path = self.graph_path();
        let (result, full) = {
            let mut graph = self.graph();
            // Cleared only with the graph in hand: a save still waiting for
            // it has saved nothing yet.
            if !self.dirty.swap(false, Ordering::SeqCst) {
                return;
            }
            (graph.save(&path), graph.is_full())
        };
        if let Err(error) = result {
            // Tried again on the next change, not in a loop: a graph that
            // is too large stays too large.
            self.notice(format!("cannot save graph.json: {error:#}"));
        }
        self.notice_if_full(full);
    }

    /// Says once that the graph is full, as soon as it is: what it refuses
    /// from then on changes nothing, and nothing would be saved to say so.
    pub fn notice_if_full(&self, full: bool) {
        if full && !self.full_noticed.swap(true, Ordering::SeqCst) {
            self.notice(
                "this workspace's graph is full: new hosts, ports and paths are no longer \
                 recorded. Open a new workspace for further targets"
                    .to_owned(),
            );
        }
    }

    /// The final save when the session ends. Returns false when the graph
    /// was still locked at `deadline`, and the save was skipped.
    fn save_on_exit(&self, path: &Path, deadline: Instant) -> bool {
        if !self.dirty.load(Ordering::SeqCst) {
            return true;
        }
        let Some(mut graph) = lock_until(&self.graph, deadline) else {
            return false;
        };
        if self.dirty.swap(false, Ordering::SeqCst) {
            // Nobody would see a notice now; what was saved before is kept.
            let _ = graph.save(path);
        }
        true
    }

    pub fn geo_db(&self) -> &GeoDb {
        &self.geo
    }

    pub fn cve_enabled(&self) -> bool {
        self.cve.is_some()
    }

    /// Runs CVE grounding for `address` immediately and adds the CVEs found to the graph.
    pub async fn ground_host(&self, address: &str) -> Option<(cve::Merged, usize, Vec<String>)> {
        self.ground_host_for(address, cve::Asked::Operator).await
    }

    /// [`Self::ground_host`] for whoever `asked`: what text asked for is
    /// limited.
    pub async fn ground_host_for(
        &self,
        address: &str,
        asked: cve::Asked,
    ) -> Option<(cve::Merged, usize, Vec<String>)> {
        let client = self.cve.as_ref()?;
        let host = self.graph().hosts.get(address).cloned()?;
        let (mut lookups, text) = match &asked {
            cve::Asked::Operator => (cve::plan(&host), Vec::new()),
            cve::Asked::Recon(ports) => cve::plan_split(&host, |port| ports.contains(&port.key())),
            cve::Asked::Text => (Vec::new(), cve::plan(&host)),
        };
        let (allowed, cut) = lock(&self.grounds).allow(text);
        lookups.extend(allowed);
        if cut && !self.ground_cut_noticed.swap(true, Ordering::SeqCst) {
            self.notice(format!(
                "CVE lookups for terminal text and imports reached this session's \
                 limit ({}); what `meow recon` finds is still looked up",
                cve::TEXT_QUESTIONS
            ));
        }
        let mut grounding = client.ground_lookups(&host, lookups).await;
        // What was left out was not asked: earlier matches for it stay.
        grounding.partial |= cut;
        let total_matches = grounding.advisories.len();
        let (merged, full) = {
            let mut graph = self.graph();
            let merged = cve::merge(&mut graph, address, &grounding);
            (merged, graph.is_full())
        };
        self.notice_if_full(full);
        if !grounding.errors.is_empty() {
            let shown: Vec<String> = grounding
                .errors
                .iter()
                .take(3)
                .map(|error| error.replace(" answered HTTP ", " error "))
                .collect();
            self.notice(format!(
                "CVE lookup for {address} incomplete: {}",
                shown.join("; ")
            ));
        }
        if merged.added > 0 || merged.dropped > 0 {
            self.mark_dirty();
        }
        if merged.dropped > 0 {
            self.notice(format!(
                "{} earlier matches for {address} no longer apply and were removed",
                merged.dropped
            ));
        }
        if merged.added > 0 {
            // What to update is on the host, in the map and the HUD.
            let noun = if merged.added == 1 { "CVE" } else { "CVEs" };
            let exploited = match merged.kev {
                0 => String::new(),
                kev => format!(" \u{b7} {kev} exploited"),
            };
            self.notice(format!(
                "{} new {noun} for {address}{exploited}",
                merged.added
            ));
        }
        Some((merged, total_matches, grounding.errors))
    }

    /// Builds [`crate::report::Inputs`] from the live session state.
    pub fn report_inputs(&self) -> crate::report::Inputs {
        let tasks = queue::tasks(&self.db_lock(), 200).unwrap_or_default();
        let mode = self.mode();
        let graph = self.graph().clone();
        let secrets = lock(&self.vault).exposed_secrets();
        let dir = self.workspace_dir();
        let (replay, chats) = crate::report::read_chats_and_replay(&dir);
        crate::report::Inputs {
            session: self.session.clone(),
            mode,
            generated_utc: now_rfc3339(),
            graph,
            tasks,
            secrets,
            replay,
            chats,
        }
    }

    /// Queues CVE lookups for a host (no-op when grounding is disabled or
    /// the host is already queued). `asked`: who wants them, which says
    /// how soon and how many.
    pub fn request_grounding(&self, address: &str, asked: cve::Asked) {
        if self.cve.is_some() && lock(&self.grounds).push(address, asked) {
            self.ground_wake.notify_one();
        }
    }

    /// Lets text ask only `questions` new CVE questions (tests).
    #[cfg(test)]
    pub(crate) fn limit_text_questions(&self, questions: usize) {
        *lock(&self.grounds) = cve::GroundQueue::new(questions);
    }

    /// How far the running stages are, as a message of its own: a tool
    /// that counts its results changes this every second, and nothing else
    /// of the state. `now_utc` is the clock the time left counts from.
    pub fn progress_snapshot(&self) -> Value {
        let now = Instant::now();
        let mut running: Vec<(i64, queue::Stage, queue::Progress)> = lock(&self.progress)
            .iter()
            .map(|((task, stage), said)| (*task, *stage, said.as_of(now)))
            .collect();
        running.sort_by_key(|(task, stage, _)| (*task, stage.as_str()));
        let running: Vec<Value> = running
            .into_iter()
            .map(|(task, stage, progress)| json!({ "task": task, "stage": stage, "progress": progress }))
            .collect();
        json!({ "now_utc": now_rfc3339(), "running": running })
    }

    /// The snapshot sent to the HUD and the browser map.
    /// Acquires each mutex individually so graph serialization and topology
    /// construction never block PTY/IPC writers or invert lock ordering.
    pub fn snapshot(&self) -> Value {
        // Every recon of this session that has work to do, however many
        // were queued after it, and the newest of the others.
        let mut tasks =
            queue::shown(&self.db_lock(), self.recon_floor, SHOWN_TASKS).unwrap_or_default();
        {
            // Only a stage that is running is somewhere on its way.
            let progress = lock(&self.progress);
            let now = Instant::now();
            for task in &mut tasks {
                for stage in task.stages.iter_mut().filter(|s| s.status == "running") {
                    stage.progress = progress
                        .get(&(task.id, stage.stage))
                        .map(|said| said.as_of(now));
                }
            }
        }
        let mode = self.mode();
        let revision = *self.revision.borrow();
        let graph = self.graph().clone();
        let notices: Vec<Notice> = lock(&self.notices).iter().cloned().collect();
        let ai = lock(&self.ai_status).clone();
        let location = lock(&self.location).clone();
        let raw_target = lock(&self.target).clone();
        let budget = self.ai.budget();

        // Each host's CVEs by the software and version they were found
        // from, the most urgent first: the map lists them so.
        let cves: serde_json::Map<String, Value> = graph
            .hosts
            .values()
            .filter(|host| !host.advisories.is_empty())
            .map(|host| {
                let groups: Vec<Value> = cve::by_software(host)
                    .iter()
                    .map(|group| {
                        json!({
                            "software": group.software,
                            "port": group.port,
                            "fix": group.fix(),
                            "kev": group.kev(),
                            // Its distribution may have the fix under the
                            // same version number.
                            "note": cve::backport_note_for(host, group.port.as_deref()),
                            "cves": group
                                .cves
                                .iter()
                                .map(|a| json!({
                                    "id": a.id,
                                    "severity": cve::severity_label(a),
                                    "serious": cve::is_serious(a),
                                }))
                                .collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                (host.address.clone(), Value::Array(groups))
            })
            .collect();
        let fixes: serde_json::Map<String, Value> = graph
            .hosts
            .values()
            .map(|host| (host.address.clone(), cve::fix_plan(host)))
            .filter(|(_, plan)| !plan.is_empty())
            .map(|(address, plan)| (address, json!(plan)))
            .collect();
        // Neither the map nor the HUD shows the raw evidence of each web
        // path, and it is most of a large graph: it stays out of the push.
        let mut shown = json!(&graph);
        if let Some(hosts) = shown.get_mut("hosts").and_then(Value::as_object_mut) {
            for host in hosts.values_mut() {
                if let Some(ports) = host.get_mut("ports").and_then(Value::as_object_mut) {
                    for port in ports.values_mut() {
                        if let Some(paths) = port.get_mut("paths") {
                            drop_path_evidence(paths);
                        }
                    }
                }
            }
        }
        let target = raw_target.map(|target| {
            let mut value = json!(&target);
            value["addresses"] = known_addresses(&graph, &target.address);
            value
        });
        json!({
            "session": self.session,
            "mode": mode,
            "port": self.port,
            "revision": revision,
            // The clock the stage times were written with: what a client
            // counts elapsed time from, whatever its own clock says.
            "now_utc": now_rfc3339(),
            "graph": shown,
            "cves": cves,
            "cve_lookups": self.cve.is_some(),
            "fixes": fixes,
            "topology": Topology::build(&graph).cytoscape_with_geo(&graph, Some(&self.geo)),
            "machine": observer::machine_report(&graph.local),
            "tasks": tasks,
            "notices": notices,
            "ai": ai,
            "location": location,
            "target": target,
            "budget": budget,
            "checks": &*lock(&self.checks),
        })
    }

    /// Carries out one command. Fast: long work is handed to background tasks.
    pub fn execute(self: &Arc<Self>, command: Command) -> Result<Value> {
        match command {
            Command::Ping => Ok(json!({ "session": self.session, "port": self.port })),
            Command::State => Ok(self.snapshot()),
            Command::SetMode { mode } => {
                lock(&self.workspace).set_mode(mode)?;
                self.notice(format!("Mode: {mode}"));
                // Tasks paused by light mode continue once it is left.
                let resumed = match mode {
                    Mode::Light => 0,
                    _ => self.resume_unfinished()?,
                };
                Ok(json!({ "mode": mode, "resumed": resumed }))
            }
            Command::Note { address, text } => {
                // U+FEFF too, as JavaScript's trim() does: the page counts so.
                let text = text
                    .trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
                    .to_owned();
                if text.is_empty() {
                    bail!("the note is empty");
                }
                // Refused whole, never cut: the page and the HUD keep it.
                if text.len() > crate::evidence::EVIDENCE_MAX {
                    bail!(
                        "the note is too long: {} bytes, {} at most",
                        text.len(),
                        crate::evidence::EVIDENCE_MAX
                    );
                }
                let record =
                    EvidenceRecord::observed(Source::ManualNote, Confidence::Medium, &text);
                let observation = Observation::Note {
                    address: address.clone(),
                    text,
                    record,
                };
                let (stored, full) = {
                    let mut graph = self.graph();
                    (graph.apply(observation), graph.is_full())
                };
                self.notice_if_full(full);
                if !stored && full {
                    bail!("the note was not stored: this workspace's graph is full");
                }
                if !stored {
                    bail!("the note was not stored (unknown host, or a duplicate)");
                }
                self.mark_dirty();
                // A note may carry a package URL worth looking up.
                if let Some(address) = &address {
                    self.request_grounding(address, cve::Asked::Operator);
                }
                Ok(json!({ "stored": true }))
            }
            Command::Observations { items, ground } => {
                let total = items.len();
                let mut touched: Vec<String> = Vec::new();
                let mut changed = 0;
                let full = {
                    let mut graph = self.graph();
                    for mut item in items {
                        // A file, not this session's scan: a name in it is a
                        // claim, whatever the file says of it.
                        if let Observation::Hostname { record, .. } = &mut item {
                            record.confidence = record.confidence.min(Confidence::Medium);
                        }
                        // Nor does it close a port the session found open.
                        if let Observation::NotOpen { own_scan, .. } = &mut item {
                            *own_scan = false;
                        }
                        let address = observation_address(&item);
                        if graph.apply(item) {
                            changed += 1;
                            if let Some(address) =
                                address.and_then(|a| graph.host(&a).map(|h| h.address.clone()))
                            {
                                if !touched.contains(&address) {
                                    touched.push(address);
                                }
                            }
                        }
                    }
                    graph.is_full()
                };
                let hosts = crate::topology::map_host_count(&self.graph());
                if changed > 0 {
                    self.mark_dirty();
                    self.notice(format!("imported {changed} new facts ({total} parsed)"));
                }
                self.notice_if_full(full);
                let grounding = ground && self.cve.is_some();
                if grounding {
                    for address in &touched {
                        self.request_grounding(address, cve::Asked::Text);
                    }
                }
                Ok(json!({
                    "parsed": total,
                    "changed": changed,
                    "hosts": hosts,
                    "grounding": grounding,
                    "full": full,
                }))
            }
            Command::Recon { target, flags } => {
                let mode = self.mode();
                if mode == Mode::Light {
                    bail!(
                        "light mode sends no packets to hosts, so recon is refused; \
                         run `meow mode mild` (or aggressive) first"
                    );
                }
                let parsed = Target::parse(&target).with_context(|| {
                    format!("'{target}' is not a host name, an IP address or a CIDR range")
                })?;
                parsed.check_size().map_err(|reason| anyhow!(reason))?;
                queue::validate_nmap_flags(&flags)?;
                let preset = self.config.recon.preset(mode, &self.profile_recon());
                queue::validate_preset_nmap_flags(&preset.nmap_ports, &preset.nmap_services)?;
                let id = queue::enqueue(&self.db_lock(), &parsed.to_string(), mode, &flags)?;
                let risky = queue::high_rate_flags(&flags).join(" ");
                if mode == Mode::Mild && !risky.is_empty() {
                    self.notice(format!(
                        "recon {parsed}: high-rate flags in mild mode ({risky})"
                    ));
                }
                let _ = self.recon_queue.send(id);
                self.notice(format!("Recon {parsed} queued \u{b7} {mode}"));
                let ahead = self.unfinished_recons()?.len().saturating_sub(1);
                Ok(
                    json!({ "task": id, "target": parsed.to_string(), "mode": mode, "ahead": ahead }),
                )
            }
            Command::Locate => {
                if !self.locating.swap(true, Ordering::SeqCst) {
                    self.handle.spawn(location_loop(Arc::clone(self)));
                }
                Ok(json!({ "locating": true }))
            }
            Command::CheckHost { address } => {
                if self.mode() == Mode::Light {
                    bail!(
                        "light mode sends no packets to hosts, so the host is not checked; \
                         run `meow mode mild` (or aggressive) first"
                    );
                }
                let host = self
                    .graph()
                    .host(&address)
                    .cloned()
                    .with_context(|| format!("{address} is not a host of this workspace"))?;
                let Ok(ip) = host.address.parse::<std::net::IpAddr>() else {
                    bail!("{} has no address to check yet", host.address);
                };
                let mut ports: Vec<u16> = host
                    .open_ports()
                    .filter(|port| port.protocol == "tcp")
                    .map(|port| port.number)
                    .take(CHECK_MAX_PORTS)
                    .collect();
                if ports.is_empty() {
                    ports = CHECK_DEFAULT_PORTS.to_vec();
                }
                {
                    let mut checks = lock(&self.checks);
                    if checks
                        .get(&host.address)
                        .is_some_and(|c| c.status == "checking")
                    {
                        return Ok(json!({ "checking": true }));
                    }
                    checks.insert(
                        host.address.clone(),
                        HostCheck {
                            at: now_rfc3339(),
                            status: "checking".to_owned(),
                            ports: Vec::new(),
                        },
                    );
                }
                self.touch();
                self.handle.spawn(check_host(
                    Arc::clone(self),
                    host.address.clone(),
                    ip,
                    ports,
                ));
                Ok(json!({ "checking": true }))
            }
            Command::LocateHost { address } => {
                let generation = self.target_generation.fetch_add(1, Ordering::SeqCst) + 1;
                let Some(address) = address
                    .map(|a| a.trim().to_owned())
                    .filter(|a| !a.is_empty())
                else {
                    *lock(&self.target) = None;
                    lock(&self.target_pictures).clear();
                    self.touch();
                    return Ok(json!({ "target": null }));
                };
                *lock(&self.target) = Some(TargetLocation {
                    address: address.clone(),
                    status: "looking",
                    place: None,
                    map: None,
                    note: None,
                    credit: None,
                    credit_url: None,
                });
                self.touch();
                self.handle
                    .spawn(locate_target(Arc::clone(self), address.clone(), generation));
                Ok(json!({ "locating": address }))
            }
            Command::Ai { tier, address } => {
                let (graph, host) = {
                    let graph = self.graph();
                    let host = graph
                        .host(&address)
                        .cloned()
                        .with_context(|| format!("unknown host '{address}'"))?;
                    (graph.clone(), host)
                };
                if tier == Tier::Research && host.advisories.is_empty() {
                    bail!("Research needs a CVE: none found for {} yet", host.address);
                }
                {
                    let mut status = lock(&self.ai_status);
                    if status.running {
                        bail!("an AI request is already running");
                    }
                    *status = AiStatus {
                        running: true,
                        tier: Some(tier),
                        address: Some(host.address.clone()),
                        ..AiStatus::default()
                    };
                }
                self.notice(format!("{} · {} · running", tier.name(), host.address));
                let state = Arc::clone(self);
                self.handle
                    .spawn(async move { state.run_ai(tier, graph, host).await });
                Ok(json!({ "started": true, "tier": tier }))
            }
        }
    }
}

impl State {
    /// Runs one AI request to the end, streaming the reply into the status
    /// that the HUD and the map show, then saves it under `chats/`.
    async fn run_ai(self: Arc<Self>, tier: Tier, graph: Graph, host: Host) {
        let _running = AiRunning(&self.ai_status);
        let streamer = Arc::clone(&self);
        let mut on_text = move |piece: &str| {
            if !piece.is_empty() {
                lock(&streamer.ai_status).text.push_str(piece);
                // Only the reply is sent again, not the whole state.
                streamer.ai_revision.send_modify(|rev| *rev += 1);
            }
        };
        let result = self
            .ai
            .run(tier, &graph, &host, &self.vault, &mut on_text)
            .await;
        let line = match result {
            Ok(outcome) => {
                let saved = ai::append_chat(&self.workspace_dir().join("chats"), &host, &outcome);
                let file = match &saved {
                    Ok(path) => format!(
                        "chats/{}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    Err(error) => format!("not saved: {error:#}"),
                };
                let how = match (&outcome.fallback_reason, outcome.cached) {
                    (Some(reason), _) => format!("local AI instead ({reason})"),
                    (None, true) => "from cache".to_owned(),
                    (None, false) => format!("by {}", outcome.model),
                };
                // "Local AI · 192.0.2.10 · done · by stub-model · $0.0000 ·
                // chats/192.0.2.10.md": the words the map and the HUD use.
                let line = format!(
                    "{} · {} · done · {how} · ${:.4} · {file}",
                    tier.name(),
                    host.address,
                    outcome.cost_usd
                );
                let mut status = lock(&self.ai_status);
                status.running = false;
                status.text = outcome.text;
                status.summary = Some(line.clone());
                line
            }
            Err(error) => {
                let line = format!("{} · {} · failed: {error:#}", tier.name(), host.address);
                let mut status = lock(&self.ai_status);
                status.running = false;
                status.error = Some(format!("{error:#}"));
                line
            }
        };
        self.notice(line);
    }
}

/// Clears "an AI request is running" when the request ends, however it
/// ends: one that stopped on a fault must not leave every later request
/// refused as "already running" for the rest of the session.
struct AiRunning<'a>(&'a Mutex<AiStatus>);

impl Drop for AiRunning<'_> {
    fn drop(&mut self) {
        let mut status = lock(self.0);
        if status.running {
            status.running = false;
            status
                .error
                .get_or_insert_with(|| "the request ended unexpectedly".to_owned());
        }
    }
}

fn observation_address(observation: &Observation) -> Option<String> {
    observation.address().map(str::to_owned)
}

// ---------------------------------------------------------------------------
// HTTP / WebSocket server
// ---------------------------------------------------------------------------

type Shared = Arc<State>;

fn deny(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "ok": false, "error": message }))).into_response()
}

/// `Host` must be a single loopback address matching the coordinator's port.
fn host_allowed(headers: &HeaderMap, port: u16) -> bool {
    let mut values = headers.get_all(header::HOST).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().is_ok_and(|host| {
        let host = host.trim();
        host == format!("127.0.0.1:{port}")
            || host.eq_ignore_ascii_case(&format!("localhost:{port}"))
    })
}

/// A browser sends `Origin` on WebSocket upgrades and cross-site requests;
/// when present it must be a single header matching the coordinator's own
/// origin. Native clients (the HUD, helper subcommands) send none.
fn origin_allowed(headers: &HeaderMap, port: u16) -> bool {
    let mut values = headers.get_all(header::ORIGIN).iter();
    let Some(value) = values.next() else {
        return true;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().is_ok_and(|origin| {
        let origin = origin.trim();
        origin.eq_ignore_ascii_case(&format!("http://127.0.0.1:{port}"))
            || origin.eq_ignore_ascii_case(&format!("http://localhost:{port}"))
    })
}

/// What a browser says of a request in a Fetch Metadata header
/// (`Sec-Fetch-Site`, `Sec-Fetch-Mode`): true when it says `expected`, or
/// says nothing (an older browser, or a client that is not one).
fn fetch_says(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return true;
    };
    values.next().is_none()
        && value
            .to_str()
            .is_ok_and(|said| said.trim().eq_ignore_ascii_case(expected))
}

/// The session token a request carries: in its `Authorization` header or
/// its `?token=` query. Never a cookie: browsers send a cookie of
/// 127.0.0.1 to every port of 127.0.0.1, so any other program listening
/// there would be handed the token.
fn token_from(headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    let mut auth_values = headers.get_all(header::AUTHORIZATION).iter();
    if let Some(first) = auth_values.next() {
        if auth_values.next().is_some() {
            return None;
        }
        let raw = first.to_str().ok()?.trim();
        let bearer = raw
            .get(..7)
            .filter(|prefix| prefix.eq_ignore_ascii_case("Bearer "))
            .map(|_| raw[7..].trim())?;
        if bearer.is_empty() {
            return None;
        }
        return Some(bearer.to_owned());
    }
    if let Some(q) = query {
        let mut found: Option<String> = None;
        for (key, value) in url::form_urlencoded::parse(q.as_bytes()) {
            if key == "token" && !value.is_empty() {
                if found.is_some() {
                    return None;
                }
                found = Some(value.into_owned());
            }
        }
        if let Some(token) = found {
            return Some(token);
        }
    }
    None
}

async fn guard(AxumState(state): AxumState<Shared>, request: Request, next: Next) -> Response {
    let mut response = check_and_run(&state, request, next).await;
    webui::security_headers(&mut response, state.port);
    response
}

/// A refusal by the guard. The connection is closed with it: a client
/// without the token cannot keep one of the connection slots by asking
/// again and again.
fn refuse(status: StatusCode, message: &str) -> Response {
    let mut response = deny(status, message);
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

async fn check_and_run(state: &Shared, request: Request, next: Next) -> Response {
    let headers = request.headers();
    if !host_allowed(headers, state.port) {
        return refuse(StatusCode::FORBIDDEN, "unexpected Host header");
    }
    if !origin_allowed(headers, state.port) {
        return refuse(StatusCode::FORBIDDEN, "cross-origin request refused");
    }
    let Some(presented) = token_from(headers, request.uri().query()) else {
        // A reload of the map, which keeps its token out of the address
        // bar: a page without secrets that reads it back from the tab.
        // Only the tab itself is answered: a page of another origin that
        // loads them learns that meow runs here.
        if request.method() == axum::http::Method::GET {
            match request.uri().path() {
                "/" if fetch_says(headers, "sec-fetch-mode", "navigate") => {
                    return webui::reload_page()
                }
                "/reload.js" if fetch_says(headers, "sec-fetch-site", "same-origin") => {
                    return webui::reload_script()
                }
                _ => {}
            }
        }
        return refuse(StatusCode::UNAUTHORIZED, "missing or wrong session token");
    };
    if !constant_time_eq(&presented, &state.token) {
        // A reload of a map tab that kept the token of a session that has
        // since ended: a page without secrets that says so and makes the
        // tab forget that token.
        if request.method() == axum::http::Method::GET
            && request.uri().path() == "/"
            && fetch_says(headers, "sec-fetch-mode", "navigate")
        {
            let mut response = webui::stale_page();
            *response.status_mut() = StatusCode::UNAUTHORIZED;
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
            return response;
        }
        return refuse(StatusCode::UNAUTHORIZED, "missing or wrong session token");
    }
    match tokio::time::timeout(REQUEST_BODY_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => refuse(StatusCode::REQUEST_TIMEOUT, "request timed out"),
    }
}

async fn get_state(AxumState(state): AxumState<Shared>) -> Json<Value> {
    Json(state.snapshot())
}

async fn post_command(
    AxumState(state): AxumState<Shared>,
    Json(command): Json<Command>,
) -> Response {
    match state.execute(command) {
        Ok(result) => Json(json!({ "ok": true, "result": result })).into_response(),
        Err(error) => deny(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    }
}

async fn get_report(AxumState(state): AxumState<Shared>) -> Response {
    let inputs = state.report_inputs();
    let filename = format!("report-{}", crate::ai::chat_file_name(&inputs.session));
    let markdown = crate::report::render(&inputs);
    let mut response = (
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        markdown,
    )
        .into_response();
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, disp);
    }
    response
}

async fn get_host_report(
    AxumState(state): AxumState<Shared>,
    AxumPath(address): AxumPath<String>,
) -> Response {
    let inputs = state.report_inputs();
    let Some(markdown) = crate::report::render_host_report(&inputs, &address) else {
        return refuse(StatusCode::NOT_FOUND, "unknown host");
    };
    let filename = format!("report-{}", crate::ai::chat_file_name(&address));
    let mut response = (
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        markdown,
    )
        .into_response();
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, disp);
    }
    response
}

async fn websocket(AxumState(state): AxumState<Shared>, upgrade: WebSocketUpgrade) -> Response {
    let Ok(permit) = Arc::clone(&state.ws_slots).try_acquire_owned() else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many open WebSocket connections",
        );
    };
    upgrade
        .max_message_size(64 * 1024)
        .max_frame_size(64 * 1024)
        .on_upgrade(move |socket| serve_socket(state, socket, permit))
}

/// The whole state as one message. It is made off the session's two
/// async threads: a large one takes seconds, and the other sockets (a tab
/// saying who it is to, the HUD) are not kept waiting meanwhile. One is
/// made at a time, and every socket that asked before it was begun gets
/// that same text: many tabs on a large session cost one state, not one
/// each.
async fn state_message(state: &Shared) -> Option<Message> {
    let asked = state.state_asks.fetch_add(1, Ordering::SeqCst) + 1;
    let mut made = state.state_made.lock().await;
    if made.0 < asked || made.1.is_none() {
        // A state made from now on answers every ask so far.
        let answers = state.state_asks.load(Ordering::SeqCst);
        let shared = Arc::clone(state);
        let text = tokio::task::spawn_blocking(move || {
            let text =
                json!({ "type": "state", "key": shared.page_key, "state": shared.snapshot() });
            Utf8Bytes::from(text.to_string())
        })
        .await
        .ok()?;
        *made = (answers, Some(text));
    }
    made.1.clone().map(Message::Text)
}

/// Pushes a state snapshot on connect and after every change (rate-limited),
/// the progress of the running stages alone when only that changed, and
/// executes commands the client sends without blocking incoming frames.
async fn serve_socket(
    state: Shared,
    mut socket: WebSocket,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let mut revision = state.revision.subscribe();
    let mut progress = state.progress_revision.subscribe();
    let mut reply = state.ai_revision.subscribe();
    // Who this is, before the state, which takes a while when it is large:
    // the page trusts a socket that says its key.
    let hello = json!({ "type": "hello", "key": state.page_key }).to_string();
    if socket.send(Message::Text(hello.into())).await.is_err() {
        return;
    }
    let Some(first) = state_message(&state).await else {
        return;
    };
    if socket.send(first).await.is_err() {
        return;
    }
    let mut pending_push = false;
    let mut pending_reply = false;
    let throttle = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(throttle);
    let reply_throttle = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(reply_throttle);
    loop {
        tokio::select! {
            changed = revision.changed(), if !pending_push => {
                if changed.is_err() {
                    break;
                }
                pending_push = true;
                throttle
                    .as_mut()
                    .reset(tokio::time::Instant::now() + WS_MIN_INTERVAL);
            }
            () = &mut throttle, if pending_push => {
                pending_push = false;
                let _ = revision.borrow_and_update();
                // The state says how far the stages are, and the AI reply
                // so far, too.
                let _ = progress.borrow_and_update();
                let _ = reply.borrow_and_update();
                pending_reply = false;
                let Some(message) = state_message(&state).await else {
                    break;
                };
                if socket.send(message).await.is_err() {
                    break;
                }
            }
            // Only the AI reply grew (it streams in): the reply alone is
            // sent, at most as often as the state.
            changed = reply.changed(), if !pending_reply => {
                if changed.is_err() {
                    break;
                }
                pending_reply = true;
                reply_throttle
                    .as_mut()
                    .reset(tokio::time::Instant::now() + WS_MIN_INTERVAL);
            }
            () = &mut reply_throttle, if pending_reply => {
                pending_reply = false;
                let _ = reply.borrow_and_update();
                let status = lock(&state.ai_status).clone();
                let message = json!({ "type": "ai", "key": state.page_key, "ai": status });
                if socket.send(Message::Text(message.to_string().into())).await.is_err() {
                    break;
                }
            }
            // Only the progress changed: that alone is sent (the loop
            // that says so keeps it to once a second).
            changed = progress.changed() => {
                if changed.is_err() {
                    break;
                }
                let _ = progress.borrow_and_update();
                let mut message = state.progress_snapshot();
                message["type"] = json!("progress");
                message["key"] = json!(state.page_key);
                if socket.send(Message::Text(message.to_string().into())).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                let Some(Ok(message)) = incoming else { break };
                let Message::Text(text) = message else { continue };
                let reply = match serde_json::from_str::<Command>(&text) {
                    Ok(command) => match state.execute(command) {
                        Ok(result) => json!({ "type": "result", "ok": true, "result": result }),
                        Err(error) => json!({ "type": "result", "ok": false, "error": format!("{error:#}") }),
                    },
                    Err(error) => json!({ "type": "result", "ok": false, "error": format!("bad command: {error}") }),
                };
                if socket.send(Message::Text(reply.to_string().into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn index(AxumState(state): AxumState<Shared>) -> Response {
    webui::page(&state.token, &state.page_key)
}

async fn asset(AxumPath(name): AxumPath<String>) -> Response {
    webui::asset(&name)
}

/// One picture of the location map, from memory: the page never fetches
/// pictures from anywhere else, and this never fetches anything.
async fn map_tile(
    AxumState(state): AxumState<Shared>,
    AxumPath((z, x, y)): AxumPath<(u8, u32, u32)>,
) -> Response {
    if !state.config.location.enabled || !state.config.location.map {
        return StatusCode::NOT_FOUND.into_response();
    }
    let found = {
        let pictures = lock(&state.pictures);
        pictures
            .iter()
            .find(|picture| (picture.z, picture.x, picture.y) == (z, x, y))
            .map(|picture| (picture.media_type, picture.bytes.clone()))
    }
    .or_else(|| {
        let target_pictures = lock(&state.target_pictures);
        target_pictures
            .iter()
            .find(|picture| (picture.z, picture.x, picture.y) == (z, x, y))
            .map(|picture| (picture.media_type, picture.bytes.clone()))
    });
    match found {
        Some((media_type, bytes)) => ([(header::CONTENT_TYPE, media_type)], bytes).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn parse_ip_unscoped(value: &str) -> Option<std::net::IpAddr> {
    match value.split_once('%') {
        None => value.parse::<std::net::IpAddr>().ok(),
        Some((bare, zone)) => {
            if zone.is_empty() || zone.contains('%') {
                return None;
            }
            bare.parse::<std::net::Ipv6Addr>()
                .ok()
                .map(std::net::IpAddr::V6)
        }
    }
}

/// Every IPv4 and IPv6 address meow has seen for the device at `address`:
/// its own, and those of entries with the same hardware address or name.
fn known_addresses(graph: &Graph, address: &str) -> Value {
    let host = graph.host(address);
    let mac = host
        .and_then(|host| host.mac.clone())
        .or_else(|| {
            graph
                .local
                .neighbors
                .iter()
                .find(|n| n.address == address)
                .and_then(|n| n.mac.clone())
        })
        .map(|mac| mac.to_ascii_lowercase());
    let names: Vec<&String> = host
        .map(|host| host.hostnames.iter().collect())
        .unwrap_or_default();
    let mut all: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    all.insert(address.to_owned());
    for other in graph.hosts.values() {
        let same_mac = mac.is_some() && other.mac.as_ref().map(|m| m.to_ascii_lowercase()) == mac;
        let same_name = other.hostnames.iter().any(|name| names.contains(&name));
        if same_mac || same_name {
            all.insert(other.address.clone());
        }
    }
    if let Some(mac) = &mac {
        for neighbour in &graph.local.neighbors {
            if neighbour
                .mac
                .as_ref()
                .map(|m| m.to_ascii_lowercase())
                .as_ref()
                == Some(mac)
            {
                all.insert(neighbour.address.clone());
            }
        }
    }
    let (mut ipv4, mut ipv6) = (Vec::new(), Vec::new());
    for entry in all {
        match parse_ip_unscoped(&entry) {
            Some(std::net::IpAddr::V4(_)) => ipv4.push(entry),
            Some(std::net::IpAddr::V6(_)) => ipv6.push(entry),
            None => {}
        }
    }
    json!({ "ipv4": ipv4, "ipv6": ipv6 })
}

const MAX_CACHED_PLACES: usize = 1024;

/// Finds where the device selected on the map is, then fetches its map's
/// pictures. A newer selection wins: a stale answer is dropped.
/// One connection attempt to `port`: accepted, refused, or no answer.
async fn try_port(ip: std::net::IpAddr, port: u16) -> PortCheck {
    let started = std::time::Instant::now();
    let attempt = tokio::time::timeout(
        CHECK_TIMEOUT,
        tokio::net::TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await;
    let (state, ms) = match attempt {
        Ok(Ok(_stream)) => (
            "open",
            Some((started.elapsed().as_secs_f64() * 10_000.0).round() / 10.0),
        ),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => ("closed", None),
        _ => ("no answer", None),
    };
    PortCheck {
        port,
        state: state.to_owned(),
        ms,
    }
}

/// "Check now": tries the ports at the same time, then records the result.
async fn check_host(state: Shared, address: String, ip: std::net::IpAddr, ports: Vec<u16>) {
    let mut results =
        futures_util::future::join_all(ports.iter().map(|port| try_port(ip, *port))).await;
    results.sort_by_key(|check| check.port);
    let answered = results.iter().any(|check| check.state != "no answer");
    let status = if answered { "up" } else { "down" };
    let open: Vec<String> = results
        .iter()
        .filter(|check| check.state == "open")
        .map(|check| format!("{} ({:.0} ms)", check.port, check.ms.unwrap_or(0.0)))
        .collect();
    state.notice(format!(
        "check {address}: {status}{}",
        if open.is_empty() {
            String::new()
        } else {
            format!(", answering on {}", open.join(", "))
        }
    ));
    lock(&state.checks).insert(
        address,
        HostCheck {
            at: now_rfc3339(),
            status: status.to_owned(),
            ports: results,
        },
    );
    state.touch();
}

async fn locate_target(state: Shared, address: String, generation: u64) {
    let settings = state.config.location.clone();
    let mut target = TargetLocation {
        address: address.clone(),
        status: "unknown",
        place: None,
        map: None,
        note: None,
        credit: None,
        credit_url: None,
    };
    let mut pictures = Vec::new();
    match parse_ip_unscoped(&address) {
        None => {
            target.status = "name_only";
            target.note = Some("only a name is known, no address to place".to_owned());
        }
        Some(ip) if geoip::is_local(ip) => {
            // On your network: it is where you are, unless a full-tunnel VPN
            // or `[location] enabled = false` hides this machine's location.
            target.status = "local";
            let lookup_allowed = {
                let graph = state.graph();
                matches!(
                    location::plan(&settings, &graph.local),
                    location::Plan::Lookup { .. }
                )
            };
            if lookup_allowed {
                if let Some(Location::Found { place, map, .. }) = &*lock(&state.location) {
                    if settings.map {
                        target.map = map.clone();
                    }
                    target.place = Some(place.clone());
                }
            }
        }
        Some(ip) => {
            let cached = lock(&state.target_places).get(&address).cloned();
            let place = match cached {
                Some(place) => Ok(place),
                None if !state.geo.available() => Err(None),
                None => {
                    let geo = state.geo.clone();
                    match tokio::task::spawn_blocking(move || geo.lookup(ip)).await {
                        Ok(Ok(place)) => {
                            let mut places = lock(&state.target_places);
                            if places.len() >= MAX_CACHED_PLACES {
                                places.clear();
                            }
                            places.insert(address.clone(), place.clone());
                            Ok(place)
                        }
                        Ok(Err(error)) => Err(Some(format!("{error:#}"))),
                        Err(error) => Err(Some(error.to_string())),
                    }
                }
            };
            match place {
                Err(None) => {
                    target.status = "no_database";
                    target.note =
                        Some("the location database is not installed: run meow tools".to_owned());
                }
                Err(Some(reason)) => target.note = Some(reason),
                Ok(None) => target.note = Some("not in the location database".to_owned()),
                Ok(Some(place)) => {
                    target.status = "found";
                    target.credit = Some(geoip::CREDIT);
                    target.credit_url = Some(geoip::CREDIT_URL);
                    // `[location] enabled = false` asks for no outside
                    // request about places at all, pictures included.
                    let map = if settings.enabled {
                        location::map_for(&settings, &place).await
                    } else {
                        None
                    };
                    match map {
                        Some(Ok((view, fetched))) => {
                            target.map = Some(Box::new(view));
                            pictures = fetched;
                        }
                        Some(Err(error)) => target.note = Some(format!("no map: {error:#}")),
                        None => {}
                    }
                    target.place = Some(place);
                }
            }
        }
    }
    if state.target_generation.load(Ordering::SeqCst) != generation {
        return;
    }
    *lock(&state.target_pictures) = pictures;
    *lock(&state.target) = Some(target);
    state.touch();
}

fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/{name}", get(asset))
        .route("/map/tile/{z}/{x}/{y}", get(map_tile))
        .route("/api/state", get(get_state))
        .route("/api/report", get(get_report))
        .route("/api/report/{address}", get(get_host_report))
        .route("/api/command", post(post_command))
        .route("/ws", get(websocket))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn_with_state(Arc::clone(&state), guard))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

/// Saves `graph.json` shortly after the last change.
async fn saver(state: Shared) {
    let mut revision = state.revision.subscribe();
    while revision.changed().await.is_ok() {
        tokio::time::sleep(SAVE_DEBOUNCE).await;
        revision.borrow_and_update();
        let state = Arc::clone(&state);
        let _ = tokio::task::spawn_blocking(move || state.save_if_dirty()).await;
    }
}

/// How far a stage said it is, and when it said so.
struct Reported {
    progress: queue::Progress,
    at: Instant,
}

impl Reported {
    /// The progress as it stands at `now`: the time left has been running
    /// out since it was reported, so `eta_s` is always the time left at the
    /// state's `now_utc`. One that has run out is no longer known.
    fn as_of(&self, now: Instant) -> queue::Progress {
        let since = now.saturating_duration_since(self.at).as_secs();
        queue::Progress {
            eta_s: self
                .progress
                .eta_s
                .and_then(|left| left.checked_sub(since))
                .filter(|left| *left > 0),
            ..self.progress.clone()
        }
    }
}

/// Pushes how far the running stage is: as soon as that changes, and then
/// at most once every [`PROGRESS_EVERY`]. Nothing is pushed while nothing
/// changes. Only the progress is pushed, not the state.
async fn progress_loop(state: Shared) {
    loop {
        state.progress_wake.notified().await;
        state.progress_revision.send_modify(|rev| *rev += 1);
        tokio::time::sleep(PROGRESS_EVERY).await;
    }
}

/// Looks after the guard: one that was killed is started again within
/// [`GUARD_CHECK_EVERY`], also while a long scan runs, and that is said.
#[cfg(unix)]
async fn guard_watch(state: Shared) {
    loop {
        tokio::time::sleep(GUARD_CHECK_EVERY).await;
        if state.is_closing() {
            return;
        }
        state.tools.check_guard();
        state.notice_tool_fault();
    }
}

/// Keeps git out of the session folder while the session runs, whether or
/// not anything else changes: a pull can change what git ignores at any
/// time.
async fn git_guard(state: Shared) {
    loop {
        tokio::time::sleep(GIT_GUARD_EVERY).await;
        let state = Arc::clone(&state);
        let _ = tokio::task::spawn_blocking(move || {
            state.watch_git(&mut lock(&state.git_watch));
        })
        .await;
    }
}

fn same_tables(a: &LocalNet, b: &LocalNet) -> bool {
    a.interfaces == b.interfaces
        && a.routes == b.routes
        && a.neighbors == b.neighbors
        && a.listeners == b.listeners
        && a.warnings == b.warnings
        && a.notes == b.notes
}

/// Re-reads the local network tables periodically (passive, zero packets).
async fn observe_loop(state: Shared) {
    loop {
        tokio::time::sleep(OBSERVE_EVERY).await;
        let targets = state.graph().target_ips();
        let tools = state.tools.clone();
        let Ok(local) =
            tokio::task::spawn_blocking(move || observer::observe_with(&tools, &targets)).await
        else {
            continue;
        };
        if state.is_closing() {
            // Cut short with the session: not what the tables hold.
            return;
        }
        let new_warnings: Vec<String> = {
            let mut graph = state.graph();
            if same_tables(&graph.local, &local) {
                continue;
            }
            let fresh = local
                .warnings
                .iter()
                .filter(|w| !graph.local.warnings.contains(w))
                .cloned()
                .collect();
            graph.local = local;
            fresh
        };
        for warning in new_warnings {
            state.notice(warning);
        }
        state.mark_dirty();
    }
}

/// Keeps the location estimate in step with the network: looked up again
/// only when the VPNs, the default gateway or this machine's address
/// change, or a while after a failed lookup.
async fn location_loop(state: Shared) {
    let settings = state.config.location.clone();
    let mut revision = state.revision.subscribe();
    let mut last_key: Option<String> = None;
    let mut retry_at: Option<std::time::Instant> = None;
    loop {
        let _ = revision.borrow_and_update();
        let (key, plan) = {
            let graph = state.graph();
            (
                location::network_key(&graph.local),
                location::plan(&settings, &graph.local),
            )
        };
        let retry = retry_at.is_some_and(|at| std::time::Instant::now() >= at);
        if last_key.as_deref() != Some(key.as_str()) || retry {
            last_key = Some(key);
            retry_at = None;
            let found = match plan {
                location::Plan::Off => Location::Off,
                location::Plan::Hidden(vpn) => Location::HiddenByVpn { vpn },
                location::Plan::Lookup { partial_vpns } => {
                    match location::lookup(&settings.url).await {
                        Ok(place) => {
                            let (map, map_error) = match location::map_for(&settings, &place).await
                            {
                                Some(Ok((view, pictures))) => {
                                    *lock(&state.pictures) = pictures;
                                    (Some(Box::new(view)), None)
                                }
                                Some(Err(error)) => {
                                    retry_at = Some(std::time::Instant::now() + LOCATE_RETRY);
                                    (None, Some(format!("{error:#}")))
                                }
                                None => (None, None),
                            };
                            Location::Found {
                                place,
                                source: location::source(&settings.url),
                                vpn: partial_vpns,
                                map,
                                map_error,
                            }
                        }
                        Err(error) => {
                            retry_at = Some(std::time::Instant::now() + LOCATE_RETRY);
                            Location::Unavailable {
                                reason: format!("{error:#}"),
                            }
                        }
                    }
                }
            };
            // Pictures of a place no longer shown are dropped, and any local
            // target mirroring our location stops showing stale coordinates.
            if !matches!(found, Location::Found { map: Some(_), .. }) {
                lock(&state.pictures).clear();
            }
            match &found {
                Location::Found { place, map, .. } => {
                    if let Some(target) = &mut *lock(&state.target) {
                        if target.status == "local" {
                            target.place = Some(place.clone());
                            target.map = map.clone();
                        }
                    }
                }
                _ => {
                    let mut cleared_local = false;
                    if let Some(target) = &mut *lock(&state.target) {
                        if target.status == "local" {
                            target.place = None;
                            target.map = None;
                            cleared_local = true;
                        }
                    }
                    if cleared_local {
                        lock(&state.target_pictures).clear();
                    }
                }
            }
            *lock(&state.location) = Some(found);
            state.touch();
        }
        let wait = retry_at
            .map(|at| {
                at.saturating_duration_since(std::time::Instant::now())
                    .min(LOCATE_EVERY)
            })
            .unwrap_or(LOCATE_EVERY);
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            changed = revision.changed() => {
                if changed.is_err() {
                    break;
                }
            }
        }
    }
}

/// Mines clean terminal lines for hosts, ports, URLs and headers.
async fn tap_loop(state: Shared, mut lines: mpsc::Receiver<String>) {
    let mut parser = TextParser::new(Source::PtyRegex);
    while let Some(line) = lines.recv().await {
        let observations = parser.feed(&line);
        if observations.is_empty() {
            continue;
        }
        let mut ground: Vec<String> = Vec::new();
        let mut changed = false;
        let full = {
            let mut graph = state.graph();
            for observation in observations {
                let versioned = matches!(
                    &observation,
                    Observation::Port {
                        product: Some(_),
                        ..
                    }
                );
                let address = observation_address(&observation);
                if graph.apply(observation) {
                    changed = true;
                    if versioned {
                        ground.extend(
                            address.and_then(|a| graph.host(&a).map(|h| h.address.clone())),
                        );
                    }
                }
            }
            graph.is_full()
        };
        if changed {
            state.mark_dirty();
        }
        state.notice_if_full(full);
        for address in ground {
            state.request_grounding(&address, cve::Asked::Text);
        }
    }
}

/// Runs CVE lookups one host at a time, off the request path: those the
/// operator asked for first.
async fn grounding_loop(state: Shared) {
    loop {
        let next = lock(&state.grounds).pop();
        match next {
            Some((address, asked)) => {
                let _ = state.ground_host_for(&address, asked).await;
            }
            None => state.ground_wake.notified().await,
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

pub struct Coordinator {
    state: Shared,
    runtime: Option<tokio::runtime::Runtime>,
    /// The only strong reference: tap sinks hold weak ones, so that the tap
    /// task ends once this is dropped, whoever still has a sink.
    tap: Option<Arc<mpsc::Sender<String>>>,
    tap_task: Option<tokio::task::JoinHandle<()>>,
    /// The recon queue's worker, which runs one stage at a time.
    recon_task: Option<tokio::task::JoinHandle<()>>,
    /// See [`Coordinator::left_recons`].
    left_recons: (Vec<queue::TaskRow>, usize),
    /// Kept from the start: the workspace lock may be held when it ends.
    graph_path: PathBuf,
    tmp_dir: PathBuf,
    _runtime_file: RuntimeFile,
}

/// Listens on the first free loopback port from `first`, or, when all
/// `attempts` of them are taken, on any free one: clients read the port
/// from `runtime.json`, so another program sitting on the usual ports
/// cannot keep a session from starting.
async fn bind_loopback(first: u16, attempts: u16) -> Result<tokio::net::TcpListener> {
    for offset in 0..attempts {
        let Some(port) = first.checked_add(offset) else {
            break;
        };
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        if let Ok(listener) = tokio::net::TcpListener::bind(address).await {
            return Ok(listener);
        }
    }
    tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .context("no free loopback port for the session")
}

/// Serves `app` on `listener`, HTTP/1.1 only. `axum::serve` would take every
/// connection offered and wait on each for ever; any local program could
/// then use up the session's file descriptors with connections that never
/// send a request. Here at most `slots` connections are held at once, and
/// one that has not sent a request head within `head_timeout` is closed.
/// A WebSocket leaves its slot once the token was accepted and it is open.
async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
    slots: Arc<tokio::sync::Semaphore>,
    head_timeout: Duration,
) {
    loop {
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                tokio::time::sleep(ACCEPT_RETRY).await;
                continue;
            }
        };
        let service = hyper_util::service::TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let mut http = hyper::server::conn::http1::Builder::new();
            http.timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(head_timeout)
                .max_buf_size(64 * 1024);
            let _ = http
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .with_upgrades()
                .await;
        });
    }
}

impl Coordinator {
    /// Starts the coordinator for an opened (and locked) workspace.
    pub fn start(workspace: Workspace, config: Config) -> Result<Self> {
        Self::start_with(workspace, config, None)
    }

    /// [`Coordinator::start`] by the `meow` program itself, found at
    /// `program`: on Unix it is started a second time as the session's
    /// guard, which stops the scanners if this process is killed outright,
    /// and the tools that run are written down in `records` for the next
    /// start to stop if the guard is killed too (see [`crate::procs`]).
    /// Without the guard everything else works, and a notice says what
    /// does not.
    pub fn start_guarded(
        workspace: Workspace,
        config: Config,
        program: std::io::Result<PathBuf>,
        records: Option<PathBuf>,
    ) -> Result<Self> {
        Self::start_with(workspace, config, Some((program, records)))
    }

    fn start_with(
        workspace: Workspace,
        config: Config,
        guard: Option<(std::io::Result<PathBuf>, Option<PathBuf>)>,
    ) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("meow-coordinator")
            .enable_all()
            .build()
            .context("cannot start the coordinator runtime")?;

        let listener = runtime.block_on(bind_loopback(FIRST_PORT, PORT_ATTEMPTS))?;
        let port = listener.local_addr()?.port();
        let token = new_token()?;

        let mut graph = Graph::load(&workspace.graph_path())?;
        graph.local = observer::observe(&graph.target_ips());
        let db = Arc::new(Mutex::new(Db::open(&workspace.state_db_path())?));
        let vault = Vault::open(Arc::clone(&db))?;
        // A key meow 0.2.3 left in a script endpoint (saved below).
        graph.hide_script_keys(&vault);
        let engine = AiEngine::new(config.ai.clone(), Arc::clone(&db))?;
        let cve = if config.cve.enabled {
            Some(CveClient::new(config.cve.clone(), Arc::clone(&db))?)
        } else {
            None
        };

        let graph_path = workspace.graph_path();
        let tmp_dir = workspace.tmp_dir();
        let _ = std::fs::remove_file(tmp_dir.join(webui::OPENER_FILE));
        let _ = std::fs::remove_file(tmp_dir.join("map-open.html"));
        let runtime_path = workspace.runtime_path();
        let info = RuntimeInfo {
            pid: std::process::id(),
            port,
            token: token.clone(),
        };
        write_private_atomic(&runtime_path, serde_json::to_string(&info)?.as_bytes())?;
        let runtime_file = RuntimeFile(runtime_path);

        let (revision, _) = watch::channel(0u64);
        let (recon_queue, recon_rx) = mpsc::unbounded_channel();
        // What the database holds of recons belongs to sessions that are
        // over. One that was killed left its stages as they were: they are
        // marked now as a session that ends in order marks them, before
        // anything else reads the queue. None of them runs again.
        let (left_recons, recon_floor) = {
            let db = lock(&db);
            queue::end_session(&db, queue::SessionEnd::Lost)?;
            (queue::take_left(&db)?, queue::newest_id(&db)?)
        };
        // What its tool was writing goes too: no tool of this session runs
        // yet.
        queue::clear_tool_leftovers(&tmp_dir);
        let (tap, tap_rx) = mpsc::channel(TAP_QUEUE);
        // The location database for scanned servers (never falls back to CWD).
        let geo_dir = if config.location.database.trim().is_empty() {
            crate::workspace::MeowHome::from_env()
                .ok()
                .map(|home| home.root().join(geoip::DIR))
        } else {
            let p = PathBuf::from(config.location.database.trim());
            let resolved = if p.is_absolute() {
                p
            } else {
                crate::workspace::MeowHome::from_env()
                    .map(|home| home.root().join(&p))
                    .unwrap_or(p)
            };
            if resolved.extension().and_then(|e| e.to_str()) == Some("mmdb") {
                resolved.parent().map(Path::to_path_buf)
            } else {
                Some(resolved)
            }
        };
        let geo = GeoDb::from_optional_dir(geo_dir);
        let git_calls = Tracker::new();
        let state = Arc::new(State {
            session: workspace.name.clone(),
            port,
            token,
            page_key: new_token()?,
            config,
            workspace: Mutex::new(workspace),
            graph: Mutex::new(graph),
            db,
            notices: Mutex::new(VecDeque::new()),
            revision,
            dirty: AtomicBool::new(true),
            grounds: Mutex::new(cve::GroundQueue::new(cve::TEXT_QUESTIONS)),
            ground_wake: tokio::sync::Notify::new(),
            ground_cut_noticed: AtomicBool::new(false),
            recon_queue,
            recon_floor,
            progress: Mutex::new(std::collections::HashMap::new()),
            progress_wake: tokio::sync::Notify::new(),
            progress_revision: watch::channel(0u64).0,
            ai_revision: watch::channel(0u64).0,
            tools: Tracker::new(),
            cve,
            vault: Mutex::new(vault),
            ai: engine,
            ai_status: Mutex::new(AiStatus::default()),
            location: Mutex::new(None),
            locating: AtomicBool::new(false),
            full_noticed: AtomicBool::new(false),
            files_doubtful: AtomicBool::new(false),
            git_watch: Mutex::new(GitWatch::using(git_calls.clone())),
            git_calls,
            pictures: Mutex::new(Vec::new()),
            geo,
            target: Mutex::new(None),
            target_pictures: Mutex::new(Vec::new()),
            target_places: Mutex::new(std::collections::HashMap::new()),
            target_generation: std::sync::atomic::AtomicU64::new(0),
            checks: Mutex::new(std::collections::HashMap::new()),
            ws_slots: Arc::new(tokio::sync::Semaphore::new(MAX_WS_CONNECTIONS)),
            state_made: tokio::sync::Mutex::new((0, None)),
            state_asks: std::sync::atomic::AtomicU64::new(0),
            handle: runtime.handle().clone(),
        });

        #[cfg(unix)]
        if let Some((program, records)) = guard {
            if let Err(error) = program.and_then(|program| state.tools.watch(&program)) {
                state.notice(format!(
                    "the scan guard did not start ({error}): {}",
                    crate::procs::UNGUARDED
                ));
            }
            // The second list, for a session killed with its guard. Where
            // it cannot be kept, the guard is the only one.
            if let Some(dir) = records {
                let _ = state.tools.record_in(&dir);
            }
            runtime.spawn(guard_watch(Arc::clone(&state)));
        }
        // Windows needs neither: a Job Object closes with the process.
        #[cfg(not(unix))]
        drop(guard);

        let app = router(Arc::clone(&state));
        runtime.spawn(serve(
            listener,
            app,
            Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            HEAD_TIMEOUT,
        ));
        runtime.spawn(saver(Arc::clone(&state)));
        runtime.spawn(observe_loop(Arc::clone(&state)));
        runtime.spawn(git_guard(Arc::clone(&state)));
        let tap_task = runtime.spawn(tap_loop(Arc::clone(&state), tap_rx));
        runtime.spawn(grounding_loop(Arc::clone(&state)));
        runtime.spawn(progress_loop(Arc::clone(&state)));
        let recon_task = runtime.spawn(queue::worker(Arc::clone(&state), recon_rx));
        let cleaned = std::mem::take(&mut state.graph().cleaned);
        if !cleaned.is_empty() {
            state.mark_dirty();
            state.notice(format!(
                "removed {} sites an earlier web crawl had followed links to ({}); crawls now stay on the host they crawl",
                cleaned.len(),
                cleaned.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                    + if cleaned.len() > 5 { ", ..." } else { "" }
            ));
        }
        state.save_if_dirty();

        Ok(Self {
            state,
            runtime: Some(runtime),
            tap: Some(Arc::new(tap)),
            tap_task: Some(tap_task),
            recon_task: Some(recon_task),
            left_recons,
            graph_path,
            tmp_dir,
            _runtime_file: runtime_file,
        })
    }

    /// The recons that the end of an earlier session cut short and that
    /// were not yet said to the user (the newest of them, and how many
    /// more). Each is here once: at the first start after that session.
    pub fn left_recons(&self) -> (&[queue::TaskRow], usize) {
        (&self.left_recons.0, self.left_recons.1)
    }

    pub fn state(&self) -> Shared {
        Arc::clone(&self.state)
    }

    pub fn info(&self) -> RuntimeInfo {
        RuntimeInfo {
            pid: std::process::id(),
            port: self.state.port,
            token: self.state.token.clone(),
        }
    }

    /// A sink for the PTY analysis tap. Lines are dropped, never queued
    /// without bound, if the coordinator falls behind, and once it stops.
    pub fn tap_sink(&self) -> LineSink {
        match &self.tap {
            Some(tap) => {
                let tap = Arc::downgrade(tap);
                Box::new(move |line| {
                    if let Some(tap) = tap.upgrade() {
                        let _ = tap.try_send(line.to_owned());
                    }
                })
            }
            None => Box::new(|_line| {}),
        }
    }

    /// Stops the background tasks and writes the final `graph.json`, in at
    /// most [`STOP_LIMIT`]. Returns what had to be skipped because it was
    /// stuck.
    pub fn shutdown(mut self) -> Vec<&'static str> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        // On a thread of its own, so that not even a file write that never
        // returns keeps the user from their shell.
        let cleanup = std::thread::Builder::new()
            .name("meow-shutdown".to_owned())
            .spawn(move || {
                let skipped = self.stop();
                // Removes runtime.json before saying it is done.
                drop(self);
                let _ = done_tx.send(skipped);
            });
        if cleanup.is_err() {
            // The coordinator went with the closure: its drop stopped it.
            return Vec::new();
        }
        done_rx
            .recv_timeout(STOP_LIMIT)
            .unwrap_or_else(|_| vec!["the rest of the cleanup"])
    }

    fn stop(&mut self) -> Vec<&'static str> {
        let mut skipped = Vec::new();
        // The scanners first, and by their process groups: nothing below
        // has to go well for them to be gone, and no stage starts another.
        let tool_ran = self.state.tools.running() > 0;
        self.state.tools.close();
        self.state.git_calls.close();
        let Some(runtime) = self.runtime.take() else {
            return skipped;
        };
        // The stage whose tool was just killed puts the tool's unfinished
        // file away: moments, and waited for no longer. It is marked
        // stopped below, with the rest of the queue. The worker ends at
        // the next task it is handed, which this is.
        let _ = self.state.recon_queue.send(0);
        if let Some(task) = self.recon_task.take().filter(|_| tool_ran) {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            runtime.spawn(async move {
                let _ = task.await;
                let _ = done_tx.send(());
            });
            let _ = done_rx.recv_timeout(STOP_STEP / 2);
        }
        // Let the tap finish the lines it already has: with the last sender
        // gone the task ends by itself. Waited for on a std channel, as the
        // runtime's own timers stop if both its workers are stuck.
        self.tap.take();
        if let Some(task) = self.tap_task.take() {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            runtime.spawn(async move {
                let _ = task.await;
                let _ = done_tx.send(());
            });
            let _ = done_rx.recv_timeout(STOP_STEP);
        }
        // Returns in time even if a task is stuck, but leaves that task
        // behind with any lock it holds: hence the deadline below.
        runtime.shutdown_timeout(STOP_STEP);
        let deadline = Instant::now() + STOP_STEP;
        // Saved whether or not it changed: a graph.json put there during
        // the session (a git pull) is not left for the next one.
        self.state.dirty.store(true, Ordering::SeqCst);
        if !self.state.save_on_exit(&self.graph_path, deadline) {
            skipped.push("saving graph.json");
        }
        // The recons end with the session: the stage whose tool was just
        // killed is marked stopped and the stages after it are left out;
        // finished stages keep their results. If the database is stuck,
        // the next session does this as it starts.
        if let Some(db) = lock_until(&self.state.db, deadline) {
            let _ = queue::end_session(&db, queue::SessionEnd::Closed);
        }
        // Clean up any browser bootstrap file containing the session token.
        let _ = std::fs::remove_file(self.tmp_dir.join(webui::OPENER_FILE));
        let _ = std::fs::remove_file(self.tmp_dir.join("map-open.html"));
        skipped
    }
}

impl Drop for Coordinator {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc;
    use crate::lock::SessionLock;
    use crate::workspace::MeowHome;
    use axum::routing::post;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    struct Fixture {
        _tmp: tempfile::TempDir,
        lock: Option<SessionLock>,
        workspace: Workspace,
        coordinator: Coordinator,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        let lock = SessionLock::acquire(&workspace.lock_path()).unwrap();
        let mut config = Config::default();
        config.cve.enabled = false;
        let coordinator = Coordinator::start(workspace.clone(), config).unwrap();
        Fixture {
            _tmp: tmp,
            lock: Some(lock),
            workspace,
            coordinator,
        }
    }

    /// A `git pull` run in the session's own shell: meow's `.gitignore`
    /// files in `./meow` and in the session are put back on the next check,
    /// and a `graph.json` put in place meanwhile is written over when the
    /// session ends.
    #[test]
    fn what_a_pull_changes_during_the_session_is_put_right() {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, &project, "acme", true, Mode::Light).unwrap();
        let _lock = SessionLock::acquire(&workspace.lock_path()).unwrap();
        let mut config = Config::default();
        config.cve.enabled = false;
        let coordinator = Coordinator::start(workspace.clone(), config).unwrap();
        let state = coordinator.state();
        assert!(!state.files_doubtful());
        let marker = project.join("meow").join(".gitignore");
        let meows = std::fs::read_to_string(&marker).unwrap();
        std::fs::write(&marker, "!*\n").unwrap();
        std::fs::write(workspace.dir.join(".gitignore"), "!*\n").unwrap();
        // Checked on a timer, whether or not anything is saved.
        state.watch_git(&mut GitWatch::default());
        // The session's files are then not taken as the user's (WS-3).
        assert!(state.files_doubtful());
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), meows);
        assert_eq!(
            std::fs::read_to_string(workspace.dir.join(".gitignore")).unwrap(),
            meows
        );
        for shown in ["meow/.gitignore", "meow/acme/.gitignore"] {
            assert!(
                lock(&state.notices)
                    .iter()
                    .any(|notice| notice.text.starts_with(shown)),
                "{shown}"
            );
        }
        std::fs::write(
            workspace.graph_path(),
            r#"{"hosts":{"198.51.100.9":{"address":"198.51.100.9"}}}"#,
        )
        .unwrap();
        drop(state);
        assert!(coordinator.shutdown().is_empty());
        let graph = std::fs::read_to_string(workspace.graph_path()).unwrap();
        assert!(!graph.contains("198.51.100.9"), "{graph}");
    }

    #[test]
    fn check_now_connects_to_known_ports_only_outside_light_mode() {
        let fx = fixture();
        let state = fx.coordinator.state();
        // One port that answers, one that refuses.
        let open = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = open.local_addr().unwrap().port();
        let closed_port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let record = EvidenceRecord::observed(Source::NmapXml, Confidence::High, "scan");
        for port in [open_port, closed_port] {
            state.graph().apply(Observation::Port {
                address: "127.0.0.1".into(),
                port,
                protocol: "tcp".into(),
                state: "open".into(),
                service: None,
                product: None,
                version: None,
                extra_info: None,
                cpes: vec![],
                record: record.clone(),
            });
        }
        let check = || {
            state.execute(Command::CheckHost {
                address: "127.0.0.1".into(),
            })
        };
        // Light mode sends nothing.
        let error = format!("{:#}", check().unwrap_err());
        assert!(error.contains("light mode sends no packets"), "{error}");
        assert!(state.snapshot()["checks"].as_object().unwrap().is_empty());

        state
            .execute(Command::SetMode { mode: Mode::Mild })
            .unwrap();
        assert_eq!(check().unwrap()["checking"], true);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let result = loop {
            let result = state.snapshot()["checks"]["127.0.0.1"].clone();
            if result["status"] != "checking" || std::time::Instant::now() > deadline {
                break result;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(result["status"], "up", "{result}");
        let ports = result["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 2);
        let answer = |port: u16| ports.iter().find(|p| p["port"] == port).unwrap().clone();
        assert_eq!(answer(open_port)["state"], "open");
        assert!(answer(open_port)["ms"].as_f64().is_some());
        assert_eq!(answer(closed_port)["state"], "closed");
        // A host the workspace does not know is not contacted.
        let error = format!(
            "{:#}",
            state
                .execute(Command::CheckHost {
                    address: "192.0.2.77".into()
                })
                .unwrap_err()
        );
        assert!(error.contains("not a host of this workspace"), "{error}");
        drop(open);
        fx.coordinator.shutdown();
    }

    #[test]
    fn location_off_means_no_picture_requests_for_a_selected_server_either() {
        use std::sync::atomic::AtomicUsize;
        const JPEG: &[u8] = crate::tiles::TEST_JPEG;
        static ASKED: AtomicUsize = AtomicUsize::new(0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            block_on(async move {
                let app = axum::Router::new().route(
                    "/tiles/{z}/{x}/{y}",
                    axum::routing::get(|| async {
                        ASKED.fetch_add(1, Ordering::SeqCst);
                        JPEG
                    }),
                );
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap()).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let address = rx.recv().unwrap();
        let place = Place {
            city: Some("Mountain View".into()),
            region: Some("California".into()),
            country: Some("United States".into()),
            latitude: 37.422,
            longitude: -122.085,
            public_address: Some("8.8.8.8".into()),
            network: None,
        };
        let select = |enabled: bool| {
            let tmp = tempfile::tempdir().unwrap();
            let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
            let (workspace, _) =
                Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
            let _lock = SessionLock::acquire(&workspace.lock_path()).unwrap();
            let mut config = Config::default();
            config.cve.enabled = false;
            config.location.enabled = enabled;
            config.location.tiles = format!("http://{address}/tiles/{{z}}/{{x}}/{{y}}");
            let coordinator = Coordinator::start(workspace, config).unwrap();
            let state = coordinator.state();
            // The place is known already, as after a database lookup.
            lock(&state.target_places).insert("8.8.8.8".to_owned(), Some(place.clone()));
            state
                .execute(Command::LocateHost {
                    address: Some("8.8.8.8".into()),
                })
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let target = loop {
                let target = state.snapshot()["target"].clone();
                if target["status"] != "looking" || std::time::Instant::now() > deadline {
                    break target;
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            coordinator.shutdown();
            target
        };
        let off = select(false);
        assert_eq!(off["status"], "found", "{off}");
        assert_eq!(off["place"]["city"], "Mountain View");
        assert!(off.get("map").is_none(), "{off}");
        assert_eq!(ASKED.load(Ordering::SeqCst), 0, "no picture was asked for");
        // On, the same selection fetches the pictures.
        let on = select(true);
        assert!(on["map"]["tiles"].as_array().is_some(), "{on}");
        assert!(ASKED.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn the_live_push_leaves_out_the_evidence_of_web_paths() {
        let mut tree = json!({ "children": {
            "admin": { "status": 403, "record": { "evidence": "GET /admin 403" }, "children": {
                "login": { "status": 200, "record": { "evidence": "GET /admin/login 200" } }
            } }
        } });
        drop_path_evidence(&mut tree);
        assert_eq!(
            tree,
            json!({ "children": { "admin": { "status": 403, "children": {
                "login": { "status": 200 }
            } } } })
        );
    }

    #[test]
    fn the_map_asks_once_and_the_estimate_lands_in_the_snapshot() {
        const JPEG: &[u8] = crate::tiles::TEST_JPEG;
        // A stand-in lookup and map picture service on its own thread.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            block_on(async move {
                let app = axum::Router::new()
                    .route(
                        "/json",
                        axum::routing::get(|| async {
                            axum::Json(json!({ "ip": "203.0.113.7", "city": "Spokane",
                                "region": "Washington", "country": "US", "loc": "47.6588,-117.4260" }))
                        }),
                    )
                    .route("/tiles/{z}/{x}/{y}", axum::routing::get(|| async { JPEG }));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap()).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let address = rx.recv().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        let _lock = SessionLock::acquire(&workspace.lock_path()).unwrap();
        let mut config = Config::default();
        config.cve.enabled = false;
        config.location.url = format!("http://{address}/json");
        config.location.tiles = format!("http://{address}/tiles/{{z}}/{{x}}/{{y}}");
        // An empty folder: no location database installed.
        let no_database = tempfile::tempdir().unwrap();
        config.location.database = no_database.path().display().to_string();
        let coordinator = Coordinator::start(workspace, config).unwrap();
        let state = coordinator.state();
        let info = coordinator.info();
        // A map picture as the page asks for it: (status, type, bytes).
        let picture = |z: u64, x: u64, y: u64| {
            block_on(async {
                let client = reqwest::Client::builder().no_proxy().build().unwrap();
                let response = client
                    .get(format!(
                        "{}/map/tile/{z}/{x}/{y}?token={}",
                        info.base_url(),
                        info.token
                    ))
                    .send()
                    .await
                    .unwrap();
                let status = response.status().as_u16();
                let kind = response
                    .headers()
                    .get("content-type")
                    .map(|value| value.to_str().unwrap().to_owned());
                (status, kind, response.bytes().await.unwrap().to_vec())
            })
        };

        // Nothing is looked up until the map asks.
        assert_eq!(state.snapshot()["location"], Value::Null);
        state.execute(Command::Locate).unwrap();
        state.execute(Command::Locate).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let location = loop {
            let location = state.snapshot()["location"].clone();
            if !location.is_null() || std::time::Instant::now() > deadline {
                break location;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        // This test machine may itself be on a VPN that takes all traffic.
        match location["status"].as_str() {
            Some("found") => {
                assert_eq!(location["place"]["city"], "Spokane");
                assert_eq!(location["place"]["latitude"], 47.6588);
                assert_eq!(location["source"], "127.0.0.1");
                // The map came with it, its pictures served from memory.
                let map = &location["map"];
                assert_eq!(
                    (map["width"].as_u64(), map["height"].as_u64()),
                    (Some(200), Some(200))
                );
                assert_eq!(map["credit"], "Map pictures from 127.0.0.1");
                assert!(location.get("map_error").is_none(), "{location}");
                let tiles: Vec<Value> = map["tiles"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .chain(map["closer"]["tiles"].as_array().unwrap())
                    .cloned()
                    .collect();
                assert!(tiles.len() > 4, "both views have pictures");
                for tile in &tiles {
                    let (z, x, y) = (
                        tile["z"].as_u64().unwrap(),
                        tile["x"].as_u64().unwrap(),
                        tile["y"].as_u64().unwrap(),
                    );
                    let (status, kind, bytes) = picture(z, x, y);
                    assert_eq!((status, kind.as_deref()), (200, Some("image/jpeg")));
                    assert_eq!(bytes, JPEG);
                }
                // Only those: nothing else is fetched or served.
                assert_eq!(picture(1, 0, 0).0, 404);
            }
            Some("hidden_by_vpn") => {
                assert!(location["vpn"].as_array().is_some());
                assert_eq!(picture(8, 44, 89).0, 404);
            }
            other => panic!("unexpected location {other:?}: {location}"),
        }

        // The round map follows the device selected on the drawing.
        let target = |address: Option<&str>| {
            state
                .execute(Command::LocateHost {
                    address: address.map(str::to_owned),
                })
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let target = state.snapshot()["target"].clone();
                if target["status"] != "looking" || std::time::Instant::now() > deadline {
                    break target;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        // On your network: where you are, with its own addresses.
        let local = target(Some("192.168.0.153"));
        assert_eq!(local["status"], "local", "{local}");
        assert_eq!(local["addresses"]["ipv4"], json!(["192.168.0.153"]));
        assert_eq!(local["addresses"]["ipv6"], json!([]));
        if location["status"] == "found" {
            assert_eq!(local["place"]["city"], "Spokane");
            assert!(local["map"]["tiles"].as_array().is_some());
        }
        // A public address needs the database, which is not installed here;
        // nothing was asked of anyone.
        let public = target(Some("8.8.8.8"));
        assert_eq!(public["status"], "no_database", "{public}");
        // `meow update` of a release install does not install it.
        let note = public["note"].as_str().unwrap();
        assert!(note.ends_with("run meow tools"), "{note}");
        assert_eq!(target(Some("www.example.com"))["status"], "name_only");
        assert_eq!(target(None), Value::Null);
        coordinator.shutdown();
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// (status, body) of a raw request with full control over the headers.
    fn request(
        info: &RuntimeInfo,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> (u16, Value) {
        block_on(async {
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let url = format!("{}{path}", info.base_url());
            let mut request = match method {
                "POST" => client.post(url),
                _ => client.get(url),
            };
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            if let Some(body) = body {
                request = request.json(&body);
            }
            let response = request.send().await.unwrap();
            let status = response.status().as_u16();
            let text = response.text().await.unwrap();
            (
                status,
                serde_json::from_str(&text).unwrap_or(Value::String(text)),
            )
        })
    }

    /// A GET with only the Host header, as raw text: status line, headers
    /// and body.
    fn raw_request(info: &RuntimeInfo, path: &str) -> String {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", info.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            info.port
        )
        .unwrap();
        let mut reply = String::new();
        let _ = stream.read_to_string(&mut reply);
        reply
    }

    fn bearer(info: &RuntimeInfo) -> String {
        format!("Bearer {}", info.token)
    }

    #[test]
    fn an_ai_request_that_ends_on_a_fault_is_no_longer_running() {
        let status = Mutex::new(AiStatus {
            running: true,
            ..AiStatus::default()
        });
        // The request's task unwinds: nothing set the status.
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _running = AiRunning(&status);
            std::panic::resume_unwind(Box::new("fault in the request"));
        }));
        assert!(unwound.is_err());
        let after = lock(&status);
        assert!(!after.running);
        assert_eq!(
            after.error.as_deref(),
            Some("the request ended unexpectedly")
        );
        drop(after);
        // A request that ended normally keeps what it reported.
        *lock(&status) = AiStatus {
            summary: Some("done".into()),
            ..AiStatus::default()
        };
        drop(AiRunning(&status));
        assert_eq!(lock(&status).error, None);
    }

    #[test]
    fn a_taken_port_range_does_not_keep_a_session_from_starting() {
        block_on(async {
            // Someone else holds the whole range (here: one port).
            let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = taken.local_addr().unwrap().port();
            let listener = bind_loopback(port, 1).await.unwrap();
            let address = listener.local_addr().unwrap();
            assert!(address.ip().is_loopback());
            assert_ne!(address.port(), port);
            assert_ne!(address.port(), 0);
            // A free range is used from its first port.
            drop(taken);
            let listener = bind_loopback(port, 1).await.unwrap();
            assert_eq!(listener.local_addr().unwrap().port(), port);
            // The top of the port numbers does not overflow.
            assert!(bind_loopback(u16::MAX, 100).await.is_ok());
        });
    }

    #[test]
    fn idle_connections_are_closed_and_never_more_than_the_limit_are_held() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const LIMIT: usize = 4;
        let head_timeout = Duration::from_millis(300);
        block_on(async {
            let app = Router::new().route("/ping", get(|| async { "pong" }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let slots = Arc::new(tokio::sync::Semaphore::new(LIMIT));
            tokio::spawn(serve(listener, app, Arc::clone(&slots), head_timeout));

            // Twenty clients connect and never send a request.
            let mut idle = Vec::new();
            for _ in 0..20 {
                idle.push(tokio::net::TcpStream::connect(address).await.unwrap());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(slots.available_permits(), 0, "only {LIMIT} are held");

            // A real request still gets its answer.
            let answer = tokio::time::timeout(Duration::from_secs(10), async {
                let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
                stream
                    .write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                let mut reply = String::new();
                stream.read_to_string(&mut reply).await.unwrap();
                reply
            })
            .await
            .expect("answered while idle connections wait");
            assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
            assert!(answer.ends_with("pong"), "{answer}");

            // Every idle client is hung up on.
            for mut stream in idle {
                let mut rest = Vec::new();
                tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest))
                    .await
                    .expect("an idle connection is closed")
                    .ok();
            }
            // One that sends half a request head fares no better.
            let mut slow = tokio::net::TcpStream::connect(address).await.unwrap();
            slow.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n")
                .await
                .unwrap();
            let mut rest = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), slow.read_to_end(&mut rest))
                .await
                .expect("a half-sent request is closed")
                .ok();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                slots.available_permits() >= LIMIT - 1,
                "slots are free again"
            );
        });
    }

    #[test]
    fn a_request_without_the_token_does_not_keep_its_connection() {
        use std::io::{Read, Write};
        let fx = fixture();
        let port = fx.coordinator.info().port;
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            stream,
            "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        )
        .unwrap();
        // Reading to the end only returns once the server has hung up.
        let mut reply = String::new();
        stream.read_to_string(&mut reply).expect("closed, not kept");
        assert!(reply.starts_with("HTTP/1.1 401"), "{reply}");
        assert!(reply.to_ascii_lowercase().contains("connection: close"));
        fx.coordinator.shutdown();
    }

    #[test]
    fn runtime_file_is_private_and_removed_at_shutdown() {
        let fx = fixture();
        let path = fx.workspace.runtime_path();
        let info = RuntimeInfo::read(&path).unwrap();
        assert_eq!(info, fx.coordinator.info());
        assert_eq!(info.pid, std::process::id());
        assert_ne!(info.port, 0);
        assert_eq!(info.token.len(), 64);
        assert!(info.token.chars().all(|c| c.is_ascii_hexdigit()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }
        fx.coordinator.shutdown();
        assert!(!path.exists());
        assert!(
            fx.workspace.graph_path().is_file(),
            "final graph.json is written"
        );
    }

    #[test]
    fn tokens_are_unique_and_compared_in_full() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_ne!(a, b);
        assert!(constant_time_eq(&a, &a.clone()));
        assert!(!constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &a[..63]));
        assert!(!constant_time_eq("", &a));
    }

    #[test]
    fn every_route_needs_the_token() {
        let fx = fixture();
        let info = fx.coordinator.info();
        for path in ["/api/state", "/", "/ws", "/map/tile/8/44/89"] {
            let (status, body) = request(&info, "GET", path, &[], None);
            if path == "/" {
                // The secret-free page a reload gets (see
                // `a_cookie_never_carries_or_grants_the_token`).
                assert_eq!(status, 200);
                assert!(!body.to_string().contains(&info.token));
            } else {
                assert_eq!(status, 401, "{path} without a token");
            }
            let (status, _) = request(&info, "GET", &format!("{path}?token=wrong"), &[], None);
            assert_eq!(status, 401, "{path} with a wrong token");
        }
        let (status, body) = request(
            &info,
            "POST",
            "/api/command",
            &[],
            Some(json!({ "cmd": "state" })),
        );
        assert_eq!((status, body["ok"].as_bool()), (401, Some(false)));

        let auth = bearer(&info);
        let (status, body) = request(
            &info,
            "GET",
            "/api/state",
            &[("Authorization", &auth)],
            None,
        );
        assert_eq!(status, 200);
        assert_eq!(body["session"], "acme");
        assert_eq!(body["mode"], "light");
        let (status, _) = request(
            &info,
            "GET",
            &format!("/api/state?token={}", info.token),
            &[],
            None,
        );
        assert_eq!(status, 200);
        let (status, _) = request(&info, "GET", &format!("/?token={}", info.token), &[], None);
        assert_eq!(status, 200);
    }

    #[test]
    fn map_page_and_assets_are_served_with_a_strict_content_policy() {
        let fx = fixture();
        let info = fx.coordinator.info();
        let fetch = |path: &str| {
            block_on(async {
                let client = reqwest::Client::builder().no_proxy().build().unwrap();
                let response = client
                    .get(format!("{}{path}", info.base_url()))
                    .send()
                    .await
                    .unwrap();
                let status = response.status().as_u16();
                let headers = response.headers().clone();
                (status, headers, response.text().await.unwrap())
            })
        };
        let (status, headers, page) = fetch(&format!("/?token={}", info.token));
        assert_eq!(status, 200);
        assert!(headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html"));
        assert!(page.contains(&format!("/assets/map.js?token={}", info.token)));
        let policy = headers["content-security-policy"].to_str().unwrap();
        assert!(policy.contains("script-src 'self';"), "{policy}");
        assert!(
            policy.contains(&format!("ws://127.0.0.1:{}", info.port)),
            "{policy}"
        );
        assert!(!policy.contains("unsafe-eval"), "{policy}");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["referrer-policy"], "no-referrer");

        for (asset, kind) in [
            ("map.js", "text/javascript"),
            ("map.css", "text/css"),
            ("cytoscape.min.js", "text/javascript"),
            ("icon-router.svg", "image/svg+xml"),
        ] {
            let (status, headers, body) = fetch(&format!("/assets/{asset}?token={}", info.token));
            assert_eq!(status, 200, "{asset}");
            assert!(
                headers["content-type"].to_str().unwrap().starts_with(kind),
                "{asset}"
            );
            assert!(!body.is_empty());
            // Assets are behind the token as well.
            assert_eq!(fetch(&format!("/assets/{asset}")).0, 401, "{asset}");
        }
        assert_eq!(
            fetch(&format!("/assets/secret.txt?token={}", info.token)).0,
            404
        );

        // The snapshot carries ready-made Cytoscape elements.
        let snapshot = fx.coordinator.state().snapshot();
        assert_eq!(snapshot["topology"]["nodes"][0]["data"]["id"], "local");
        // And the report on this machine that the map shows beside it.
        assert!(snapshot["machine"]["headline"].is_string());
        assert_eq!(snapshot["machine"]["sections"][0]["title"], "Open ports");
        assert_eq!(snapshot["machine"]["sections"][1]["title"], "Interfaces");
        assert!(snapshot["machine"]["vpn"].is_array());
        assert!(snapshot["topology"]["edges"].is_array());
    }

    #[test]
    fn foreign_hosts_and_origins_are_refused_even_with_the_token() {
        let fx = fixture();
        let info = fx.coordinator.info();
        let auth = bearer(&info);
        let own_origin = format!("http://127.0.0.1:{}", info.port);

        // DNS rebinding: the right token but a Host that is not loopback.
        let (status, body) = request(
            &info,
            "GET",
            "/api/state",
            &[("Authorization", &auth), ("Host", "evil.example:8765")],
            None,
        );
        assert_eq!(
            (status, body["error"].as_str()),
            (403, Some("unexpected Host header"))
        );

        // Cross-site request from a web page.
        for origin in ["https://evil.example", "http://127.0.0.1:1", "null"] {
            let (status, _) = request(
                &info,
                "POST",
                "/api/command",
                &[("Authorization", &auth), ("Origin", origin)],
                Some(json!({ "cmd": "state" })),
            );
            assert_eq!(status, 403, "origin {origin}");
        }
        let (status, _) = request(
            &info,
            "POST",
            "/api/command",
            &[("Authorization", &auth), ("Origin", &own_origin)],
            Some(json!({ "cmd": "state" })),
        );
        assert_eq!(status, 200);

        // A command meow does not know is refused: the verdict of 0.2.2
        // among them.
        for unknown in [
            json!({ "cmd": "verdict", "address": "192.0.2.5", "advisory": "CVE-2021-23017",
                    "status": "Confirmed" }),
            json!({ "cmd": "no_such_command" }),
        ] {
            let (status, _) = request(
                &info,
                "POST",
                "/api/command",
                &[("Authorization", &auth)],
                Some(unknown.clone()),
            );
            assert!((400..500).contains(&status), "{unknown}: {status}");
            assert!(serde_json::from_value::<Command>(unknown).is_err());
        }
    }

    #[test]
    fn websocket_upgrade_checks_origin_and_token() {
        let fx = fixture();
        let info = fx.coordinator.info();
        let connect = |origin: Option<&str>, token: &str| {
            let mut request = format!("ws://127.0.0.1:{}/ws?token={token}", info.port)
                .into_client_request()
                .unwrap();
            if let Some(origin) = origin {
                request
                    .headers_mut()
                    .insert("Origin", origin.parse().unwrap());
            }
            block_on(async { tokio_tungstenite::connect_async(request).await.map(|_| ()) })
        };
        // Cross-site WebSocket hijacking attempt: a page on another origin
        // that somehow knows the token is still refused.
        assert!(connect(Some("https://evil.example"), &info.token).is_err());
        assert!(connect(None, "wrong").is_err());
        assert!(connect(
            Some(&format!("http://localhost:{}", info.port)),
            &info.token
        )
        .is_ok());
        assert!(connect(None, &info.token).is_ok());
    }

    #[test]
    fn websocket_pushes_state_and_runs_commands() {
        let fx = fixture();
        let info = fx.coordinator.info();
        block_on(async {
            let url = format!("ws://127.0.0.1:{}/ws?token={}", info.port, info.token);
            let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
            let mut next = async || -> Value {
                loop {
                    let message = tokio::time::timeout(Duration::from_secs(10), socket.next())
                        .await
                        .expect("timed out waiting for the coordinator")
                        .unwrap()
                        .unwrap();
                    if let WsMessage::Text(text) = message {
                        return serde_json::from_str(&text).unwrap();
                    }
                }
            };
            // First who it is, then the state (v0.2.6 review MAP-1).
            let hello = next().await;
            assert_eq!(hello["type"], "hello");
            let first = next().await;
            assert_eq!(first["type"], "state");
            assert_eq!(first["state"]["graph"]["hosts"], json!({}));
            // Every push carries the key served in the map page, which is
            // how the page tells its session from whatever else may answer
            // on this port later. The key is in the page and nowhere else.
            let page_key = fx.coordinator.state().page_key.clone();
            assert_eq!(page_key.len(), 64);
            assert_ne!(page_key, info.token);
            assert_eq!(first["key"], json!(page_key));
            assert_eq!(hello, json!({ "type": "hello", "key": page_key }));
            assert!(!first["state"].to_string().contains(&page_key));
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let page = client
                .get(format!("{}/?token={}", info.base_url(), info.token))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(page.contains(&format!("<meta name=\"meow-page\" content=\"{page_key}\">")));
            let api = client
                .get(format!(
                    "{}/api/state?token={}",
                    info.base_url(),
                    info.token
                ))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(!api.contains(&page_key));

            // A change made elsewhere is pushed without being asked for.
            fx.coordinator
                .state()
                .execute(Command::Note {
                    address: None,
                    text: "scope is 10.0.0.0/24".into(),
                })
                .unwrap();
            let pushed = next().await;
            assert_eq!(pushed["type"], "state");
            assert_eq!(
                pushed["state"]["graph"]["notes"][0]["claim"],
                "scope is 10.0.0.0/24"
            );
            assert_eq!(
                pushed["state"]["graph"]["notes"][0]["source"],
                "manual_note"
            );
        });

        block_on(async {
            let url = format!("ws://127.0.0.1:{}/ws?token={}", info.port, info.token);
            let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
            socket.next().await.unwrap().unwrap(); // initial state
            socket
                .send(WsMessage::Text(
                    r#"{"cmd":"set_mode","mode":"mild"}"#.into(),
                ))
                .await
                .unwrap();
            socket
                .send(WsMessage::Text("not json".into()))
                .await
                .unwrap();
            let mut results = Vec::new();
            while results.len() < 2 {
                let WsMessage::Text(text) = socket.next().await.unwrap().unwrap() else {
                    continue;
                };
                let value: Value = serde_json::from_str(&text).unwrap();
                if value["type"] == "result" {
                    results.push(value);
                }
            }
            assert_eq!(results[0]["ok"], true);
            assert_eq!(results[1]["ok"], false);
        });
        assert_eq!(fx.coordinator.state().mode(), Mode::Mild);
        let profile = std::fs::read_to_string(fx.workspace.profile_path()).unwrap();
        assert!(profile.contains("mode = \"mild\""), "{profile}");
    }

    #[test]
    fn helpers_reach_a_live_session_and_fall_back_when_there_is_none() {
        let mut fx = fixture();
        let result = ipc::send(
            &fx.workspace,
            &Command::SetMode {
                mode: Mode::Aggressive,
            },
        )
        .unwrap()
        .expect("the coordinator is live");
        assert_eq!(result["mode"], "aggressive");
        assert_eq!(fx.coordinator.state().mode(), Mode::Aggressive);

        // Errors from the coordinator come back as errors, not as "offline".
        let error = ipc::send(
            &fx.workspace,
            &Command::Ai {
                tier: Tier::Local,
                address: "10.0.0.5".into(),
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("unknown host"), "{error:#}");

        let workspace = fx.workspace.clone();
        fx.coordinator.shutdown();
        drop(fx.lock.take());
        assert_eq!(ipc::send(&workspace, &Command::State).unwrap(), None);

        // A stale runtime.json (crashed session) also means "offline".
        std::fs::write(
            workspace.runtime_path(),
            r#"{"pid":1,"port":9,"token":"x"}"#,
        )
        .unwrap();
        assert_eq!(ipc::send(&workspace, &Command::State).unwrap(), None);
    }

    #[test]
    fn an_import_only_claims_names_and_a_full_graph_says_so_at_once() {
        let fx = fixture();
        let state = fx.coordinator.state();
        let name = |address: &str, hostname: &str, confidence| Observation::Hostname {
            address: address.into(),
            hostname: hostname.into(),
            record: EvidenceRecord::observed(Source::NmapXml, confidence, "x"),
        };
        state
            .graph()
            .apply(name("192.0.2.10", "portal.example", Confidence::High));
        // `meow add` is never this session's scan, whatever its records say.
        state
            .execute(Command::Observations {
                items: vec![name("198.51.100.66", "portal.example", Confidence::High)],
                ground: false,
            })
            .unwrap();
        let graph = state.graph().clone();
        assert!(graph.hosts["192.0.2.10"]
            .hostnames
            .contains("portal.example"));
        assert!(graph.hosts["198.51.100.66"].hostnames.is_empty());

        // Fill the graph with hosts; the one after them is refused, which
        // changes nothing, and is told at once.
        let host = |n: usize| Observation::Host {
            address: format!("10.{}.{}.{}", n >> 16, (n >> 8) & 255, n & 255),
            os: None,
            mac: None,
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "up"),
        };
        let room = 4096 - state.graph().hosts.len();
        let result = state
            .execute(Command::Observations {
                items: (0..room).map(host).collect(),
                ground: false,
            })
            .unwrap();
        assert_eq!(result["full"], false);
        let full_notice = |state: &State| {
            lock(&state.notices)
                .iter()
                .any(|n| n.text.contains("graph is full"))
        };
        assert!(!full_notice(&state));
        let result = state
            .execute(Command::Observations {
                items: vec![host(room)],
                ground: false,
            })
            .unwrap();
        assert_eq!(
            (result["changed"].as_u64(), result["full"].as_bool()),
            (Some(0), Some(true))
        );
        assert!(full_notice(&state), "no notice for a full graph");
        let refused = state
            .execute(Command::Note {
                address: Some("192.0.2.10".into()),
                text: "check later".into(),
            })
            .unwrap_err();
        assert!(
            format!("{refused:#}").contains("graph is full"),
            "{refused:#}"
        );
    }

    /// v0.2.6 review MAP-1: sockets that ask for the state while one is
    /// being made share it; one that asks after a change gets a new one.
    #[test]
    fn sockets_asking_for_the_state_at_once_share_one() {
        let fx = fixture();
        let state = fx.coordinator.state();
        let text = |message: Option<Message>| match message {
            Some(Message::Text(text)) => text,
            other => panic!("{other:?}"),
        };
        state.handle.clone().block_on(async {
            let making = state.state_made.lock().await;
            let asks: Vec<_> = (0..4)
                .map(|_| {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move { state_message(&state).await })
                })
                .collect();
            while state.state_asks.load(Ordering::SeqCst) < 4 {
                tokio::task::yield_now().await;
            }
            drop(making);
            let mut made = Vec::new();
            for ask in asks {
                made.push(text(ask.await.unwrap()));
            }
            let first = made[0].as_str().as_ptr();
            assert!(
                made.iter().all(|text| text.as_str().as_ptr() == first),
                "made more than once"
            );
            assert!(!made[0].contains("192.0.2.77"));
            state
                .execute(Command::Observations {
                    items: vec![Observation::Host {
                        address: "192.0.2.77".into(),
                        os: None,
                        mac: None,
                        record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "up"),
                    }],
                    ground: false,
                })
                .unwrap();
            let later = text(state_message(&state).await);
            assert_ne!(later.as_str().as_ptr(), first);
            assert!(later.contains("192.0.2.77"));
            let value: Value = serde_json::from_str(&later).unwrap();
            assert_eq!(value["type"], "state");
            assert_eq!(value["key"], json!(state.page_key));
        });
    }

    #[test]
    fn imported_observations_and_cves_reach_the_map_and_the_graph_file() {
        let fx = fixture();
        let state = fx.coordinator.state();
        let items = crate::parsers::nmap::parse(crate::parsers::nmap::SAMPLE, false).unwrap();
        let result = state
            .execute(Command::Observations {
                items,
                ground: true,
            })
            .unwrap();
        assert_eq!(result["hosts"], 2);
        assert_eq!(
            result["grounding"], false,
            "CVE lookups are disabled in this fixture"
        );
        assert!(result["changed"].as_u64().unwrap() > 5);

        let cve = |id: &str, kev: bool, cvss: f64, fixed_in: Option<&str>| crate::graph::Advisory {
            fixed_in: fixed_in.map(Into::into),
            last_affected: None,
            id: id.into(),
            title: format!("about {id}"),
            severity: None,
            cvss: Some(cvss),
            kev,
            matched: "cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*".into(),
            port: Some("443/tcp".into()),
            references: vec![],
            record: EvidenceRecord::observed(Source::NvdApi, Confidence::Medium, "{}"),
        };
        state
            .graph()
            .add_advisory("10.0.0.5", cve("CVE-2021-3618", false, 7.4, Some("1.21.0")));
        state
            .graph()
            .add_advisory("10.0.0.5", cve("CVE-2021-23017", true, 7.7, Some("1.20.1")));
        state
            .graph()
            .add_advisory("10.0.0.5", cve("CVE-2009-3896", false, 5.0, None));

        // The map gets them by software and version, the most urgent first.
        let snapshot = state.snapshot();
        assert!(snapshot.get("checklists").is_none());
        let groups = snapshot["cves"]["10.0.0.5"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["software"], "nginx 1.18.0");
        assert_eq!(groups[0]["port"], "443/tcp");
        assert_eq!(groups[0]["fix"], "fixed in 1.21.0");
        assert_eq!(groups[0]["kev"], 1);
        // The nginx banner names Ubuntu, which may have the fix already.
        assert_eq!(
            groups[0]["note"],
            crate::osint::distro_backport_note("ubuntu").unwrap()
        );
        assert_eq!(snapshot["cve_lookups"], false);
        let listed: Vec<(&str, &str, bool)> = groups[0]["cves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["id"].as_str().unwrap(),
                    c["severity"].as_str().unwrap(),
                    c["serious"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            listed,
            [
                ("CVE-2021-23017", "High 7.7", true),
                ("CVE-2021-3618", "High 7.4", true),
                ("CVE-2009-3896", "Medium 5.0", false),
            ]
        );
        assert!(snapshot["cves"].get("10.0.0.9").is_none());
        let node = snapshot["topology"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["data"]["id"] == "host:10.0.0.5")
            .unwrap();
        assert_eq!(node["data"]["cves"], 3);
        assert_eq!(node["data"]["serious_cves"], 2);
        assert_eq!(node["data"]["kev"], 1);

        // Records sent over IPC by meow 0.2.2 still parse.
        let old_cmd: Command = serde_json::from_value(json!({
            "cmd": "observations",
            "ground": false,
            "items": [{
                "kind": "http",
                "address": "192.0.2.44",
                "port": 8080,
                "scheme": "http",
                "server": "Apache/2.4.49",
                "location": null,
                "record": {
                    "source": "http_header",
                    "timestamp_utc": "2026-11-12T00:00:00Z",
                    "confidence": "High",
                    "evidence": "Server: Apache/2.4.49",
                    "verification_status": "Confirmed"
                }
            }]
        }))
        .unwrap();
        state.execute(old_cmd).unwrap();
        assert_eq!(
            state.graph().hosts["192.0.2.44"].ports["8080/tcp"].facts[0]
                .record
                .source,
            Source::HttpHeader
        );

        let path = fx.workspace.graph_path();
        fx.coordinator.shutdown();
        let saved = Graph::load(&path).unwrap();
        assert_eq!(saved.hosts["10.0.0.5"].advisories.len(), 3);
    }

    #[test]
    fn terminal_lines_from_the_tap_feed_the_graph() {
        let fx = fixture();
        let mut sink = fx.coordinator.tap_sink();
        for line in [
            "Nmap scan report for app.lab.local (10.0.0.5)",
            "22/tcp   open  ssh     OpenSSH 8.2p1",
            "$ curl -sI http://10.0.0.5:8080/portal/",
            "Server: nginx/1.18.0",
        ] {
            sink(line);
        }
        let state = fx.coordinator.state();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let done = state.graph().host("10.0.0.5").is_some_and(|h| {
                h.ports.contains_key("8080/tcp")
                    && h.ports["8080/tcp"]
                        .http
                        .as_ref()
                        .is_some_and(|x| x.server.is_some())
            });
            if done {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "tap lines never reached the graph"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let graph = state.graph();
        let host = graph.host("app.lab.local").unwrap();
        assert_eq!(
            host.ports["22/tcp"].facts[0].record.source,
            Source::PtyRegex
        );
    }

    /// Shuts the coordinator down on another thread; `None` if that took
    /// longer than `limit`.
    fn shutdown_within(
        coordinator: Coordinator,
        limit: Duration,
    ) -> Option<(Vec<&'static str>, Duration)> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let skipped = coordinator.shutdown();
            let _ = done_tx.send((skipped, started.elapsed()));
        });
        done_rx.recv_timeout(limit).ok()
    }

    /// A task the runtime had to leave behind (as the waf-cdn deadlock did)
    /// can hold the database and the graph for good: leaving the session
    /// still ends in time, saying what it skipped.
    #[test]
    fn leaving_does_not_wait_for_ever_on_a_lock_a_stuck_task_holds() {
        let fx = fixture();
        let state = fx.coordinator.state();
        state.mark_dirty();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let holder = Arc::clone(&state);
        std::thread::spawn(move || {
            let _db = holder.db_lock();
            let _graph = holder.graph();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        held_rx.recv().unwrap();

        let (skipped, took) = shutdown_within(fx.coordinator, STOP_LIMIT + Duration::from_secs(2))
            .expect("leaving the session waited for ever on a stuck lock");
        assert_eq!(skipped, ["saving graph.json"]);
        assert!(took < STOP_LIMIT, "{took:?}");
        // The session's runtime record is gone all the same.
        assert!(!fx.workspace.runtime_path().exists());
        drop(release_tx);
    }

    /// A tap sink that outlives the session (the PTY's tap thread when a
    /// background job still holds the terminal) no longer delays leaving.
    #[test]
    fn a_tap_sink_left_alive_does_not_delay_leaving() {
        let fx = fixture();
        let mut sink = fx.coordinator.tap_sink();
        sink("22/tcp   open  ssh     OpenSSH 8.2p1");
        let (skipped, took) =
            shutdown_within(fx.coordinator, STOP_LIMIT).expect("leaving the session took too long");
        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(took < STOP_STEP, "{took:?}");
        // Lines after that go nowhere, without an error.
        sink("80/tcp   open  http    nginx 1.18.0");
    }

    /// How far a running stage is goes out with the state, beside the
    /// stage's times and the session's clock, and is never stored.
    #[test]
    fn a_running_stage_carries_its_progress_in_the_state() {
        use queue::{Progress, Stage};
        let fx = fixture();
        let state = fx.coordinator.state();
        let id = {
            let db = state.db_lock();
            let id = queue::enqueue(&db, "192.0.2.5", Mode::Mild, &[]).unwrap();
            queue::set_stage(&db, id, Stage::Lan, "running", "").unwrap();
            queue::set_stage(&db, id, Stage::Lan, "done", "3 neighbours").unwrap();
            queue::set_stage(&db, id, Stage::Ports, "running", "").unwrap();
            id
        };
        let stage = |name: &str| -> Value {
            let snapshot = state.snapshot();
            assert_eq!(snapshot["tasks"][0]["id"], id);
            let stages = snapshot["tasks"][0]["stages"].as_array().unwrap();
            assert_eq!(stages.len(), queue::STAGES.len());
            stages.iter().find(|s| s["stage"] == name).unwrap().clone()
        };
        let is_time = |value: &Value| {
            value
                .as_str()
                .is_some_and(|text| crate::timeutil::parse_rfc3339(text).is_some())
        };
        // The session's clock, and each stage's times where it has them.
        assert!(is_time(&state.snapshot()["now_utc"]));
        let lan = stage("lan");
        assert!(is_time(&lan["started_utc"]) && is_time(&lan["finished_utc"]));
        assert_eq!(
            stage("services"),
            json!({ "stage": "services", "status": "pending", "detail": "" })
        );
        let ports = stage("ports");
        assert!(is_time(&ports["started_utc"]), "{ports}");
        let keys: Vec<&String> = ports.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["detail", "stage", "started_utc", "status"]);

        // What a tool reports is bounded and cleaned before it is kept.
        state.set_progress(
            id,
            Stage::Ports,
            Progress {
                percent: Some(250),
                eta_s: Some(u64::MAX),
                note: Some(format!("\u{1b}[31mSYN\u{7} scan {}", "A".repeat(500))),
                ..Progress::default()
            },
        );
        let progress = stage("ports")["progress"].clone();
        assert_eq!(progress["percent"], 100);
        assert_eq!(progress["eta_s"], 7 * 24 * 3600);
        let note = progress["note"].as_str().unwrap();
        assert!(note.starts_with("[31mSYN scan AAAA"), "{note}");
        assert_eq!(note.len(), queue::PROGRESS_NOTE_MAX);
        let keys: Vec<&String> = progress.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["eta_s", "note", "percent"]);
        // Items, as meow's own probes count them.
        state.set_progress(id, Stage::Ports, Progress::items(3, 9));
        assert_eq!(stage("ports")["progress"], json!({ "done": 3, "total": 9 }));

        // Only a running stage is on its way, whatever was said of another.
        state.set_progress(id, Stage::Services, Progress::items(1, 2));
        state.set_progress(id + 1, Stage::Ports, Progress::items(1, 2));
        assert!(stage("services").get("progress").is_none());
        assert!(stage("lan").get("progress").is_none());
        // Nothing to say is nothing kept.
        state.set_progress(id, Stage::Ports, Progress::default());
        assert!(stage("ports").get("progress").is_none());
        assert!(!lock(&state.progress).contains_key(&(id, Stage::Ports)));

        // The stage ends: its progress is not shown, and is gone before
        // the stage runs again.
        state.set_progress(id, Stage::Ports, Progress::items(8, 9));
        queue::set_stage(&state.db_lock(), id, Stage::Ports, "done", "3 open").unwrap();
        let ports = stage("ports");
        assert!(ports.get("progress").is_none(), "{ports}");
        assert!(is_time(&ports["finished_utc"]));
        state.clear_progress(id, Stage::Ports);
        queue::set_stage(&state.db_lock(), id, Stage::Ports, "running", "").unwrap();
        let ports = stage("ports");
        assert!(ports.get("progress").is_none() && ports.get("finished_utc").is_none());
        // The database never holds any of it.
        let stored = queue::task(&state.db_lock(), id).unwrap().unwrap();
        assert!(stored.stages.iter().all(|s| s.progress.is_none()));
        fx.coordinator.shutdown();
    }

    /// A workspace whose database holds recons, as a killed session, a
    /// stale copy or someone else's files would: a new session.
    fn session_over(
        tmp: &tempfile::TempDir,
        mode: Mode,
        plant: impl FnOnce(&crate::db::Db),
    ) -> (SessionLock, Coordinator) {
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (mut workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        workspace.set_mode(mode).unwrap();
        plant(&crate::db::Db::open(&workspace.state_db_path()).unwrap());
        let lock = SessionLock::acquire(&workspace.lock_path()).unwrap();
        let mut config = Config::default();
        config.cve.enabled = false;
        // Were a stage ever to start, it would say so and send nothing.
        config.recon.skip = queue::STAGES
            .iter()
            .map(|stage| stage.as_str().to_owned())
            .collect();
        (lock, Coordinator::start(workspace, config).unwrap())
    }

    /// A queue that is in the database when a session starts never runs:
    /// not by itself, and not when the mode is set. Its stages are marked
    /// as the end of a session marks them, and the user is told once.
    #[test]
    fn a_session_never_runs_what_it_did_not_queue() {
        use queue::Stage;
        for mode in [Mode::Mild, Mode::Aggressive] {
            let tmp = tempfile::tempdir().unwrap();
            let mut ids = (0, 0, 0, 0);
            let (held, coordinator) = session_over(&tmp, mode, |db| {
                // Waiting whole; cut while a stage ran; stopped by light mode
                // before and after its stage started.
                ids.0 = queue::enqueue(db, "192.0.2.5", mode, &[]).unwrap();
                ids.1 = queue::enqueue(db, "192.0.2.6", mode, &[]).unwrap();
                queue::set_stage(db, ids.1, Stage::Lan, "done", "3 neighbours").unwrap();
                queue::set_stage(db, ids.1, Stage::Dns, "running", "").unwrap();
                ids.2 = queue::enqueue(db, "192.0.2.7", mode, &[]).unwrap();
                queue::set_stage(db, ids.2, Stage::Lan, "interrupted", queue::LIGHT_DETAIL)
                    .unwrap();
                ids.3 = queue::enqueue(db, "192.0.2.8", mode, &[]).unwrap();
                queue::set_stage(db, ids.3, Stage::Lan, "running", "").unwrap();
                queue::set_stage(db, ids.3, Stage::Lan, "interrupted", queue::LIGHT_DETAIL)
                    .unwrap();
            });
            let state = coordinator.state();
            let rows = |id: i64| -> Vec<(String, String)> {
                queue::task(&state.db_lock(), id)
                    .unwrap()
                    .unwrap()
                    .stages
                    .into_iter()
                    .map(|stage| (stage.status, stage.detail))
                    .collect()
            };
            let not_run = ("skipped".to_owned(), queue::NOT_RUN_ENDED.to_owned());
            let found = [rows(ids.0), rows(ids.1), rows(ids.2), rows(ids.3)];
            assert!(found[0].iter().all(|row| *row == not_run), "{found:?}");
            assert_eq!(
                found[1][..2],
                [
                    ("done".to_owned(), "3 neighbours".to_owned()),
                    ("interrupted".to_owned(), queue::CLOSED_DETAIL.to_owned())
                ]
            );
            assert!(found[1][2..].iter().all(|row| *row == not_run));
            assert!(found[2].iter().all(|row| *row == not_run), "{found:?}");
            assert_eq!(
                found[3][0],
                ("interrupted".to_owned(), queue::CLOSED_DETAIL.to_owned())
            );
            assert!(found[3][1..].iter().all(|row| *row == not_run));
            for id in [ids.0, ids.1, ids.2, ids.3] {
                assert!(!state.owns_recon(id));
            }

            // Told once, as plain lines.
            let (left, more) = coordinator.left_recons();
            assert_eq!(
                left.iter().map(|task| task.id).collect::<Vec<_>>(),
                [ids.0, ids.1, ids.2, ids.3]
            );
            assert_eq!(more, 0);
            assert!(left[1]
                .left_line(true)
                .starts_with("Recon 192.0.2.6 cut short at dns \u{b7} "));
            assert!(left[3]
                .left_line(true)
                .starts_with("Recon 192.0.2.8 cut short at lan \u{b7} "));

            // Nothing runs, whatever the mode is set to, and not even a
            // row that is put back to waiting behind the session's back.
            state
                .db_lock()
                .conn()
                .execute(
                    "UPDATE task_stages SET status = 'pending', detail = '' WHERE task_id = ?1",
                    [ids.0],
                )
                .unwrap();
            for set in [Mode::Light, Mode::Mild, Mode::Aggressive, mode] {
                let result = state.execute(Command::SetMode { mode: set }).unwrap();
                assert_eq!(result["resumed"], 0, "{set}");
            }
            assert!(state.unfinished_recons().unwrap().is_empty());
            state.recon_queue.send(ids.0).unwrap();
            state.recon_queue.send(ids.1).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            assert!(rows(ids.0).iter().all(|row| row.0 == "pending"));
            assert_eq!(rows(ids.1), found[1]);
            assert_eq!(rows(ids.2), found[2]);
            assert_eq!(rows(ids.3), found[3]);
            assert!(
                !lock(&state.notices)
                    .iter()
                    .any(|notice| notice.text.contains("started")),
                "{:?}",
                lock(&state.notices)
            );

            // What this session queues is its own.
            let own = state
                .execute(Command::Recon {
                    target: "192.0.2.9".to_owned(),
                    flags: Vec::new(),
                })
                .unwrap();
            assert_eq!(own["ahead"], 0, "nothing of before is ahead of it");
            let own = own["task"].as_i64().unwrap();
            assert!(state.owns_recon(own));
            // (Every stage is turned off here: it is over in a moment.)
            let deadline = Instant::now() + Duration::from_secs(20);
            while queue::task(&state.db_lock(), own)
                .unwrap()
                .unwrap()
                .unfinished()
            {
                assert!(
                    Instant::now() < deadline,
                    "the session's own recon did not run"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            coordinator.shutdown();
            drop(held);

            // The next start says nothing of them again, and still runs none.
            let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
            let (workspace, _) =
                Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
            let _lock = SessionLock::acquire(&workspace.lock_path()).unwrap();
            let mut config = Config::default();
            config.cve.enabled = false;
            let again = Coordinator::start(workspace, config).unwrap();
            let (left, more) = again.left_recons();
            assert!(
                left.iter().all(|task| task.id == ids.0) && more == 0,
                "only the row that was put back: {left:?}"
            );
            assert!(again.state().unfinished_recons().unwrap().is_empty());
            again.shutdown();
        }
    }

    /// A session that is closed ends its recons, and whoever watches is
    /// not left with a stage that looks as if it will go on.
    #[test]
    fn closing_a_session_ends_its_recons_and_the_next_start_says_so_once() {
        use queue::Stage;
        let tmp = tempfile::tempdir().unwrap();
        let (held, coordinator) = session_over(&tmp, Mode::Mild, |_| {});
        assert_eq!(coordinator.left_recons(), (&[][..], 0));
        let state = coordinator.state();
        let id = {
            let db = state.db_lock();
            let id = queue::enqueue(&db, "192.0.2.5", Mode::Mild, &[]).unwrap();
            queue::set_stage(&db, id, Stage::Lan, "done", "3 neighbours").unwrap();
            queue::set_stage(&db, id, Stage::Dns, "running", "").unwrap();
            id
        };
        assert!(state.owns_recon(id));
        coordinator.shutdown();
        let stored = queue::task(&state.db_lock(), id).unwrap().unwrap();
        let said: Vec<(&str, &str)> = stored
            .stages
            .iter()
            .map(|stage| (stage.status.as_str(), stage.detail.as_str()))
            .collect();
        assert_eq!(
            said[..3],
            [
                ("done", "3 neighbours"),
                ("interrupted", "stopped: the session was closed"),
                ("skipped", "not run: the session was closed")
            ]
        );
        assert!(said[2..].iter().all(|row| *row == said[2]), "{said:?}");
        drop(state);
        drop(held);

        let (held, second) = session_over(&tmp, Mode::Mild, |_| {});
        let (left, more) = second.left_recons();
        assert_eq!((left, more), (std::slice::from_ref(&stored), 0));
        // Shown as it was left: done, stopped, the rest left out.
        let shown = second.state().snapshot();
        let statuses: Vec<&str> = shown["tasks"][0]["stages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|stage| stage["status"].as_str().unwrap())
            .collect();
        assert_eq!(statuses[..3], ["done", "interrupted", "skipped"]);
        assert!(!second.state().owns_recon(id));
        second.shutdown();
        drop(held);

        let (_lock, third) = session_over(&tmp, Mode::Mild, |_| {});
        assert_eq!(third.left_recons(), (&[][..], 0));
        assert_eq!(
            queue::task(&third.state().db_lock(), id).unwrap().unwrap(),
            stored
        );
        third.shutdown();
    }

    /// The time left is the time left when the state is made, not when
    /// the tool last said it.
    #[test]
    fn the_time_left_runs_out_between_two_reports() {
        use queue::Progress;
        let at = Instant::now();
        let said = Reported {
            progress: Progress {
                percent: Some(40),
                eta_s: Some(44),
                note: Some("SYN Stealth Scan".to_owned()),
                ..Progress::default()
            },
            at,
        };
        let later = |secs: u64| said.as_of(at + Duration::from_secs(secs));
        assert_eq!(later(0), said.progress);
        assert_eq!(later(4).eta_s, Some(40));
        assert_eq!(later(43).eta_s, Some(1));
        // Run out: no longer known, never below nothing. The rest stays.
        let unknown = Progress {
            eta_s: None,
            ..said.progress.clone()
        };
        for secs in [44, 45, 3600] {
            assert_eq!(later(secs), unknown, "{secs}");
        }
        // A reading from before it was said changes nothing.
        if let Some(earlier) = at.checked_sub(Duration::from_secs(5)) {
            assert_eq!(said.as_of(earlier), said.progress);
        }
        // Nothing to count down: as it was said.
        let items = Reported {
            progress: Progress::items(3, 9),
            at,
        };
        assert_eq!(
            items.as_of(at + Duration::from_secs(60)),
            Progress::items(3, 9)
        );
    }

    /// A change of progress is pushed at once, further ones about a second
    /// later in one push, and none while nothing changes. Only the progress
    /// is pushed: the state is not sent again for it.
    #[test]
    fn progress_is_pushed_when_it_changes_and_at_most_once_a_second() {
        use queue::{Progress, Stage};
        let fx = fixture();
        let state = fx.coordinator.state();
        let revision = || *state.progress_revision.borrow();
        let changed_within = |from: u64, limit: Duration| {
            let deadline = Instant::now() + limit;
            while revision() == from && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            revision() != from
        };
        // What starting the session itself pushes is over.
        let state_revision = || *state.revision.borrow();
        let mut whole = state_revision();
        loop {
            std::thread::sleep(Duration::from_millis(400));
            if state_revision() == whole {
                break;
            }
            whole = state_revision();
        }
        let quiet = revision();
        assert_eq!(quiet, 0, "nothing has said how far it is");

        state.set_progress(1, Stage::Ports, Progress::items(1, 50));
        assert!(changed_within(quiet, Duration::from_secs(5)), "not pushed");
        let pushed = Instant::now();
        let first = revision();
        assert_eq!(first, quiet + 1);
        for done in 2..=20 {
            state.set_progress(1, Stage::Ports, Progress::items(done, 50));
        }
        if pushed.elapsed() < PROGRESS_EVERY / 2 {
            assert_eq!(revision(), first, "pushed again at once");
        }
        assert!(changed_within(first, Duration::from_secs(5)), "not pushed");
        assert!(
            pushed.elapsed() >= PROGRESS_EVERY * 4 / 5,
            "{:?}",
            pushed.elapsed()
        );
        assert_eq!(revision(), first + 1, "one push for all of them");

        // The same again is no change: nothing is pushed.
        state.set_progress(1, Stage::Ports, Progress::items(20, 50));
        assert!(!changed_within(
            first + 1,
            PROGRESS_EVERY + Duration::from_millis(300)
        ));
        assert_eq!(state_revision(), whole, "the state was not sent again");
        assert_eq!(
            state.progress_snapshot()["running"],
            json!([{ "task": 1, "stage": "ports", "progress": { "done": 20, "total": 50 } }])
        );
        fx.coordinator.shutdown();
    }

    /// What a client is sent while a stage counts its results: a small
    /// message with the progress alone, never the whole state.
    #[test]
    fn a_progress_tick_is_a_small_message_and_not_the_state() {
        use queue::{Progress, Stage};
        let fx = fixture();
        let info = fx.coordinator.info();
        let state = fx.coordinator.state();
        let id = {
            let db = state.db_lock();
            let id = queue::enqueue(&db, "192.0.2.5", Mode::Mild, &[]).unwrap();
            queue::set_stage(&db, id, Stage::Ports, "running", "").unwrap();
            id
        };
        block_on(async {
            let url = format!("ws://127.0.0.1:{}/ws?token={}", info.port, info.token);
            let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
            let mut next = async |limit: Duration| -> Option<(Value, usize)> {
                loop {
                    let message = tokio::time::timeout(limit, socket.next()).await.ok()?;
                    if let WsMessage::Text(text) = message.unwrap().unwrap() {
                        return Some((serde_json::from_str(&text).unwrap(), text.len()));
                    }
                }
            };
            let patient = Duration::from_secs(10);
            let (hello, _) = next(patient).await.unwrap();
            assert_eq!(hello["type"], "hello");
            let (first, whole) = next(patient).await.unwrap();
            assert_eq!(first["type"], "state");
            // Whatever starting the session still pushes is over.
            while next(Duration::from_millis(900)).await.is_some() {}

            let said = Progress {
                percent: Some(42),
                eta_s: Some(90),
                note: Some("SYN Stealth Scan".to_owned()),
                ..Progress::default()
            };
            state.set_progress(id, Stage::Ports, said);
            let (tick, size) = next(patient).await.unwrap();
            assert_eq!(tick["type"], "progress");
            assert_eq!(tick["key"], json!(state.page_key));
            let now = tick["now_utc"].as_str().unwrap_or_default();
            assert!(crate::timeutil::parse_rfc3339(now).is_some(), "{tick}");
            let running = tick["running"].as_array().unwrap();
            assert_eq!(running.len(), 1, "{tick}");
            assert_eq!(
                (&running[0]["task"], &running[0]["stage"]),
                (&json!(id), &json!("ports"))
            );
            assert_eq!(running[0]["progress"]["percent"], 42);
            assert_eq!(running[0]["progress"]["note"], "SYN Stealth Scan");
            assert!(running[0]["progress"]["eta_s"].as_u64().unwrap() <= 90);
            assert!(tick.get("state").is_none() && tick.get("graph").is_none());
            assert!(size < 400 && size < whole, "{size} of {whole} bytes");

            // More of it: progress messages only, at most one a second.
            for done in 43..=60 {
                let more = Progress {
                    percent: Some(done),
                    ..Progress::default()
                };
                state.set_progress(id, Stage::Ports, more);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let mut ticks = 0;
            while let Some((message, _)) = next(Duration::from_millis(1500)).await {
                assert_eq!(message["type"], "progress", "{message}");
                ticks += 1;
            }
            assert!((1..=3).contains(&ticks), "{ticks} messages in 1.8 s");

            // The stage ends: that is a change of the state, which no
            // longer says how far the stage was; neither does a tick.
            queue::set_stage(&state.db_lock(), id, Stage::Ports, "done", "2 open ports").unwrap();
            state.clear_progress(id, Stage::Ports);
            state.touch();
            let (ended, _) = next(patient).await.unwrap();
            assert_eq!(ended["type"], "state");
            let at = queue::STAGES.iter().position(|s| *s == Stage::Ports);
            let ports = &ended["state"]["tasks"][0]["stages"][at.unwrap()];
            assert_eq!(
                (&ports["stage"], &ports["status"]),
                (&json!("ports"), &json!("done"))
            );
            assert!(ports.get("progress").is_none());
            assert_eq!(state.progress_snapshot()["running"], json!([]));
        });
        fx.coordinator.shutdown();
    }

    /// The state carries every recon of this session that has work to do,
    /// however many were queued after it: they run oldest first, so the
    /// newest alone would leave out the one that is running.
    #[test]
    fn the_state_carries_every_unfinished_recon_and_the_newest_of_the_rest() {
        let fx = fixture();
        let state = fx.coordinator.state();
        let ids: Vec<i64> = {
            let db = state.db_lock();
            (0..SHOWN_TASKS + 6)
                .map(|n| queue::enqueue(&db, &format!("192.0.2.{n}"), Mode::Mild, &[]).unwrap())
                .collect()
        };
        let shown = |state: &State| -> Vec<i64> {
            state.snapshot()["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|task| task["id"].as_i64().unwrap())
                .collect()
        };
        let newest_first = |ids: &[i64]| ids.iter().rev().copied().collect::<Vec<_>>();
        // All of them wait: all of them are there, the first one too.
        assert_eq!(shown(&state), newest_first(&ids));
        {
            let db = state.db_lock();
            queue::set_stage(&db, ids[0], queue::Stage::Lan, "running", "").unwrap();
        }
        let first = state.snapshot()["tasks"][ids.len() - 1].clone();
        assert_eq!(
            (&first["id"], &first["stages"][0]["status"]),
            (&json!(ids[0]), &json!("running"))
        );
        // Finished ones fill what room is left, the newest of them.
        let finish = |id: i64| {
            let db = state.db_lock();
            for stage in queue::STAGES {
                queue::set_stage(&db, id, stage, "done", "").unwrap();
            }
        };
        let (done, waiting) = ids.split_at(ids.len() - 4);
        for id in done.iter().skip(1) {
            finish(*id);
        }
        let mut expected = newest_first(waiting);
        expected.extend(newest_first(done).into_iter().take(SHOWN_TASKS - 5));
        expected.push(ids[0]);
        assert_eq!(shown(&state), expected);
        // With nothing left to do: the newest.
        finish(ids[0]);
        for id in waiting {
            finish(*id);
        }
        assert_eq!(shown(&state), newest_first(&ids)[..SHOWN_TASKS]);
        fx.coordinator.shutdown();
    }

    /// Leaving ends the scanners before anything else: the whole tree of
    /// a running tool is gone, its stage is marked stopped, what was
    /// finished stays as it is and what had not started is left out.
    #[cfg(unix)]
    #[test]
    fn leaving_kills_what_recon_started_and_keeps_what_is_done() {
        use crate::procs::tests::{started, tool, wait_gone};
        use queue::Stage;
        let fx = fixture();
        let state = fx.coordinator.state();
        let id = {
            let db = state.db_lock();
            let id = queue::enqueue(&db, "192.0.2.5", Mode::Mild, &[]).unwrap();
            queue::set_stage(&db, id, Stage::Lan, "done", "3 neighbours").unwrap();
            queue::set_stage(&db, id, Stage::Dns, "failed", "no answer").unwrap();
            queue::set_stage(&db, id, Stage::Ports, "running", "").unwrap();
            id
        };
        state.set_progress(id, Stage::Ports, queue::Progress::items(1, 2));
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let (mut child, group) = state
            .tools()
            .spawn_std(&mut tool(dir.path(), &pids))
            .unwrap();
        let ids = started(&pids);
        assert!(!state.is_closing());

        let (skipped, took) =
            shutdown_within(fx.coordinator, STOP_LIMIT).expect("leaving the session took too long");
        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(took < STOP_STEP, "{took:?}");
        assert!(state.is_closing());
        let _ = child.wait();
        for pid in ids {
            wait_gone(pid);
        }
        drop(group);
        // Nothing new starts in a session that is over.
        assert!(state
            .tools()
            .spawn_std(&mut tool(dir.path(), &pids))
            .is_err());

        let task = queue::task(&state.db_lock(), id).unwrap().unwrap();
        let of = |stage: Stage| task.stages.iter().find(|s| s.stage == stage).unwrap();
        assert_eq!(
            (
                of(Stage::Lan).status.as_str(),
                of(Stage::Lan).detail.as_str()
            ),
            ("done", "3 neighbours")
        );
        assert_eq!(of(Stage::Dns).status, "failed");
        let ports = of(Stage::Ports);
        assert_eq!(
            (ports.status.as_str(), ports.detail.as_str()),
            ("interrupted", "stopped: the session was closed")
        );
        assert!(ports.started_utc.is_some() && ports.finished_utc.is_some());
        // What had not started is left out: nothing waits for a later
        // session.
        for waiting in [Stage::Asn, Stage::Services, Stage::Dirs] {
            let stage = of(waiting);
            assert_eq!(
                (stage.status.as_str(), stage.detail.as_str()),
                ("skipped", "not run: the session was closed")
            );
        }
        assert!(!task.unfinished());
        // Shown without the progress it had.
        let shown = state.snapshot();
        assert!(shown["tasks"][0]["stages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|stage| stage.get("progress").is_none()));
    }

    /// The guard is an extra: a session that cannot start it runs all the
    /// same, and says once what that means.
    #[cfg(unix)]
    #[test]
    fn a_session_without_its_guard_runs_and_says_so_once() {
        for program in [
            Ok(PathBuf::from("/nonexistent/meow")),
            Err(std::io::Error::other("no path to this program")),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
            let (workspace, _) =
                Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
            let _lock = SessionLock::acquire(&workspace.lock_path()).unwrap();
            let mut config = Config::default();
            config.cve.enabled = false;
            let coordinator = Coordinator::start_guarded(workspace, config, program, None).unwrap();
            let state = coordinator.state();
            assert_eq!(state.tools().guard_pid(), None);
            state.notice_tool_fault();
            let said: Vec<String> = lock(&state.notices)
                .iter()
                .filter(|notice| notice.text.contains("guard"))
                .map(|notice| notice.text.clone())
                .collect();
            assert_eq!(said.len(), 1, "{said:?}");
            assert!(
                said[0].starts_with("the scan guard did not start (")
                    && said[0].ends_with("would keep running if meow itself were killed"),
                "{said:?}"
            );
            // Its tools still start, and still end with it.
            let mut sleep = std::process::Command::new("sleep");
            sleep.arg("300");
            let (mut child, _group) = state.tools().spawn_std(&mut sleep).unwrap();
            assert!(coordinator.shutdown().is_empty());
            assert!(!child.wait().unwrap().success());
        }
    }

    /// A stand-in for a local OpenAI-compatible server, on its own thread.
    fn local_model_server() -> String {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            block_on(async {
                let app = Router::new().route(
                    "/v1/chat/completions",
                    post(|Json(body): Json<Value>| async move {
                        let asked = body["messages"][1]["content"].as_str().unwrap_or("").to_owned();
                        let host = if asked.contains("10.0.0.5") { "10.0.0.5" } else { "?" };
                        Json(json!({ "choices": [ { "message": {
                            "content": format!("## 1. Risk\nnginx on {host} is outdated.\n## 2. Fix\nUpgrade.\n## 3. Rule\nalert") } } ] }))
                    }),
                );
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(format!("http://{}/v1", listener.local_addr().unwrap()))
                    .unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        rx.recv().unwrap()
    }

    /// A stand-in for NVD, OSV and the KEV list that answers nothing and
    /// keeps the NVD questions it was asked.
    fn cve_stand_in() -> (String, Arc<Mutex<Vec<String>>>) {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&asked);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            block_on(async move {
                let app = Router::new()
                    .route(
                        "/nvd",
                        get(
                            move |query: axum::extract::Query<
                                std::collections::HashMap<String, String>,
                            >| async move {
                                if let Some(words) = query.get("keywordSearch") {
                                    lock(&log).push(words.clone());
                                }
                                Json(json!({ "totalResults": 0, "vulnerabilities": [] }))
                            },
                        ),
                    )
                    .route(
                        "/kev",
                        get(|| async { Json(json!({ "vulnerabilities": [] })) }),
                    )
                    .route(
                        "/osv/v1/querybatch",
                        post(|| async { Json(json!({ "results": [] })) }),
                    );
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(format!("http://{}", listener.local_addr().unwrap()))
                    .unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        (rx.recv().unwrap(), asked)
    }

    #[test]
    fn terminal_text_asks_only_so_many_cve_questions_and_the_operator_goes_first() {
        let (base, asked) = cve_stand_in();
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        let _lock = SessionLock::acquire(&workspace.lock_path()).unwrap();
        let mut config = Config::default();
        config.cve.nvd_api_key = Some("stand-in".into());
        config.cve.nvd_url = format!("{base}/nvd");
        config.cve.osv_url = format!("{base}/osv");
        config.cve.kev_url = format!("{base}/kev");
        let coordinator = Coordinator::start(workspace, config).unwrap();
        let state = coordinator.state();
        // Two new questions for this session's terminal text.
        *lock(&state.grounds) = cve::GroundQueue::new(2);
        let wait_for = |what: &str, done: &dyn Fn() -> bool| {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !done() {
                assert!(Instant::now() < deadline, "{what}: {:?}", lock(&asked));
                std::thread::sleep(Duration::from_millis(20));
            }
        };

        let mut sink = coordinator.tap_sink();
        for line in [
            "Nmap scan report for 198.51.100.1",
            "21/tcp open ftp ProdA 1.0",
            "22/tcp open ssh ProdB 1.0",
            "23/tcp open telnet ProdC 1.0",
            "",
            "Nmap scan report for 198.51.100.2",
            "21/tcp open ftp ProdA 1.0",
            "",
        ] {
            sink(line);
        }
        let told = || {
            lock(&state.notices)
                .iter()
                .any(|n| n.text.contains("reached this session's limit"))
        };
        wait_for("two questions and the notice", &|| {
            lock(&asked).len() == 2 && told()
        });
        // The second host's software was asked about already.
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(lock(&asked).len(), 2, "{:?}", lock(&asked));

        // The operator's own request is not limited.
        state.request_grounding("198.51.100.1", cve::Asked::Operator);
        wait_for("the operator's question", &|| lock(&asked).len() == 3);
        assert_eq!(lock(&asked)[2], "ProdC 1.0");

        // A recon task's request is not limited for the ports its scans
        // found, and is for those text added to the host.
        for line in [
            "Nmap scan report for 198.51.100.3",
            "80/tcp open http ProdD 1.0",
            "81/tcp open http ProdE 1.0",
            "",
        ] {
            sink(line);
        }
        wait_for("the text host", &|| {
            state
                .graph()
                .hosts
                .get("198.51.100.3")
                .is_some_and(|h| h.ports.len() == 2)
        });
        let own = ["80/tcp".to_owned()].into();
        block_on(state.ground_host_for("198.51.100.3", cve::Asked::Recon(own))).unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(lock(&asked)[3..], ["ProdD 1.0"]);
    }

    #[test]
    fn ai_requests_stream_into_the_status_and_are_saved_per_host() {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        let mut config = Config::default();
        config.cve.enabled = false;
        config.ai.local_url = local_model_server();
        let coordinator = Coordinator::start(workspace.clone(), config).unwrap();
        let state = coordinator.state();

        let ask = |tier: Tier, address: &str| {
            state.execute(Command::Ai {
                tier,
                address: address.to_owned(),
            })
        };
        assert!(ask(Tier::Local, "10.0.0.5")
            .unwrap_err()
            .to_string()
            .contains("unknown host"));

        let items = crate::parsers::nmap::parse(crate::parsers::nmap::SAMPLE, false).unwrap();
        state
            .execute(Command::Observations {
                items,
                ground: false,
            })
            .unwrap();
        // Deep research needs a CVE to research, and nothing more.
        let refused = ask(Tier::Research, "10.0.0.5").unwrap_err().to_string();
        assert!(
            refused.contains("Research needs a CVE: none found for 10.0.0.5"),
            "{refused}"
        );

        assert_eq!(ask(Tier::Local, "10.0.0.5").unwrap()["started"], true);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let status = state.snapshot()["ai"].clone();
            if status["running"] == false && status["summary"].is_string() {
                assert_eq!(status["tier"], "local");
                assert_eq!(status["address"], "10.0.0.5");
                assert!(status["text"]
                    .as_str()
                    .unwrap()
                    .contains("nginx on 10.0.0.5 is outdated."));
                assert!(status["summary"]
                    .as_str()
                    .unwrap()
                    .contains("· chats/10.0.0.5.md"));
                break;
            }
            assert!(status["error"].is_null(), "{status}");
            assert!(
                std::time::Instant::now() < deadline,
                "the AI request never finished: {status}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let chat = std::fs::read_to_string(workspace.chats_dir().join("10.0.0.5.md")).unwrap();
        assert!(chat.contains("[L] Local triage"), "{chat}");
        assert!(chat.contains("nginx on 10.0.0.5 is outdated."), "{chat}");
        assert!(chat.contains("_Cost: $0.0000_"), "{chat}");
        let snapshot = state.snapshot();
        assert_eq!(snapshot["budget"]["calls"], 0, "local calls are free");
        assert_eq!(snapshot["budget"]["max_calls"], 20);
        assert!(snapshot["notices"]
            .to_string()
            .contains("Local AI · 10.0.0.5 · done · by local"));

        // With a CVE found, [R] starts. No key is set here, so it ends
        // without asking anyone.
        if std::env::var(crate::ai::API_KEY_ENV).is_err() {
            state.graph().add_advisory(
                "10.0.0.5",
                crate::graph::Advisory {
                    fixed_in: None,
                    last_affected: None,
                    id: "CVE-2021-23017".into(),
                    title: "t".into(),
                    severity: None,
                    cvss: None,
                    kev: false,
                    matched: "cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*".into(),
                    port: Some("443/tcp".into()),
                    references: vec![],
                    record: EvidenceRecord::observed(Source::NvdApi, Confidence::Medium, "{}"),
                },
            );
            assert_eq!(ask(Tier::Research, "10.0.0.5").unwrap()["started"], true);
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while state.snapshot()["ai"]["running"] == true {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    #[test]
    fn two_sessions_get_different_ports() {
        let a = fixture();
        let b = fixture();
        assert_ne!(a.coordinator.info().port, b.coordinator.info().port);
        assert_ne!(a.coordinator.info().token, b.coordinator.info().token);
    }

    #[test]
    fn a_cookie_never_carries_or_grants_the_token() {
        let fx = fixture();
        let info = fx.coordinator.info();
        // The page is served without setting a cookie: browsers would send
        // it to every other port of 127.0.0.1.
        let reply = raw_request(&info, &format!("/?token={}", info.token));
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(
            !reply.to_ascii_lowercase().contains("set-cookie"),
            "{reply}"
        );

        // A cookie with the right value opens nothing.
        let cookie = format!(
            "meow_token_{}={}; meow_token={}",
            info.port, info.token, info.token
        );
        for path in [
            "/api/state",
            "/api/state?token=",
            "/assets/map.js",
            "/map/tile/1/0/0",
        ] {
            let (status, _) = request(&info, "GET", path, &[("Cookie", &cookie)], None);
            assert_eq!(status, 401, "{path}");
        }
        let (status, _) = request(
            &info,
            "POST",
            "/api/command",
            &[("Cookie", &cookie)],
            Some(json!({"cmd": "set_mode", "mode": "aggressive"})),
        );
        assert_eq!(status, 401);
        // A reload without the token gets a page with no secret in it,
        // whose script finds the token in the tab's own storage.
        let reply = raw_request(&info, "/");
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(!reply.contains(&info.token), "{reply}");
        assert!(reply.contains("/reload.js"), "{reply}");
        let script = raw_request(&info, "/reload.js");
        assert!(
            script.contains("sessionStorage.getItem('meow-map-token')"),
            "{script}"
        );
        assert!(!script.contains(&info.token));
        // Another page may not load it (every port of 127.0.0.1 is the
        // same site): its onload would say that meow runs on this port.
        assert!(
            script
                .to_ascii_lowercase()
                .contains("cross-origin-resource-policy: same-origin"),
            "{script}"
        );
        let get = |path: &str, headers: &[(&str, &str)]| request(&info, "GET", path, headers, None);
        for site in ["cross-site", "same-site", "none"] {
            let (status, _) = get("/reload.js", &[("Sec-Fetch-Site", site)]);
            assert_eq!(status, 401, "{site}");
        }
        let (status, body) = get("/reload.js", &[("Sec-Fetch-Site", "same-origin")]);
        assert_eq!(status, 200, "{body}");
        // The reload page is for the tab only, not a probe of another page.
        let probe = [
            ("Sec-Fetch-Site", "cross-site"),
            ("Sec-Fetch-Mode", "no-cors"),
        ];
        assert_eq!(get("/", &probe).0, 401);
        let reload = [("Sec-Fetch-Site", "none"), ("Sec-Fetch-Mode", "navigate")];
        let (status, body) = get("/", &reload);
        assert_eq!(status, 200);
        assert!(body.to_string().contains("/reload.js"), "{body}");
        // `meow map` opens the map from a file: a cross-site navigation,
        // with the token.
        let opener = [
            ("Sec-Fetch-Site", "cross-site"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Dest", "document"),
        ];
        let (status, body) = get(&format!("/?token={}", info.token), &opener);
        assert_eq!(status, 200);
        assert!(body.to_string().contains("map.js"), "{body}");

        // Duplicate Host or Origin headers are refused.
        let mut headers = HeaderMap::new();
        headers.append(
            header::HOST,
            format!("127.0.0.1:{}", info.port).parse().unwrap(),
        );
        headers.append(header::HOST, "evil.example".parse().unwrap());
        assert!(!host_allowed(&headers, info.port));

        let mut origins = HeaderMap::new();
        origins.append(
            header::ORIGIN,
            format!("http://127.0.0.1:{}", info.port).parse().unwrap(),
        );
        origins.append(header::ORIGIN, "http://evil.example".parse().unwrap());
        assert!(!origin_allowed(&origins, info.port));

        // Bootstrap HTML is cleaned up on shutdown.
        let bootstrap = webui::write_bootstrap(
            &fx.workspace.tmp_dir(),
            &webui::map_url(info.port, &info.token),
        )
        .unwrap();
        assert!(bootstrap.exists());
        fx.coordinator.shutdown();
        assert!(!bootstrap.exists());
    }

    #[test]
    fn second_pass_http_ws_and_ip_guards_hold() {
        // 1. RuntimeInfo::read rejects pid == 0.
        let tmp = tempfile::tempdir().unwrap();
        let rt_path = tmp.path().join("runtime.json");
        write_private_atomic(
            &rt_path,
            br#"{"pid":0,"port":8765,"token":"abcdef0123456789"}"#,
        )
        .unwrap();
        assert!(RuntimeInfo::read(&rt_path).is_none());

        // 2. parse_ip_unscoped allows `%zone` only on valid IPv6 addresses.
        assert!(parse_ip_unscoped("8.8.8.8%eth0").is_none());
        assert!(parse_ip_unscoped("127.0.0.1%lo").is_none());
        assert!(parse_ip_unscoped("fe80::1%").is_none());
        assert!(parse_ip_unscoped("fe80::1%eth0%extra").is_none());
        assert_eq!(
            parse_ip_unscoped("fe80::1%eth0"),
            Some("fe80::1".parse().unwrap())
        );

        let fx = fixture();
        let info = fx.coordinator.info();
        // 4. Malformed or duplicate Authorization headers and duplicate
        // `?token=` query parameters are refused.
        let (status, _) = request(
            &info,
            "GET",
            "/api/state",
            &[("Authorization", "Basic dXNlcjpwYXNz")],
            None,
        );
        assert_eq!(status, 401);

        let mut dup_auth = HeaderMap::new();
        dup_auth.append(header::AUTHORIZATION, bearer(&info).parse().unwrap());
        dup_auth.append(header::AUTHORIZATION, bearer(&info).parse().unwrap());
        assert!(token_from(&dup_auth, None).is_none());

        let (status, _) = request(
            &info,
            "GET",
            &format!("/api/state?token={}&token={}", info.token, info.token),
            &[],
            None,
        );
        assert_eq!(status, 401);

        // A WebSocket with only a cookie is refused.
        block_on(async {
            let ws_cookie_url = format!("ws://127.0.0.1:{}/ws", info.port);
            let mut req = ws_cookie_url.as_str().into_client_request().unwrap();
            req.headers_mut().insert(
                header::COOKIE,
                format!("meow_token_{}={}", info.port, info.token)
                    .parse()
                    .unwrap(),
            );
            let err = tokio_tungstenite::connect_async(req).await.unwrap_err();
            let tokio_tungstenite::tungstenite::Error::Http(resp) = err else {
                panic!("expected an HTTP refusal for cookie-only /ws, got {err:?}");
            };
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        });

        // 5. Upgraded WebSockets are bounded by MAX_WS_CONNECTIONS and release
        // their slot when closed.
        block_on(async {
            let url = format!("ws://127.0.0.1:{}/ws?token={}", info.port, info.token);
            let mut open_sockets = Vec::new();
            for _ in 0..MAX_WS_CONNECTIONS {
                let req = url.as_str().into_client_request().unwrap();
                let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
                let first = ws.next().await.unwrap().unwrap();
                assert!(matches!(first, WsMessage::Text(_)));
                open_sockets.push(ws);
            }
            let extra = url.as_str().into_client_request().unwrap();
            let err = tokio_tungstenite::connect_async(extra).await.unwrap_err();
            let tokio_tungstenite::tungstenite::Error::Http(resp) = err else {
                panic!("expected HTTP 503 refusal, got {err:?}");
            };
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

            let mut released = open_sockets.pop().unwrap();
            let _ = released.close(None).await;
            drop(released);
            tokio::time::sleep(Duration::from_millis(50)).await;

            let retry = url.as_str().into_client_request().unwrap();
            let (mut ws, _) = tokio_tungstenite::connect_async(retry).await.unwrap();
            assert!(ws.next().await.is_some());
        });
    }
}

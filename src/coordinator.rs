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
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Request, State as AxumState};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};

use crate::ai::{self, AiEngine, Tier};
use crate::checklist;
use crate::cve::{self, CveClient};
use crate::db::Db;
use crate::endpoint::Target;
use crate::evidence::{Confidence, EvidenceRecord, Source, VerificationStatus};
use crate::graph::{Graph, Host, LocalNet, Observation};
use crate::mode::Mode;
use crate::observer;
use crate::parsers::text::TextParser;
use crate::pty::LineSink;
use crate::queue;
use crate::timeutil::now_rfc3339;
use crate::topology::Topology;
use crate::vault::Vault;
use crate::webui;
use crate::workspace::{write_private_atomic, Config, Workspace};

pub const FIRST_PORT: u16 = 8765;
const PORT_ATTEMPTS: u16 = 100;
const MAX_NOTICES: usize = 100;
const TAP_QUEUE: usize = 4096;
const SAVE_DEBOUNCE: Duration = Duration::from_millis(750);
const OBSERVE_EVERY: Duration = Duration::from_secs(30);
const WS_MIN_INTERVAL: Duration = Duration::from_millis(400);
const BODY_LIMIT: usize = 64 * 1024 * 1024;

/// Contents of `runtime.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub pid: u32,
    pub port: u16,
    pub token: String,
}

impl RuntimeInfo {
    pub fn read(path: &Path) -> Option<Self> {
        serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
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
    }
}

/// 256 random bits as 64 hex characters.
pub fn new_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no secure random source: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
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
    /// Operator verdict on an advisory.
    Verdict {
        address: String,
        advisory: String,
        status: VerificationStatus,
    },
    /// Queues an authorized asset and service inventory (`meow recon`).
    Recon {
        target: String,
        /// Extra nmap flags, given after `--`.
        flags: Vec<String>,
    },
    /// Puts unfinished tasks back on the queue.
    Resume,
    /// Starts an AI request for a host (`[L]`, `[C]` or `[R]`).
    Ai {
        tier: Tier,
        address: String,
    },
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
    pub config: Config,
    workspace: Mutex<Workspace>,
    graph: Mutex<Graph>,
    pub db: Arc<Mutex<Db>>,
    notices: Mutex<VecDeque<Notice>>,
    /// Bumped on every visible change; WebSocket clients and the saver watch it.
    revision: watch::Sender<u64>,
    dirty: AtomicBool,
    ground_queue: mpsc::UnboundedSender<String>,
    recon_queue: mpsc::UnboundedSender<i64>,
    cve: Option<CveClient>,
    vault: Mutex<Vault>,
    ai: AiEngine,
    ai_status: Mutex<AiStatus>,
    /// The coordinator's runtime, for work started from any thread.
    handle: tokio::runtime::Handle,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock must not take the whole session down.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl State {
    pub fn graph(&self) -> MutexGuard<'_, Graph> {
        lock(&self.graph)
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

    /// Puts every unfinished task back on the queue; returns how many.
    pub fn resume_unfinished(&self) -> Result<usize> {
        let unfinished = queue::unfinished(&self.db_lock())?;
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
        let mut notices = lock(&self.notices);
        if notices.len() >= MAX_NOTICES {
            notices.pop_front();
        }
        notices.push_back(Notice {
            at: now_rfc3339(),
            text: text.into(),
        });
        drop(notices);
        self.touch();
    }

    fn save_if_dirty(&self) {
        if !self.dirty.swap(false, Ordering::SeqCst) {
            return;
        }
        let path = self.graph_path();
        let result = self.graph().save(&path);
        if let Err(error) = result {
            self.dirty.store(true, Ordering::SeqCst);
            self.notice(format!("cannot save graph.json: {error:#}"));
        }
    }

    /// Queues CVE lookups for a host (no-op when grounding is disabled).
    pub fn request_grounding(&self, address: &str) {
        if self.cve.is_some() {
            let _ = self.ground_queue.send(address.to_owned());
        }
    }

    /// The snapshot sent to the HUD and the browser map.
    pub fn snapshot(&self) -> Value {
        let graph = self.graph();
        let mut checklists = serde_json::Map::new();
        for host in graph.hosts.values() {
            let mut per_host = serde_json::Map::new();
            for advisory in &host.advisories {
                let list = checklist::for_advisory(&graph, host, advisory);
                let items: Vec<Value> = list
                    .items
                    .iter()
                    .map(|c| json!({ "label": c.label, "done": c.done, "detail": c.detail, "required": c.required }))
                    .collect();
                per_host.insert(
                    advisory.id.clone(),
                    json!({ "items": items, "research_ready": list.research_ready() }),
                );
            }
            if !per_host.is_empty() {
                checklists.insert(host.address.clone(), Value::Object(per_host));
            }
        }
        let fixes: serde_json::Map<String, Value> = graph
            .hosts
            .values()
            .map(|host| (host.address.clone(), cve::fix_plan(host)))
            .filter(|(_, plan)| !plan.is_empty())
            .map(|(address, plan)| (address, json!(plan)))
            .collect();
        json!({
            "session": self.session,
            "mode": self.mode(),
            "port": self.port,
            "revision": *self.revision.borrow(),
            "graph": &*graph,
            "checklists": checklists,
            "fixes": fixes,
            "topology": Topology::build(&graph).cytoscape(&graph),
            "machine": observer::machine_report(&graph.local),
            "tasks": queue::tasks(&self.db_lock(), 20).unwrap_or_default(),
            "notices": &*lock(&self.notices),
            "ai": &*lock(&self.ai_status),
            "budget": self.ai.budget(),
        })
    }

    /// Carries out one command. Fast: long work is handed to background tasks.
    pub fn execute(self: &Arc<Self>, command: Command) -> Result<Value> {
        match command {
            Command::Ping => Ok(json!({ "session": self.session, "port": self.port })),
            Command::State => Ok(self.snapshot()),
            Command::SetMode { mode } => {
                lock(&self.workspace).set_mode(mode)?;
                self.notice(format!("mode set to {mode}"));
                // Tasks paused by light mode continue once it is left.
                let resumed = match mode {
                    Mode::Light => 0,
                    _ => self.resume_unfinished()?,
                };
                Ok(json!({ "mode": mode, "resumed": resumed }))
            }
            Command::Note { address, text } => {
                let text = text.trim().to_owned();
                if text.is_empty() {
                    bail!("the note is empty");
                }
                let record =
                    EvidenceRecord::observed(Source::ManualNote, Confidence::Medium, &text);
                let observation = Observation::Note {
                    address: address.clone(),
                    text,
                    record,
                };
                if !self.graph().apply(observation) {
                    bail!("the note was not stored (unknown host, or a duplicate)");
                }
                self.mark_dirty();
                // A note may carry a package URL worth looking up.
                if let Some(address) = &address {
                    self.request_grounding(address);
                }
                Ok(json!({ "stored": true }))
            }
            Command::Observations { items, ground } => {
                let total = items.len();
                let mut touched: Vec<String> = Vec::new();
                let mut changed = 0;
                {
                    let mut graph = self.graph();
                    for item in items {
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
                }
                let hosts = self.graph().hosts.len();
                if changed > 0 {
                    self.mark_dirty();
                    self.notice(format!("imported {changed} new facts ({total} parsed)"));
                }
                let grounding = ground && self.cve.is_some();
                if grounding {
                    for address in &touched {
                        self.request_grounding(address);
                    }
                }
                Ok(
                    json!({ "parsed": total, "changed": changed, "hosts": hosts, "grounding": grounding }),
                )
            }
            Command::Verdict {
                address,
                advisory,
                status,
            } => {
                self.graph()
                    .set_advisory_status(&address, &advisory, status)?;
                self.mark_dirty();
                self.notice(format!("{advisory} on {address} marked {status}"));
                Ok(json!({ "status": status }))
            }
            Command::Recon { target, flags } => {
                let mode = self.mode();
                if mode == Mode::Light {
                    bail!(
                        "light mode sends no packets, so recon is refused; \
                         run `meow mode mild` (or aggressive) first"
                    );
                }
                let parsed = Target::parse(&target).with_context(|| {
                    format!("'{target}' is not a host name, an IP address or a CIDR range")
                })?;
                let id = queue::enqueue(&self.db_lock(), &parsed.to_string(), mode, &flags)?;
                let risky = queue::high_rate_flags(&flags).join(" ");
                if mode == Mode::Mild && !risky.is_empty() {
                    self.notice(format!(
                        "recon {parsed}: high-rate flags in mild mode ({risky})"
                    ));
                }
                let _ = self.recon_queue.send(id);
                self.notice(format!("recon {parsed} queued as task {id} ({mode})"));
                let ahead = queue::unfinished(&self.db_lock())?.len().saturating_sub(1);
                Ok(
                    json!({ "task": id, "target": parsed.to_string(), "mode": mode, "ahead": ahead }),
                )
            }
            Command::Resume => Ok(json!({ "resumed": self.resume_unfinished()? })),
            Command::Ai { tier, address } => {
                let (graph, host) = {
                    let graph = self.graph();
                    let host = graph
                        .host(&address)
                        .cloned()
                        .with_context(|| format!("unknown host '{address}'"))?;
                    (graph.clone(), host)
                };
                if tier == Tier::Research && !checklist::host_research_ready(&graph, &host) {
                    bail!(
                        "[R] is not ready for {}: the stack and route evidence is incomplete \
                         (see the verification checklist)",
                        host.address
                    );
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
                self.notice(format!(
                    "[{}] {} started for {}",
                    tier.key(),
                    tier.label(),
                    host.address
                ));
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
        let streamer = Arc::clone(&self);
        let mut on_text = move |piece: &str| {
            if !piece.is_empty() {
                lock(&streamer.ai_status).text.push_str(piece);
                streamer.touch();
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
                        "saved to chats/{}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    Err(error) => format!("not saved: {error:#}"),
                };
                let how = match (&outcome.fallback_reason, outcome.cached) {
                    (Some(reason), _) => format!("answered locally ({reason})"),
                    (None, true) => "answered from the prompt cache".to_owned(),
                    (None, false) => format!("answered by {}", outcome.model),
                };
                let line = format!(
                    "[{}] for {} {how}, ${:.4}, {file}",
                    tier.key(),
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
                let line = format!("[{}] for {} failed: {error:#}", tier.key(), host.address);
                let mut status = lock(&self.ai_status);
                status.running = false;
                status.error = Some(format!("{error:#}"));
                line
            }
        };
        self.notice(line);
    }
}

fn observation_address(observation: &Observation) -> Option<String> {
    match observation {
        Observation::Host { address, .. }
        | Observation::Hostname { address, .. }
        | Observation::Port { address, .. }
        | Observation::TlsSan { address, .. }
        | Observation::Http { address, .. }
        | Observation::Path { address, .. } => Some(address.clone()),
        Observation::Note { address, .. } => address.clone(),
    }
}

// ---------------------------------------------------------------------------
// HTTP / WebSocket server
// ---------------------------------------------------------------------------

type Shared = Arc<State>;

fn deny(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "ok": false, "error": message }))).into_response()
}

fn allowed_origins(port: u16) -> [String; 2] {
    [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
    ]
}

/// `Host` must be the loopback address the coordinator listens on.
fn host_allowed(headers: &HeaderMap, port: u16) -> bool {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| {
            host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}")
        })
}

/// A browser sends `Origin` on WebSocket upgrades and cross-site requests;
/// when present it must be the coordinator's own origin. Native clients
/// (the HUD, helper subcommands) send none.
fn origin_allowed(headers: &HeaderMap, port: u16) -> bool {
    match headers.get(header::ORIGIN) {
        None => true,
        Some(value) => value.to_str().is_ok_and(|origin| {
            allowed_origins(port)
                .iter()
                .any(|allowed| allowed == origin)
        }),
    }
}

fn token_from(headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    if let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        return Some(bearer.trim().to_owned());
    }
    url::form_urlencoded::parse(query?.as_bytes())
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.into_owned())
}

async fn guard(AxumState(state): AxumState<Shared>, request: Request, next: Next) -> Response {
    let mut response = check_and_run(&state, request, next).await;
    webui::security_headers(&mut response, state.port);
    response
}

async fn check_and_run(state: &Shared, request: Request, next: Next) -> Response {
    let headers = request.headers();
    if !host_allowed(headers, state.port) {
        return deny(StatusCode::FORBIDDEN, "unexpected Host header");
    }
    if !origin_allowed(headers, state.port) {
        return deny(StatusCode::FORBIDDEN, "cross-origin request refused");
    }
    let presented = token_from(headers, request.uri().query());
    if !presented.is_some_and(|token| constant_time_eq(&token, &state.token)) {
        return deny(StatusCode::UNAUTHORIZED, "missing or wrong session token");
    }
    next.run(request).await
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

async fn websocket(AxumState(state): AxumState<Shared>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| serve_socket(state, socket))
}

/// Pushes a state snapshot on connect and after every change (rate-limited),
/// and executes commands the client sends.
async fn serve_socket(state: Shared, mut socket: WebSocket) {
    let mut revision = state.revision.subscribe();
    let send_state = |state: &Shared| {
        Message::Text(
            json!({ "type": "state", "state": state.snapshot() })
                .to_string()
                .into(),
        )
    };
    if socket.send(send_state(&state)).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            changed = revision.changed() => {
                if changed.is_err() {
                    break;
                }
                // Coalesce bursts of changes into one snapshot.
                tokio::time::sleep(WS_MIN_INTERVAL).await;
                revision.borrow_and_update();
                if socket.send(send_state(&state)).await.is_err() {
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
    webui::page(&state.token)
}

async fn asset(AxumPath(name): AxumPath<String>) -> Response {
    webui::asset(&name)
}

fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/{name}", get(asset))
        .route("/api/state", get(get_state))
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
        let Ok(local) = tokio::task::spawn_blocking(move || observer::observe(&targets)).await
        else {
            continue;
        };
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
        {
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
        }
        if changed {
            state.mark_dirty();
        }
        for address in ground {
            state.request_grounding(&address);
        }
    }
}

/// Runs CVE lookups one host at a time, off the request path.
async fn grounding_loop(state: Shared, mut queue: mpsc::UnboundedReceiver<String>) {
    while let Some(address) = queue.recv().await {
        let Some(client) = &state.cve else { continue };
        let Some(host) = state.graph().hosts.get(&address).cloned() else {
            continue;
        };
        let grounding = client.ground(&host).await;
        let (merged, first_fix) = {
            let mut graph = state.graph();
            let merged = cve::merge(&mut graph, &address, &grounding);
            let first_fix = graph
                .hosts
                .get(&address)
                .and_then(|host| cve::fix_plan(host).into_iter().next());
            (merged, first_fix)
        };
        // Every source that failed, not only the first: a missing catalog
        // and an unanswered database are different problems.
        if !grounding.errors.is_empty() {
            let shown: Vec<&str> = grounding
                .errors
                .iter()
                .take(3)
                .map(String::as_str)
                .collect();
            state.notice(format!(
                "CVE lookup for {address} is incomplete: {}",
                shown.join("; ")
            ));
        }
        if merged.added > 0 || merged.dropped > 0 {
            state.mark_dirty();
        }
        if merged.dropped > 0 {
            state.notice(format!(
                "{} earlier matches for {address} no longer apply and were removed",
                merged.dropped
            ));
        }
        if merged.added > 0 {
            // Say what these are and what answers most of them, in words
            // that do not need the evidence model explained first.
            let fix = first_fix
                .map(|fix| format!(" Most come from one place: {}", fix.action))
                .unwrap_or_default();
            let noun = if merged.added == 1 {
                "advisory"
            } else {
                "advisories"
            };
            state.notice(format!(
                "{} possible {noun} for {address} ({} known exploited), matched by version \
                 number only and not verified.{fix}",
                merged.added, merged.kev
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

pub struct Coordinator {
    state: Shared,
    runtime: Option<tokio::runtime::Runtime>,
    tap: Option<mpsc::Sender<String>>,
    tap_task: Option<tokio::task::JoinHandle<()>>,
    _runtime_file: RuntimeFile,
}

async fn bind_loopback() -> Result<tokio::net::TcpListener> {
    let mut last_error = None;
    for offset in 0..PORT_ATTEMPTS {
        let address = SocketAddr::from(([127, 0, 0, 1], FIRST_PORT + offset));
        match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => return Ok(listener),
            Err(error) => last_error = Some(error),
        }
    }
    Err(anyhow!(
        "no free loopback port in {FIRST_PORT}-{}: {}",
        FIRST_PORT + PORT_ATTEMPTS - 1,
        last_error.map(|e| e.to_string()).unwrap_or_default()
    ))
}

impl Coordinator {
    /// Starts the coordinator for an opened (and locked) workspace.
    pub fn start(workspace: Workspace, config: Config) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("meow-coordinator")
            .enable_all()
            .build()
            .context("cannot start the coordinator runtime")?;

        let listener = runtime.block_on(bind_loopback())?;
        let port = listener.local_addr()?.port();
        let token = new_token()?;

        let mut graph = Graph::load(&workspace.graph_path())?;
        graph.local = observer::observe(&graph.target_ips());
        let db = Arc::new(Mutex::new(Db::open(&workspace.state_db_path())?));
        let vault = Vault::open(Arc::clone(&db))?;
        let engine = AiEngine::new(config.ai.clone(), Arc::clone(&db))?;
        let cve = if config.cve.enabled {
            Some(CveClient::new(config.cve.clone(), Arc::clone(&db))?)
        } else {
            None
        };

        let runtime_path = workspace.runtime_path();
        let info = RuntimeInfo {
            pid: std::process::id(),
            port,
            token: token.clone(),
        };
        write_private_atomic(&runtime_path, serde_json::to_string(&info)?.as_bytes())?;
        let runtime_file = RuntimeFile(runtime_path);

        let (revision, _) = watch::channel(0u64);
        let (ground_queue, ground_rx) = mpsc::unbounded_channel();
        let (recon_queue, recon_rx) = mpsc::unbounded_channel();
        // Stages left "running" belong to a session that ended mid-run.
        queue::mark_running_interrupted(&lock(&db))?;
        let (tap, tap_rx) = mpsc::channel(TAP_QUEUE);
        let state = Arc::new(State {
            session: workspace.name.clone(),
            port,
            token,
            config,
            workspace: Mutex::new(workspace),
            graph: Mutex::new(graph),
            db,
            notices: Mutex::new(VecDeque::new()),
            revision,
            dirty: AtomicBool::new(true),
            ground_queue,
            recon_queue,
            cve,
            vault: Mutex::new(vault),
            ai: engine,
            ai_status: Mutex::new(AiStatus::default()),
            handle: runtime.handle().clone(),
        });

        let app = router(Arc::clone(&state));
        runtime.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        runtime.spawn(saver(Arc::clone(&state)));
        runtime.spawn(observe_loop(Arc::clone(&state)));
        let tap_task = runtime.spawn(tap_loop(Arc::clone(&state), tap_rx));
        runtime.spawn(grounding_loop(Arc::clone(&state), ground_rx));
        runtime.spawn(queue::worker(Arc::clone(&state), recon_rx));
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
            tap: Some(tap),
            tap_task: Some(tap_task),
            _runtime_file: runtime_file,
        })
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
    /// without bound, if the coordinator falls behind.
    pub fn tap_sink(&self) -> LineSink {
        match self.tap.clone() {
            Some(tap) => Box::new(move |line| {
                let _ = tap.try_send(line.to_owned());
            }),
            None => Box::new(|_line| {}),
        }
    }

    /// Stops the background tasks and writes the final `graph.json`.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        // Let the tap finish the lines it already has: once every sender is
        // gone the task ends by itself.
        self.tap.take();
        if let Some(task) = self.tap_task.take() {
            let _ = runtime
                .block_on(async { tokio::time::timeout(Duration::from_secs(2), task).await });
        }
        runtime.shutdown_timeout(Duration::from_secs(2));
        self.state.save_if_dirty();
        // A tool that was running has just been killed with the runtime.
        let _ = queue::mark_running_interrupted(&self.state.db_lock());
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
    use crate::workspace::MeowHome;
    use axum::routing::post;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    struct Fixture {
        _tmp: tempfile::TempDir,
        workspace: Workspace,
        coordinator: Coordinator,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        let mut config = Config::default();
        config.cve.enabled = false;
        let coordinator = Coordinator::start(workspace.clone(), config).unwrap();
        Fixture {
            _tmp: tmp,
            workspace,
            coordinator,
        }
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

    fn bearer(info: &RuntimeInfo) -> String {
        format!("Bearer {}", info.token)
    }

    #[test]
    fn runtime_file_is_private_and_removed_at_shutdown() {
        let fx = fixture();
        let path = fx.workspace.runtime_path();
        let info = RuntimeInfo::read(&path).unwrap();
        assert_eq!(info, fx.coordinator.info());
        assert_eq!(info.pid, std::process::id());
        assert!((FIRST_PORT..FIRST_PORT + PORT_ATTEMPTS).contains(&info.port));
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
        for path in ["/api/state", "/", "/ws"] {
            let (status, _) = request(&info, "GET", path, &[], None);
            assert_eq!(status, 401, "{path} without a token");
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
            let first = next().await;
            assert_eq!(first["type"], "state");
            assert_eq!(first["state"]["graph"]["hosts"], json!({}));

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
        let fx = fixture();
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
            &Command::Verdict {
                address: "10.0.0.5".into(),
                advisory: "CVE-0000-0000".into(),
                status: VerificationStatus::Confirmed,
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("no advisory"), "{error:#}");

        let workspace = fx.workspace.clone();
        fx.coordinator.shutdown();
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
    fn imported_observations_and_verdicts_reach_the_graph_file() {
        let fx = fixture();
        let state = fx.coordinator.state();
        let items = crate::parsers::nmap::parse(crate::parsers::nmap::SAMPLE).unwrap();
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
                matched: "m".into(),
                port: Some("443/tcp".into()),
                references: vec![],
                record: EvidenceRecord::hypothesis(Source::NvdApi, Confidence::Medium, "{}"),
            },
        );
        // Observed -> Confirmed is impossible; a hypothesis can be confirmed.
        assert!(state
            .execute(Command::Verdict {
                address: "10.0.0.5".into(),
                advisory: "CVE-2021-23017".into(),
                status: VerificationStatus::Observed,
            })
            .is_err());
        state
            .execute(Command::Verdict {
                address: "10.0.0.5".into(),
                advisory: "CVE-2021-23017".into(),
                status: VerificationStatus::Confirmed,
            })
            .unwrap();

        let snapshot = state.snapshot();
        let checklist = &snapshot["checklists"]["10.0.0.5"]["CVE-2021-23017"];
        assert_eq!(checklist["items"].as_array().unwrap().len(), 6);
        assert!(snapshot["notices"].as_array().unwrap().len() >= 2);

        let path = fx.workspace.graph_path();
        fx.coordinator.shutdown();
        let saved = Graph::load(&path).unwrap();
        assert_eq!(
            saved.hosts["10.0.0.5"].advisories[0]
                .record
                .verification_status,
            VerificationStatus::Confirmed
        );
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
        assert_eq!(
            host.ports["22/tcp"].facts[0].record.verification_status,
            VerificationStatus::Observed
        );
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

        let items = crate::parsers::nmap::parse(crate::parsers::nmap::SAMPLE).unwrap();
        state
            .execute(Command::Observations {
                items,
                ground: false,
            })
            .unwrap();
        // Deep research needs stack and route evidence first.
        let refused = ask(Tier::Research, "10.0.0.5").unwrap_err().to_string();
        assert!(
            refused.contains("[R] is not ready for 10.0.0.5"),
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
                    .contains("saved to chats/10.0.0.5.md"));
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
            .contains("[L] for 10.0.0.5 answered by local"));
    }

    #[test]
    fn two_sessions_get_different_ports() {
        let a = fixture();
        let b = fixture();
        assert_ne!(a.coordinator.info().port, b.coordinator.info().port);
        assert_ne!(a.coordinator.info().token, b.coordinator.info().token);
    }
}

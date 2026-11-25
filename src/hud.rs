//! `meow hud`: the companion terminal panel.
//!
//! It attaches to a live session over the coordinator WebSocket and shows
//! the host list, the selected host (what to update, its ports and paths),
//! the CVEs found on it by software version, the recon queue and the
//! notices. A catch-up box takes operator notes; `?` lists the keys. Panels
//! with nothing in them are left out. When no session is running it opens
//! the workspace files read-only.
//!
//! This is a separate process from the PTY host, so reading terminal events
//! with crossterm is fine here.

use std::cell::Cell;
use std::io::IsTerminal;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap};
use ratatui::Frame;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::ai::{Budget, Tier};
use crate::coordinator::{AiStatus, Command, Notice};
use crate::cve;
use crate::db::Db;
use crate::evidence::{sanitize, Confidence, Source};
use crate::graph::{Advisory, Fact, Graph, Host, LocalNet, PathNode, Port};
use crate::mode::Mode;
use crate::observer::{active_vpns, machine_report, MachineReport};
use crate::queue::{self, StageRow, TaskRow};
use crate::timeutil::parse_rfc3339;
use crate::topology::{host_os, host_role, only_mentioned};
use crate::workspace::Workspace;

const MAX_PATH_LINES: usize = 40;
const MAX_FACT_LINES: usize = 60;
/// The longest note the catch-up box takes from a paste: what the graph
/// keeps of a note.
const NOTE_MAX: usize = crate::evidence::EVIDENCE_MAX;
/// An AI reply cut off by the end of its session.
const AI_STOPPED: &str = "stopped: the session ended";

/// What the coordinator pushes on every change.
#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    pub session: String,
    pub mode: Mode,
    pub graph: Graph,
    #[serde(default)]
    pub tasks: Vec<TaskRow>,
    #[serde(default)]
    pub notices: Vec<Notice>,
    #[serde(default)]
    pub ai: AiStatus,
    #[serde(default)]
    pub budget: Budget,
    /// The session's clock when it sent this: the stage times count from it.
    #[serde(default)]
    pub now_utc: String,
}

impl Snapshot {
    /// Reads the workspace files directly, for when no session is running.
    pub fn offline(workspace: &Workspace) -> Result<Self> {
        let mut tasks = if workspace.state_db_path().symlink_metadata().is_ok() {
            queue::tasks(&Db::open(&workspace.state_db_path())?, 20)?
        } else {
            Vec::new()
        };
        // A session that was killed left its stages as they were.
        queue::show_ended(&mut tasks);
        Ok(Self {
            session: sanitize(&workspace.name, 80),
            mode: workspace.profile.mode,
            graph: Graph::load(&workspace.graph_path())?,
            tasks,
            notices: Vec::new(),
            ai: AiStatus::default(),
            budget: Budget::default(),
            now_utc: String::new(),
        })
    }
}

/// How far one running stage is, as a `progress` message says it.
#[derive(Debug, Deserialize)]
struct Tick {
    task: i64,
    stage: queue::Stage,
    #[serde(default)]
    progress: queue::Progress,
}

/// The most stages one `progress` message is read for.
const MAX_TICKS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Hosts,
    Advisories,
}

#[derive(Debug, PartialEq)]
pub enum Action {
    None,
    Quit,
    Send(Command),
}

pub struct Model {
    pub snapshot: Option<Snapshot>,
    /// A live session is attached (commands can be sent).
    pub live: bool,
    pub focus: Focus,
    host_index: usize,
    advisory_index: usize,
    inspector_scroll: u16,
    /// How far the panel under it can scroll, as the last frame drew it.
    scroll_limit: Cell<u16>,
    /// What the status says once the session accepts the last command.
    sent: Option<String>,
    /// The note being typed in the catch-up box, if it is open.
    pub note: Option<String>,
    pub status: String,
    /// The upper-right panel shows the AI reply instead of the inspector.
    pub show_ai: bool,
    /// The upper-right panel shows everything known about this machine.
    pub show_machine: bool,
    /// The key card (`?`) is open over the panel.
    pub help: bool,
    /// The session this panel was attached to has ended.
    ended: bool,
    /// How long ago the snapshot arrived: a running stage's clock goes on
    /// between two of them.
    pub age: Duration,
    /// How far the snapshot's `now_utc` was behind the session's clock when
    /// it arrived, as far as the stamps before it tell.
    pub lead: Duration,
    sync: ClockSync,
}

/// The session's clock, read from the stamps it sends. A stamp is cut to
/// whole seconds, so it is up to a second behind when it arrives: of
/// several readings the one furthest ahead is the nearest. The map page
/// reads the clock the same way, so both show the same second.
#[derive(Debug, Clone, Copy)]
struct ClockSync {
    /// Where this panel's own steady clock starts.
    since: std::time::Instant,
    /// The session's clock less this panel's, in milliseconds.
    offset: Option<i128>,
}

impl ClockSync {
    fn new() -> Self {
        Self {
            since: std::time::Instant::now(),
            offset: None,
        }
    }

    /// Takes the stamp of a state that arrived just now; returns how far
    /// behind the session's clock it is.
    fn read(&mut self, stamp: SystemTime) -> Duration {
        let session = stamp
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as i128);
        self.behind(session - self.since.elapsed().as_millis() as i128)
    }

    /// `fresh`: the session's clock less this panel's, by the stamp just
    /// read.
    fn behind(&mut self, fresh: i128) -> Duration {
        let best = match self.offset {
            // The same clock: the reading furthest ahead is the nearest.
            Some(known) if (fresh - known).abs() < 2000 => known.max(fresh),
            // The first reading, or the session's clock was set.
            _ => fresh,
        };
        self.offset = Some(best);
        Duration::from_millis(u64::try_from(best - fresh).unwrap_or(0))
    }
}

impl Model {
    pub fn new(live: bool) -> Self {
        Self {
            snapshot: None,
            live,
            focus: Focus::Hosts,
            host_index: 0,
            advisory_index: 0,
            inspector_scroll: 0,
            scroll_limit: Cell::new(u16::MAX),
            sent: None,
            note: None,
            status: String::new(),
            show_ai: false,
            show_machine: false,
            help: false,
            ended: false,
            age: Duration::ZERO,
            lead: Duration::ZERO,
            sync: ClockSync::new(),
        }
    }

    /// The session is gone, and its recons ended with it: the running
    /// stage stopped, the rest left out. Shown as the next session will
    /// find them.
    pub fn session_ended(&mut self) {
        self.live = false;
        // The header says so.
        self.ended = true;
        if let Some(snapshot) = &mut self.snapshot {
            queue::show_ended(&mut snapshot.tasks);
            // A reply cut off by the end is not coming.
            if snapshot.ai.running {
                snapshot.ai.running = false;
                snapshot.ai.error = Some(AI_STOPPED.to_owned());
            }
        }
    }

    /// What the session sent cannot be read: said, and the HUD stops
    /// reading.
    pub fn cannot_read(&mut self, error: &str) {
        self.status = format!("Cannot read the session: {}", sanitize(error, 200));
        self.session_ended();
    }

    /// A stage is running: its clock is worth drawing every second.
    pub fn has_running_stage(&self) -> bool {
        self.snapshot.as_ref().is_some_and(|snapshot| {
            snapshot
                .tasks
                .iter()
                .any(|task| task.stages.iter().any(|stage| stage.status == "running"))
        })
    }

    /// Machines that were seen first; names that were only printed in the
    /// terminal come after them.
    pub fn hosts(&self) -> Vec<&Host> {
        let mut hosts: Vec<&Host> = self
            .snapshot
            .as_ref()
            .map(|s| s.graph.hosts.values().collect())
            .unwrap_or_default();
        hosts.sort_by_key(|host| only_mentioned(host));
        hosts
    }

    pub fn selected_host(&self) -> Option<&Host> {
        self.hosts().get(self.host_index).copied()
    }

    /// The selected host's CVEs, most urgent first: known exploited, then
    /// by score.
    pub fn advisories(&self) -> Vec<&Advisory> {
        let mut list: Vec<&Advisory> = self
            .selected_host()
            .map(|h| h.advisories.iter().collect())
            .unwrap_or_default();
        list.sort_by(|a, b| cve::cmp_urgency(a, b));
        list
    }

    pub fn selected_advisory(&self) -> Option<&Advisory> {
        self.advisories().get(self.advisory_index).copied()
    }

    /// The panel the arrow keys move in: the CVE list only while the
    /// selected host has CVEs to move through.
    pub fn focused(&self) -> Focus {
        match self.focus {
            Focus::Advisories if self.advisories().is_empty() => Focus::Hosts,
            focus => focus,
        }
    }

    /// What a key that needs the session says without one.
    fn not_live(&self) -> String {
        match &self.snapshot {
            Some(snapshot) => format!("No session running: `meow {}` starts it", snapshot.session),
            None => "No session running".to_owned(),
        }
    }

    fn clamp(&mut self) {
        self.host_index = self.host_index.min(self.hosts().len().saturating_sub(1));
        self.advisory_index = self
            .advisory_index
            .min(self.advisories().len().saturating_sub(1));
    }

    /// Handles one text message from the coordinator.
    pub fn apply_message(&mut self, text: &str) {
        let Ok(message) = serde_json::from_str::<Value>(text) else {
            return;
        };
        match message.get("type").and_then(Value::as_str) {
            Some("state") => {
                // Keep the selection on the same host and the same CVE
                // across updates: a new match that ranks higher must not put
                // another one under the cursor.
                let selected = self.selected_host().map(|h| h.address.clone());
                let advisory = self.selected_advisory().map(|a| a.id.clone());
                match serde_json::from_value::<Snapshot>(message["state"].clone()) {
                    Ok(mut snapshot) => {
                        snapshot.session = sanitize(&snapshot.session, 80);
                        snapshot.graph.sanitize_loaded();
                        for notice in &mut snapshot.notices {
                            notice.at = sanitize(&notice.at, 40);
                            notice.text = sanitize(&notice.text, 400);
                        }
                        if let Some(address) = &mut snapshot.ai.address {
                            *address = sanitize(address, 120);
                        }
                        snapshot.now_utc = sanitize(&snapshot.now_utc, 40);
                        self.lead = parse_rfc3339(&snapshot.now_utc)
                            .map_or(Duration::ZERO, |stamp| self.sync.read(stamp));
                        self.snapshot = Some(snapshot);
                        self.age = Duration::ZERO;
                    }
                    Err(error) => {
                        self.status =
                            format!("Unreadable state: {}", sanitize(&error.to_string(), 200))
                    }
                }
                if let Some(address) = selected {
                    if let Some(index) = self.hosts().iter().position(|h| h.address == address) {
                        self.host_index = index;
                    }
                }
                if let Some(id) = advisory {
                    if let Some(index) = self.advisories().iter().position(|a| a.id == id) {
                        self.advisory_index = index;
                    }
                }
                self.clamp();
            }
            // How far the running stages are, and nothing else: sent while
            // a tool counts its results, in place of the whole state.
            Some("progress") => {
                let Some(snapshot) = &mut self.snapshot else {
                    return;
                };
                let said: Vec<Tick> = message
                    .get("running")
                    .and_then(Value::as_array)
                    .map(|running| {
                        running
                            .iter()
                            .take(MAX_TICKS)
                            .filter_map(|tick| serde_json::from_value(tick.clone()).ok())
                            .collect()
                    })
                    .unwrap_or_default();
                for task in &mut snapshot.tasks {
                    for stage in task.stages.iter_mut().filter(|s| s.status == "running") {
                        stage.progress = said
                            .iter()
                            .find(|tick| tick.task == task.id && tick.stage == stage.stage)
                            .map(|tick| tick.progress.clone());
                    }
                }
                // The time left counts from this message's clock.
                if let Some(now) = message.get("now_utc").and_then(Value::as_str) {
                    snapshot.now_utc = sanitize(now, 40);
                    self.lead = parse_rfc3339(&snapshot.now_utc)
                        .map_or(Duration::ZERO, |stamp| self.sync.read(stamp));
                    self.age = Duration::ZERO;
                }
            }
            // The AI reply so far, and nothing else: sent while it streams
            // in, in place of the whole state.
            Some("ai") => {
                let Some(snapshot) = &mut self.snapshot else {
                    return;
                };
                if let Ok(mut ai) = serde_json::from_value::<AiStatus>(message["ai"].clone()) {
                    if let Some(address) = &mut ai.address {
                        *address = sanitize(address, 120);
                    }
                    snapshot.ai = ai;
                }
            }
            Some("result") => {
                self.status = match message.get("ok").and_then(Value::as_bool) {
                    Some(true) => self.sent.take().unwrap_or_else(|| "Done".to_owned()),
                    _ => format!(
                        "Refused: {}",
                        sanitize(
                            message
                                .get("error")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown error"),
                            200
                        )
                    ),
                };
            }
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: isize) {
        // A CVE list that emptied hands the arrows back to the hosts.
        self.focus = self.focused();
        let (index, len) = match self.focus {
            Focus::Hosts => (
                &mut self.host_index,
                self.snapshot.as_ref().map_or(0, |s| s.graph.hosts.len()),
            ),
            Focus::Advisories => {
                let len = self.selected_host().map_or(0, |h| h.advisories.len());
                (&mut self.advisory_index, len)
            }
        };
        if len == 0 {
            return;
        }
        *index = (*index as isize + delta).clamp(0, len as isize - 1) as usize;
        if self.focus == Focus::Hosts {
            self.advisory_index = 0;
            self.inspector_scroll = 0;
        }
    }

    fn ask_ai(&mut self, tier: Tier) -> Action {
        let Some(host) = self.selected_host() else {
            self.status = "Select a host first".to_owned();
            return Action::None;
        };
        let command = Command::Ai {
            tier,
            address: host.address.clone(),
        };
        if self.live {
            self.show_ai = true;
            self.inspector_scroll = 0;
            // The AI panel says how it goes.
            self.sent = Some(String::new());
        }
        Action::Send(command)
    }

    /// Handles text pasted into the terminal. It is text for the catch-up
    /// box and nothing else: a line break in it does not send the note, and
    /// what follows does not run as keys (a mode, an AI request).
    /// With the box closed a paste does nothing.
    pub fn on_paste(&mut self, text: &str) -> Action {
        if let Some(note) = &mut self.note {
            let need_space = !note.is_empty() && !note.ends_with(' ');
            let room = NOTE_MAX.saturating_sub(note.len() + usize::from(need_space));
            if room > 0 {
                let clean = sanitize(text, room);
                if !clean.is_empty() {
                    if need_space {
                        note.push(' ');
                    }
                    for ch in clean.chars() {
                        if note.len() + ch.len_utf8() > NOTE_MAX {
                            break;
                        }
                        note.push(ch);
                    }
                }
            }
        }
        Action::None
    }

    /// Handles one key press and says what, if anything, to do about it.
    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        // The catch-up box captures all typing while it is open.
        if let Some(note) = &mut self.note {
            match key.code {
                KeyCode::Esc => self.note = None,
                KeyCode::Backspace => {
                    note.pop();
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    note.clear();
                }
                KeyCode::Delete => {
                    note.clear();
                }
                KeyCode::Char(_)
                    if key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {}
                KeyCode::Char(ch) if !ch.is_control() && !crate::evidence::is_hidden(ch) => {
                    if note.len() + ch.len_utf8() <= NOTE_MAX {
                        note.push(ch);
                    }
                }
                KeyCode::Enter => {
                    let text = self.note.take().unwrap_or_default();
                    if text.trim().is_empty() {
                        return Action::None;
                    }
                    if !self.live {
                        self.status = self.not_live();
                        return Action::None;
                    }
                    self.sent = Some("Note saved".to_owned());
                    return Action::Send(Command::Note {
                        address: self.selected_host().map(|h| h.address.clone()),
                        text,
                    });
                }
                _ => {}
            }
            return Action::None;
        }
        // The key card closes on any key, which does nothing else.
        if self.help {
            self.help = false;
            return Action::None;
        }

        let action = match key.code {
            KeyCode::Char(_)
                if key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                Action::None
            }
            KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
                Action::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
                Action::None
            }
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                // To the CVE list only where there is one.
                self.focus = match self.focused() {
                    Focus::Hosts if !self.advisories().is_empty() => Focus::Advisories,
                    _ => Focus::Hosts,
                };
                Action::None
            }
            KeyCode::Char('?') => {
                self.help = true;
                Action::None
            }
            KeyCode::PageDown => {
                self.inspector_scroll = self
                    .inspector_scroll
                    .saturating_add(8)
                    .min(self.scroll_limit.get());
                Action::None
            }
            KeyCode::PageUp => {
                self.inspector_scroll = self.inspector_scroll.saturating_sub(8);
                Action::None
            }
            KeyCode::Char('n') => {
                self.note = Some(String::new());
                Action::None
            }
            KeyCode::Char('L') => self.ask_ai(Tier::Local),
            KeyCode::Char('C') => self.ask_ai(Tier::Cloud),
            KeyCode::Char('R') => self.ask_ai(Tier::Research),
            KeyCode::Char('a') => {
                self.show_ai = !self.show_ai;
                self.show_machine = false;
                self.inspector_scroll = 0;
                Action::None
            }
            KeyCode::Char('m') => {
                self.show_machine = !self.show_machine;
                self.show_ai = false;
                self.inspector_scroll = 0;
                Action::None
            }
            KeyCode::Char('1') => Action::Send(Command::SetMode { mode: Mode::Light }),
            KeyCode::Char('2') => Action::Send(Command::SetMode { mode: Mode::Mild }),
            KeyCode::Char('3') => Action::Send(Command::SetMode {
                mode: Mode::Aggressive,
            }),
            _ => Action::None,
        };
        if matches!(action, Action::Send(_)) && !self.live {
            self.status = self.not_live();
            return Action::None;
        }
        if let Action::Send(Command::SetMode { mode }) = &action {
            self.sent = Some(match mode {
                Mode::Light => "Mode: light \u{b7} 0 packets to hosts".to_owned(),
                Mode::Mild => "Mode: mild \u{b7} slow, rate-limited scans".to_owned(),
                Mode::Aggressive => {
                    "Mode: aggressive \u{b7} labs and authorized hosts only".to_owned()
                }
            });
        }
        action
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

use crate::theme::{BAD, BRAND, DIM, FOCUS, GOOD, SELECTED, TITLE, WARN};
/// Between the parts of a line: `3 hosts · 8 CVEs`.
const SEP: &str = " \u{b7} ";

/// Breaks `text` into lines of at most `width` characters at spaces; a word
/// longer than a line is split.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let width = width.max(8);
    let mut lines = vec![String::new()];
    let mut used = 0;
    for word in text.split(' ').filter(|word| !word.is_empty()) {
        let mut word: Vec<char> = word.chars().collect();
        if used > 0 && used + 1 + word.len() > width {
            lines.push(String::new());
            used = 0;
        }
        if used > 0 {
            lines.last_mut().expect("never empty").push(' ');
            used += 1;
        }
        while used + word.len() > width {
            let rest = word.split_off(width - used);
            lines.last_mut().expect("never empty").extend(word);
            lines.push(String::new());
            used = 0;
            word = rest;
        }
        used += word.len();
        lines.last_mut().expect("never empty").extend(word);
    }
    lines
}

fn panel(title: &str, focused: bool) -> Block<'_> {
    // The panel with the keys: a green border and a bold title.
    let (border, heading) = if focused { (FOCUS, TITLE) } else { (DIM, DIM) };
    Block::bordered()
        .title(Span::styled(format!(" {title} "), heading))
        .border_style(border)
}

/// How a list shows its selected row: black on lime while the list has the
/// keys, reversed when it does not. The row's own colours are dropped
/// (`plain`), so every part of it reads on either.
fn selected_style(focused: bool) -> Style {
    if focused {
        SELECTED
    } else {
        Style::new().add_modifier(Modifier::REVERSED)
    }
}

/// `line` without its colours: the selected row's highlight shows whole.
fn plain(line: Line<'_>) -> Line<'_> {
    Line::from(
        line.spans
            .into_iter()
            .map(|span| Span::raw(span.content))
            .collect::<Vec<_>>(),
    )
}

/// `$0.25`, and `$1` for a whole amount.
fn dollars(amount: f64) -> String {
    let cents = format!("{amount:.2}");
    match cents.strip_suffix(".00") {
        Some(whole) => format!("${whole}"),
        None => format!("${cents}"),
    }
}

/// `1 host`, `3 hosts`.
fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn width_of(spans: &[Span]) -> usize {
    spans.iter().map(Span::width).sum()
}

/// `parts` with ` · ` between them.
fn joined(parts: Vec<Span<'static>>) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for part in parts {
        if !spans.is_empty() {
            spans.push(Span::styled(SEP, DIM));
        }
        spans.push(part);
    }
    spans
}

fn path_lines(node: &PathNode, depth: usize, out: &mut Vec<Line<'static>>) {
    for (name, child) in &node.children {
        if out.len() >= MAX_PATH_LINES {
            return;
        }
        let slash = if child.children.is_empty() { "" } else { "/" };
        let status = child.status.map(|s| format!("  {s}")).unwrap_or_default();
        out.push(Line::from(vec![
            Span::raw(format!(
                "{}/{}{slash}",
                " ".repeat(COLUMN + 2 + 2 * depth),
                sanitize(name, 200)
            )),
            Span::styled(status, DIM),
        ]));
        path_lines(child, depth + 1, out);
    }
}

/// The host panel's title in `room` columns: the address and what the
/// host is, as far as it is known and fits: `192.0.2.10 · Server · Linux
/// 5.4`.
fn host_title(graph: &Graph, host: &Host, room: usize) -> String {
    let mut parts = vec![sanitize(&host.address, 120)];
    if !only_mentioned(host) {
        let (role, _) = host_role(graph, host);
        parts.push(role.title().to_owned());
        if let Some(os) = host_os(host) {
            let name = format!("{} {}", os.name.trim(), os.version.trim());
            if !name.trim().is_empty() {
                parts.push(sanitize(name.trim(), 120));
            }
            if os.guessed {
                parts.push("OS from a banner".to_owned());
            }
        }
    }
    while parts.len() > 1 && Span::raw(parts.join(SEP)).width() > room {
        parts.pop();
    }
    fit(&parts.join(SEP), room)
}

/// Facts about a host the panel already shows: the host is listed, its
/// OS is in the title and its names have a row of their own.
fn said_elsewhere(claim: &str) -> bool {
    claim == "host is up"
        || claim.starts_with("operating system: ")
        || claim.starts_with("hostname ")
}

/// Facts about a port the panel already shows: what the port is and its
/// state (`22/tcp ssh open`), its certificate names and its server.
fn said_on_port(claim: &str, port: &Port) -> bool {
    claim.starts_with(&format!("{} ", port.key()))
        || claim.starts_with("TLS certificate names ")
        || (claim.starts_with("HTTP Server header: ")
            && port.http.as_ref().is_some_and(|h| h.server.is_some()))
}

/// A fact as the panel says it: `ssh-hostkey 3072 SHA256:… (RSA)` for
/// `nmap script ssh-hostkey: …`, whose source says nmap.
fn fact_text(fact: &Fact) -> String {
    let claim = sanitize(&fact.claim, 300);
    match claim.strip_prefix("nmap script ") {
        Some(script) if fact.record.source == Source::NmapXml => script.replacen(": ", " ", 1),
        _ => claim,
    }
}

/// Where a fact came from, in a word.
fn source_word(source: Source) -> &'static str {
    match source {
        Source::PtyRegex => "terminal",
        Source::NmapXml => "nmap",
        Source::HttpHeader => "http",
        Source::TlsSan | Source::TlsCert => "tls",
        Source::KatanaJsonl => "katana",
        Source::FeroxJson => "feroxbuster",
        Source::NvdApi => "NVD",
        Source::OsvApi => "OSV",
        Source::CisaKev => "CISA",
        Source::ManualNote => "note",
        Source::LogRegex => "log",
        Source::GitDiff => "git diff",
        Source::LocalNet => "this machine",
        Source::Dns => "dns",
        Source::Rdap => "rdap",
        Source::AsnDns => "asn",
        Source::CtLog => "ct log",
        Source::SshKex => "ssh",
        Source::WafCdn => "waf/cdn",
        Source::Favicon => "favicon",
        Source::Traceroute => "traceroute",
        Source::JsScan => "js",
    }
}

/// The width of the labels in the host panel: `Update  `.
const COLUMN: usize = 8;

/// The selected host: what to update, its names, its ports and what else
/// was seen on it, each under a label. What it is, is in the panel's title.
/// Sections with nothing in them are left out.
fn inspector_lines(host: &Host, room: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if only_mentioned(host) {
        lines.push(Line::styled(
            "Mentioned in the shell \u{b7} not scanned",
            DIM,
        ));
    }
    let lead = |label: &str, first: bool| {
        let label = if first { label } else { "" };
        Span::styled(format!("{label:<COLUMN$}"), TITLE)
    };
    let under = || Span::raw(" ".repeat(COLUMN + 2));
    // What to do about the CVEs: one update per piece of software.
    let fixes = cve::fix_plan(host);
    for (index, fix) in fixes.iter().take(5).enumerate() {
        let update = format!(
            "{} to {}",
            sanitize(&fix.software, 200),
            sanitize(&fix.target, 120)
        );
        let close = fix
            .port
            .as_ref()
            .map(|port| format!("or close {}", sanitize(&cve::port_words(port), 80)));
        let cves = Span::styled(count(fix.advisories, "CVE", "CVEs"), DIM);
        let kev = (fix.kev > 0).then(|| Span::styled(format!("{} exploited", fix.kev), BAD));
        // As the map says it, on one row where it fits.
        let mut one = vec![lead("Update", index == 0)];
        let what = match &close {
            Some(close) => format!("{update}, {close}"),
            None => update.clone(),
        };
        one.extend(joined(
            [
                vec![Span::raw(what)],
                vec![cves.clone()],
                kev.clone().into_iter().collect(),
            ]
            .concat(),
        ));
        if width_of(&one) <= room {
            lines.push(Line::from(one));
            continue;
        }
        // Else what is exploited stays on the first row.
        let mut first = vec![lead("Update", index == 0)];
        first.extend(joined(
            [vec![Span::raw(update)], kev.into_iter().collect()].concat(),
        ));
        lines.push(Line::from(first));
        let mut rest = vec![under()];
        rest.extend(joined(
            [
                close
                    .map(|close| Span::styled(close, DIM))
                    .into_iter()
                    .collect(),
                vec![cves],
            ]
            .concat(),
        ));
        lines.push(Line::from(rest));
    }
    if fixes.len() > 5 {
        lines.push(Line::from(vec![
            lead("", false),
            Span::styled(format!("+{} more", fixes.len() - 5), DIM),
        ]));
    }
    if !host.hostnames.is_empty() {
        let names: Vec<&str> = host.hostnames.iter().map(String::as_str).collect();
        lines.push(Line::from(vec![
            lead("Names", true),
            Span::raw(sanitize(&names.join(", "), 300)),
        ]));
    }
    let mut ports: Vec<&Port> = host.ports.values().collect();
    ports.sort_by_key(|port| (port.number, port.protocol.clone()));
    for (index, port) in ports.iter().copied().enumerate() {
        // Open is what a port listed here usually is; any other state is said.
        let (state, style) = if port.is_open() {
            (String::new(), Style::new())
        } else {
            (format!(" {}", sanitize(&port.state, 40)), DIM)
        };
        lines.push(Line::from(vec![
            lead("Ports", index == 0),
            Span::styled(format!("{}{state}", sanitize(&port.label(), 300)), style),
        ]));
        let indent = " ".repeat(COLUMN + 2);
        if let Some(server) = port.http.as_ref().and_then(|h| h.server.as_ref()) {
            lines.push(Line::styled(
                format!("{indent}server {}", sanitize(server, 200)),
                DIM,
            ));
        }
        // Names the Names row does not have already.
        let names: Vec<&str> = port
            .tls_sans
            .iter()
            .filter(|name| !host.hostnames.contains(*name))
            .map(String::as_str)
            .collect();
        if !names.is_empty() {
            lines.push(Line::styled(
                format!("{indent}cert names {}", sanitize(&names.join(", "), 300)),
                DIM,
            ));
        }
        let mut paths = Vec::new();
        path_lines(&port.paths, 0, &mut paths);
        let truncated = paths.len() >= MAX_PATH_LINES;
        lines.extend(paths);
        if truncated {
            lines.push(Line::styled(format!("{indent}+ more paths"), DIM));
        }
    }
    let on_ports = ports.iter().flat_map(|port| {
        port.facts
            .iter()
            .filter(move |fact| !said_on_port(&fact.claim, port))
    });
    let facts: Vec<&Fact> = host
        .facts
        .iter()
        .filter(|fact| !said_elsewhere(&fact.claim))
        .chain(on_ports)
        .take(MAX_FACT_LINES)
        .collect();
    for (index, fact) in facts.into_iter().enumerate() {
        let unsure = if fact.record.confidence == Confidence::Low {
            " \u{b7} unsure"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            lead("Facts", index == 0),
            Span::raw(fact_text(fact)),
            Span::styled(
                format!("  {}{unsure}", source_word(fact.record.source)),
                DIM,
            ),
        ]));
    }
    lines
}

/// `Ubuntu backports fixes: check `dpkg -l` first`, from the longer note
/// the CVE lookups give; the note as it is if it does not read like one.
fn short_backport_note(note: &str) -> String {
    let distro = note.split(" backports").next().unwrap_or(note);
    match note.split('`').nth(1) {
        Some(command) if distro.len() < note.len() => {
            format!("{distro} backports fixes: check `{command}` first")
        }
        _ => format!("{note}."),
    }
}

/// A CVE's score, or its rating where it has no score.
fn score_of(advisory: &Advisory) -> String {
    match (advisory.cvss, cve::severity_word(advisory)) {
        (Some(score), _) => format!("{score:.1}"),
        (None, Some(word)) => word,
        (None, None) => "unrated".to_owned(),
    }
}

/// The selected CVE; its ID is the panel's title.
/// `listed`: the list row shows the score and, for one known exploited,
/// says so; the detail then does not say it again.
fn advisory_detail(host: &Host, advisory: &Advisory, listed: bool) -> Vec<Line<'static>> {
    let style = if cve::is_serious(advisory) { BAD } else { WARN };
    let mut head = Vec::new();
    match (cve::severity_word(advisory), listed) {
        (Some(word), true) => head.push(Span::styled(word, style)),
        _ => head.push(Span::styled(cve::severity_label(advisory), style)),
    }
    if advisory.kev && !listed {
        head.push(Span::styled("exploited", BAD));
    }
    // The software and version it was found from, and every port it runs on.
    let (found_from, ports) = cve::by_software(host)
        .into_iter()
        .find(|group| group.cves.iter().any(|a| a.id == advisory.id))
        .map(|group| (group.software, group.port))
        .unwrap_or_else(|| (advisory.matched.clone(), advisory.port.clone()));
    let mut from = vec![Span::styled(sanitize(&found_from, 200), DIM)];
    if let Some(ports) = &ports {
        from.push(Span::styled(sanitize(ports, 80), DIM));
    }
    let mut lines = vec![
        Line::from(joined(head)),
        Line::raw(sanitize(&advisory.title, 400)),
        Line::from(joined(from)),
    ];
    let fix = match (&advisory.fixed_in, &advisory.last_affected) {
        (Some(fixed), _) => Some(format!("Fixed in {fixed}")),
        (None, Some(last)) => Some(format!("Affected up to {last}: update past it")),
        (None, None) => None,
    };
    lines.extend(fix.map(|text| Line::styled(sanitize(&text, 120), GOOD)));
    lines.extend(
        cve::backport_note_for(host, advisory.port.as_deref())
            .map(|note| Line::styled(short_backport_note(note), DIM)),
    );
    lines
}

/// `en0  192.0.2.50/24  gateway 192.0.2.1` as its name and the rest.
fn interface_row(line: &str) -> (String, String) {
    let mut parts = line.split("  ").map(str::trim).filter(|p| !p.is_empty());
    let name = parts.next().unwrap_or_default();
    let rest: Vec<&str> = parts.collect();
    (sanitize(name, 40), sanitize(&rest.join(SEP), 300))
}

/// This machine's open ports, on one line: `22/tcp · 631/tcp local only`.
fn own_ports(lines: &[String]) -> Vec<Span<'static>> {
    let mut parts = Vec::new();
    for line in lines.iter().filter(|line| *line != "none listening") {
        match line.strip_prefix("this machine only: ") {
            Some(ports) => parts.push(Span::styled(
                format!("{} local only", sanitize(ports, 300)),
                DIM,
            )),
            None => parts.push(Span::raw(sanitize(line, 300))),
        }
    }
    joined(parts)
}

/// `line` in at most `room` columns, its spans keeping their styles: cut
/// with `…` where it is too long.
fn fit_line(line: Line<'static>, room: usize) -> Line<'static> {
    if line.width() <= room {
        return line;
    }
    let mut spans = Vec::new();
    let mut used = 0;
    for span in line.spans {
        let width = span.width();
        if used + width < room {
            used += width;
            spans.push(span);
            continue;
        }
        let cut = fit(&span.content, room - used);
        let cut = if cut.is_empty() {
            "\u{2026}".to_owned()
        } else {
            cut
        };
        spans.push(Span::styled(cut, span.style));
        break;
    }
    Line::from(spans)
}

/// A route warning in a few words, for the box: `No route to 192.0.2.7 ·
/// VPN down?`, `4444/tcp on eth0 · lab via tun0 · bind to 10.10.14.3 or
/// 0.0.0.0`. The `m` view has the whole sentence.
fn short_warning(warning: &str) -> String {
    if let Some((target, _)) = warning
        .strip_prefix("No route to ")
        .and_then(|rest| rest.split_once(": no local interface"))
    {
        return format!("No route to {target}{SEP}VPN down?");
    }
    let listener = warning.strip_prefix("Listener ").and_then(|rest| {
        let (socket, rest) = rest.split_once(" is bound to ")?;
        let (owner, rest) = rest.split_once(", but the lab is reached via ")?;
        let (lab, rest) = rest.split_once(": targets cannot connect back (")?;
        let hint = rest.strip_suffix(')')?;
        let (protocol, address) = socket.split_once('/')?;
        let port = address.rsplit(':').next()?;
        Some(format!(
            "{port}/{protocol} on {owner}{SEP}lab via {lab}{SEP}{hint}"
        ))
    });
    listener.unwrap_or_else(|| warning.to_owned())
}

/// What could not be read: the missing tools on one line (`ip, ss not
/// installed`), any other note as it is.
fn not_read(notes: &[String]) -> Vec<String> {
    const MISSING: &str = " is not installed in the system directories";
    let tools: Vec<&str> = notes
        .iter()
        .filter_map(|note| note.strip_suffix(MISSING))
        .map(|tool| tool.trim_matches('`'))
        .collect();
    let mut said = Vec::new();
    if !tools.is_empty() {
        said.push(format!("{} not installed", tools.join(", ")));
    }
    said.extend(
        notes
            .iter()
            .filter(|note| !note.ends_with(MISSING))
            .cloned(),
    );
    said
}

/// What this machine is and whether a VPN is up, in `room` columns:
/// `MacBook Pro · macOS 15.1 · VPN utun3`, or `no VPN` once the interfaces
/// were read and none is one. Where it does not fit, the OS and then the
/// kind of machine give way to the VPN. None before anything is read.
fn machine_headline(local: &LocalNet, room: usize) -> Option<Line<'static>> {
    let system = [
        local.system.kind.trim().to_owned(),
        format!("{} {}", local.system.os.trim(), local.system.version.trim())
            .trim()
            .to_owned(),
    ];
    let mut parts: Vec<Span> = system
        .into_iter()
        .filter(|part| !part.is_empty())
        .map(|part| Span::styled(sanitize(&part, 120), TITLE))
        .collect();
    let vpns: Vec<String> = active_vpns(local)
        .into_iter()
        .map(|(name, _)| sanitize(&name, 40))
        .collect();
    let vpn = if !vpns.is_empty() {
        Some(Span::styled(format!("VPN {}", vpns.join(", ")), GOOD))
    } else {
        (!local.interfaces.is_empty()).then(|| Span::styled("no VPN", WARN))
    };
    let all = |parts: &[Span<'static>]| joined([parts, vpn.as_slice()].concat());
    while !parts.is_empty() && vpn.is_some() && width_of(&all(&parts)) > room {
        parts.pop();
    }
    let line = all(&parts);
    (!line.is_empty()).then(|| fit_line(Line::from(line), room))
}

/// A `label  value` row; `wrap`: the value goes on under the label's
/// column instead of being cut.
struct Row {
    label: String,
    value: Vec<Span<'static>>,
    wrap: bool,
}

fn row(label: &str, value: Vec<Span<'static>>) -> Row {
    Row {
        label: label.to_owned(),
        value,
        wrap: false,
    }
}

/// Where the values of `rows` start: after the longest label.
fn label_column<'a>(rows: impl Iterator<Item = &'a Row>) -> usize {
    rows.map(|row| row.label.chars().count())
        .max()
        .unwrap_or(0)
        .min(12)
        + 2
}

/// Rows of `label  value` in `room` columns, the values from `column` on;
/// a label is not repeated on the rows under it.
fn label_rows(rows: Vec<Row>, room: usize, column: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut last = String::new();
    for row in rows {
        let shown = if row.label == last {
            ""
        } else {
            row.label.as_str()
        };
        let lead = Span::styled(format!("{shown:<column$}"), DIM);
        if row.wrap {
            let style = row.value.first().map_or(Style::new(), |span| span.style);
            let text: String = row.value.iter().map(|span| span.content.as_ref()).collect();
            for (index, piece) in wrap_words(&text, room.saturating_sub(column))
                .into_iter()
                .enumerate()
            {
                let lead = if index == 0 {
                    lead.clone()
                } else {
                    Span::raw(" ".repeat(column))
                };
                lines.push(Line::from(vec![lead, Span::styled(piece, style)]));
            }
        } else {
            let mut spans = vec![lead];
            spans.extend(row.value);
            lines.push(fit_line(Line::from(spans), room));
        }
        last = row.label;
    }
    lines
}

/// This machine in `room` columns: what it is and its VPN, the route
/// warnings, its open ports, the interfaces it uses and what could not be
/// read. `short`: the warnings in a few words, as the box shows them.
/// Also how many lines come before the ports: the box keeps those.
fn machine_rows(
    local: &LocalNet,
    report: &MachineReport,
    room: usize,
    short: bool,
) -> (Vec<Line<'static>>, usize) {
    let mut lines: Vec<Line> = machine_headline(local, room).into_iter().collect();
    let section = |title: &str| report.sections.iter().find(|s| s.title == title);
    let mut warnings = Vec::new();
    for warning in &local.warnings {
        let text = if short {
            short_warning(warning)
        } else {
            warning.clone()
        };
        warnings.push(Row {
            wrap: true,
            ..row("Warning", vec![Span::styled(sanitize(&text, 400), WARN)])
        });
    }
    let mut rows = Vec::new();
    if let Some(ports) = section("Open ports").map(|s| own_ports(&s.lines)) {
        if !ports.is_empty() {
            rows.push(row("Ports", ports));
        }
    }
    // Not read yet: what could not be read says why, if it failed.
    let interfaces = section("Interfaces").filter(|_| !local.interfaces.is_empty());
    for line in interfaces.iter().flat_map(|s| &s.lines) {
        if line.starts_with("not connected") {
            rows.push(row("Network", vec![Span::styled("not connected", WARN)]));
            continue;
        }
        let (name, rest) = interface_row(line);
        // The first line says it is a VPN.
        let rest = rest.replace(&format!("{SEP}VPN, "), SEP);
        rows.push(row(&name, vec![Span::raw(rest)]));
    }
    for note in not_read(&local.notes) {
        rows.push(Row {
            wrap: !short,
            ..row("Not read", vec![Span::styled(sanitize(&note, 300), WARN)])
        });
    }
    // One column for all, the warnings first.
    let column = label_column(warnings.iter().chain(&rows));
    lines.extend(label_rows(warnings, room, column));
    let pinned = lines.len();
    lines.extend(label_rows(rows, room, column));
    (lines, pinned)
}

/// Behind `m`, in place of the box: all of this machine, the warnings in
/// full, then its routes, neighbours and other interfaces and when it was
/// read.
fn machine_lines(local: &LocalNet, report: &MachineReport, room: usize) -> Vec<Line<'static>> {
    let (mut lines, _) = machine_rows(local, report, room, false);
    let used = report
        .sections
        .iter()
        .find(|s| s.title == "Interfaces")
        .map(|s| s.lines.clone())
        .unwrap_or_default();
    let in_box: Vec<String> = used.iter().map(|line| interface_row(line).0).collect();
    for section in report.sections.iter().filter(|section| !section.open) {
        let title = section.title.split(" (").next().unwrap_or(&section.title);
        let mut said = Vec::new();
        for line in section.lines.iter().filter(|line| *line != "none") {
            let line = match title {
                // The interface's row says its gateway.
                "Routes" if line.starts_with("default via ") => {
                    let gateway = line["default via ".len()..].split(' ').next();
                    match gateway {
                        Some(gateway) if used.iter().any(|u| u.contains(gateway)) => continue,
                        _ => line.clone(),
                    }
                }
                "Routes" => match line.strip_suffix(
                    " more left out: single hosts, multicast, link-local and idle interfaces",
                ) {
                    Some(left_out) => format!("+{left_out} more: host routes, multicast, idle"),
                    None => line.replace(" (directly attached)", " \u{b7} direct"),
                },
                "All interfaces" => {
                    if let Some((_, idle)) = line.split_once(" without a usable address: ") {
                        format!("no address: {idle}")
                    } else {
                        let parts: Vec<&str> = line.split("  ").collect();
                        if in_box
                            .iter()
                            .any(|name| Some(&name.as_str()) == parts.first())
                        {
                            continue;
                        }
                        let mut shown = vec![parts[0]];
                        shown.extend(parts.iter().skip(3));
                        if parts.get(2) == Some(&"down") {
                            shown.push("down");
                        }
                        shown.join(" ")
                    }
                }
                _ => line.clone(),
            };
            said.push(Line::raw(format!("  {}", sanitize(&line, 400))));
        }
        if said.is_empty() {
            continue;
        }
        let title = match title {
            "All interfaces" => "Other interfaces",
            other => other,
        };
        lines.push(Line::styled(title.to_owned(), TITLE));
        lines.extend(said);
    }
    match report.observed_utc.get(11..19) {
        Some(time) => {
            lines.push(Line::styled(
                format!("Read {time} UTC \u{b7} nothing sent"),
                DIM,
            ));
        }
        None if lines.is_empty() => lines.push(Line::styled("Not read yet", DIM)),
        None => {}
    }
    lines
}

/// The top line: the session, its mode and what was found, numbers first.
/// What does not fit gives way: the host count (the list has them), the
/// cloud AI spend, the CVE count; the session, its mode, what is exploited
/// and the cloud AI near its daily cap stay.
fn draw_header(frame: &mut Frame, area: Rect, model: &Model) {
    let Some(snapshot) = &model.snapshot else {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" =^..^= meow hud ", BRAND),
                Span::styled(
                    match model.ended {
                        true => "\u{b7} session ended",
                        false => "\u{b7} waiting for the session",
                    },
                    DIM,
                ),
            ])),
            area,
        );
        return;
    };
    let graph = &snapshot.graph;
    let mode_style = match snapshot.mode {
        Mode::Light => GOOD,
        Mode::Mild => WARN,
        Mode::Aggressive => BAD,
    };
    let seen = graph.hosts.values().filter(|h| !only_mentioned(h)).count();
    let cves = graph.advisory_count();
    let exploited = graph
        .hosts
        .values()
        .flat_map(|host| &host.advisories)
        .filter(|advisory| advisory.kev)
        .count();
    // Which part goes first where the line is too narrow: the highest
    // number; 0 stays.
    let mut parts: Vec<(u8, Span<'static>)> =
        vec![(0, Span::styled(snapshot.mode.as_str(), mode_style))];
    if !model.live {
        let said = if model.ended {
            "session ended"
        } else {
            "no session"
        };
        parts.push((0, Span::styled(said, WARN)));
    }
    if seen > 0 {
        parts.push((4, Span::raw(count(seen, "host", "hosts"))));
    }
    if cves > 0 {
        parts.push((2, Span::raw(count(cves, "CVE", "CVEs"))));
    }
    if exploited > 0 {
        parts.push((1, Span::styled(format!("{exploited} exploited"), BAD)));
    }
    let budget = &snapshot.budget;
    // What calls still running set aside may yet be given back.
    let capped = budget.calls >= budget.max_calls
        || budget.spent_usd - budget.held_usd.max(0.0) >= budget.max_usd;
    if budget.has_key && budget.usage_unreadable {
        parts.push((1, Span::styled("cloud AI off: ai-usage unreadable", WARN)));
    } else if budget.has_key && capped {
        // C asks local AI and R is off until tomorrow.
        parts.push((1, Span::styled("cloud AI cap reached", BAD)));
    } else if budget.has_key {
        // Near the cap, the spend and the calls stay longest.
        let near = budget.spent_usd * 4.0 >= budget.max_usd * 3.0;
        let spent = format!(
            "cloud AI {}/{} today",
            dollars(budget.spent_usd),
            dollars(budget.max_usd)
        );
        parts.push(match near {
            true => (1, Span::styled(spent, WARN)),
            false => (3, Span::styled(spent, DIM)),
        });
        // The calls only once they, not the spend, are near the cap.
        if budget.calls * 4 >= budget.max_calls * 3 {
            let calls = format!("{}/{} calls", budget.calls, budget.max_calls);
            parts.push((1, Span::styled(calls, WARN)));
        }
    } else if budget.setup_unreadable {
        let file = match budget.config_unreadable {
            true => "cloud AI off: config.toml unreadable",
            false => "cloud AI off: ai.toml unreadable",
        };
        parts.push((1, Span::styled(file, WARN)));
    }
    // The session on a lime badge; the separator's first space pads it.
    let head = Span::styled(format!(" =^..^= {}", snapshot.session), BRAND);
    let line = |parts: &[(u8, Span<'static>)]| {
        let mut spans = vec![head.clone()];
        for (at, (_, part)) in parts.iter().enumerate() {
            if at == 0 {
                spans.push(Span::styled(" ", BRAND));
                spans.push(Span::styled(&SEP[1..], DIM));
            } else {
                spans.push(Span::styled(SEP, DIM));
            }
            spans.push(part.clone());
        }
        spans
    };
    while width_of(&line(&parts)) > area.width as usize {
        let Some(last) = parts.iter().map(|(keep, _)| *keep).max().filter(|k| *k > 0) else {
            break;
        };
        let at = parts
            .iter()
            .rposition(|(keep, _)| *keep == last)
            .expect("found");
        parts.remove(at);
    }
    frame.render_widget(Paragraph::new(Line::from(line(&parts))), area);
}

/// One row of the host list in `room` columns: the host and what is on
/// it, as much as fits (`192.0.2.10  3 ports · 4 CVEs · 1 exploited`). The
/// ports give way first, then the name, then the CVE count; where no count
/// fits, the address alone in the colour of the worst of it.
fn host_row(host: &Host, room: usize) -> Line<'static> {
    if only_mentioned(host) {
        // A name from a URL in the terminal, not a machine seen.
        let row = format!("{}  mentioned", host.label());
        if Span::raw(row.as_str()).width() <= room {
            return Line::styled(row, DIM);
        }
        return Line::styled(fit(&host.label(), room), DIM);
    }
    let style = if host.advisories.iter().any(cve::is_serious) {
        BAD
    } else {
        WARN
    };
    let ports = host.open_ports().count();
    let cves = host.advisories.len();
    let exploited = host.advisories.iter().filter(|a| a.kev).count();
    let ports = (ports > 0).then(|| Span::styled(count(ports, "port", "ports"), DIM));
    let cves = (cves > 0).then(|| Span::styled(count(cves, "CVE", "CVEs"), style));
    let exploited = (exploited > 0).then(|| Span::styled(format!("{exploited} exploited"), BAD));
    let label = host.label();
    let named = label != host.address;
    let all = vec![ports.clone(), cves.clone(), exploited.clone()];
    let urgent = vec![cves.clone(), exploited.clone()];
    let mut options = Vec::new();
    if named {
        options.push((label.as_str(), all.clone()));
        options.push((label.as_str(), urgent.clone()));
    }
    options.push((host.address.as_str(), all));
    options.push((host.address.as_str(), urgent));
    options.push((host.address.as_str(), vec![exploited.clone()]));
    options.push((host.address.as_str(), vec![cves.clone()]));
    for (label, option) in options {
        let parts: Vec<Span<'static>> = option.into_iter().flatten().collect();
        if parts.is_empty() {
            continue;
        }
        let mut spans = vec![Span::raw(label.to_owned()), Span::raw("  ")];
        spans.extend(joined(parts));
        if width_of(&spans) <= room {
            return Line::from(spans);
        }
    }
    let colour = match (exploited, cves) {
        (Some(_), _) => BAD,
        (None, Some(_)) => style,
        (None, None) => Style::new(),
    };
    if named && Span::raw(label.as_str()).width() <= room {
        return Line::styled(label, colour);
    }
    Line::styled(fit(&host.address, room), colour)
}

fn draw_hosts(frame: &mut Frame, area: Rect, model: &Model) {
    let room = (area.width as usize).saturating_sub(2);
    let items: Vec<ListItem> = model
        .hosts()
        .iter()
        .enumerate()
        .map(|(index, host)| match index == model.host_index {
            true => ListItem::new(plain(host_row(host, room))),
            false => ListItem::new(host_row(host, room)),
        })
        .collect();
    let focused = model.focused() == Focus::Hosts;
    let list = List::new(items)
        .block(panel("Hosts", focused))
        .highlight_style(selected_style(focused));
    let mut state = ListState::default().with_selected(Some(model.host_index));
    frame.render_stateful_widget(list, area, &mut state);
}

/// The selected host's CVEs, most urgent first, and the one selected. Only
/// drawn for a host that has CVEs.
fn draw_advisories(frame: &mut Frame, area: Rect, model: &Model) {
    let advisories = model.advisories();
    let row = |advisory: &Advisory, exploited: bool| {
        let style = if cve::is_serious(advisory) { BAD } else { WARN };
        let mut spans = vec![
            Span::raw(advisory.id.clone()),
            Span::styled(format!("  {}", score_of(advisory)), style),
        ];
        if exploited && advisory.kev {
            spans.push(Span::styled("  exploited", BAD));
        }
        spans
    };
    // As wide as its rows need, from a third to three fifths of the panel.
    let wanted = advisories
        .iter()
        .map(|advisory| width_of(&row(advisory, true)) + 2)
        .max()
        .unwrap_or(0) as u16;
    let list_width = wanted.clamp(area.width / 3, area.width * 3 / 5);
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Length(list_width), Constraint::Min(0)]).areas(area);
    let room = (list_width as usize).saturating_sub(2);
    let fits = |advisory: &Advisory| width_of(&row(advisory, true)) <= room;
    let items: Vec<ListItem> = advisories
        .iter()
        .enumerate()
        .map(|(index, advisory)| {
            // Too narrow for the word: the colour and the detail say it.
            let line = fit_line(Line::from(row(advisory, fits(advisory))), room);
            match index == model.advisory_index {
                true => ListItem::new(plain(line)),
                false => ListItem::new(line),
            }
        })
        .collect();
    // How many: the host's row says it.
    let focused = model.focused() == Focus::Advisories;
    let list = List::new(items)
        .block(panel("CVEs", focused))
        .highlight_style(selected_style(focused));
    let mut state = ListState::default()
        .with_selected((!advisories.is_empty()).then_some(model.advisory_index));
    frame.render_stateful_widget(list, list_area, &mut state);

    if let (Some(host), Some(advisory)) = (model.selected_host(), model.selected_advisory()) {
        frame.render_widget(
            Paragraph::new(advisory_detail(host, advisory, fits(advisory)))
                .wrap(Wrap { trim: false })
                .block(panel(
                    &fit(
                        &sanitize(&advisory.id, 80),
                        (detail_area.width as usize).saturating_sub(2),
                    ),
                    false,
                )),
            detail_area,
        );
    }
}

/// The session's clock, carried on by this panel's own since the snapshot
/// arrived. Nothing is counted from this machine's idea of the date.
struct Clock {
    now: Option<SystemTime>,
    age: Duration,
}

impl Clock {
    /// How long ago `started_utc` was.
    fn since(&self, started_utc: Option<&str>) -> Option<Duration> {
        let started = parse_rfc3339(started_utc?)?;
        Some(self.now?.duration_since(started).unwrap_or_default() + self.age)
    }
}

/// `0:42`, `12:05`, `1:02:03`.
fn clock_time(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    match secs / 3600 {
        0 => format!("{}:{:02}", secs / 60, secs % 60),
        hours => format!("{hours}:{:02}:{:02}", secs % 3600 / 60, secs % 60),
    }
}

/// `45s`, `12m`, `1h05m`: time left, which is an estimate. From a minute
/// on it is the nearest minute, as on the map (`about 12 min left`).
fn rough_time(secs: u64) -> String {
    let minutes = (secs + 30) / 60;
    match (secs, minutes) {
        (0..60, _) => format!("{secs}s"),
        (_, 0..60) => format!("{minutes}m"),
        _ => format!("{}h{:02}m", minutes / 60, minutes % 60),
    }
}

/// `text` in at most `room` columns: cut with `…` where it is too long,
/// and nothing at all where not even a few letters of it fit.
fn fit(text: &str, room: usize) -> String {
    if Span::raw(text).width() <= room {
        return text.to_owned();
    }
    if room < 4 {
        return String::new();
    }
    let mut cut = String::new();
    for c in text.chars() {
        cut.push(c);
        if Span::raw(cut.as_str()).width() > room - 1 {
            cut.pop();
            break;
        }
    }
    format!("{}…", cut.trim_end())
}

/// One cell of a task's bar: each status has a mark and a colour of its
/// own, so it reads without colours too.
fn stage_cell(status: &str) -> Span<'static> {
    let (mark, style) = match status {
        "done" => ("█", GOOD),
        "running" => (">", WARN.add_modifier(Modifier::BOLD)),
        "failed" => ("x", BAD),
        "interrupted" => ("!", Style::new().fg(Color::Magenta)),
        "skipped" => ("-", Style::new().fg(Color::Blue)),
        _ => ("·", DIM),
    };
    Span::styled(mark, style)
}

/// What a task is doing now, in at most `width` columns: `ports 0:42 ·
/// SYN Stealth Scan 12% (56s left)` for a running stage, `ports stopped`
/// for one that was cut off, `waiting` before the first, `stopped` for one
/// whose session ended with no stage running, `not run` for one it ended
/// before it began. Empty for a task that is over.
fn current_stage(task: &TaskRow, clock: &Clock, width: usize) -> Vec<Span<'static>> {
    let Some(stage) = task
        .stages
        .iter()
        .find(|s| matches!(s.status.as_str(), "running" | "interrupted" | "pending"))
    else {
        if dropped(task) {
            return vec![Span::styled("not run", Style::new().fg(Color::Magenta))];
        }
        if task.stages.iter().any(StageRow::not_run) {
            return vec![Span::styled("stopped", Style::new().fg(Color::Magenta))];
        }
        return Vec::new();
    };
    let name = stage.stage.as_str();
    match stage.status.as_str() {
        "running" => running_stage(name, stage, clock, width),
        "interrupted" => vec![Span::styled(
            format!("{name} stopped"),
            Style::new().fg(Color::Magenta),
        )],
        _ if task.stages.iter().all(|s| s.status == "pending") => {
            vec![Span::styled("waiting", DIM)]
        }
        _ => vec![Span::styled(format!("{name} waiting"), DIM)],
    }
}

/// A running stage in at most `width` columns: its name, how many of its
/// items are done and how long it has run; then what its tool is on, with
/// the tool's own figures: `services 1/4 0:42 · Service scan 12% (56s
/// left)`. A percent and a time left are those of the scan named before
/// them, not of the stage: nmap starts both over with each of its scans.
fn running_stage(name: &str, stage: &StageRow, clock: &Clock, width: usize) -> Vec<Span<'static>> {
    let (mut items, mut percent, mut note, mut left) =
        (String::new(), String::new(), String::new(), String::new());
    if let Some(progress) = &stage.progress {
        if let (Some(done), Some(total)) = (progress.done, progress.total) {
            items = format!("{done}/{total}");
        }
        if let Some(value) = progress.percent {
            percent = format!("{}%", value.min(100));
        }
        // What the tool says in words: the scan a percent is of, or all
        // there is (`412 results so far`).
        if !percent.is_empty() || items.is_empty() {
            note = sanitize(progress.note.as_deref().unwrap_or(""), 80);
        }
        // The time left when the state was made, less the time since.
        if let Some(secs) = progress
            .eta_s
            .map(|secs| secs.saturating_sub(clock.age.as_secs()))
            .filter(|secs| *secs > 0)
        {
            left = format!(" ({} left)", rough_time(secs));
        }
    }
    let elapsed = clock
        .since(stage.started_utc.as_deref())
        .map(clock_time)
        .unwrap_or_default();
    let line = |items: &str, note: &str, percent: &str| {
        let join = |words: [&str; 3]| {
            let words: Vec<&str> = words.into_iter().filter(|word| !word.is_empty()).collect();
            words.join(" ")
        };
        let (stage, tool) = (join([name, items, &elapsed]), join([note, percent, ""]));
        if tool.is_empty() {
            stage
        } else {
            format!("{stage} \u{b7} {tool}")
        }
    };
    let fits = |text: &str, left: &str| Span::raw(text).width() + left.len() <= width;
    // In a narrow panel these give way, in this order: the time left, the
    // count, the tool's words (cut, then left out), the percent. The time
    // the stage has run is never cut: half a clock reads as another time.
    let whole = line(&items, &note, &percent);
    let (text, left) = if fits(&whole, &left) {
        (whole, left)
    } else if fits(&whole, "") {
        (whole, String::new())
    } else {
        let bare = line("", "", &percent);
        // A note takes a separator of three columns, or the space before
        // the percent.
        let taken = Span::raw(bare.as_str()).width() + if percent.is_empty() { 3 } else { 1 };
        let cut = fit(&note, width.saturating_sub(taken));
        let text = [
            line("", &note, &percent),
            line("", &cut, &percent),
            bare,
            line("", "", ""),
        ]
        .into_iter()
        .find(|text| fits(text, ""))
        .unwrap_or_else(|| match elapsed.is_empty() {
            true => name.to_owned(),
            false => elapsed.clone(),
        });
        (text, String::new())
    };
    let mut spans = vec![Span::styled(text, WARN.add_modifier(Modifier::BOLD))];
    if !left.is_empty() {
        spans.push(Span::styled(left, DIM));
    }
    spans
}

/// One target's recon as the queue panel shows it.
struct Shown<'a> {
    task: &'a TaskRow,
    /// Runs of the same target that wait behind this one.
    queued: usize,
    /// Newer runs of it that the end of a session dropped before they began.
    not_run: usize,
    /// Its other runs.
    earlier: usize,
    /// 0: a stage is running. 1: stages are left. 2: nothing is left.
    rank: u8,
}

/// Whether the end of a session dropped `task` before any of its stages ran.
fn dropped(task: &TaskRow) -> bool {
    task.stages.iter().any(StageRow::not_run)
        && !task
            .stages
            .iter()
            .any(|stage| matches!(stage.status.as_str(), "done" | "failed" | "interrupted"))
}

/// The recons to show, one for each target, in the order they matter: the
/// one that is running, those that wait (the next one first), then those
/// that are over (the newest first, those that never began last). Of a
/// target that was queued more than once, the run that has work to do: the
/// one that is running, else the oldest that waits (tasks run oldest
/// first), else the newest that began, else the newest. The map picks and
/// orders the same way.
fn shown_runs(tasks: &[TaskRow]) -> Vec<Shown<'_>> {
    let running = |task: &TaskRow| task.stages.iter().any(|stage| stage.status == "running");
    let mut shown: Vec<Shown> = Vec::new();
    // The session lists the newest first.
    for newest in tasks {
        if shown.iter().any(|run| run.task.target == newest.target) {
            continue;
        }
        let runs = || tasks.iter().filter(|task| task.target == newest.target);
        let task = runs()
            .find(|task| running(task))
            .or_else(|| runs().rfind(|task| task.unfinished()))
            .or_else(|| runs().find(|task| !dropped(task)))
            .unwrap_or(newest);
        let newer = || runs().filter(|run| run.id > task.id);
        let queued = newer().filter(|run| run.unfinished()).count();
        let not_run = newer()
            .filter(|run| !run.unfinished() && dropped(run))
            .count();
        shown.push(Shown {
            task,
            queued,
            not_run,
            earlier: runs().count() - 1 - queued - not_run,
            rank: match (running(task), task.unfinished()) {
                (true, _) => 0,
                (false, true) => 1,
                (false, false) => 2,
            },
        });
    }
    shown.sort_by_key(|run| {
        let turn = if run.rank == 1 {
            run.task.id
        } else {
            -run.task.id
        };
        (run.rank, dropped(run.task), turn)
    });
    shown
}

/// The progress of one task in `width` columns: its target, a bar with a
/// cell for every stage, how many stages are over, and what it is doing
/// now. On one line where that fits, on up to three where it does not,
/// the lines after the first indented so that only targets start a line.
fn task_lines(run: &Shown, clock: &Clock, width: usize) -> Vec<Line<'static>> {
    let task = run.task;
    let mut head = vec![Span::raw(sanitize(&task.target, 120))];
    let others: Vec<String> = [
        (run.queued, "queued"),
        (run.not_run, "not run"),
        (run.earlier, "earlier"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, what)| format!("+{count} {what}"))
    .collect();
    if !others.is_empty() {
        head.push(Span::styled(format!(" ({})", others.join(", ")), DIM));
    }
    // Stages the end of the session left out are not counted as over.
    let count = Span::raw(format!("{}/{}", task.stages_over(), task.stages.len()));
    // A panel too narrow for the bar still says how far the task is.
    let bar = if task.stages.len() + 1 + count.width() <= width {
        let mut bar: Vec<Span> = task.stages.iter().map(|s| stage_cell(&s.status)).collect();
        bar.push(Span::raw(" "));
        bar.push(count);
        bar
    } else {
        vec![count]
    };
    let mut lines = Vec::new();
    let mut line: Vec<Span> = Vec::new();
    let mut used = 0;
    // Nothing on the line yet but its indent.
    let mut fresh = true;
    // What it is doing may start a line of its own, after the indent.
    let now = current_stage(task, clock, width.saturating_sub(2));
    for part in [head, bar, now] {
        let part_width: usize = part.iter().map(Span::width).sum();
        if part_width == 0 {
            continue;
        }
        if !fresh && used + 2 + part_width > width {
            lines.push(Line::from(std::mem::take(&mut line)));
            used = 0;
            fresh = true;
            // Indented where that fits.
            if part_width + 2 <= width {
                line.push(Span::raw("  "));
                used = 2;
            }
        }
        if !fresh {
            line.push(Span::raw("  "));
            used += 2;
        }
        line.extend(part);
        used += part_width;
        fresh = false;
    }
    lines.push(Line::from(line));
    lines
}

/// The line under a task's bar. Of a recon that the end of its session cut
/// short: why (the row says where). Else the stages that failed, by name:
/// the bar's marks have none. Else what the latest stage with a result
/// said; why a stage was left out only where no stage has more to say.
fn said_under(task: &TaskRow) -> Option<String> {
    let of =
        |stage: &StageRow| format!("{}: {}", stage.stage.as_str(), sanitize(&stage.detail, 300));
    let cut = task
        .stages
        .iter()
        .any(|s| (s.status == "interrupted" && !s.live()) || s.not_run());
    if cut {
        return Some("session ended".to_owned());
    }
    let failed: Vec<&StageRow> = task
        .stages
        .iter()
        .filter(|stage| stage.status == "failed")
        .collect();
    match failed.as_slice() {
        [] => {}
        [one] if one.detail.is_empty() => return Some(format!("{} failed", one.stage.as_str())),
        [one] => {
            return Some(format!(
                "{} failed: {}",
                one.stage.as_str(),
                sanitize(&one.detail, 300)
            ))
        }
        many => {
            let names: Vec<&str> = many.iter().map(|stage| stage.stage.as_str()).collect();
            return Some(format!("failed: {}", names.join(", ")));
        }
    }
    let said = |skipped: bool| {
        task.stages
            .iter()
            .rev()
            .find(|s| !s.detail.is_empty() && (s.status == "skipped") == skipped)
    };
    said(false).or_else(|| said(true)).map(of)
}

/// The most recons the queue panel lays out.
const MAX_SHOWN: usize = 12;

/// What the marks of a task's bar stand for, where a row is free for it.
fn legend(width: usize) -> Option<Line<'static>> {
    let mut spans = Vec::new();
    for status in [
        "done",
        "running",
        "failed",
        "interrupted",
        "skipped",
        "pending",
    ] {
        if !spans.is_empty() {
            spans.push(Span::raw("  "));
        }
        spans.push(stage_cell(status));
        spans.push(Span::styled(
            format!(" {}", queue::status_word(status)),
            DIM,
        ));
    }
    let line = Line::from(spans);
    (line.width() <= width).then_some(line)
}

/// The queue panel's lines for `rows` rows of `room` columns. The recon
/// that is running comes first and keeps all its lines; where the panel is
/// too short, the lines under the others' bars go first, then whole recons
/// from the end, and the last row says how many were left out.
fn queue_lines(tasks: &[TaskRow], clock: &Clock, room: usize, rows: usize) -> Vec<Line<'static>> {
    let shown = shown_runs(tasks);
    if shown.is_empty() {
        return Vec::new();
    }
    struct Block {
        main: Vec<Line<'static>>,
        under: Vec<Line<'static>>,
        running: bool,
    }
    let mut blocks: Vec<Block> = shown
        .iter()
        .take(MAX_SHOWN)
        .map(|run| Block {
            main: task_lines(run, clock, room),
            under: said_under(run.task)
                .map(|said| {
                    wrap_words(&said, room.saturating_sub(4))
                        .into_iter()
                        .map(|piece| Line::styled(format!("    {piece}"), DIM))
                        .collect()
                })
                .unwrap_or_default(),
            running: run.rank == 0,
        })
        .collect();
    let height = |blocks: &[Block]| -> usize {
        blocks
            .iter()
            .map(|block| block.main.len() + block.under.len())
            .sum()
    };
    // Too many lines: first without what the others say under their bars.
    for index in (0..blocks.len()).rev() {
        if height(&blocks) <= rows {
            break;
        }
        if !blocks[index].running {
            blocks[index].under.clear();
        }
    }
    // Still too many: whole recons from the end, with a row to say so.
    let mut kept = blocks.len();
    let fits = |blocks: &[Block], kept: usize| {
        height(&blocks[..kept]) + usize::from(kept < shown.len()) <= rows
    };
    while kept > 1 && !fits(&blocks, kept) {
        kept -= 1;
    }
    // Not even the first one: without the line under its bar.
    if !fits(&blocks, kept) {
        blocks[0].under.clear();
    }
    let mut lines: Vec<Line> = blocks
        .drain(..kept)
        .flat_map(|block| block.main.into_iter().chain(block.under))
        .collect();
    let left_out = &shown[kept..];
    if !left_out.is_empty() {
        let what = if left_out.iter().all(|run| run.rank == 1) {
            "waiting"
        } else {
            "more"
        };
        lines.push(Line::styled(format!("+{} {what}", left_out.len()), DIM));
    } else if let Some(legend) = legend(room).filter(|_| lines.len() < rows) {
        // At the foot of the panel, where it is out of the way.
        lines.resize(rows - 1, Line::default());
        lines.push(legend);
    }
    lines
}

/// The recon queue and the notices, side by side; one of them alone takes
/// the whole row. The row is left out when both are empty.
fn draw_activity(frame: &mut Frame, area: Rect, model: &Model, snapshot: &Snapshot) {
    let (queue_area, notice_area) = match (snapshot.tasks.is_empty(), snapshot.notices.is_empty()) {
        (false, false) => {
            let [queue, notices] =
                Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .areas(area);
            (Some(queue), Some(notices))
        }
        (false, true) => (Some(area), None),
        (true, false) => (None, Some(area)),
        (true, true) => return,
    };
    if let Some(queue_area) = queue_area {
        let clock = Clock {
            now: parse_rfc3339(&snapshot.now_utc).map(|now| now + model.lead),
            age: model.age,
        };
        let lines = queue_lines(
            &snapshot.tasks,
            &clock,
            (queue_area.width as usize).saturating_sub(2),
            (queue_area.height as usize).saturating_sub(2),
        );
        frame.render_widget(
            Paragraph::new(lines).block(panel("Recon", false)),
            queue_area,
        );
    }
    let Some(notice_area) = notice_area else {
        return;
    };
    // Newest first, each one whole: a long notice continues on the next
    // line under its text instead of being cut at the border.
    let rows = notice_area.height.saturating_sub(2) as usize;
    let room = (notice_area.width as usize).saturating_sub(2 + 6);
    let mut notices: Vec<Line> = Vec::new();
    for notice in snapshot.notices.iter().rev() {
        if notices.len() >= rows {
            break;
        }
        let time = format!("{:<6}", notice.at.get(11..16).unwrap_or(""));
        for (index, piece) in wrap_words(&sanitize(&notice.text, 400), room)
            .into_iter()
            .enumerate()
        {
            let lead = if index == 0 {
                time.clone()
            } else {
                " ".repeat(6)
            };
            notices.push(Line::from(vec![Span::styled(lead, DIM), Span::raw(piece)]));
        }
    }
    notices.truncate(rows);
    frame.render_widget(
        Paragraph::new(notices).block(panel("Notices", false)),
        notice_area,
    );
}

/// The keys that do something now, as `key action` pairs, most needed
/// first; the rest are on the key card. What does not fit is left out,
/// `? help` and `q quit` never.
fn key_hints(model: &Model, scrolls: Scroll) -> Vec<(&'static str, &'static str)> {
    if model.note.is_some() {
        return vec![("Enter", "save"), ("Esc", "cancel"), ("Ctrl+U", "clear")];
    }
    if model.help {
        return vec![("any key", "close")];
    }
    let Some(snapshot) = &model.snapshot else {
        return vec![("q", "quit")];
    };
    let mut keys = Vec::new();
    let moves = match model.focused() {
        Focus::Hosts => model.hosts().len(),
        Focus::Advisories => model.advisories().len(),
    };
    if moves > 1 {
        keys.push(("\u{2191}\u{2193}", "move"));
    }
    match scrolls {
        Scroll::All => {}
        Scroll::More => keys.push(("PgDn", "more")),
        Scroll::Scrolled => keys.push(("PgUp/PgDn", "scroll")),
    }
    if !model.advisories().is_empty() {
        keys.push(match model.focused() {
            Focus::Hosts => ("Tab", "CVEs"),
            Focus::Advisories => ("Tab", "hosts"),
        });
    }
    // Not while the AI panel lists them.
    let ai = &snapshot.ai;
    let listed = model.show_ai
        && !ai.running
        && ai.text.is_empty()
        && ai.error.is_none()
        && ai.summary.is_none();
    if model.live && model.selected_host().is_some() && !listed {
        keys.push(("L/C/R", "ask AI"));
    }
    if model.show_ai {
        keys.push(("a", "back"));
    } else if snapshot.ai.tier.is_some() {
        keys.push(("a", "answer"));
    }
    // `m` and `n` are on the key card unless one is needed to go back.
    if model.show_machine {
        keys.push(("m", "back"));
    }
    keys.push(("?", "help"));
    keys.push(("q", "quit"));
    keys
}

/// The keys of [`key_hints`] in `width` columns: the ones before `?` give
/// way from the end.
fn key_line(mut keys: Vec<(&'static str, &'static str)>, width: usize) -> Line<'static> {
    let line = |keys: &[(&'static str, &'static str)]| {
        let mut spans = vec![Span::raw(" ")];
        for (index, (key, action)) in keys.iter().enumerate() {
            if index > 0 {
                spans.push(Span::styled(SEP, DIM));
            }
            spans.push(Span::raw(*key));
            spans.push(Span::styled(format!(" {action}"), DIM));
        }
        spans
    };
    while width_of(&line(&keys)) > width && keys.len() > 2 {
        let last = keys.len() - 3;
        keys.remove(last);
    }
    Line::from(line(&keys))
}

/// The status or the note being typed, if any, over the key line.
fn draw_footer(frame: &mut Frame, area: Rect, model: &Model, scrolls: Scroll) {
    let [top, keys] = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
    let said = match &model.note {
        Some(text) => {
            let target = model
                .selected_host()
                .map_or("the session".to_owned(), |h| sanitize(&h.address, 120));
            Some(Line::from(vec![
                Span::styled(format!(" Note on {target}: "), TITLE),
                Span::raw(text.clone()),
                Span::styled("_", TITLE),
            ]))
        }
        None if !model.status.is_empty() => Some(Line::styled(format!(" {}", model.status), WARN)),
        None => None,
    };
    if let Some(said) = said {
        frame.render_widget(Paragraph::new(said), top);
    }
    let hints = key_hints(model, scrolls);
    frame.render_widget(Paragraph::new(key_line(hints, keys.width as usize)), keys);
}

/// The rows `lines` take in a panel of `area`, wrapped.
fn rows_of(lines: &[Line], area: Rect) -> usize {
    let room = (area.width as usize).saturating_sub(2).max(1);
    lines
        .iter()
        .map(|line| line.width().div_ceil(room).max(1))
        .sum()
}

/// Where a panel that scrolls stands, for the key line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scroll {
    /// It shows all it has.
    All,
    /// It has more below and was not scrolled.
    More,
    /// It was scrolled.
    Scrolled,
}

/// A panel that scrolls with PgUp/PgDn, no further than its last line.
fn draw_scrolling(
    frame: &mut Frame,
    area: Rect,
    model: &Model,
    lines: Vec<Line<'static>>,
    block: Block,
) -> Scroll {
    let rows = area.height.saturating_sub(2) as usize;
    let limit = rows_of(&lines, area).saturating_sub(rows);
    let limit = u16::try_from(limit).unwrap_or(u16::MAX);
    model.scroll_limit.set(limit);
    let scroll = model.inspector_scroll.min(limit);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .block(block),
        area,
    );
    match (scroll, limit) {
        (0, 0) => Scroll::All,
        (0, _) => Scroll::More,
        _ => Scroll::Scrolled,
    }
}

fn draw_ai(frame: &mut Frame, area: Rect, model: &Model, snapshot: &Snapshot) -> Scroll {
    let ai = &snapshot.ai;
    let title = match (ai.tier, &ai.address) {
        (Some(tier), Some(address)) => {
            let mut title = format!("{}{SEP}{}", tier.name(), sanitize(address, 120));
            if ai.running {
                title.push_str(SEP);
                title.push_str("running");
            }
            title
        }
        _ => "AI".to_owned(),
    };
    let mut lines: Vec<Line> = ai
        .text
        .lines()
        .map(|line| {
            let line = sanitize(line, 2000);
            // A heading without its marks.
            match line.strip_prefix('#') {
                Some(heading) => {
                    Line::styled(heading.trim_start_matches('#').trim().to_owned(), TITLE)
                }
                None => Line::raw(line),
            }
        })
        .collect();
    if let Some(error) = &ai.error {
        lines.push(Line::styled(sanitize(error, 600), BAD));
    }
    if let Some(summary) = &ai.summary {
        lines.push(Line::raw(""));
        lines.push(Line::styled(sanitize(summary, 400), DIM));
    }
    if lines.is_empty() && ai.running {
        lines.push(Line::styled("Waiting for the model\u{2026}", DIM));
    } else if lines.is_empty() {
        // Nothing asked yet: the keys, and what the cloud gets.
        lines.push(Line::from(joined(vec![
            Span::raw("L local AI"),
            Span::raw("C cloud AI"),
            Span::raw("R research"),
        ])));
        let cloud = if snapshot.budget.has_key {
            "C and R send masked text to cloud AI"
        } else {
            "No cloud key: C asks local AI, R is off"
        };
        lines.push(Line::styled(cloud, DIM));
    }
    draw_scrolling(frame, area, model, lines, panel(&title, true))
}

/// What each key does, behind `?`.
const HELP: [(&str, &str); 14] = [
    ("\u{2191}\u{2193} j k", "move"),
    ("Tab \u{2190} \u{2192}", "hosts or CVEs"),
    ("PgUp PgDn", "scroll the host, AI or machine panel"),
    ("L", "ask local AI"),
    ("C", "ask cloud AI \u{b7} masked text \u{b7} daily cap"),
    ("R", "CVE research \u{b7} versions only \u{b7} daily cap"),
    ("a", "show or hide the AI answer"),
    ("m", "show or hide all of this machine"),
    ("n", "note on the host"),
    ("1", "light \u{b7} 0 packets to hosts"),
    ("2", "mild \u{b7} slow, rate-limited scans"),
    (
        "3",
        "aggressive \u{b7} fast scans \u{b7} labs and authorized hosts only",
    ),
    ("q Esc", "quit"),
    ("exploited", "known exploited in the wild (CISA KEV)"),
];

/// The key card, over the middle of the panel. An action too long for the
/// card goes on under its own column; a card too tall for the terminal
/// ends in `…`.
fn draw_help(frame: &mut Frame, area: Rect) {
    let column = HELP
        .iter()
        .map(|(key, _)| Span::raw(*key).width())
        .max()
        .unwrap_or(0)
        + 2;
    let longest = HELP
        .iter()
        .map(|(_, action)| Span::raw(*action).width())
        .max()
        .unwrap_or(0);
    // The border and a column of room on each side.
    let width = ((column + longest + 4) as u16).min(area.width);
    let room = (width as usize).saturating_sub(4 + column).max(8);
    let mut lines: Vec<Line> = Vec::new();
    for (key, action) in HELP {
        for (index, piece) in wrap_words(action, room).into_iter().enumerate() {
            let key = if index == 0 { key } else { "" };
            lines.push(Line::from(vec![
                Span::styled(format!("{key:<column$}"), TITLE),
                Span::raw(piece),
            ]));
        }
    }
    let rows = area.height.saturating_sub(2) as usize;
    if lines.len() > rows {
        lines.truncate(rows.saturating_sub(1));
        lines.push(Line::styled("\u{2026}", DIM));
    }
    let height = (lines.len() as u16 + 2).min(area.height);
    let card = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, card);
    let block = panel("Keys", true).padding(Padding::horizontal(1));
    frame.render_widget(Paragraph::new(lines).block(block), card);
}

/// The smallest terminal the panel is drawn in.
const MIN_SIZE: (u16, u16) = (60, 12);

/// Draws the whole panel. Everything comes from `model`; the frame only
/// tells it how far the panel under the box can scroll.
pub fn draw(frame: &mut Frame, model: &Model) {
    let area = frame.area();
    if area.width < MIN_SIZE.0 || area.height < MIN_SIZE.1 {
        // Too small to show an address or a CVE whole.
        let said = format!("Too small: {}x{} needed", MIN_SIZE.0, MIN_SIZE.1);
        frame.render_widget(
            Paragraph::new(Line::styled(said, WARN)).wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    // A tall terminal gives the queue and the notices more lines; with
    // neither, their row is left out.
    let activity_rows = match &model.snapshot {
        Some(s) if !s.tasks.is_empty() || !s.notices.is_empty() => {
            if area.height >= 40 {
                12
            } else {
                8
            }
        }
        _ => 0,
    };
    // A row for the status or the note only when there is one.
    let footer_rows = 1 + u16::from(model.note.is_some() || !model.status.is_empty());
    // Not without a line inside its border.
    let activity_rows = match area.height.saturating_sub(1 + 8 + footer_rows) {
        free if free < 3 => 0,
        free => activity_rows.min(free),
    };
    let [header, body, activity, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Length(activity_rows),
        Constraint::Length(footer_rows),
    ])
    .areas(area);
    draw_header(frame, header, model);
    let Some(snapshot) = &model.snapshot else {
        draw_footer(frame, footer, model, Scroll::All);
        return;
    };
    // Wide enough for `192.0.2.10  1 exploited`, but not more than 2/5.
    let list = (body.width * 28)
        .div_ceil(100)
        .max(25)
        .min(body.width * 2 / 5);
    let [hosts, right] =
        Layout::horizontal([Constraint::Length(list), Constraint::Min(0)]).areas(body);
    // Top right: this machine, as tall as it needs but never crowding out
    // the host panels below it; left out until something is known, and
    // while `m` shows all of it.
    let local = &snapshot.graph.local;
    let report = machine_report(local);
    let room = (right.width as usize).saturating_sub(2);
    let (mut machine_top, pinned) = machine_rows(local, &report, room, true);
    if model.show_machine {
        machine_top.clear();
    }
    let right = if machine_top.is_empty() {
        right
    } else {
        // Room for the first line, the warnings and a line to say what
        // more there is, up to half the column.
        let most = (right.height / 3)
            .max(pinned as u16 + 3)
            .min(right.height / 2);
        let wanted = (machine_top.len() as u16 + 2).min(most).max(3);
        let rows = wanted as usize - 2;
        if machine_top.len() > rows {
            let hidden = machine_top.len() - rows.saturating_sub(1);
            machine_top.truncate(rows.saturating_sub(1));
            machine_top.push(Line::styled(
                format!("+{hidden} more \u{b7} m shows all"),
                DIM,
            ));
        }
        let [machine, rest] =
            Layout::vertical([Constraint::Length(wanted), Constraint::Min(0)]).areas(right);
        frame.render_widget(
            Paragraph::new(machine_top).block(panel("This machine", false)),
            machine,
        );
        rest
    };
    // The CVE panels only for a host that has CVEs.
    let has_cves = !model.advisories().is_empty();
    let [inspector, advisories] = if has_cves {
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(right)
    } else {
        [right, Rect::default()]
    };
    draw_hosts(frame, hosts, model);
    let room = (inspector.width as usize).saturating_sub(2);
    let scrolls = if model.show_ai {
        draw_ai(frame, inspector, model, snapshot)
    } else if model.show_machine {
        let lines = machine_lines(local, &report, room);
        draw_scrolling(frame, inspector, model, lines, panel("This machine", true))
    } else {
        let (lines, title) = match model.selected_host() {
            Some(host) => (
                inspector_lines(host, room),
                host_title(&snapshot.graph, host, room),
            ),
            None => (
                vec![Line::styled(
                    "No hosts yet: scan in the shell or `meow add <file>`",
                    DIM,
                )],
                "Host".to_owned(),
            ),
        };
        draw_scrolling(frame, inspector, model, lines, panel(&title, false))
    };
    if has_cves {
        draw_advisories(frame, advisories, model);
    }
    if activity_rows > 0 {
        draw_activity(frame, activity, model, snapshot);
    }
    draw_footer(frame, footer, model, scrolls);
    if model.help {
        draw_help(frame, area);
    }
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The largest message the HUD reads: the session sends its whole state
/// as one, and a graph near its cap makes one of tens of MB.
const MAX_MESSAGE_BYTES: usize = 2 * crate::graph::MAX_GRAPH_BYTES as usize;

/// Whether a read failed on what the session sent (too large, not text),
/// not because the session went away.
fn is_unreadable(error: &tokio_tungstenite::tungstenite::Error) -> bool {
    use tokio_tungstenite::tungstenite::error::{Error, ProtocolError};
    match error {
        Error::Capacity(_) | Error::Utf8(_) | Error::AttackAttempt => true,
        Error::Protocol(ProtocolError::ResetWithoutClosingHandshake) => false,
        Error::Protocol(_) => true,
        _ => false,
    }
}

async fn connect(workspace: &Workspace) -> Option<Socket> {
    let info = crate::ipc::runtime_info(workspace)?;
    connect_to(&format!(
        "ws://127.0.0.1:{}/ws?token={}",
        info.port, info.token
    ))
    .await
}

async fn connect_to(url: &str) -> Option<Socket> {
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_frame_size(Some(MAX_MESSAGE_BYTES))
        .max_message_size(Some(MAX_MESSAGE_BYTES));
    let attempt = tokio::time::timeout(
        Duration::from_secs(3),
        tokio_tungstenite::connect_async_with_config(url, Some(config), false),
    )
    .await;
    attempt.ok()?.ok().map(|(socket, _)| socket)
}

/// Forwards terminal events from a blocking thread.
fn spawn_input() -> mpsc::UnboundedReceiver<Event> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || loop {
        match event::poll(Duration::from_millis(200)) {
            Ok(true) => {
                let Ok(event) = event::read() else { break };
                if tx.send(event).is_err() {
                    break;
                }
            }
            Ok(false) if tx.is_closed() => break,
            Ok(false) => {}
            Err(_) => break,
        }
    });
    rx
}

async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    model: &mut Model,
    mut socket: Option<Socket>,
) -> Result<()> {
    let mut input = spawn_input();
    let mut arrived = std::time::Instant::now();
    // Often enough that a running stage's clock moves on the second.
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // Once the session is gone its clocks stand still.
        if model.live {
            model.age = arrived.elapsed();
        }
        terminal
            .draw(|frame| draw(frame, model))
            .context("cannot draw the panel")?;
        tokio::select! {
            // Only to draw again: the time a stage has been running.
            _ = tick.tick(), if model.live && model.has_running_stage() => {}
            event = input.recv() => {
                let Some(event) = event else { break };
                let action = match event {
                    Event::Key(key) if key.kind == KeyEventKind::Press => model.on_key(key),
                    Event::Paste(text) => model.on_paste(&text),
                    _ => continue,
                };
                match action {
                    Action::Quit => break,
                    Action::None => {}
                    Action::Send(command) => {
                        let Some(live) = socket.as_mut() else { continue };
                        let text = serde_json::to_string(&command)?;
                        if live.send(Message::Text(text.into())).await.is_err() {
                            socket = None;
                            model.session_ended();
                        }
                    }
                }
            }
            message = async {
                match socket.as_mut() {
                    Some(live) => live.next().await,
                    None => std::future::pending().await,
                }
            } => match message {
                Some(Ok(Message::Text(text))) => {
                    model.apply_message(&text);
                    // A new state starts its age again.
                    if model.age.is_zero() {
                        arrived = std::time::Instant::now();
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(error)) if is_unreadable(&error) => {
                    socket = None;
                    model.cannot_read(&error.to_string());
                }
                _ => {
                    socket = None;
                    model.session_ended();
                }
            },
        }
    }
    Ok(())
}

/// Restores the terminal when the panel exits or unwinds.
struct TerminalRestore;

impl Drop for TerminalRestore {
    fn drop(&mut self) {
        let _ = execute!(std::io::stdout(), DisableBracketedPaste);
        ratatui::restore();
        crate::pty::ensure_cooked_terminal();
    }
}

/// Runs the panel until the operator quits.
pub fn run(workspace: &Workspace) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("cannot take over the terminal (is this a TTY?)");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(async {
        let socket = connect(workspace).await;
        let mut model = Model::new(socket.is_some());
        if socket.is_none() {
            model.snapshot = Some(Snapshot::offline(workspace)?);
        }
        crate::pty::ensure_cooked_terminal();
        let mut terminal =
            ratatui::try_init().context("cannot take over the terminal (is this a TTY?)")?;
        let _restore = TerminalRestore;
        // A paste then arrives as one piece of text, not as key presses.
        let _ = execute!(std::io::stdout(), EnableBracketedPaste);
        event_loop(&mut terminal, &mut model, socket).await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Confidence, EvidenceRecord, Source};
    use crate::graph::{Interface, Listener, Neighbor, Observation, Route, SystemInfo};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use serde_json::json;

    fn graph() -> Graph {
        let mut graph = Graph::default();
        for (address, port, product, version) in [
            ("10.10.10.5", 80, "nginx", Some("1.18.0")),
            ("10.10.10.5", 22, "OpenSSH", Some("8.2p1")),
            ("10.10.10.9", 3306, "MySQL", None),
        ] {
            graph.apply(Observation::Port {
                address: address.into(),
                port,
                protocol: "tcp".into(),
                state: "open".into(),
                service: Some("svc".into()),
                product: Some(product.into()),
                version: version.map(Into::into),
                extra_info: None,
                cpes: vec![],
                record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
            });
        }
        for path in ["/portal/config/", "/portal/login.php"] {
            graph.apply(Observation::Path {
                address: "10.10.10.5".into(),
                port: 80,
                scheme: "http".into(),
                path: path.into(),
                status: Some(200),
                record: EvidenceRecord::observed(Source::FeroxJson, Confidence::High, "x"),
            });
        }
        graph.local.routes.push(Route {
            destination: "10.10.10.0/23".into(),
            gateway: Some("10.10.14.1".into()),
            interface: "tun0".into(),
        });
        for (id, cvss, kev) in [
            ("CVE-2019-0001", 5.0, false),
            ("CVE-2021-23017", 7.7, false),
            ("CVE-2020-0002", 4.0, true),
        ] {
            graph.add_advisory(
                "10.10.10.5",
                Advisory {
                    fixed_in: None,
                    last_affected: None,
                    id: id.into(),
                    title: format!("title of {id}"),
                    severity: Some("HIGH".into()),
                    cvss: Some(cvss),
                    kev,
                    matched: "cpe:2.3:a:nginx:nginx:1.18.0".into(),
                    port: Some("80/tcp".into()),
                    references: vec![],
                    record: EvidenceRecord::observed(Source::NvdApi, Confidence::Medium, "{}"),
                },
            );
        }
        graph.apply(Observation::Script {
            address: "10.10.10.5".into(),
            port: Some(22),
            protocol: "tcp".into(),
            id: "ssh-hostkey".into(),
            output: "2048 aa:bb (RSA)".into(),
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
        });
        graph
    }

    fn state_message(graph: &Graph) -> String {
        json!({
            "type": "state",
            "state": {
                "session": "acme", "mode": "mild", "graph": graph,
                "tasks": [ { "id": 1, "target": "10.10.10.0/23", "mode": "mild", "extra_flags": [], "created_utc": "",
                    "stages": [
                        { "stage": "ports", "status": "done", "detail": "2 hosts up" },
                        { "stage": "services", "status": "running", "detail": "" },
                        { "stage": "crawl", "status": "pending", "detail": "" },
                        { "stage": "dirs", "status": "pending", "detail": "" } ] } ],
                "notices": [ { "at": "2026-11-12T09:41:00Z", "text": "not running as root: -sS replaced with -sT (connect scan)" } ],
                "cves": {}, "topology": {},
                "budget": { "spent_usd": 0.25, "calls": 3, "max_usd": 1.0, "max_calls": 20, "has_key": true }
            }
        })
        .to_string()
    }

    fn model() -> Model {
        let mut model = Model::new(true);
        model.apply_message(&state_message(&graph()));
        model
    }

    fn screen(model: &Model, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, model)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn every_panel_is_drawn_from_the_session_state() {
        let model = model();
        let text = screen(&model, 160, 64);
        for expected in [
            " =^..^= acme · mild · 2 hosts · 3 CVEs · 1 exploited · cloud AI $0.25/$1 today ",
            "┌ Hosts ─",
            "10.10.10.5  2 ports · 3 CVEs · 1 exploited",
            "10.10.10.9  1 port",
            "┌ 10.10.10.5 · Server ─",
            "│Update  cpe:2.3:a:nginx:nginx:1.18.0 to its newest release, or close 80/tcp \u{b7} \
             3 CVEs \u{b7} 1 exploited ",
            "│Ports   22/tcp svc OpenSSH 8.2p1 ",
            "│        80/tcp svc nginx 1.18.0 ",
            "/portal/",
            "/config  200",
            "/login.php  200",
            "│Facts   ssh-hostkey 2048 aa:bb (RSA)  nmap",
            "┌ CVEs ─",
            "CVE-2020-0002  4.0  exploited",
            "CVE-2021-23017  7.7 ",
            "┌ CVE-2020-0002 ─",
            // The list row says the score and that it is exploited.
            "│High   ",
            "title of CVE-2020-0002",
            "cpe:2.3:a:nginx:nginx:1.18.0 · 80/tcp",
            "┌ Recon ─",
            "10.10.10.0/23  █>·· 1/4  services",
            "  ports: 2 hosts up",
            "┌ Notices ─",
            "09:41 not running as root: -sS replaced with -sT (connect scan)",
            " ↑↓ move · Tab CVEs · L/C/R ask AI · ? help · q quit",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        // Where the list is too narrow to say it, the detail does.
        let narrow = screen(&model, 66, 30);
        assert!(narrow.contains("│CVE-2020-0002  4.0 "), "{narrow}");
        assert!(narrow.contains("│High 4.0 ·"), "{narrow}");
        assert!(narrow.contains("│exploited"), "{narrow}");
        // Each fact once, and nothing that only says it is not known: the
        // port's own fact is its line under Ports, the host has no OS.
        for unwanted in ["svc nginx 1.18.0 open", "not known", "->", "unknown"] {
            assert!(!text.contains(unwanted), "{unwanted:?} in:\n{text}");
        }
    }

    #[test]
    fn long_notices_wrap_and_the_host_says_what_to_update() {
        let mut graph = graph();
        for advisory in &mut graph.hosts.get_mut("10.10.10.5").unwrap().advisories {
            advisory.fixed_in = Some("1.20.1".into());
        }
        let mut message: Value = serde_json::from_str(&state_message(&graph)).unwrap();
        message["state"]["notices"] = json!([ {
            "at": "2026-11-12T09:41:00Z",
            "text": "3 new CVEs for 10.10.10.5 (1 known exploited), found by software version. \
                     Most come from one place: Update nginx 1.18.0 to 1.20.1 or later, or close \
                     80/tcp if the service is not needed."
        } ]);
        let mut model = Model::new(true);
        model.apply_message(&message.to_string());

        let text = screen(&model, 160, 54);
        for expected in [
            "│Update  cpe:2.3:a:nginx:nginx:1.18.0 to 1.20.1 or later, or close 80/tcp · 3 CVEs · \
             1 exploited ",
            "Fixed in 1.20.1",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        // Where the line is too narrow, what is exploited stays on it and
        // the rest goes under it.
        let narrow = screen(&model, 100, 40);
        for expected in [
            "│Update  cpe:2.3:a:nginx:nginx:1.18.0 to 1.20.1 or later · 1 exploited ",
            "│          or close 80/tcp · 3 CVEs ",
        ] {
            assert!(
                narrow.contains(expected),
                "missing {expected:?} in:\n{narrow}"
            );
        }

        // On a narrow screen the notice continues under its own text.
        let narrow = screen(&model, 100, 30);
        for expected in [
            "09:41 3 new CVEs for",
            "      if the service is not needed.",
        ] {
            assert!(
                narrow.contains(expected),
                "missing {expected:?} in:\n{narrow}"
            );
        }

        assert_eq!(
            wrap_words("one two three four", 9),
            ["one two", "three", "four"]
        );
        assert_eq!(wrap_words("abcdefghijkl mn", 8), ["abcdefgh", "ijkl mn"]);
    }

    /// A state whose tasks are `runs`: (id, target, the status of each
    /// stage), newest first. `closed` is a stage the end of the session
    /// stopped, `not run` one it left out.
    fn runs_message(runs: &[(i64, &str, &[&str])]) -> Value {
        let tasks: Vec<Value> = runs
            .iter()
            .map(|(id, target, statuses)| {
                let stages: Vec<Value> = queue::STAGES
                    .iter()
                    .zip(*statuses)
                    .map(|(stage, status)| {
                        let (status, detail) = match *status {
                            "closed" => ("interrupted", queue::CLOSED_DETAIL),
                            "not run" => ("skipped", queue::NOT_RUN_CLOSED),
                            status => (status, ""),
                        };
                        let mut row = json!({ "stage": stage, "status": status, "detail": detail });
                        if status == "running" {
                            row["started_utc"] = json!("2026-11-12T10:00:00Z");
                        }
                        row
                    })
                    .collect();
                json!({ "id": id, "target": target, "mode": "mild", "extra_flags": [],
                    "created_utc": "", "stages": stages })
            })
            .collect();
        let mut message: Value = serde_json::from_str(&state_message(&Graph::default())).unwrap();
        message["state"]["now_utc"] = json!("2026-11-12T10:00:42Z");
        message["state"]["tasks"] = json!(tasks);
        message
    }

    /// The queue panel's rows at this size, without its border.
    fn queue_rows(model: &Model, width: u16, height: u16) -> Vec<String> {
        let text = screen(model, width, height);
        let lines: Vec<&str> = text.lines().collect();
        let top = lines
            .iter()
            .position(|line| line.contains("┌ Recon ─"))
            .expect("the queue panel");
        let bottom = top
            + lines[top..]
                .iter()
                .position(|line| line.starts_with('└'))
                .expect("its foot");
        let inner = (width / 2) as usize - 2;
        lines[top + 1..bottom]
            .iter()
            .map(|line| line.chars().skip(1).take(inner).collect::<String>())
            .map(|row| row.trim_end().to_owned())
            .collect()
    }

    /// A target queued again while its first run is still going: the run
    /// that is running stays on its row, and the new one is counted.
    #[test]
    fn a_target_queued_again_keeps_showing_the_run_that_has_work() {
        const RUNNING: [&str; 17] = [
            "done", "done", "done", "done", "done", "done", "done", "done", "running", "pending",
            "pending", "pending", "pending", "pending", "pending", "pending", "pending",
        ];
        let message = runs_message(&[
            (3, "192.0.2.10", &["pending"; 17]),
            (2, "192.0.2.10", &RUNNING),
            (1, "192.0.2.10", &["done"; 17]),
        ]);
        let model = shown(&message);
        let rows = queue_rows(&model, 200, 40);
        assert_eq!(
            rows[0],
            "192.0.2.10 (+1 queued, +1 earlier)  ████████>········ 8/17  services 0:42"
        );
        // One row for the target, and nothing says it waits.
        assert!(rows[1..9].iter().all(String::is_empty), "{rows:?}");

        // Both stopped by light mode: the older one is next, so it is
        // shown; once it runs again it still is.
        let mut paused = RUNNING;
        paused[8] = "interrupted";
        let message = runs_message(&[
            (3, "192.0.2.10", &["pending"; 17]),
            (2, "192.0.2.10", &paused),
        ]);
        let rows = queue_rows(&shown(&message), 160, 40);
        assert_eq!(
            rows[0],
            "192.0.2.10 (+1 queued)  ████████!········ 8/17  services stopped"
        );
        // Nothing left to do in any of them: the newest.
        let mut failed = ["done"; 17];
        failed[16] = "failed";
        let message = runs_message(&[(3, "192.0.2.10", &failed), (2, "192.0.2.10", &["done"; 17])]);
        let rows = queue_rows(&shown(&message), 160, 40);
        assert_eq!(
            rows[..2],
            [
                "192.0.2.10 (+1 earlier)  ████████████████x 17/17",
                "    dirs failed"
            ]
        );
        // The session was closed: the run it stopped is shown, not the
        // newer one it dropped before it began, and before the targets
        // whose runs never began.
        let mut cut = ["not run"; 17];
        cut[..8].fill("done");
        cut[8] = "closed";
        let message = runs_message(&[
            (4, "192.0.2.11", &["not run"; 17]),
            (3, "192.0.2.10", &["not run"; 17]),
            (2, "192.0.2.10", &cut),
        ]);
        let rows = queue_rows(&shown(&message), 160, 40);
        assert_eq!(
            rows[..4],
            [
                "192.0.2.10 (+1 not run)  ████████!-------- 8/17  services stopped",
                "    session ended",
                "192.0.2.11  ----------------- 0/17  not run",
                "    session ended",
            ]
        );
    }

    /// Several targets: the one that is running first with all its lines,
    /// then those that wait in the order they will run, then what is over;
    /// what does not fit is counted, never cut in the middle.
    #[test]
    fn the_running_recon_comes_first_and_what_is_left_out_is_counted() {
        const RUNNING: [&str; 17] = [
            "skipped", "skipped", "skipped", "skipped", "skipped", "done", "running", "pending",
            "pending", "pending", "pending", "pending", "pending", "pending", "pending", "pending",
            "pending",
        ];
        let mut runs: Vec<(i64, String, &[&str])> = (2..=6)
            .rev()
            .map(|id| (id, format!("192.0.2.{}", 30 + id), &["pending"; 17][..]))
            .collect();
        runs.push((1, "192.0.2.31".to_owned(), &RUNNING));
        runs.push((0, "192.0.2.30".to_owned(), &["done"; 17]));
        let runs: Vec<(i64, &str, &[&str])> = runs
            .iter()
            .map(|(id, target, statuses)| (*id, target.as_str(), *statuses))
            .collect();
        let mut message = runs_message(&runs);
        message["state"]["tasks"][5]["stages"][5]["detail"] = json!("2 open ports");
        message["state"]["tasks"][5]["stages"][6]["progress"] =
            json!({ "percent": 11, "eta_s": 36, "note": "SYN Stealth Scan" });
        let model = shown(&message);

        // Tall and wide: all seven, in order.
        let rows = queue_rows(&model, 160, 40);
        assert_eq!(
            rows[..9],
            [
                "192.0.2.31  -----█>·········· 6/17",
                "  trace 0:42 · SYN Stealth Scan 11% (36s left)",
                "    ports: 2 open ports",
                "192.0.2.32  ················· 0/17  waiting",
                "192.0.2.33  ················· 0/17  waiting",
                "192.0.2.34  ················· 0/17  waiting",
                "192.0.2.35  ················· 0/17  waiting",
                "192.0.2.36  ················· 0/17  waiting",
                "192.0.2.30  █████████████████ 17/17",
            ],
        );
        // A row is free at the foot: what the marks stand for.
        assert_eq!(
            rows[9],
            "█ done  > running  x failed  ! stopped  - skipped  · waiting"
        );

        // 160 x 30: six rows. The running one with all its lines, the next
        // ones, and how many more there are.
        let rows = queue_rows(&model, 160, 30);
        assert_eq!(
            rows,
            [
                "192.0.2.31  -----█>·········· 6/17",
                "  trace 0:42 · SYN Stealth Scan 11% (36s left)",
                "    ports: 2 open ports",
                "192.0.2.32  ················· 0/17  waiting",
                "192.0.2.33  ················· 0/17  waiting",
                "+4 more",
            ]
        );
        // 80 x 24: six rows of 38 columns. The running recon keeps its
        // lines; the others are counted.
        let rows = queue_rows(&model, 80, 24);
        assert_eq!(
            rows,
            [
                "192.0.2.31  -----█>·········· 6/17",
                "  trace 0:42 · SYN Stealth Scan 11%",
                "    ports: 2 open ports",
                "192.0.2.32  ················· 0/17",
                "  waiting",
                "+5 more",
            ]
        );
        // Only waiting ones are left out: said so. What the others say
        // under their bars goes before a recon does.
        let mut waiting = runs_message(&runs[..6]);
        waiting["state"]["tasks"][4]["stages"][0]["status"] = json!("skipped");
        waiting["state"]["tasks"][4]["stages"][0]["detail"] = json!("turned off");
        let rows = queue_rows(&shown(&waiting), 160, 30);
        assert_eq!(
            rows,
            [
                "192.0.2.31  -----█>·········· 6/17  trace 0:42",
                "192.0.2.32  -················ 1/17  dns waiting",
                "192.0.2.33  ················· 0/17  waiting",
                "192.0.2.34  ················· 0/17  waiting",
                "192.0.2.35  ················· 0/17  waiting",
                "192.0.2.36  ················· 0/17  waiting",
            ]
        );
        let rows = queue_rows(&shown(&waiting), 80, 24);
        assert_eq!(
            rows,
            [
                "192.0.2.31  -----█>·········· 6/17",
                "  trace 0:42",
                "192.0.2.32  -················ 1/17",
                "  dns waiting",
                "+4 waiting",
                "",
            ]
        );
        // No recon: no panel for it, and the notices take the row.
        let none = screen(&shown(&runs_message(&[])), 160, 40);
        assert!(!none.contains("Recon"), "{none}");
        assert!(
            none.contains(&format!("┌ Notices {}┐", "─".repeat(149))),
            "{none}"
        );
    }

    /// While a tool counts its results the session sends only how far the
    /// running stages are: the panel takes that in without a new state.
    #[test]
    fn a_progress_message_moves_the_running_stage_without_a_new_state() {
        let message = recon_message(
            &SEVENTEEN,
            json!({ "started_utc": "2026-11-12T10:00:00Z", "progress": { "done": 3 , "note": "3 results so far" } }),
        );
        let mut model = shown(&message);
        assert!(screen(&model, 160, 40).contains("trace 0:42 · 3 results so far"));
        model.age = Duration::from_secs(3);
        let tick = |running: Value| {
            json!({ "type": "progress", "key": "k", "now_utc": "2026-11-12T10:00:50Z",
                "running": running })
            .to_string()
        };
        model.apply_message(&tick(json!([
            { "task": 7, "stage": "trace",
              "progress": { "percent": 40, "eta_s": 30, "note": "SYN Stealth Scan" } },
            // Not a running stage of a task that is shown: ignored.
            { "task": 7, "stage": "lan", "progress": { "percent": 99 } },
            { "task": 8, "stage": "trace", "progress": { "percent": 98 } },
            { "task": 7, "stage": "no-such-stage", "progress": { "percent": 97 } },
            "junk",
        ])));
        assert_eq!(model.status, "");
        assert_eq!(
            model.age,
            Duration::ZERO,
            "the time left counts from this message"
        );
        let text = screen(&model, 160, 40);
        assert!(
            text.contains("trace 0:50 · SYN Stealth Scan 40% (30s left)"),
            "{text}"
        );
        assert!(!text.contains("99%") && !text.contains("98%") && !text.contains("97%"));
        let tasks = &model.snapshot.as_ref().unwrap().tasks;
        assert!(tasks[0].stages[0].progress.is_none());
        // A stage the message no longer names says nothing any more.
        model.apply_message(&tick(json!([])));
        let text = screen(&model, 160, 40);
        assert!(text.contains(" 6/17  trace 0:50  "), "{text}");
        // What is not a list changes nothing but the clock; no state yet,
        // nothing at all.
        model.apply_message(&tick(json!("all of them")));
        assert!(screen(&model, 160, 40).contains(" 6/17  trace 0:50  "));
        let mut empty = Model::new(true);
        empty.apply_message(&tick(json!([])));
        assert!(empty.snapshot.is_none());
    }

    #[test]
    fn only_the_newest_run_of_a_target_is_shown() {
        let mut message: Value = serde_json::from_str(&state_message(&graph())).unwrap();
        let run = |id: i64, status: &str| {
            json!({ "id": id, "target": "10.10.10.5", "mode": "mild", "extra_flags": [], "created_utc": "",
                "stages": [ { "stage": "ports", "status": status, "detail": "" } ] })
        };
        message["state"]["tasks"] = json!([run(3, "running"), run(2, "done"), run(1, "done")]);
        let mut model = Model::new(true);
        model.apply_message(&message.to_string());
        let rows = queue_rows(&model, 160, 64);
        assert_eq!(rows[0], "10.10.10.5 (+2 earlier)  > 0/1  ports");
        let shown = rows.iter().filter(|row| row.contains("10.10.10.5"));
        assert_eq!(shown.count(), 1, "{rows:?}");
    }

    /// A state with one recon task whose stages have `statuses`, in order.
    fn recon_message(statuses: &[&str], running: Value) -> Value {
        let stages: Vec<Value> = queue::STAGES
            .iter()
            .zip(statuses)
            .map(|(stage, status)| {
                let mut row = json!({ "stage": stage, "status": status, "detail": "" });
                if *status == "running" {
                    for (key, value) in running.as_object().unwrap() {
                        row[key] = value.clone();
                    }
                }
                row
            })
            .collect();
        let mut message: Value = serde_json::from_str(&state_message(&Graph::default())).unwrap();
        message["state"]["now_utc"] = json!("2026-11-12T10:00:42Z");
        message["state"]["tasks"] = json!([ { "id": 7, "target": "192.0.2.5", "mode": "mild",
            "extra_flags": [], "created_utc": "", "stages": stages } ]);
        message
    }

    const SEVENTEEN: [&str; 17] = [
        "done", "done", "skipped", "done", "failed", "done", "running", "pending", "pending",
        "pending", "pending", "pending", "pending", "pending", "pending", "pending", "pending",
    ];

    fn shown(message: &Value) -> Model {
        let mut model = Model::new(true);
        model.apply_message(&message.to_string());
        assert_eq!(model.status, "", "the state was not read");
        model
    }

    #[test]
    fn a_recon_task_shows_a_bar_and_how_far_the_running_stage_is() {
        let message = recon_message(
            &SEVENTEEN,
            json!({ "started_utc": "2026-11-12T10:00:00Z", "detail": "",
                "progress": { "percent": 12, "eta_s": 56, "note": "SYN Stealth Scan" } }),
        );
        let mut model = shown(&message);
        assert!(model.has_running_stage());
        // On a wide screen: one line.
        let wide = screen(&model, 200, 40);
        assert!(
            wide.contains(
                "192.0.2.5  ██-█x█>·········· 6/17  trace 0:42 · SYN Stealth Scan 12% (56s left)"
            ),
            "{wide}"
        );
        // Where that is too long, what it is doing has a line of its own.
        let wide = screen(&model, 160, 40);
        for expected in [
            "│192.0.2.5  ██-█x█>·········· 6/17 ",
            "│  trace 0:42 · SYN Stealth Scan 12% (56s left) ",
        ] {
            assert!(wide.contains(expected), "missing {expected:?} in:\n{wide}");
        }
        // In 80 columns the same; the time left is the first to give way.
        let narrow = screen(&model, 80, 24);
        for expected in [
            "│192.0.2.5  ██-█x█>·········· 6/17 ",
            "│  trace 0:42 · SYN Stealth Scan 12% ",
        ] {
            assert!(
                narrow.contains(expected),
                "missing {expected:?} in:\n{narrow}"
            );
        }
        // The stamp was cut to the second and earlier ones said the
        // session's clock is further on: the stage's clock is too.
        model.lead = Duration::from_millis(800);
        model.age = Duration::from_millis(300);
        let ahead = screen(&model, 160, 40);
        assert!(
            ahead.contains("trace 0:43 · SYN Stealth Scan 12% (56s left)"),
            "{ahead}"
        );
        model.lead = Duration::ZERO;
        // Between two states the panel's own clock carries on.
        model.age = Duration::from_secs(5);
        let later = screen(&model, 160, 40);
        assert!(
            later.contains("trace 0:47 · SYN Stealth Scan 12% (51s left)"),
            "{later}"
        );
        model.age = Duration::from_secs(3600);
        let late = screen(&model, 160, 40);
        assert!(
            late.contains("6/17  trace 1:00:42 · SYN Stealth Scan 12%  "),
            "{late}"
        );
        assert!(!late.contains("left)"), "{late}");

        // Items instead of a percent, both, or only what the tool says.
        for (progress, expected) in [
            (json!({ "done": 3, "total": 9 }), "trace 3/9 0:42  "),
            (
                json!({ "done": 1, "total": 4, "percent": 100, "eta_s": 7200 }),
                "trace 1/4 0:42 · 100% (2h00m left)",
            ),
            // The scan a percent is of is named with it.
            (
                json!({ "done": 1, "total": 4, "percent": 37, "eta_s": 44, "note": "Service scan" }),
                "trace 1/4 0:42 · Service scan 37% (44s left)",
            ),
            // A count of items says what it counts: no words with it.
            (
                json!({ "done": 3, "total": 9, "note": "hosts" }),
                "trace 3/9 0:42  ",
            ),
            (
                json!({ "done": 412, "note": "412 results so far" }),
                "trace 0:42 · 412 results so far  ",
            ),
            (json!({ "eta_s": 90 }), "trace 0:42 (2m left)"),
            (json!({}), "trace 0:42  "),
        ] {
            let message = recon_message(
                &SEVENTEEN,
                json!({ "started_utc": "2026-11-12T10:00:00Z", "progress": progress }),
            );
            let text = screen(&shown(&message), 160, 40);
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        // No times, or times that are none: the name alone, and no clock.
        for running in [
            json!({}),
            json!({ "started_utc": "yesterday" }),
            json!({ "started_utc": "2026-11-12T10:00:00Z\u{1b}[2J" }),
        ] {
            let text = screen(&shown(&recon_message(&SEVENTEEN, running)), 160, 40);
            assert!(text.contains(" 6/17  trace  "), "{text}");
        }
        // A start after the session's own clock counts as now.
        let ahead = recon_message(&SEVENTEEN, json!({ "started_utc": "2026-11-12T10:05:00Z" }));
        assert!(screen(&shown(&ahead), 160, 40).contains(" 6/17  trace 0:00  "));
    }

    #[test]
    fn a_session_that_ends_leaves_its_running_stage_shown_as_stopped() {
        let message = recon_message(
            &SEVENTEEN,
            json!({ "started_utc": "2026-11-12T10:00:00Z",
                "progress": { "percent": 75, "eta_s": 50 } }),
        );
        let mut model = shown(&message);
        assert!(screen(&model, 160, 40).contains("trace 0:42 · 75% (50s left)"));
        model.age = Duration::from_secs(9);

        model.session_ended();
        assert!(!model.live && !model.has_running_stage());
        let text = screen(&model, 160, 40);
        for expected in [
            " =^..^= acme · mild · session ended · ",
            "192.0.2.5  ██-█x█!---------- 6/17  trace stopped",
            "    session ended",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert!(!text.contains("75%") && !text.contains("left)"), "{text}");
        // Finished stages are as they were; the ones that had not started
        // are left out, and are not counted as over.
        let stages = &model.snapshot.as_ref().unwrap().tasks[0].stages;
        let statuses: Vec<&str> = stages.iter().map(|s| s.status.as_str()).collect();
        let mut expected = SEVENTEEN;
        expected[6] = "interrupted";
        for status in &mut expected[7..] {
            *status = "skipped";
        }
        assert_eq!(statuses, expected);
        assert!(stages[7..]
            .iter()
            .all(|s| s.detail == "not run: the session was closed"));
        assert_eq!(stages[2].detail, "", "turned off, as it was");

        // A recon none of whose stages had started: not run, nothing over.
        let mut model = shown(&recon_message(&["pending"; 17], json!({})));
        model.session_ended();
        let text = screen(&model, 160, 40);
        assert!(
            text.contains("192.0.2.5  ----------------- 0/17  not run"),
            "{text}"
        );
        // The line under the bar says why.
        assert!(text.contains("│    session ended "), "{text}");
        // One that was cut after results: the first stage left out, not
        // the last, and not the result before it.
        let mut message = recon_message(&["pending"; 17], json!({}));
        for index in 0..3 {
            message["state"]["tasks"][0]["stages"][index]["status"] = json!("done");
            message["state"]["tasks"][0]["stages"][index]["detail"] = json!("3 found");
        }
        let mut model = shown(&message);
        model.session_ended();
        let text = screen(&model, 160, 40);
        assert!(
            text.contains("192.0.2.5  ███-------------- 3/17  stopped"),
            "{text}"
        );
        assert!(text.contains("│    session ended "), "{text}");
        // Nothing to show yet: nothing to change.
        Model::new(true).session_ended();
    }

    #[test]
    fn every_stage_status_has_a_mark_and_a_colour_of_its_own() {
        let mut marks = std::collections::BTreeSet::new();
        let mut colours = std::collections::BTreeSet::new();
        for status in [
            "pending",
            "running",
            "done",
            "skipped",
            "failed",
            "interrupted",
        ] {
            let cell = stage_cell(status);
            assert_eq!(cell.width(), 1, "{status}");
            marks.insert(cell.content.to_string());
            colours.insert(format!("{:?}", cell.style.fg));
        }
        assert_eq!((marks.len(), colours.len()), (6, 6));
        // What this version does not know is drawn as waiting.
        assert_eq!(
            stage_cell("\u{1b}[2J").content,
            stage_cell("pending").content
        );

        // On the screen: the colours of the bar's cells.
        let mut statuses = SEVENTEEN;
        statuses[6] = "interrupted";
        let model = shown(&recon_message(&statuses, json!({})));
        assert!(!model.has_running_stage());
        let mut terminal = Terminal::new(TestBackend::new(160, 40)).unwrap();
        terminal.draw(|frame| draw(frame, &model)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let text = screen(&model, 160, 40);
        assert!(
            text.contains("192.0.2.5  ██-█x█!·········· 6/17  trace stopped"),
            "{text}"
        );
        let row = text
            .lines()
            .position(|line| line.contains("192.0.2.5"))
            .unwrap();
        let line = text.lines().nth(row).unwrap();
        let start = line.chars().position(|c| c == '█').unwrap();
        let colour = |offset: usize| buffer[((start + offset) as u16, row as u16)].fg;
        assert_eq!(
            [colour(0), colour(2), colour(4), colour(6), colour(7)],
            [
                Color::Green,
                Color::Blue,
                Color::Red,
                Color::Magenta,
                // Pending: the terminal's own text colour, faint.
                Color::Reset
            ]
        );

        // A task that is over: its count, and nothing it is doing.
        let over = shown(&recon_message(&["done"; 17], json!({})));
        let text = screen(&over, 160, 40);
        assert!(
            text.contains("192.0.2.5  █████████████████ 17/17  "),
            "{text}"
        );
        // One that has not begun.
        let waiting = shown(&recon_message(&["pending"; 17], json!({})));
        assert!(screen(&waiting, 160, 40).contains(" 0/17  waiting"));
    }

    /// A stamp is up to a second old when it arrives; the reading furthest
    /// ahead is the nearest, and the others say how far behind they are.
    #[test]
    fn the_session_clock_is_the_reading_furthest_ahead() {
        let mut sync = ClockSync::new();
        let behind = |sync: &mut ClockSync, fresh: i128| sync.behind(fresh).as_millis();
        assert_eq!(behind(&mut sync, 5_000), 0);
        // Cut later in its second: 600 ms behind the reading before it.
        assert_eq!(behind(&mut sync, 4_400), 600);
        // Nearer than any before: the new best.
        assert_eq!(behind(&mut sync, 5_300), 0);
        assert_eq!(behind(&mut sync, 5_000), 300);
        // The session's clock was set, either way: start again from it.
        assert_eq!(behind(&mut sync, 90_000), 0);
        assert_eq!(behind(&mut sync, 89_500), 500);
        assert_eq!(behind(&mut sync, 1_000), 0);

        // Read from states: one stamp, then the same stamp a moment later
        // (so further behind), and no stamp at all.
        let mut model = Model::new(true);
        let message = recon_message(&SEVENTEEN, json!({}));
        model.apply_message(&message.to_string());
        assert_eq!(model.lead, Duration::ZERO);
        std::thread::sleep(Duration::from_millis(30));
        model.apply_message(&message.to_string());
        assert!(
            (Duration::from_millis(30)..Duration::from_secs(1)).contains(&model.lead),
            "{:?}",
            model.lead
        );
        let mut unstamped = message.clone();
        unstamped["state"]["now_utc"] = json!("soon");
        model.apply_message(&unstamped.to_string());
        assert_eq!(model.lead, Duration::ZERO);
    }

    /// Under the bar: the stages that failed, by name (the bar's marks have
    /// none); else the result of the latest stage that has one, not the
    /// reason a stage after it was left out.
    #[test]
    fn the_line_under_the_bar_names_what_failed_or_else_the_latest_result() {
        let mut message =
            recon_message(&SEVENTEEN, json!({ "started_utc": "2026-11-12T10:00:00Z" }));
        let details = [
            (0, "3 neighbours"),
            (2, "turned off in config.toml (recon.skip)"),
            (3, "4 open ports"),
            (4, "no route"),
            (5, "2 open ports"),
        ];
        for (index, detail) in details {
            message["state"]["tasks"][0]["stages"][index]["detail"] = json!(detail);
        }
        let set = |message: &mut Value, index: usize, key: &str, value: &str| {
            message["state"]["tasks"][0]["stages"][index][key] = json!(value);
        };
        // Stage 4 failed: it is named, and why, though a later stage has a
        // result.
        let text = screen(&shown(&message), 160, 40);
        assert!(text.contains("  mail-dns failed: no route"), "{text}");
        assert!(!text.contains("ports: 2 open ports"), "{text}");
        set(&mut message, 4, "detail", "");
        let text = screen(&shown(&message), 160, 40);
        assert!(text.contains("  mail-dns failed  "), "{text}");
        // Several: their names.
        set(&mut message, 3, "status", "failed");
        let text = screen(&shown(&message), 160, 40);
        assert!(text.contains("  failed: subdomains, mail-dns  "), "{text}");

        // None failed: the latest result.
        set(&mut message, 3, "status", "done");
        set(&mut message, 4, "status", "done");
        let text = screen(&shown(&message), 160, 40);
        assert!(text.contains("  ports: 2 open ports"), "{text}");
        // A stage left out after the last result does not take its place.
        set(&mut message, 5, "status", "skipped");
        set(&mut message, 5, "detail", "turned off");
        let text = screen(&shown(&message), 160, 40);
        assert!(text.contains("  subdomains: 4 open ports"), "{text}");
        assert!(!text.contains("ports: turned off"), "{text}");
        // Where every stage with something to say was left out, the last
        // of them says why.
        for index in [0, 3] {
            set(&mut message, index, "detail", "");
        }
        let text = screen(&shown(&message), 160, 40);
        assert!(text.contains("  ports: turned off"), "{text}");
    }

    #[test]
    fn the_recon_line_gives_way_on_narrow_screens_and_shows_only_plain_text() {
        let message = recon_message(
            &SEVENTEEN,
            json!({ "started_utc": "2026-11-12T10:00:00Z",
                "progress": { "percent": 12, "eta_s": 56 } }),
        );
        let model = shown(&message);
        for width in [1, 8, 20, 30, 40, 50, 60, 79, 80, 100, 120, 200] {
            for height in [1, 5, 12, 24, 50] {
                let text = screen(&model, width, height);
                // Never wider than its panel: nothing is drawn over the
                // notices beside it.
                for line in text.lines() {
                    assert_eq!(line.chars().count(), width as usize);
                }
            }
        }
        // Too narrow for a cell per stage: the count still says how far.
        let clock = Clock {
            now: parse_rfc3339("2026-11-12T10:00:42Z"),
            age: Duration::ZERO,
        };
        let task = &model.snapshot.as_ref().unwrap().tasks[0];
        let plain = |lines: Vec<Line>| -> Vec<String> {
            lines.iter().map(|line| line.to_string()).collect()
        };
        let run = |task, earlier: usize| Shown {
            task,
            queued: 0,
            not_run: 0,
            earlier,
            rank: 0,
        };
        assert_eq!(
            plain(task_lines(&run(task, 0), &clock, 21)),
            ["192.0.2.5  6/17", "  trace 0:42 · 12%"]
        );
        assert_eq!(
            plain(task_lines(&run(task, 2), &clock, 38)),
            [
                "192.0.2.5 (+2 earlier)",
                "  ██-█x█>·········· 6/17",
                "  trace 0:42 · 12% (56s left)"
            ]
        );
        // No room at all: the time, whole.
        assert_eq!(
            plain(task_lines(&run(task, 0), &clock, 0)),
            ["192.0.2.5", "6/17", "0:42"]
        );

        // Words from a tool give way to the clock where the panel is
        // narrow: they are cut, the time the stage has run is not.
        let mut wordy = recon_message(
            &SEVENTEEN,
            json!({ "started_utc": "2026-11-12T10:00:00Z",
                "progress": { "done": 3, "note": "site 1 of 3, 3 results so far" } }),
        );
        let wordy_model = shown(&wordy);
        let wordy_task = &wordy_model.snapshot.as_ref().unwrap().tasks[0];
        assert_eq!(
            plain(task_lines(&run(wordy_task, 0), &clock, 38)),
            [
                "192.0.2.5  ██-█x█>·········· 6/17",
                "  trace 0:42 · site 1 of 3, 3 results…"
            ]
        );
        let last = |width: usize| plain(task_lines(&run(wordy_task, 0), &clock, width)).pop();
        assert_eq!(
            last(44).as_deref(),
            Some("  trace 0:42 · site 1 of 3, 3 results so far")
        );
        assert_eq!(last(19).as_deref(), Some("  trace 0:42 · sit…"));
        // No room for even a few letters: the name and the clock.
        assert_eq!(
            plain(task_lines(&run(wordy_task, 0), &clock, 16)),
            ["192.0.2.5  6/17", "  trace 0:42"]
        );
        assert_eq!(last(12).as_deref(), Some("  trace 0:42"));
        assert_eq!(last(11).as_deref(), Some("  0:42"));
        assert_eq!(fit("résultats so far", 9), "résultat…");
        assert_eq!(fit("so far", 6), "so far");
        assert_eq!(fit("so far", 3), "");
        // With a time left too: it is the first to go.
        wordy["state"]["tasks"][0]["stages"][6]["progress"]["eta_s"] = json!(600);
        let both = shown(&wordy);
        let both_task = &both.snapshot.as_ref().unwrap().tasks[0];
        let last = |width: usize| plain(task_lines(&run(both_task, 0), &clock, width)).pop();
        assert_eq!(
            last(55).as_deref(),
            Some("  trace 0:42 · site 1 of 3, 3 results so far (10m left)")
        );
        assert_eq!(
            last(54).as_deref(),
            Some("  trace 0:42 · site 1 of 3, 3 results so far")
        );
        assert_eq!(
            last(40).as_deref(),
            Some("  trace 0:42 · site 1 of 3, 3 results s…")
        );

        // A long-running stage with every figure, in panels from 40
        // columns of terminal up: the line fits its panel at every width,
        // and the clock is never cut (half of it reads as another time).
        let long = recon_message(
            &SEVENTEEN,
            json!({ "started_utc": "2026-11-12T08:58:39Z",
                "progress": { "done": 1, "total": 4, "percent": 42, "eta_s": 3900,
                    "note": "Service scan" } }),
        );
        let long_model = shown(&long);
        let long_task = &long_model.snapshot.as_ref().unwrap().tasks[0];
        let last = |width: usize| {
            plain(task_lines(&run(long_task, 0), &clock, width))
                .pop()
                .unwrap()
        };
        for width in 8..=80 {
            let line = last(width);
            assert!(line.chars().count() <= width, "{width}: {line:?}");
            assert!(line.contains("1:02:03"), "{width}: {line:?}");
        }
        assert_eq!(
            [
                last(20),
                last(21),
                last(26),
                last(30),
                last(35),
                last(39),
                last(51)
            ],
            [
                "  trace 1:02:03",
                "  trace 1:02:03 · 42%",
                "  trace 1:02:03 · Ser… 42%",
                "  trace 1:02:03 · Service… 42%",
                "  trace 1:02:03 · Service scan 42%",
                "  trace 1/4 1:02:03 · Service scan 42%",
                "  trace 1/4 1:02:03 · Service scan 42% (1h05m left)",
            ]
        );

        // What a tool or a scanned server wrote is shown as plain text.
        let mut none_failed = SEVENTEEN;
        none_failed[4] = "done";
        let hostile = recon_message(
            &none_failed,
            json!({ "started_utc": "2026-11-12T10:00:00Z",
                "detail": "note\u{1b}]52;c;x\u{7}",
                "progress": { "done": 2, "note": "\u{1b}[2J\u{202e}results\u{7} so far" } }),
        );
        let text = screen(&shown(&hostile), 160, 40);
        assert!(!text.contains(['\u{1b}', '\u{7}', '\u{202e}']), "{text}");
        assert!(text.contains("trace 0:42 · [2Jresults so far"), "{text}");
        assert!(text.contains("  trace: note]52;c;x"), "{text}");

        assert_eq!(clock_time(Duration::from_secs(59)), "0:59");
        assert_eq!(clock_time(Duration::from_secs(3723)), "1:02:03");
        assert_eq!(
            [
                rough_time(45),
                rough_time(61),
                rough_time(3600),
                rough_time(3900)
            ],
            ["45s", "1m", "1h00m", "1h05m"]
        );
        // The nearest minute, like the map's "about N min left".
        assert_eq!(
            [59, 60, 89, 90, 3569, 3570, 7170].map(rough_time),
            ["59s", "1m", "1m", "2m", "59m", "1h00m", "2h00m"]
        );
    }

    #[test]
    fn advisories_are_ordered_known_exploited_then_by_score() {
        let model = model();
        let ids: Vec<&str> = model.advisories().iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["CVE-2020-0002", "CVE-2021-23017", "CVE-2019-0001"]);
        assert_eq!(model.selected_advisory().unwrap().id, "CVE-2020-0002");
    }

    #[test]
    fn a_paste_is_text_for_the_note_box_and_never_keys() {
        let mut model = model();
        let before = (model.host_index, model.advisory_index);
        // With the box closed a paste does nothing: not `3` (aggressive),
        // not `C` (a cloud request), not `q`.
        assert_eq!(model.on_paste("3cCRq\nf"), Action::None);
        assert_eq!((model.host_index, model.advisory_index), before);
        assert_eq!(model.note, None);

        // With the box open it is appended as one line of text. The line
        // break does not send the note, and what follows it is not run.
        model.on_key(key(KeyCode::Char('n')));
        model.on_key(key(KeyCode::Char('x')));
        assert_eq!(
            model.on_paste("seen in scan\r\n3c\u{1b}[2J\tend"),
            Action::None
        );
        assert_eq!(model.note.as_deref(), Some("x seen in scan 3c[2J end"));
        // Only the Enter key sends it, whole.
        match model.on_key(key(KeyCode::Enter)) {
            Action::Send(Command::Note { text, .. }) => {
                assert_eq!(text, "x seen in scan 3c[2J end")
            }
            other => panic!("{other:?}"),
        }
        // A paste longer than a note can be is cut, not sent in parts.
        model.on_key(key(KeyCode::Char('n')));
        model.on_paste(&"word ".repeat(2000));
        assert!(model.note.as_ref().unwrap().len() <= NOTE_MAX);
    }

    #[test]
    fn the_advisory_under_the_cursor_stays_the_same_one_across_updates() {
        let mut model = model();
        model.on_key(key(KeyCode::Tab));
        model.on_key(key(KeyCode::Char('j')));
        let chosen = model.selected_advisory().unwrap().id.clone();
        assert_eq!(chosen, "CVE-2021-23017");
        // A new match that ranks first arrives.
        let mut graph = graph();
        graph.add_advisory(
            "10.10.10.5",
            Advisory {
                id: "CVE-2026-9999".into(),
                title: "new".into(),
                severity: Some("CRITICAL".into()),
                cvss: Some(10.0),
                kev: true,
                matched: "x".into(),
                port: None,
                fixed_in: None,
                last_affected: None,
                references: vec![],
                record: EvidenceRecord::observed(Source::NvdApi, Confidence::Medium, "{}"),
            },
        );
        model.apply_message(&state_message(&graph));
        assert_eq!(model.selected_advisory().unwrap().id, chosen);
    }

    #[test]
    fn keys_navigate_and_produce_commands() {
        let mut model = model();
        assert_eq!(model.on_key(key(KeyCode::Down)), Action::None);
        assert_eq!(model.selected_host().unwrap().address, "10.10.10.9");
        assert_eq!(
            model.on_key(key(KeyCode::Down)),
            Action::None,
            "stays on the last host"
        );
        assert_eq!(model.selected_host().unwrap().address, "10.10.10.9");

        model.on_key(key(KeyCode::Up));
        model.on_key(key(KeyCode::Tab));
        assert_eq!(model.focus, Focus::Advisories);
        model.on_key(key(KeyCode::Char('j')));
        assert_eq!(model.selected_advisory().unwrap().id, "CVE-2021-23017");
        // The verdict keys of 0.2.2 do nothing now.
        for old in ['c', 'f', 'u'] {
            assert_eq!(model.on_key(key(KeyCode::Char(old))), Action::None);
        }
        assert_eq!(
            model.on_key(key(KeyCode::Char('2'))),
            Action::Send(Command::SetMode { mode: Mode::Mild })
        );
        assert_eq!(model.on_key(key(KeyCode::Char('q'))), Action::Quit);
        assert_eq!(
            model.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Action::Quit
        );
    }

    #[test]
    fn ai_keys_ask_for_the_selected_host_and_show_the_reply() {
        let mut model = model();
        // The AI tiers are the capital letters.
        for (key_char, tier) in [
            ('L', Tier::Local),
            ('C', Tier::Cloud),
            ('R', Tier::Research),
        ] {
            assert_eq!(
                model.on_key(key(KeyCode::Char(key_char))),
                Action::Send(Command::Ai {
                    tier,
                    address: "10.10.10.5".into(),
                })
            );
        }
        assert!(model.show_ai, "asking switches to the AI view");
        let text = screen(&model, 160, 46);
        // Nothing back yet: the keys, and what the cloud gets.
        for expected in [
            "┌ AI ─",
            "│L local AI · C cloud AI · R research ",
            "│C and R send masked text to cloud AI ",
            " a back ",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        // Without a key the cloud keys say what they do instead.
        let mut keyless: Value = serde_json::from_str(&state_message(&graph())).unwrap();
        keyless["state"]["budget"]["has_key"] = json!(false);
        let mut without = Model::new(true);
        without.apply_message(&keyless.to_string());
        without.on_key(key(KeyCode::Char('a')));
        let text = screen(&without, 160, 46);
        assert!(
            text.contains("No cloud key: C asks local AI, R is off"),
            "{text}"
        );
        assert!(
            !text.contains("cloud AI $"),
            "no spend without a key: {text}"
        );

        // The reply streams in through state updates.
        let mut state: Value = serde_json::from_str(&state_message(&graph())).unwrap();
        state["state"]["ai"] = json!({
            "running": true, "tier": "cloud", "address": "10.10.10.5",
            "text": "## 1. Evidence-Backed Risk\nUpgrade nginx\u{1b}[2J on 10.10.10.5", "error": null, "summary": null
        });
        model.apply_message(&state.to_string());
        let text = screen(&model, 160, 46);
        assert!(
            text.contains("┌ Cloud AI · 10.10.10.5 · running ─"),
            "{text}"
        );
        // A heading without its marks.
        assert!(text.contains("│1. Evidence-Backed Risk "), "{text}");
        assert!(!text.contains("##"), "{text}");
        assert!(text.contains("Upgrade nginx[2J on 10.10.10.5"), "{text}");
        // ... and then through messages of the reply alone.
        let mut reply = state["state"]["ai"].clone();
        reply["text"] =
            json!("## 1. Evidence-Backed Risk\nUpgrade nginx on 10.10.10.5\nThen restart it.");
        model.apply_message(&json!({ "type": "ai", "key": "k", "ai": reply }).to_string());
        let text = screen(&model, 160, 46);
        assert!(text.contains("│Then restart it."), "{text}");
        assert!(
            text.contains("┌ Cloud AI · 10.10.10.5 · running ─"),
            "{text}"
        );

        state["state"]["ai"]["running"] = json!(false);
        state["state"]["ai"]["error"] =
            json!("the model server answered HTTP 402: Insufficient credits");
        state["state"]["ai"]["summary"] = json!(
            "[C] for 10.10.10.5 answered by test/triage, $0.0042, saved to chats/10.10.10.5.md"
        );
        model.apply_message(&state.to_string());
        let text = screen(&model, 160, 46);
        assert!(text.contains("┌ Cloud AI · 10.10.10.5 ─"), "{text}");
        assert!(!text.contains("· running"), "{text}");
        assert!(text.contains("HTTP 402: Insufficient credits"), "{text}");
        assert!(text.contains("saved to chats/10.10.10.5.md"), "{text}");

        // `a` goes back to the inspector.
        model.on_key(key(KeyCode::Char('a')));
        let text = screen(&model, 160, 46);
        assert!(text.contains("┌ 10.10.10.5 · Server ─"), "{text}");
        assert!(text.contains(" a answer "), "{text}");

        // Without a session nothing is sent, and without a host nothing is asked.
        let mut offline = Model::new(false);
        offline.apply_message(&state_message(&graph()));
        assert_eq!(offline.on_key(key(KeyCode::Char('C'))), Action::None);
        assert_eq!(offline.status, "No session running: `meow acme` starts it");
        let mut empty = Model::new(true);
        empty.apply_message(&state_message(&Graph::default()));
        assert_eq!(empty.on_key(key(KeyCode::Char('L'))), Action::None);
        assert_eq!(empty.status, "Select a host first");
    }

    #[test]
    fn catch_up_box_captures_typing_until_enter() {
        let mut model = model();
        model.on_key(key(KeyCode::Char('n')));
        assert_eq!(model.note.as_deref(), Some(""));
        // Keys that are commands elsewhere are plain text here.
        for ch in "qc pkg:npm/lodash@4.17.20x".chars() {
            assert_eq!(model.on_key(key(KeyCode::Char(ch))), Action::None);
        }
        model.on_key(key(KeyCode::Backspace));
        let text = screen(&model, 120, 40);
        assert!(
            text.contains(" Note on 10.10.10.5: qc pkg:npm/lodash@4.17.20_"),
            "{text}"
        );
        // Only the keys that work while typing.
        assert!(
            text.contains(" Enter save · Esc cancel · Ctrl+U clear"),
            "{text}"
        );
        assert_eq!(
            model.on_key(key(KeyCode::Enter)),
            Action::Send(Command::Note {
                address: Some("10.10.10.5".into()),
                text: "qc pkg:npm/lodash@4.17.20".into(),
            })
        );
        assert_eq!(model.note, None);

        // Esc cancels, and an empty note is not sent.
        model.on_key(key(KeyCode::Char('n')));
        model.on_key(key(KeyCode::Char('x')));
        // Ctrl/Alt modified characters do not insert into the note, and Ctrl+U clears it.
        model.on_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL));
        model.on_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::ALT));
        assert_eq!(model.note.as_deref(), Some("x"));
        model.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(model.note.as_deref(), Some(""));
        // Paste turns line breaks into spaces, strips control/hidden chars, and caps byte length at NOTE_MAX.
        model.on_paste("hello\x1b\nworld");
        assert_eq!(model.note.as_deref(), Some("hello world"));
        model.on_paste(&"a".repeat(3_000));
        assert_eq!(model.note.as_ref().unwrap().len(), NOTE_MAX);
        assert_eq!(model.on_key(key(KeyCode::Esc)), Action::None);
        assert_eq!(model.note, None);

        // Multibyte UTF-8 pastes and hidden bidi overrides also stay strictly within NOTE_MAX bytes.
        model.on_key(key(KeyCode::Char('n')));
        model.on_paste(&"\u{202e}é".repeat(1_500));
        let note = model.note.as_ref().unwrap();
        assert!(note.len() <= NOTE_MAX);
        assert!(!note.contains('\u{202e}'));
        model.on_key(key(KeyCode::Esc));

        // Ctrl/Alt-modified keys (other than Ctrl+C) never fire hotkeys in normal mode.
        for ch in ['f', 'u', '1', '3', 'q', 'n', 'C'] {
            assert_eq!(
                model.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL)),
                Action::None
            );
            assert_eq!(
                model.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::ALT)),
                Action::None
            );
        }

        model.on_key(key(KeyCode::Char('n')));
        assert_eq!(model.on_key(key(KeyCode::Enter)), Action::None);
    }

    #[test]
    fn updates_keep_the_selection_and_show_results() {
        let mut model = model();
        model.on_key(key(KeyCode::Down));
        let mut graph = graph();
        graph.apply(Observation::Port {
            address: "10.10.10.1".into(),
            port: 53,
            protocol: "udp".into(),
            state: "open".into(),
            service: None,
            product: None,
            version: None,
            extra_info: None,
            cpes: vec![],
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
        });
        model.apply_message(&state_message(&graph));
        assert_eq!(model.hosts().len(), 3);
        assert_eq!(
            model.selected_host().unwrap().address,
            "10.10.10.9",
            "selection follows the host"
        );

        model.apply_message(
            r#"{"type":"result","ok":false,"error":"light mode sends no packets\u001b[2J"}"#,
        );
        assert_eq!(model.status, "Refused: light mode sends no packets[2J");
        model.apply_message(r#"{"type":"result","ok":true,"result":{}}"#);
        assert_eq!(model.status, "Done");
        model.apply_message("not json");
        model.apply_message(r#"{"type":"state","state":{"session":5}}"#);
        assert!(model.status.starts_with("Unreadable state"));
        assert_eq!(
            model.hosts().len(),
            3,
            "a bad update keeps the last good state"
        );
    }

    #[test]
    fn read_only_mode_never_sends() {
        let tmp = tempfile::tempdir().unwrap();
        let home = crate::workspace::MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        graph().save(&workspace.graph_path()).unwrap();
        {
            let db = Db::open(&workspace.state_db_path()).unwrap();
            queue::enqueue(&db, "10.10.10.0/23", Mode::Mild, &[]).unwrap();
        }
        let mut model = Model::new(false);
        model.snapshot = Some(Snapshot::offline(&workspace).unwrap());
        let text = screen(&model, 140, 40);
        assert!(
            text.contains(" =^..^= acme · light · no session · "),
            "{text}"
        );
        assert!(text.contains("10.10.10.5"), "{text}");
        // Only the keys that do something without a session.
        assert!(
            text.contains(" ↑↓ move · Tab CVEs · ? help · q quit"),
            "{text}"
        );
        // No session is open: what one left waiting is over.
        assert!(
            text.contains("10.10.10.0/23  ----------------- 0/17  not run"),
            "{text}"
        );

        model.on_key(key(KeyCode::Tab));
        assert_eq!(model.on_key(key(KeyCode::Char('2'))), Action::None);
        assert_eq!(model.status, "No session running: `meow acme` starts it");
        model.on_key(key(KeyCode::Char('n')));
        model.on_key(key(KeyCode::Char('x')));
        assert_eq!(model.on_key(key(KeyCode::Enter)), Action::None);
    }

    #[test]
    fn this_machine_sits_at_the_top_right_and_in_full_behind_m() {
        let mut graph = graph();
        let interface = |name: &str, kind: &str, addresses: &[&str]| Interface {
            name: name.into(),
            kind: kind.into(),
            up: true,
            addresses: addresses.iter().map(|a| (*a).to_owned()).collect(),
        };
        graph.local.observed_utc = "2026-11-12T09:40:00Z".into();
        graph.local.system = SystemInfo {
            kind: "MacBook Pro".into(),
            os: "macOS".into(),
            version: "15.1".into(),
        };
        graph.local.interfaces = vec![
            interface("en0", "wifi", &["fe80::aa/64", "10.44.8.20/22"]),
            interface("utun0", "vpn", &["fe80::2/64"]),
        ];
        graph.local.routes.insert(
            0,
            Route {
                destination: "0.0.0.0/0".into(),
                gateway: Some("10.44.8.1".into()),
                interface: "en0".into(),
            },
        );
        graph.local.listeners.push(Listener {
            protocol: "tcp".into(),
            address: "127.0.0.1".into(),
            port: 631,
        });
        for last in 2..=7 {
            graph.local.neighbors.push(Neighbor {
                address: format!("10.44.8.{last}"),
                mac: Some(format!("02:00:5e:00:53:0{last}")),
                interface: "en0".into(),
            });
        }
        // Nothing read yet: no box, and nothing that only says so.
        let text = screen(&model(), 160, 50);
        assert!(!text.contains("This machine"), "{text}");
        for unwanted in ["no address", "not known", "none listening", "unknown"] {
            assert!(!text.contains(unwanted), "{unwanted:?} in:\n{text}");
        }

        let mut model = Model::new(true);
        model.apply_message(&state_message(&graph));
        let text = screen(&model, 160, 50);
        // An idle tunnel with only a link-local address is not a VPN, and
        // is not listed as an interface in use.
        for expected in [
            "┌ This machine ─",
            // No VPN is something to know before scanning.
            "│MacBook Pro · macOS 15.1 · no VPN ",
            "│Ports  631/tcp local only ",
            "│en0    10.44.8.20/22 · gateway 10.44.8.1 ",
            // The selected host is said the same way.
            "┌ 10.10.10.5 · Server ─",
            "│Ports   22/tcp svc OpenSSH 8.2p1 ",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        for unwanted in ["utun0", "Routes", "Neighbours"] {
            assert!(
                !text.contains(unwanted),
                "{unwanted:?}: the tables stay out of the way"
            );
        }

        // `m` swaps the box and the inspector for all of this machine;
        // `m` again swaps back. Each thing once: the gateway is on its
        // interface's row, not again as a route.
        assert_eq!(model.on_key(key(KeyCode::Char('m'))), Action::None);
        let text = screen(&model, 160, 50);
        for expected in [
            "┌ This machine ─",
            "│MacBook Pro · macOS 15.1 · no VPN ",
            "│Routes ",
            "│  +1 more: host routes, multicast, idle ",
            "│Neighbours ",
            "│  10.44.8.2 02:00:5e:00:53:02 en0 ",
            " m back ",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert!(!text.contains("┌ 10.10.10.5"), "{text}");
        assert!(!text.contains("default via"), "{text}");
        assert_eq!(text.matches("10.44.8.20/22").count(), 1, "{text}");
        assert_eq!(text.matches("This machine").count(), 1, "{text}");
        // It scrolls like the inspector does, and no further than its end.
        let short = screen(&model, 160, 30);
        assert!(short.contains(" PgDn more "), "{short}");
        for _ in 0..5 {
            model.on_key(key(KeyCode::PageDown));
        }
        let scrolled = screen(&model, 160, 30);
        assert!(!scrolled.contains("│MacBook Pro"), "{scrolled}");
        assert!(scrolled.contains("│Other interfaces "), "{scrolled}");
        assert!(
            scrolled.contains("│Read 09:40:00 UTC · nothing sent "),
            "{scrolled}"
        );
        assert!(scrolled.contains(" PgUp/PgDn scroll "), "{scrolled}");
        model.on_key(key(KeyCode::PageUp));
        assert!(screen(&model, 160, 30).contains("│MacBook Pro"));
        model.on_key(key(KeyCode::Char('m')));
        assert!(screen(&model, 160, 50).contains("┌ 10.10.10.5 · Server ─"));

        // A tunnel with a real address is reported as the VPN it is.
        graph.local.interfaces[1]
            .addresses
            .push("10.10.14.3/23".into());
        model.apply_message(&state_message(&graph));
        let text = screen(&model, 160, 50);
        assert!(
            text.contains("│utun0  10.10.14.3/23 · no route uses it "),
            "{text}"
        );
        assert!(
            text.contains("│MacBook Pro · macOS 15.1 · VPN utun0 "),
            "{text}"
        );
        // The AI view and the machine view replace each other.
        model.on_key(key(KeyCode::Char('m')));
        model.on_key(key(KeyCode::Char('a')));
        assert!(model.show_ai && !model.show_machine);
        model.on_key(key(KeyCode::Char('m')));
        assert!(model.show_machine && !model.show_ai);
    }

    /// What must be acted on stays in sight in 80 columns: the VPN state
    /// on the box's first line, then the route warnings in a few words;
    /// what does not fit is counted, and `m` shows it, the warnings whole.
    #[test]
    fn route_warnings_and_the_vpn_stay_in_sight_in_80_columns() {
        let mut graph = graph();
        graph.local.system = SystemInfo {
            kind: "Linux machine".into(),
            os: "Ubuntu".into(),
            version: "24.04".into(),
        };
        graph.local.interfaces = vec![Interface {
            name: "eth0".into(),
            kind: "ethernet".into(),
            up: true,
            addresses: vec!["192.0.2.50/24".into()],
        }];
        graph.local.warnings = vec![
            "No route to 198.51.100.77: no local interface or route covers it (is the VPN up?)"
                .into(),
        ];
        graph.local.notes = vec![
            "`ip` is not installed in the system directories".into(),
            "`ss` is not installed in the system directories".into(),
        ];
        let mut model = Model::new(true);
        model.apply_message(&state_message(&graph));
        let text = screen(&model, 80, 24);
        for expected in [
            "│Linux machine · Ubuntu 24.04 · no VPN ",
            "│Warning   No route to 198.51.100.77 · VPN down? ",
            " more · m shows all ",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        model.on_key(key(KeyCode::Char('m')));
        let text = screen(&model, 120, 40);
        for expected in [
            "│Warning   No route to 198.51.100.77: no local interface or route covers it (is the ",
            "│          VPN up?) ",
            "│Not read  ip, ss not installed ",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert_eq!(
            short_warning(
                "Listener tcp/192.0.2.50:4444 is bound to eth0, but the lab is reached via \
                 tun0: targets cannot connect back (bind to 10.10.14.3 or 0.0.0.0)"
            ),
            "4444/tcp on eth0 · lab via tun0 · bind to 10.10.14.3 or 0.0.0.0"
        );
        assert_eq!(short_warning("something else"), "something else");
    }

    /// A host's row keeps its name before its port count, and where no
    /// count fits, the address says in its colour what is on it.
    #[test]
    fn a_host_row_keeps_the_name_and_the_colour_of_what_is_on_it() {
        let mut graph = graph();
        let host = graph.hosts.get_mut("10.10.10.5").unwrap();
        host.hostnames.insert("example.com".into());
        let host = graph.hosts["10.10.10.5"].clone();
        let plain = |line: Line| {
            line.spans
                .iter()
                .map(|s| s.content.to_string())
                .collect::<String>()
        };
        assert_eq!(
            plain(host_row(&host, 50)),
            "10.10.10.5 (example.com)  3 CVEs · 1 exploited"
        );
        assert_eq!(
            plain(host_row(&host, 44)),
            "10.10.10.5  2 ports · 3 CVEs · 1 exploited"
        );
        assert_eq!(
            plain(host_row(&host, 34)),
            "10.10.10.5  3 CVEs · 1 exploited"
        );
        assert_eq!(plain(host_row(&host, 23)), "10.10.10.5  1 exploited");
        let bare = host_row(&host, 12);
        assert_eq!(plain(bare.clone()), "10.10.10.5");
        assert_eq!(bare.style.fg, Some(Color::Red), "{bare:?}");
        // Never cut into another address that looks whole.
        assert_eq!(plain(host_row(&host, 8)), "10.10.1…");
    }

    /// The status says what the session accepted, not just that it did.
    #[test]
    fn the_status_says_what_was_done() {
        let mut model = model();
        assert!(matches!(
            model.on_key(key(KeyCode::Char('3'))),
            Action::Send(_)
        ));
        model.apply_message(r#"{"type":"result","ok":true}"#);
        assert_eq!(
            model.status,
            "Mode: aggressive · labs and authorized hosts only"
        );
        model.on_key(key(KeyCode::Char('n')));
        model.on_paste("seen by hand");
        assert!(matches!(model.on_key(key(KeyCode::Enter)), Action::Send(_)));
        model.apply_message(r#"{"type":"result","ok":true}"#);
        assert_eq!(model.status, "Note saved");
        // Too small to show an address or a CVE whole: said instead.
        assert!(screen(&model, 59, 30).starts_with("Too small: 60x12 needed"));
        assert!(screen(&model, 80, 11).starts_with("Too small: 60x12 needed"));
    }

    #[test]
    fn small_and_empty_screens_do_not_panic() {
        let mut empty = Model::new(true);
        let text = screen(&empty, 80, 24);
        assert!(
            text.contains(" =^..^= meow hud · waiting for the session"),
            "{text}"
        );
        assert!(text.contains(" q quit"), "{text}");
        empty.apply_message(&state_message(&Graph::default()));
        let text = screen(&empty, 80, 24);
        assert!(
            text.contains("│No hosts yet: scan in the shell or `meow add <file>`"),
            "{text}"
        );
        // Nothing found: no counts of nothing, and no CVE panels.
        assert!(text.contains(" =^..^= acme · mild · cloud AI "), "{text}");
        assert!(!text.contains("CVE") && !text.contains("0 hosts"), "{text}");
        for (width, height) in [(20, 5), (1, 1), (200, 60), (200, 12), (60, 20), (40, 14)] {
            let mut model = model();
            screen(&model, width, height);
            model.on_key(key(KeyCode::Char('?')));
            screen(&model, width, height);
        }
        // Too short for the queue and the notices: their row is left out
        // rather than drawn as two empty borders.
        let short = screen(&model(), 200, 12);
        assert!(!short.contains("Notices"), "{short}");
    }

    /// The header says the most with the fewest words, and fits 80
    /// columns: what does not fit gives way, the calls first.
    #[test]
    fn the_header_puts_numbers_first_and_fits_its_width() {
        let model = model();
        let line = |width: u16| {
            screen(&model, width, 30)
                .lines()
                .next()
                .unwrap()
                .trim_end()
                .to_owned()
        };
        assert_eq!(
            line(120),
            " =^..^= acme · mild · 2 hosts · 3 CVEs · 1 exploited · cloud AI $0.25/$1 today"
        );
        assert_eq!(line(80), line(120), "it fits 80 columns");
        assert_eq!(line(60), " =^..^= acme · mild · 3 CVEs · 1 exploited");
        // Too narrow for an address or a CVE whole: said instead.
        assert_eq!(line(40), "Too small: 60x12 needed");
        assert_eq!(dollars(0.25), "$0.25");
        assert_eq!(dollars(1.0), "$1");
        assert_eq!(dollars(12.5), "$12.50");
        // The calls are said once they, not the spend, near the cap.
        let mut near: Value = serde_json::from_str(&state_message(&graph())).unwrap();
        near["state"]["budget"]["calls"] = json!(15);
        let mut busy = Model::new(true);
        busy.apply_message(&near.to_string());
        let text = screen(&busy, 120, 30);
        assert!(
            text.contains(" · cloud AI $0.25/$1 today · 15/20 calls"),
            "{text}"
        );
        // Near the cap the calls outrank the counts, even in 80 columns.
        let text = screen(&busy, 80, 24);
        assert!(text.contains(" · 15/20 calls"), "{text}");
        // Money another session's running call set aside is no cap.
        let mut held: Value = serde_json::from_str(&state_message(&graph())).unwrap();
        held["state"]["budget"]["spent_usd"] = json!(1.05);
        held["state"]["budget"]["held_usd"] = json!(0.8);
        busy.apply_message(&held.to_string());
        let text = screen(&busy, 120, 30);
        assert!(text.contains(" · cloud AI $1.05/$1 today"), "{text}");
        held["state"]["budget"]["held_usd"] = json!(0.0);
        busy.apply_message(&held.to_string());
        let text = screen(&busy, 120, 30);
        assert!(text.contains(" · cloud AI cap reached"), "{text}");
        // At the cap C asks local AI and R is off: said in red.
        near["state"]["budget"]["calls"] = json!(20);
        busy.apply_message(&near.to_string());
        let text = screen(&busy, 80, 24);
        assert!(text.contains(" · cloud AI cap reached"), "{text}");
        assert!(!text.contains("calls"), "{text}");
        // So is a day's record of all sessions that cannot be read.
        near["state"]["budget"]["usage_unreadable"] = json!(true);
        busy.apply_message(&near.to_string());
        let text = screen(&busy, 120, 30);
        assert!(
            text.contains(" · cloud AI off: ai-usage unreadable"),
            "{text}"
        );
        // A setup that cannot be read is said; a missing key is not.
        let mut message: Value = serde_json::from_str(&state_message(&graph())).unwrap();
        message["state"]["budget"]["has_key"] = json!(false);
        message["state"]["budget"]["setup_unreadable"] = json!(true);
        let mut unreadable = Model::new(true);
        unreadable.apply_message(&message.to_string());
        let text = screen(&unreadable, 120, 30);
        assert!(
            text.contains(" · cloud AI off: ai.toml unreadable"),
            "{text}"
        );
        message["state"]["budget"]["config_unreadable"] = json!(true);
        let mut unreadable = Model::new(true);
        unreadable.apply_message(&message.to_string());
        let text = screen(&unreadable, 120, 30);
        assert!(
            text.contains(" · cloud AI off: config.toml unreadable"),
            "{text}"
        );
        message["state"]["budget"]["setup_unreadable"] = json!(false);
        message["state"]["budget"]["config_unreadable"] = json!(false);
        let mut keyless = Model::new(true);
        keyless.apply_message(&message.to_string());
        let text = screen(&keyless, 120, 30);
        assert!(!text.contains("cloud AI"), "{text}");
    }

    /// v0.2.6 review MAP-3: an AI reply cut off by the end of its session
    /// is shown as stopped, not as running.
    #[test]
    fn an_ai_reply_cut_off_by_the_end_of_the_session_is_stopped() {
        let mut state: Value = serde_json::from_str(&state_message(&graph())).unwrap();
        state["state"]["ai"] = json!({
            "running": true, "tier": "local", "address": "10.10.10.5",
            "text": "## Risk\nword1", "error": null, "summary": null
        });
        let mut model = Model::new(true);
        model.apply_message(&state.to_string());
        model.on_key(key(KeyCode::Char('a')));
        let text = screen(&model, 160, 46);
        assert!(
            text.contains("┌ Local AI · 10.10.10.5 · running ─"),
            "{text}"
        );
        model.session_ended();
        let ai = &model.snapshot.as_ref().unwrap().ai;
        assert!(!ai.running);
        assert_eq!(ai.error.as_deref(), Some("stopped: the session ended"));
        let text = screen(&model, 160, 46);
        assert!(text.contains("┌ Local AI · 10.10.10.5 ─"), "{text}");
        assert!(text.contains("stopped: the session ended"), "{text}");
        assert!(text.contains("session ended"), "{text}");
        // One that had ended stays as it was.
        let mut done = Model::new(true);
        state["state"]["ai"]["running"] = json!(false);
        done.apply_message(&state.to_string());
        done.session_ended();
        assert_eq!(done.snapshot.as_ref().unwrap().ai.error, None);
    }

    /// v0.2.6 review HUD-BIG: a state over 16 MiB, as a session near the
    /// graph's cap sends, is read; one that cannot be read is said.
    #[tokio::test]
    async fn a_state_over_16_mib_is_read() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws?token=t", listener.local_addr().unwrap());
        let mut state: Value = serde_json::from_str(&state_message(&graph())).unwrap();
        state["state"]["notices"] =
            json!([{ "at": "2026-11-23T00:00:00Z", "text": "x".repeat(20 << 20) }]);
        let state = state.to_string();
        assert!(state.len() > 16 << 20);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let hello = json!({ "type": "hello", "key": "k" }).to_string();
            socket.send(Message::Text(hello.into())).await.unwrap();
            socket.send(Message::Text(state.into())).await.unwrap();
            let _ = socket.next().await;
        });
        let mut socket = connect_to(&url).await.expect("connected");
        let mut model = Model::new(true);
        for _ in 0..2 {
            match socket.next().await {
                Some(Ok(Message::Text(text))) => model.apply_message(&text),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(model.status, "");
        let snapshot = model.snapshot.as_ref().expect("the state was read");
        assert_eq!(snapshot.notices[0].text.len(), 400);
        drop(socket);
        server.await.unwrap();

        // What cannot be read is said, and the session is no longer read.
        let too_big = tokio_tungstenite::tungstenite::Error::Capacity(
            tokio_tungstenite::tungstenite::error::CapacityError::MessageTooLong {
                size: 300 << 20,
                max_size: MAX_MESSAGE_BYTES,
            },
        );
        assert!(is_unreadable(&too_big));
        assert!(!is_unreadable(
            &tokio_tungstenite::tungstenite::Error::ConnectionClosed
        ));
        let mut model = Model::new(true);
        model.cannot_read(&too_big.to_string());
        let text = screen(&model, 120, 30);
        assert!(text.contains(" =^..^= meow hud · session ended"), "{text}");
        assert!(
            text.contains("Cannot read the session: Space limit exceeded"),
            "{text}"
        );
    }

    /// `?` shows every key; any key closes it and does nothing else.
    #[test]
    fn question_mark_shows_the_keys_and_any_key_closes_them() {
        let mut model = model();
        assert_eq!(model.on_key(key(KeyCode::Char('?'))), Action::None);
        assert!(model.help);
        let text = screen(&model, 120, 40);
        for expected in [
            "┌ Keys ─",
            "│ C          ask cloud AI · masked text · daily cap ",
            "│ 3          aggressive · fast scans · labs and authorized hosts only │",
            "│ exploited  known exploited in the wild (CISA KEV) ",
            " any key close",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        // Narrow: a long action goes on under its column, never cut.
        let narrow = screen(&model, 60, 30);
        for expected in [
            "│ 3          aggressive · fast scans · labs and authorized ",
            "│            hosts only ",
            "│ q Esc      quit ",
        ] {
            assert!(
                narrow.contains(expected),
                "missing {expected:?} in:\n{narrow}"
            );
        }
        // Short: the card ends in `…`.
        assert!(screen(&model, 60, 16).contains("│ …"));
        // A key that would ask the cloud or change the mode only closes it.
        for code in [KeyCode::Char('C'), KeyCode::Char('3'), KeyCode::Esc] {
            assert!(model.help);
            assert_eq!(model.on_key(key(code)), Action::None, "{code:?}");
            assert!(!model.help);
            model.on_key(key(KeyCode::Char('?')));
        }
        assert_eq!(
            model.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Action::Quit
        );
        // In the note box `?` is text.
        let mut typing = self::model();
        typing.on_key(key(KeyCode::Char('n')));
        typing.on_key(key(KeyCode::Char('?')));
        assert!(!typing.help);
        assert_eq!(typing.note.as_deref(), Some("?"));
    }

    /// Tab goes to the CVE list only where there is one; a host without
    /// CVEs has no CVE panels, and the arrows stay on the hosts.
    #[test]
    fn a_host_without_cves_keeps_the_arrows_on_the_hosts() {
        let mut model = model();
        model.on_key(key(KeyCode::Down));
        assert_eq!(model.selected_host().unwrap().address, "10.10.10.9");
        let text = screen(&model, 160, 50);
        assert!(!text.contains("CVEs─") && !text.contains("Tab "), "{text}");
        model.on_key(key(KeyCode::Tab));
        assert_eq!(model.focused(), Focus::Hosts);
        model.on_key(key(KeyCode::Up));
        assert_eq!(model.selected_host().unwrap().address, "10.10.10.5");
        model.on_key(key(KeyCode::Tab));
        assert_eq!(model.focused(), Focus::Advisories);
        assert!(screen(&model, 160, 50).contains(" Tab hosts "));
    }

    #[test]
    fn websocket_state_messages_strip_escape_sequences_before_rendering() {
        let mut hud_model = Model::new(true);
        let hostile = serde_json::json!({
            "type": "state",
            "state": {
                "session": "lab\u{001b}]52;c;abc\u{0007}",
                "mode": "mild",
                "graph": {
                    "version": crate::graph::GRAPH_VERSION,
                    "updated_utc": "2026-11-12T00:00:00Z",
                    "hosts": {
                        "192.0.2.50": {
                            "address": "192.0.2.50",
                            "ports": {
                                "80/tcp": {
                                    "number": 80,
                                    "protocol": "tcp",
                                    "state": "open",
                                    "product": "nginx\u{001b}[31m"
                                }
                            },
                            "advisories": [{
                                "id": "CVE-2024-7777\u{001b}]0;pwn\u{0007}",
                                "title": "bad\u{001b}[2Jtitle",
                                "matched": "nginx\u{001b}",
                                "port": "80/tcp\u{001b}",
                                "source": "nvd_api",
                                "timestamp_utc": "2026-11-12T00:00:00Z",
                                "confidence": "Medium",
                                "evidence": "ev\u{001b}",
                                "verification_status": "UnverifiedHypothesis"
                            }]
                        }
                    }
                },
                "tasks": [{
                    "id": 1,
                    "target": "192.0.2.0/24\u{001b}[2J",
                    "mode": "mild",
                    "extra_flags": [],
                    "created_utc": "",
                    "stages": [{ "stage": "ports", "status": "done\u{001b}", "detail": "ok\u{001b}" }]
                }],
                "notices": [{ "at": "2026-11-12T09:00:00Z\u{001b}[2J", "text": "alert\u{001b}]52;c;x\u{0007}" }],
                "ai": {
                    "tier": "local",
                    "address": "192.0.2.50\u{001b}]52;c;x\u{0007}",
                    "running": false,
                    "text": "ok"
                }
            }
        });
        hud_model.apply_message(&hostile.to_string());
        let rendered = screen(&hud_model, 160, 50);
        assert!(!rendered.contains('\x1b') && !rendered.contains('\x07'));
        assert!(rendered.contains("192.0.2.50"));
        assert!(rendered.contains("CVE-2024-7777]0;pwn"));
        hud_model.show_ai = true;
        let ai_rendered = screen(&hud_model, 160, 50);
        assert!(!ai_rendered.contains('\x1b') && !ai_rendered.contains('\x07'));
    }

    #[test]
    fn connect_ignores_stale_runtime_without_sending_token() {
        use crate::coordinator::RuntimeInfo;
        use crate::workspace::MeowHome;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = Arc::clone(&hits);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        std::fs::write(workspace.lock_path(), "99999\n").unwrap();
        std::fs::write(
            workspace.runtime_path(),
            serde_json::to_vec(&RuntimeInfo {
                pid: 99999,
                port,
                token: "secret_ws_token".to_owned(),
            })
            .unwrap(),
        )
        .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let connected = rt.block_on(connect(&workspace));
        if listener.accept().is_ok() {
            hits_srv.fetch_add(1, Ordering::SeqCst);
        }
        assert!(connected.is_none());
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "HUD must not open a WebSocket to a stale runtime.json port when session.lock is unheld"
        );
    }
}

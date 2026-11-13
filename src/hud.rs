//! `meow hud`: the companion terminal panel.
//!
//! It attaches to a live session over the coordinator WebSocket and shows
//! the host list, a node and sub-path inspector, the evidence-versus-
//! hypothesis checklist for each advisory, the CVE feed, the background
//! queue and the notice log. A catch-up box takes operator notes, and
//! verdict keys confirm or dismiss hypotheses. When no session is running
//! it opens the workspace files read-only.
//!
//! This is a separate process from the PTY host, so reading terminal events
//! with crossterm is fine here.

use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::ai::{Budget, Tier};
use crate::checklist;
use crate::coordinator::{AiStatus, Command, Notice, RuntimeInfo};
use crate::cve;
use crate::db::Db;
use crate::evidence::{sanitize, VerificationStatus};
use crate::graph::{Advisory, Graph, Host, PathNode};
use crate::mode::Mode;
use crate::observer::{machine_report, MachineReport};
use crate::queue::{self, TaskRow};
use crate::topology::{host_headline, host_open_ports, only_mentioned};
use crate::workspace::Workspace;

const MAX_PATH_LINES: usize = 40;
const MAX_FACT_LINES: usize = 60;

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
}

impl Snapshot {
    /// Reads the workspace files directly, for when no session is running.
    pub fn offline(workspace: &Workspace) -> Result<Self> {
        let tasks = if workspace.state_db_path().is_file() {
            queue::tasks(&Db::open(&workspace.state_db_path())?, 20)?
        } else {
            Vec::new()
        };
        Ok(Self {
            session: workspace.name.clone(),
            mode: workspace.profile.mode,
            graph: Graph::load(&workspace.graph_path())?,
            tasks,
            notices: Vec::new(),
            ai: AiStatus::default(),
            budget: Budget::default(),
        })
    }
}

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
    /// The note being typed in the catch-up box, if it is open.
    pub note: Option<String>,
    pub status: String,
    /// The upper-right panel shows the AI reply instead of the inspector.
    pub show_ai: bool,
    /// The upper-right panel shows everything known about this machine.
    pub show_machine: bool,
}

fn advisory_rank(advisory: &Advisory) -> (bool, i64) {
    // Known-exploited first, then by severity score, highest first.
    (!advisory.kev, -(advisory.cvss.unwrap_or(0.0) * 10.0) as i64)
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
            note: None,
            status: String::new(),
            show_ai: false,
            show_machine: false,
        }
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

    /// The selected host's advisories, most urgent first.
    pub fn advisories(&self) -> Vec<&Advisory> {
        let mut list: Vec<&Advisory> = self
            .selected_host()
            .map(|h| h.advisories.iter().collect())
            .unwrap_or_default();
        list.sort_by_key(|a| advisory_rank(a));
        list
    }

    pub fn selected_advisory(&self) -> Option<&Advisory> {
        self.advisories().get(self.advisory_index).copied()
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
                // Keep the selection on the same host across updates.
                let selected = self.selected_host().map(|h| h.address.clone());
                match serde_json::from_value::<Snapshot>(message["state"].clone()) {
                    Ok(snapshot) => self.snapshot = Some(snapshot),
                    Err(error) => {
                        self.status = format!("unreadable state from the session: {error}")
                    }
                }
                if let Some(address) = selected {
                    if let Some(index) = self.hosts().iter().position(|h| h.address == address) {
                        self.host_index = index;
                    }
                }
                self.clamp();
            }
            Some("result") => {
                self.status = match message.get("ok").and_then(Value::as_bool) {
                    Some(true) => "done".to_owned(),
                    _ => format!(
                        "refused: {}",
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

    fn verdict(&mut self, status: VerificationStatus) -> Action {
        let (Some(host), Some(advisory)) = (self.selected_host(), self.selected_advisory()) else {
            self.status = "select a host and an advisory first".to_owned();
            return Action::None;
        };
        Action::Send(Command::Verdict {
            address: host.address.clone(),
            advisory: advisory.id.clone(),
            status,
        })
    }

    fn ask_ai(&mut self, tier: Tier) -> Action {
        let Some(host) = self.selected_host() else {
            self.status = "select a host first".to_owned();
            return Action::None;
        };
        let command = Command::Ai {
            tier,
            address: host.address.clone(),
        };
        if self.live {
            self.show_ai = true;
            self.inspector_scroll = 0;
        }
        Action::Send(command)
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
                KeyCode::Char(ch) => note.push(ch),
                KeyCode::Enter => {
                    let text = self.note.take().unwrap_or_default();
                    if text.trim().is_empty() {
                        return Action::None;
                    }
                    if !self.live {
                        self.status =
                            "read-only: no session is running for this workspace".to_owned();
                        return Action::None;
                    }
                    return Action::Send(Command::Note {
                        address: self.selected_host().map(|h| h.address.clone()),
                        text,
                    });
                }
                _ => {}
            }
            return Action::None;
        }

        let action = match key.code {
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
                self.focus = match self.focus {
                    Focus::Hosts => Focus::Advisories,
                    Focus::Advisories => Focus::Hosts,
                };
                Action::None
            }
            KeyCode::PageDown => {
                self.inspector_scroll = self.inspector_scroll.saturating_add(8);
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
            KeyCode::Char('c') => self.verdict(VerificationStatus::Confirmed),
            KeyCode::Char('f') => self.verdict(VerificationStatus::FalsePositive),
            KeyCode::Char('u') => self.verdict(VerificationStatus::UnverifiedHypothesis),
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
            self.status = "read-only: no session is running for this workspace".to_owned();
            return Action::None;
        }
        action
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const DIM: Style = Style::new().fg(Color::DarkGray);
const GOOD: Style = Style::new().fg(Color::Green);
const WARN: Style = Style::new().fg(Color::Yellow);
const BAD: Style = Style::new().fg(Color::Red);
const TITLE: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);

fn status_style(status: VerificationStatus) -> Style {
    match status {
        VerificationStatus::Confirmed => BAD,
        VerificationStatus::FalsePositive => GOOD,
        VerificationStatus::UnverifiedHypothesis => WARN,
        VerificationStatus::Observed => DIM,
    }
}

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
    let style = if focused { TITLE } else { DIM };
    Block::bordered().title(title).border_style(style)
}

fn path_lines(node: &PathNode, depth: usize, out: &mut Vec<Line<'static>>) {
    for (name, child) in &node.children {
        if out.len() >= MAX_PATH_LINES {
            return;
        }
        let slash = if child.children.is_empty() { "" } else { "/" };
        let status = child.status.map(|s| format!("  {s}")).unwrap_or_default();
        out.push(Line::from(vec![
            Span::raw(format!("{}/{name}{slash}", "  ".repeat(depth + 3))),
            Span::styled(status, DIM),
        ]));
        path_lines(child, depth + 1, out);
    }
}

fn inspector_lines(graph: &Graph, host: &Host) -> Vec<Line<'static>> {
    // What it is in one line, then what is open on it.
    let mut lines = vec![
        Line::styled(sanitize(&host_headline(graph, host), 300), TITLE),
        Line::from(vec![
            Span::styled("Open ports  ", DIM),
            Span::raw(sanitize(&host_open_ports(host), 300)),
        ]),
    ];
    let names: Vec<&str> = host.hostnames.iter().map(String::as_str).collect();
    if !names.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Names       ", DIM),
            Span::raw(sanitize(&names.join(", "), 300)),
        ]));
    }
    // What to do about the advisories: one update per piece of software.
    let fixes = cve::fix_plan(host);
    if !fixes.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("What to update", TITLE));
        for fix in fixes.iter().take(5) {
            let known = if fix.kev > 0 {
                format!(", {} known exploited", fix.kev)
            } else {
                String::new()
            };
            lines.push(Line::raw(format!("  {}", sanitize(&fix.action, 300))));
            lines.push(Line::styled(
                format!(
                    "      answers {} matched by version only{known}",
                    fix.advisories
                ),
                DIM,
            ));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled("Ports", TITLE));
    for port in host.ports.values() {
        let style = if port.is_open() { Style::new() } else { DIM };
        lines.push(Line::styled(
            format!("  {} {}", port.label(), port.state),
            style,
        ));
        if let Some(server) = port.http.as_ref().and_then(|h| h.server.as_ref()) {
            lines.push(Line::styled(format!("      Server: {server}"), DIM));
        }
        if !port.tls_sans.is_empty() {
            let names: Vec<&str> = port.tls_sans.iter().map(String::as_str).collect();
            lines.push(Line::styled(
                format!("      SAN: {}", names.join(", ")),
                DIM,
            ));
        }
        let mut paths = Vec::new();
        path_lines(&port.paths, 0, &mut paths);
        let truncated = paths.len() >= MAX_PATH_LINES;
        lines.extend(paths);
        if truncated {
            lines.push(Line::styled("      ... more paths not shown", DIM));
        }
    }
    if host.ports.is_empty() {
        lines.push(Line::styled("  none seen", DIM));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled("Evidence (Observed)", TITLE));
    let facts = host
        .facts
        .iter()
        .chain(host.ports.values().flat_map(|p| p.facts.iter()))
        .take(MAX_FACT_LINES);
    for fact in facts {
        lines.push(Line::from(vec![
            Span::raw(format!("  {} ", fact.claim)),
            Span::styled(
                format!(
                    "[{} / {:?}]",
                    fact.record.source.as_str(),
                    fact.record.confidence
                ),
                DIM,
            ),
        ]));
    }
    lines
}

fn advisory_detail(snapshot: &Snapshot, host: &Host, advisory: &Advisory) -> Vec<Line<'static>> {
    let list = checklist::for_advisory(&snapshot.graph, host, advisory);
    let (done, total) = list.progress();
    let mut lines = vec![
        Line::from(vec![
            Span::styled(advisory.id.clone(), TITLE),
            Span::raw("  "),
            Span::styled(
                advisory.record.verification_status.to_string(),
                status_style(advisory.record.verification_status),
            ),
        ]),
        Line::raw(advisory.title.clone()),
        Line::styled(
            format!(
                "{}  {}",
                advisory.port.as_deref().unwrap_or("-"),
                advisory.matched
            ),
            DIM,
        ),
    ];
    let fix = match (&advisory.fixed_in, &advisory.last_affected) {
        (Some(fixed), _) => Some(format!("Fixed in {fixed}")),
        (None, Some(last)) => Some(format!("Affected up to {last}; update past it")),
        (None, None) => None,
    };
    lines.extend(fix.map(|text| Line::styled(sanitize(&text, 120), GOOD)));
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("Verification checklist ({done}/{total})"),
        TITLE,
    ));
    for item in &list.items {
        let (mark, style) = if item.done {
            ("[x]", GOOD)
        } else {
            ("[ ]", DIM)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{mark} {}", item.label), style),
            Span::styled(format!("  {}", item.detail), DIM),
        ]));
    }
    if list.research_ready()
        && advisory.record.verification_status == VerificationStatus::UnverifiedHypothesis
    {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "[R] Deep Research Ready",
            GOOD.add_modifier(Modifier::BOLD),
        ));
    }
    lines
}

/// The box at the top right: what this machine is, its open ports and its
/// interfaces. Always in view; `m` shows the routes and neighbours too.
fn machine_box_lines(report: &MachineReport) -> Vec<Line<'static>> {
    let vpn = if report.vpn.is_empty() {
        Span::styled("   no VPN", DIM)
    } else {
        let names: Vec<&str> = report
            .vpn
            .iter()
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        Span::styled(format!("   VPN {}", sanitize(&names.join(", "), 80)), GOOD)
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(sanitize(&report.headline, 200), TITLE),
        vpn,
    ])];
    for section in report.sections.iter().filter(|section| section.open) {
        let style = if section.warn { WARN } else { Style::default() };
        let label = format!("{:<12}", section.title);
        for (index, line) in section.lines.iter().enumerate() {
            let label = if index == 0 {
                label.clone()
            } else {
                " ".repeat(12)
            };
            lines.push(Line::from(vec![
                Span::styled(label, DIM),
                Span::styled(sanitize(line, 300), style),
            ]));
        }
    }
    lines
}

/// Everything the observer read about this machine, section by section.
fn machine_lines(report: &MachineReport) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for section in &report.sections {
        if !lines.is_empty() {
            lines.push(Line::raw(""));
        }
        lines.push(Line::styled(section.title.clone(), TITLE));
        let style = if section.warn { WARN } else { Style::default() };
        for line in &section.lines {
            lines.push(Line::styled(format!("  {}", sanitize(line, 400)), style));
        }
    }
    if let Some(time) = report.observed_utc.get(11..19) {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("Read from this machine at {time} UTC. Nothing was sent to find this out."),
            DIM,
        ));
    }
    lines
}

fn draw_header(frame: &mut Frame, area: Rect, model: &Model) {
    let Some(snapshot) = &model.snapshot else {
        frame.render_widget(
            Paragraph::new(" meow hud: waiting for the session ..."),
            area,
        );
        return;
    };

    let mode_style = match snapshot.mode {
        Mode::Light => GOOD,
        Mode::Mild => WARN,
        Mode::Aggressive => BAD,
    };
    let link = if model.live {
        Span::styled("live", GOOD)
    } else {
        Span::styled("read-only (no session running)", WARN)
    };
    let line = Line::from(vec![
        Span::styled(" meow hud ", TITLE),
        Span::raw(format!("| {} | mode ", snapshot.session)),
        Span::styled(snapshot.mode.as_str(), mode_style),
        Span::raw({
            let names = snapshot
                .graph
                .hosts
                .values()
                .filter(|host| only_mentioned(host))
                .count();
            let seen = snapshot.graph.hosts.len() - names;
            let mentioned = if names > 0 {
                format!(" ({names} names only mentioned)")
            } else {
                String::new()
            };
            format!(
                " | {seen} hosts{mentioned} | {} advisories | ",
                snapshot.graph.advisory_count()
            )
        }),
        link,
        Span::styled(
            if snapshot.budget.has_key {
                format!(
                    " | cloud ${:.2} of ${:.2}, {} of {} calls today",
                    snapshot.budget.spent_usd,
                    snapshot.budget.max_usd,
                    snapshot.budget.calls,
                    snapshot.budget.max_calls
                )
            } else {
                " | cloud: no API key (run `meow setup`)".to_owned()
            },
            DIM,
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_hosts(frame: &mut Frame, area: Rect, model: &Model, snapshot: &Snapshot) {
    let items: Vec<ListItem> = model
        .hosts()
        .iter()
        .map(|host| {
            let open = host
                .advisories
                .iter()
                .filter(|a| {
                    a.record.verification_status == VerificationStatus::UnverifiedHypothesis
                })
                .count();
            if only_mentioned(host) {
                // A name from a URL in the terminal, not a machine seen.
                return ListItem::new(Line::styled(format!("{}  mentioned", host.label()), DIM));
            }
            let mut spans = vec![Span::raw(host.label())];
            spans.push(Span::styled(
                format!("  p:{}", host.open_ports().count()),
                DIM,
            ));
            if open > 0 {
                spans.push(Span::styled(format!(" h:{open}"), WARN));
            }
            if host.advisories.iter().any(|a| a.kev) {
                spans.push(Span::styled(" KEV", BAD));
            }
            if checklist::host_research_ready(&snapshot.graph, host) {
                spans.push(Span::styled(" [R]", GOOD));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let list = List::new(items)
        .block(panel("Hosts", model.focus == Focus::Hosts))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    let mut state = ListState::default().with_selected(Some(model.host_index));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_advisories(frame: &mut Frame, area: Rect, model: &Model, snapshot: &Snapshot) {
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).areas(area);
    let advisories = model.advisories();
    let items: Vec<ListItem> = advisories
        .iter()
        .map(|advisory| {
            let score = advisory
                .cvss
                .map(|s| format!(" {s:.1}"))
                .unwrap_or_default();
            let mut spans = vec![Span::raw(format!("{}{score}", advisory.id))];
            if advisory.kev {
                spans.push(Span::styled(" KEV", BAD));
            }
            spans.push(Span::styled(
                format!(" {}", advisory.record.verification_status),
                status_style(advisory.record.verification_status),
            ));
            ListItem::new(Line::from(spans))
        })
        .collect();
    let title = format!("CVE feed: hypotheses and findings ({})", advisories.len());
    let list = List::new(items)
        .block(panel(&title, model.focus == Focus::Advisories))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    let mut state = ListState::default()
        .with_selected((!advisories.is_empty()).then_some(model.advisory_index));
    frame.render_stateful_widget(list, list_area, &mut state);

    let detail = match (model.selected_host(), model.selected_advisory()) {
        (Some(host), Some(advisory)) => advisory_detail(snapshot, host, advisory),
        _ => vec![Line::styled(
            "No advisories matched for this host yet.",
            DIM,
        )],
    };
    frame.render_widget(
        Paragraph::new(detail)
            .wrap(Wrap { trim: false })
            .block(panel("Evidence vs. hypothesis", false)),
        detail_area,
    );
}

fn draw_activity(frame: &mut Frame, area: Rect, snapshot: &Snapshot) {
    let [queue_area, notice_area] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
    let mut lines: Vec<Line> = Vec::new();
    // The newest run of each target; earlier runs are only counted.
    let mut shown: Vec<&TaskRow> = Vec::new();
    for task in &snapshot.tasks {
        if !shown.iter().any(|t| t.target == task.target) {
            shown.push(task);
        }
    }
    for task in shown.into_iter().take(4) {
        let runs = snapshot
            .tasks
            .iter()
            .filter(|t| t.target == task.target)
            .count();
        let mut spans = vec![Span::raw(format!("recon {} ", task.target))];
        if runs > 1 {
            spans.push(Span::styled(format!("(+{} earlier) ", runs - 1), DIM));
        }
        for stage in &task.stages {
            let style = match stage.status.as_str() {
                "done" => GOOD,
                "running" => WARN.add_modifier(Modifier::BOLD),
                "failed" | "interrupted" => BAD,
                _ => DIM,
            };
            spans.push(Span::styled(
                format!("{}:{} ", stage.stage.as_str(), stage.status),
                style,
            ));
        }
        lines.push(Line::from(spans));
        if let Some(active) = task.stages.iter().rev().find(|s| !s.detail.is_empty()) {
            let room = (queue_area.width as usize).saturating_sub(4);
            for piece in wrap_words(&sanitize(&active.detail, 300), room) {
                lines.push(Line::styled(format!("  {piece}"), DIM));
            }
        }
    }
    if lines.is_empty() {
        lines.push(Line::styled(
            "No recon tasks. Queue one with `meow recon <target>`.",
            DIM,
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(panel("Background queue", false)),
        queue_area,
    );

    // Newest first, each one whole: a long notice continues on the next
    // line under its text instead of being cut at the border.
    let rows = notice_area.height.saturating_sub(2) as usize;
    let room = (notice_area.width as usize).saturating_sub(2 + 9);
    let mut notices: Vec<Line> = Vec::new();
    for notice in snapshot.notices.iter().rev() {
        if notices.len() >= rows {
            break;
        }
        let time = format!("{:<9}", notice.at.get(11..19).unwrap_or(""));
        for (index, piece) in wrap_words(&sanitize(&notice.text, 400), room)
            .into_iter()
            .enumerate()
        {
            let lead = if index == 0 {
                time.clone()
            } else {
                " ".repeat(9)
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

fn draw_footer(frame: &mut Frame, area: Rect, model: &Model) {
    let [input_area, help_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    let input = match &model.note {
        Some(text) => {
            let target = model
                .selected_host()
                .map_or("workspace".to_owned(), |h| h.address.clone());
            Line::from(vec![
                Span::styled(format!(" note for {target}> "), TITLE),
                Span::raw(text.clone()),
                Span::styled("_", TITLE),
            ])
        }
        None => Line::styled(format!(" {}", model.status), WARN),
    };
    frame.render_widget(Paragraph::new(input), input_area);
    let help = if model.note.is_some() {
        " Enter save   Esc cancel"
    } else {
        " Up/Down select  Tab panel  n note  c confirm  f false positive  u reopen  L/C/R ask AI  a AI view  m this machine  1/2/3 mode  PgUp/PgDn scroll  q quit"
    };
    frame.render_widget(Paragraph::new(Line::styled(help, DIM)), help_area);
}

fn draw_ai(frame: &mut Frame, area: Rect, model: &Model, snapshot: &Snapshot) {
    let ai = &snapshot.ai;
    let title = match (ai.tier, &ai.address) {
        (Some(tier), Some(address)) => format!(
            "AI: [{}] {} for {address}{}",
            tier.key(),
            tier.label(),
            if ai.running { " (running)" } else { "" }
        ),
        _ => "AI: press L (local), C (cloud) or R (research) on a host".to_owned(),
    };
    let mut lines: Vec<Line> = ai
        .text
        .lines()
        .map(|line| {
            let line = sanitize(line, 2000);
            if line.starts_with('#') {
                Line::styled(line, TITLE)
            } else {
                Line::raw(line)
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
    if lines.is_empty() {
        let hint = if ai.running {
            "Waiting for the model ..."
        } else {
            "No AI reply yet."
        };
        lines.push(Line::styled(hint, DIM));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((model.inspector_scroll, 0))
            .block(panel(&title, true)),
        area,
    );
}

/// Draws the whole panel. Pure: everything comes from `model`.
pub fn draw(frame: &mut Frame, model: &Model) {
    // A tall terminal gives the queue and the notices more lines.
    let activity_rows = if frame.area().height >= 40 { 12 } else { 8 };
    let [header, body, activity, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Length(activity_rows),
        Constraint::Length(2),
    ])
    .areas(frame.area());
    draw_header(frame, header, model);
    draw_footer(frame, footer, model);
    let Some(snapshot) = &model.snapshot else {
        return;
    };
    let [hosts, right] =
        Layout::horizontal([Constraint::Percentage(28), Constraint::Percentage(72)]).areas(body);
    // Top right: this machine, as tall as it needs but never crowding out
    // the host panels below it.
    let report = machine_report(&snapshot.graph.local);
    let machine_lines_top = machine_box_lines(&report);
    let wanted = (machine_lines_top.len() as u16 + 2)
        .min(right.height / 3)
        .max(3);
    let [machine, right] =
        Layout::vertical([Constraint::Length(wanted), Constraint::Min(0)]).areas(right);
    frame.render_widget(
        Paragraph::new(machine_lines_top).block(panel(
            "This machine: address -> type -> OS -> version (m for routes and neighbours)",
            false,
        )),
        machine,
    );
    let [inspector, advisories] =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(right);
    draw_hosts(frame, hosts, model, snapshot);
    if model.show_ai {
        draw_ai(frame, inspector, model, snapshot);
    } else if model.show_machine {
        frame.render_widget(
            Paragraph::new(machine_lines(&report))
                .wrap(Wrap { trim: false })
                .scroll((model.inspector_scroll, 0))
                .block(panel(
                    "This machine in full: ports, interfaces, routes, neighbours",
                    true,
                )),
            inspector,
        );
    } else {
        let lines = match model.selected_host() {
            Some(host) => inspector_lines(&snapshot.graph, host),
            None => vec![Line::styled(
                "No hosts yet. Import a scan with `meow add <file>`, or work in the session shell.",
                DIM,
            )],
        };
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((model.inspector_scroll, 0))
                .block(panel("Inspector: node, ports and sub-paths", false)),
            inspector,
        );
    }
    draw_advisories(frame, advisories, model, snapshot);
    draw_activity(frame, activity, snapshot);
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(info: &RuntimeInfo) -> Option<Socket> {
    let url = format!("ws://127.0.0.1:{}/ws?token={}", info.port, info.token);
    let attempt = tokio::time::timeout(
        Duration::from_secs(3),
        tokio_tungstenite::connect_async(url),
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
    loop {
        terminal
            .draw(|frame| draw(frame, model))
            .context("cannot draw the panel")?;
        tokio::select! {
            event = input.recv() => {
                let Some(event) = event else { break };
                let Event::Key(key) = event else { continue };
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match model.on_key(key) {
                    Action::Quit => break,
                    Action::None => {}
                    Action::Send(command) => {
                        let Some(live) = socket.as_mut() else { continue };
                        let text = serde_json::to_string(&command)?;
                        if live.send(Message::Text(text.into())).await.is_err() {
                            socket = None;
                            model.live = false;
                            model.status = "the session has ended".to_owned();
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
                Some(Ok(Message::Text(text))) => model.apply_message(&text),
                Some(Ok(_)) => {}
                _ => {
                    socket = None;
                    model.live = false;
                    model.status = "the session has ended; showing its last state".to_owned();
                }
            },
        }
    }
    Ok(())
}

/// Runs the panel until the operator quits.
pub fn run(workspace: &Workspace) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(async {
        let socket = match RuntimeInfo::read(&workspace.runtime_path()) {
            Some(info) => connect(&info).await,
            None => None,
        };
        let mut model = Model::new(socket.is_some());
        if socket.is_none() {
            model.snapshot = Some(Snapshot::offline(workspace)?);
        }
        let mut terminal =
            ratatui::try_init().context("cannot take over the terminal (is this a TTY?)")?;
        let result = event_loop(&mut terminal, &mut model, socket).await;
        ratatui::restore();
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Confidence, EvidenceRecord, Source};
    use crate::graph::{Interface, Listener, Observation, Route, SystemInfo};
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
                    record: EvidenceRecord::hypothesis(Source::NvdApi, Confidence::Medium, "{}"),
                },
            );
        }
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
                "checklists": {}, "topology": {},
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
            "meow hud",
            "| acme | mode mild | 2 hosts | 3 advisories | live",
            "Hosts",
            "10.10.10.5  p:2 h:3 KEV [R]",
            "10.10.10.9  p:1",
            "Inspector: node, ports and sub-paths",
            "80/tcp svc nginx 1.18.0 open",
            "/portal/",
            "/config  200",
            "/login.php  200",
            "Evidence (Observed)",
            "[nmap_xml / High]",
            "CVE feed: hypotheses and findings (3)",
            "Evidence vs. hypothesis",
            "Verification checklist (4/6)",
            "[x] Service identified",
            "[x] Route to the host  via 10.10.14.1 on tun0",
            "[ ] Operator verdict",
            "[R] Deep Research Ready",
            "Background queue",
            "recon 10.10.10.0/23 ports:done services:running crawl:pending dirs:pending",
            "Notices",
            "09:41:00 not running as root: -sS replaced with -sT (connect scan)",
            "n note  c confirm  f false positive",
            "L/C/R ask AI",
            "| cloud $0.25 of $1.00, 3 of 20 calls today",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    #[test]
    fn long_notices_wrap_and_the_host_says_what_to_update() {
        let mut graph = graph();
        for advisory in &mut graph.hosts.get_mut("10.10.10.5").unwrap().advisories {
            advisory.fixed_in = Some("1.20.1".into());
        }
        let mut message: serde_json::Value = serde_json::from_str(&state_message(&graph)).unwrap();
        message["state"]["notices"] = json!([ {
            "at": "2026-11-12T09:41:00Z",
            "text": "3 possible advisories for 10.10.10.5 (1 known exploited), matched by version \
                     number only and not verified. Most come from one place: Update nginx to 1.20.1 or later."
        } ]);
        let mut model = Model::new(true);
        model.apply_message(&message.to_string());

        let text = screen(&model, 160, 54);
        for expected in [
            "What to update",
            "Update cpe:2.3:a:nginx:nginx:1.18.0 to 1.20.1 or later, or close 80/tcp if the service",
            "answers 3 matched by version only, 1 known exploited",
            "Fixed in 1.20.1",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }

        // On a narrow screen the notice continues under its own text.
        let narrow = screen(&model, 100, 30);
        for expected in ["09:41:00 3 possible advisories", "         or later."] {
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

    #[test]
    fn only_the_newest_run_of_a_target_is_shown() {
        let mut message: serde_json::Value =
            serde_json::from_str(&state_message(&graph())).unwrap();
        let run = |id: i64, status: &str| {
            json!({ "id": id, "target": "10.10.10.5", "mode": "mild", "extra_flags": [], "created_utc": "",
                "stages": [ { "stage": "ports", "status": status, "detail": "" } ] })
        };
        message["state"]["tasks"] = json!([run(3, "running"), run(2, "done"), run(1, "done")]);
        let mut model = Model::new(true);
        model.apply_message(&message.to_string());
        let text = screen(&model, 160, 64);
        assert!(
            text.contains("recon 10.10.10.5 (+2 earlier) ports:running"),
            "{text}"
        );
        assert_eq!(text.matches("recon 10.10.10.5").count(), 1, "{text}");
    }

    #[test]
    fn advisories_are_ordered_known_exploited_then_by_score() {
        let model = model();
        let ids: Vec<&str> = model.advisories().iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["CVE-2020-0002", "CVE-2021-23017", "CVE-2019-0001"]);
        assert_eq!(model.selected_advisory().unwrap().id, "CVE-2020-0002");
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
        // No advisory on this host: a verdict key explains instead of sending.
        assert_eq!(model.on_key(key(KeyCode::Char('c'))), Action::None);
        assert!(model.status.contains("select a host and an advisory"));

        model.on_key(key(KeyCode::Up));
        model.on_key(key(KeyCode::Tab));
        assert_eq!(model.focus, Focus::Advisories);
        model.on_key(key(KeyCode::Char('j')));
        assert_eq!(
            model.on_key(key(KeyCode::Char('c'))),
            Action::Send(Command::Verdict {
                address: "10.10.10.5".into(),
                advisory: "CVE-2021-23017".into(),
                status: VerificationStatus::Confirmed,
            })
        );
        assert!(matches!(
            model.on_key(key(KeyCode::Char('f'))),
            Action::Send(Command::Verdict {
                status: VerificationStatus::FalsePositive,
                ..
            })
        ));
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
        // Lower-case c is "confirm"; the AI tiers are the capital letters.
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
        assert!(
            text.contains("AI: press L (local), C (cloud) or R (research) on a host"),
            "{text}"
        );
        assert!(text.contains("No AI reply yet."), "{text}");

        // The reply streams in through state updates.
        let mut state: Value = serde_json::from_str(&state_message(&graph())).unwrap();
        state["state"]["ai"] = json!({
            "running": true, "tier": "cloud", "address": "10.10.10.5",
            "text": "## 1. Evidence-Backed Risk\nUpgrade nginx\u{1b}[2J on 10.10.10.5", "error": null, "summary": null
        });
        model.apply_message(&state.to_string());
        let text = screen(&model, 160, 46);
        assert!(
            text.contains("AI: [C] Cloud triage for 10.10.10.5 (running)"),
            "{text}"
        );
        assert!(text.contains("## 1. Evidence-Backed Risk"), "{text}");
        assert!(text.contains("Upgrade nginx[2J on 10.10.10.5"), "{text}");

        state["state"]["ai"]["running"] = json!(false);
        state["state"]["ai"]["error"] =
            json!("the model server answered HTTP 402: Insufficient credits");
        state["state"]["ai"]["summary"] = json!(
            "[C] for 10.10.10.5 answered by test/triage, $0.0042, saved to chats/10.10.10.5.md"
        );
        model.apply_message(&state.to_string());
        let text = screen(&model, 160, 46);
        assert!(!text.contains("(running)"), "{text}");
        assert!(text.contains("HTTP 402: Insufficient credits"), "{text}");
        assert!(text.contains("saved to chats/10.10.10.5.md"), "{text}");

        // `a` goes back to the inspector.
        model.on_key(key(KeyCode::Char('a')));
        assert!(screen(&model, 160, 46).contains("Inspector: node, ports and sub-paths"));

        // Without a session nothing is sent, and without a host nothing is asked.
        let mut offline = Model::new(false);
        offline.apply_message(&state_message(&graph()));
        assert_eq!(offline.on_key(key(KeyCode::Char('C'))), Action::None);
        assert!(offline.status.starts_with("read-only"));
        let mut empty = Model::new(true);
        empty.apply_message(&state_message(&Graph::default()));
        assert_eq!(empty.on_key(key(KeyCode::Char('L'))), Action::None);
        assert_eq!(empty.status, "select a host first");
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
        assert!(screen(&model, 120, 40).contains("note for 10.10.10.5> qc pkg:npm/lodash@4.17.20_"));
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
        assert_eq!(model.on_key(key(KeyCode::Esc)), Action::None);
        assert_eq!(model.note, None);
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
        assert_eq!(model.status, "refused: light mode sends no packets[2J");
        model.apply_message(r#"{"type":"result","ok":true,"result":{}}"#);
        assert_eq!(model.status, "done");
        model.apply_message("not json");
        model.apply_message(r#"{"type":"state","state":{"session":5}}"#);
        assert!(model.status.starts_with("unreadable state"));
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
        assert!(text.contains("read-only (no session running)"), "{text}");
        assert!(text.contains("10.10.10.5"), "{text}");
        assert!(text.contains("recon 10.10.10.0/23 ports:pending"), "{text}");

        model.on_key(key(KeyCode::Tab));
        assert_eq!(model.on_key(key(KeyCode::Char('c'))), Action::None);
        assert!(model.status.starts_with("read-only"));
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
        // Nothing read yet: the box says so instead of showing nothing.
        let text = screen(&model(), 160, 50);
        for expected in [
            "This machine: address -> type -> OS -> version",
            "no address -> computer -> OS not known -> version not known   no VPN",
            "Open ports  none listening",
            "Interfaces  unknown: the network tables could not be read",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }

        let mut model = Model::new(true);
        model.apply_message(&state_message(&graph));
        let text = screen(&model, 160, 50);
        // An idle tunnel with only a link-local address is not a VPN, and
        // is not listed as an interface in use.
        for expected in [
            "10.44.8.20 -> MacBook Pro -> macOS -> 15.1   no VPN",
            "Open ports  this machine only: 631/tcp",
            "Interfaces  en0 10.44.8.20/22 gateway 10.44.8.1",
            "m this machine",
            // The selected host gets the same one-line answer.
            "10.10.10.5 -> Server -> OS not known -> version not known",
            "Open ports  22/tcp svc, 80/tcp svc",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert!(!text.contains("utun0"), "{text}");
        assert!(!text.contains("Routes ("), "the tables stay out of the way");

        // `m` swaps the inspector for the full report; `m` again swaps back.
        assert_eq!(model.on_key(key(KeyCode::Char('m'))), Action::None);
        let text = screen(&model, 160, 50);
        for expected in [
            "This machine in full: ports, interfaces, routes, neighbours",
            "Routes (1 of 2)",
            "  default via 10.44.8.1 on en0",
            "Neighbours (0)",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert!(!text.contains("Inspector: node, ports and sub-paths"));
        // The report scrolls like the inspector does.
        model.on_key(key(KeyCode::PageDown));
        let scrolled = screen(&model, 160, 50);
        assert!(scrolled.contains("All interfaces (2)"), "{scrolled}");
        assert!(
            scrolled.contains("Read from this machine at 09:40:00 UTC"),
            "{scrolled}"
        );
        model.on_key(key(KeyCode::Char('m')));
        assert!(screen(&model, 160, 50).contains("Inspector: node, ports and sub-paths"));

        // A tunnel with a real address is reported as the VPN it is.
        graph.local.interfaces[1]
            .addresses
            .push("10.10.14.3/23".into());
        model.apply_message(&state_message(&graph));
        let text = screen(&model, 160, 50);
        assert!(text.contains("-> macOS -> 15.1   VPN utun0"), "{text}");
        assert!(
            text.contains("utun0 10.10.14.3/23 VPN, no route uses it"),
            "{text}"
        );
        // The AI view and the machine view replace each other.
        model.on_key(key(KeyCode::Char('m')));
        model.on_key(key(KeyCode::Char('a')));
        assert!(model.show_ai && !model.show_machine);
        model.on_key(key(KeyCode::Char('m')));
        assert!(model.show_machine && !model.show_ai);
    }

    #[test]
    fn small_and_empty_screens_do_not_panic() {
        let mut empty = Model::new(true);
        assert!(screen(&empty, 80, 24).contains("waiting for the session"));
        empty.apply_message(&state_message(&Graph::default()));
        let text = screen(&empty, 80, 24);
        assert!(text.contains("No hosts yet."), "{text}");
        for (width, height) in [(20, 5), (1, 1), (200, 60)] {
            screen(&model(), width, height);
        }
    }
}

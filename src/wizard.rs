//! Interactive Cat-Themed First-Run & Setup GUI (`Ratatui` TUI) plus shared
//! Cat ASCII headers across `meow`.
//!
//! Runs strictly on the main thread when attached to an interactive terminal
//! (`stdin` + `stdout` are TTYs and `TERM != "dumb"`), never inside the PTY
//! host process. Secret fields (cloud API keys and optional NVD API keys) are
//! rendered as `*` bullets while typing/pasting and by `setup::masked` after
//! entry, so raw key characters never touch the screen buffer or logs.

use std::env;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::ai::{self, AiOverrides, AiSettings, CloudProvider};
use crate::anthropic;
use crate::evidence::sanitize;
use crate::mode::Mode;
use crate::queue;
use crate::setup;
use crate::tools;
use crate::workspace::{read_private_bounded, validate_name, Config, MeowHome};

const MAX_EDIT_CHARS: usize = 4096;
const MAX_WIZARD_CONFIG_BYTES: u64 = 256 * 1024;

/// Crisp 7-bit Cat + wordmark ASCII banner for `meow --help` and `--plain`.
pub const CAT_CLI_BANNER: &str = concat!(
    "   /\\_/\\    _ __ ___   ___  _____      __\n",
    "  ( o.o )  | '_ ` _ \\ / _ \\/ _ \\ \\ /\\ / /\n",
    "   > ^ <   | | | | | |  __/ (_) \\ V  V /\n",
    "  /|   |\\  |_| |_| |_|\\___|\\___/ \\_/\\_/\n",
    " (_|   |_)  local security triage, topology & audit shell"
);

/// Compact Cat ASCII header shown above `meow list` on an interactive TTY.
pub const CAT_LIST_HEADER: &str = concat!(
    "  /\\_/\\   meow :: workspaces  (tip: `meow setup` opens the interactive cat GUI)\n",
    " ( ^.^ )  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
);

/// Mode-reactive 3-line Cat ASCII header printed when opening a session on a TTY.
pub fn session_header(name: &str, mode: Mode, created: bool) -> String {
    let safe_name = sanitize(name, 64);
    let verb = if created { "new" } else { "resumed" };
    match mode {
        Mode::Light => format!(
            "   |\\__/,|   (`\\   meow :: {safe_name} ({verb}, light mode)\n\
             \x20_.| -.- |_   ) )  passive triage shell -- 0 outbound packets unless you run a command\n\
             -(((---(((--------\n"
        ),
        Mode::Mild => format!(
            "   /\\_/\\     _     meow :: {safe_name} ({verb}, mild mode)\n\
             \x20 ( o.o )  _//     polite recon shell -- rate-limited discovery & live topology map\n\
             \x20  > ^ <  (_/      -----------------------------------------------------------------\n"
        ),
        Mode::Aggressive => format!(
            "  /\\___/\\   /      meow :: {safe_name} ({verb}, aggressive mode)\n\
             \x20( >'w'< ) //      lab-speed recon shell -- fast Nmap & auto-tuned web discovery\n\
             \x20 /     \\ V        -----------------------------------------------------------------\n"
        ),
    }
}

/// Outcome returned when the setup GUI exits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardOutcome {
    Cancelled,
    Saved { launch_workspace: Option<String> },
}

/// The five interactive tabs of the setup wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Mode,
    LocalAi,
    CloudAi,
    Toolkit,
    Launch,
}

impl Step {
    pub const ALL: [Self; 5] = [
        Self::Mode,
        Self::LocalAi,
        Self::CloudAi,
        Self::Toolkit,
        Self::Launch,
    ];

    pub fn index(self) -> usize {
        match self {
            Self::Mode => 0,
            Self::LocalAi => 1,
            Self::CloudAi => 2,
            Self::Toolkit => 3,
            Self::Launch => 4,
        }
    }

    pub fn short_title(self) -> &'static str {
        match self {
            Self::Mode => "1 Prowl Mode",
            Self::LocalAi => "2 Local AI [L]",
            Self::CloudAi => "3 Cloud AI [C/R]",
            Self::Toolkit => "4 Claws & Radar",
            Self::Launch => "5 Launchpad",
        }
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// Cloud provider choice on Step 3 (`Cloud Whiskers`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudChoice {
    LocalOnly,
    Claude,
    OpenRouter,
}

/// Which text/secret field is currently open in the inline editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditField {
    LocalUrl,
    LocalModel,
    CloudApiKey,
    CloudUrl,
    CloudModel,
    ResearchModel,
    Fallbacks,
    NvdApiKey,
    WorkspaceName,
}

impl EditField {
    pub fn is_secret(self) -> bool {
        matches!(self, Self::CloudApiKey | Self::NvdApiKey)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::LocalUrl => "Local AI server URL (http:// or https://)",
            Self::LocalModel => "Local model name (leave empty to let server choose)",
            Self::CloudApiKey => "Cloud API key (hidden -- never echoed; Ctrl-U clears)",
            Self::CloudUrl => "Cloud service URL (https:// required unless loopback)",
            Self::CloudModel => "[C] Cloud triage model",
            Self::ResearchModel => "[R] Grounded research model",
            Self::Fallbacks => "Claude refusal fallback models (comma-separated, or 'none')",
            Self::NvdApiKey => "Optional NIST NVD API key (hidden -- Ctrl-U clears)",
            Self::WorkspaceName => "First workspace name (letters, digits, '-', '_', '.' or empty)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditState {
    pub field: EditField,
    pub buffer: String,
    /// Ctrl+V was pressed: the edit box says how to paste instead.
    pub paste_hint: bool,
}

/// Readiness of external recon scanners and wordlists on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCheck {
    pub name: String,
    pub found: Option<String>,
    pub hint: String,
}

/// Discovered local model from `[p]` sniffing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredModel {
    pub server_name: String,
    pub url: String,
    pub model: String,
}

/// Side effect requested by a key press inside the wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardAction {
    None,
    ProbeLocal,
    TestConnections,
    Save,
    Quit,
}

/// State machine for the Interactive Cat Setup GUI.
pub struct Wizard {
    pub first_run: bool,
    pub step: Step,
    pub cursors: [usize; 5],
    pub editing: Option<EditState>,
    pub status: String,
    pub status_warn: bool,

    // Editable configuration state
    pub default_mode: Mode,
    pub local_url: String,
    pub local_model: String,
    pub cloud_choice: CloudChoice,
    pub cloud_url: String,
    pub cloud_model: String,
    pub research_model: String,
    pub cloud_fallbacks: Vec<String>,
    pub cloud_api_key: Option<String>,
    pub env_key_source: Option<String>,
    pub cve_enabled: bool,
    pub nvd_api_key: Option<String>,
    pub location_enabled: bool,
    pub location_map: bool,
    pub launch_workspace: String,

    // Live probes & system checks
    pub discovered_local: Vec<DiscoveredModel>,
    pub tools: Vec<ToolCheck>,
    pub test_results: Vec<String>,
    pub config_file: PathBuf,
    pub ai_file: PathBuf,
}

impl Wizard {
    /// Builds a wizard pre-populated from any existing `~/.meow/config.toml`
    /// and `~/.meow/ai.toml` WITHOUT creating files on disk until saved.
    pub fn load(home: &MeowHome, first_run: bool) -> Result<Self> {
        let config_file = home.config_path();
        let ai_file = home.ai_path();
        let mut config = match std::fs::symlink_metadata(&config_file) {
            Ok(_) => {
                let text = read_private_bounded(&config_file, MAX_WIZARD_CONFIG_BYTES)?;
                crate::workspace::parse_toml::<Config>(&text, &config_file)?
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(err) => {
                return Err(err).with_context(|| format!("cannot read {}", config_file.display()))
            }
        };
        config.ai.user_file = Some(ai_file.clone());
        config.recon.wordlist_dir = Some(home.root().join("wordlists"));

        let own = AiOverrides::load(&ai_file)?;
        let effective = config.ai.effective();
        let env_key_source = config
            .ai
            .key_source()
            .filter(|src| src != "your setup file");

        let has_any_key = own.api_key.as_deref().is_some_and(|k| !k.trim().is_empty())
            || effective.api_key().is_some();
        let cloud_choice = if own.disable_cloud
            || (!has_any_key && own.cloud_provider.is_none() && own.cloud_url.is_none())
        {
            CloudChoice::LocalOnly
        } else if effective.provider() == CloudProvider::Anthropic {
            CloudChoice::Claude
        } else {
            CloudChoice::OpenRouter
        };

        let mode_cursor = match config.default_mode {
            Mode::Light => 0,
            Mode::Mild => 1,
            Mode::Aggressive => 2,
        };
        let cloud_cursor = match cloud_choice {
            CloudChoice::LocalOnly => 0,
            CloudChoice::Claude => 1,
            CloudChoice::OpenRouter => 2,
        };
        // Row 0 on Launch is optional WorkspaceName; Row 1 is the primary Save action.
        let launch_cursor = 1;
        let tools = scan_tools(&config, home);

        let welcome = if first_run {
            "Welcome to meow! Use arrows + Enter to customize, or press 's' anytime to save."
        } else {
            "Use Tab/1-5 to switch tabs, arrows + Enter to edit, 's' to save, or 'q' to cancel."
        };

        Ok(Self {
            first_run,
            step: Step::Mode,
            cursors: [mode_cursor, 0, cloud_cursor, 0, launch_cursor],
            editing: None,
            status: welcome.to_owned(),
            status_warn: false,
            default_mode: config.default_mode,
            local_url: sanitize(&effective.local_url, 200),
            local_model: sanitize(&effective.local_model, 120),
            cloud_choice,
            cloud_url: sanitize(&effective.cloud_url, 200),
            cloud_model: sanitize(&effective.cloud_model, 120),
            research_model: sanitize(&effective.research_model, 120),
            cloud_fallbacks: effective
                .fallbacks()
                .into_iter()
                .map(|m| sanitize(&m, 120))
                .collect(),
            cloud_api_key: own.api_key.filter(|k| !k.trim().is_empty()),
            env_key_source: env_key_source.map(|s| sanitize(&s, 80)),
            cve_enabled: config.cve.enabled,
            nvd_api_key: config.cve.nvd_api_key.filter(|k| !k.trim().is_empty()),
            location_enabled: config.location.enabled,
            location_map: config.location.map,
            launch_workspace: String::new(),
            discovered_local: Vec::new(),
            tools,
            test_results: Vec::new(),
            config_file,
            ai_file,
        })
    }

    pub fn cursor(&self) -> usize {
        self.cursors[self.step.index()]
    }

    fn set_status(&mut self, msg: impl Into<String>, warn: bool) {
        self.status = msg.into();
        self.status_warn = warn;
    }

    fn row_count(&self, step: Step) -> usize {
        match step {
            Step::Mode => 3,
            Step::LocalAi => 6 + self.discovered_local.len(),
            Step::CloudAi => 8,
            Step::Toolkit => 5,
            Step::Launch => 4,
        }
    }

    fn clamp_cursor(&mut self) {
        let len = self.row_count(self.step);
        let slot = &mut self.cursors[self.step.index()];
        if len == 0 {
            *slot = 0;
        } else if *slot >= len {
            *slot = len - 1;
        }
    }

    fn move_cursor(&mut self, delta: isize) {
        let len = self.row_count(self.step);
        if len == 0 {
            return;
        }
        let slot = &mut self.cursors[self.step.index()];
        *slot = (*slot as isize + delta).clamp(0, len as isize - 1) as usize;
    }

    /// Mode previewed on Step 1: follows the cursor on Step 1 so the Cat ASCII
    /// header reacts live as the user moves up and down!
    pub fn previewed_mode(&self) -> Mode {
        if self.step == Step::Mode {
            match self.cursor() {
                0 => Mode::Light,
                1 => Mode::Mild,
                _ => Mode::Aggressive,
            }
        } else {
            self.default_mode
        }
    }

    fn select_cloud_choice(&mut self, choice: CloudChoice) {
        let prev = self.cloud_choice;
        self.cloud_choice = choice;
        match choice {
            CloudChoice::LocalOnly => {
                self.cloud_api_key = None;
                self.set_status(
                    "Cloud AI disabled ($0.00 local-only mode). Stored API key will be cleared on save.",
                    false,
                );
            }
            CloudChoice::Claude => {
                let cleared = prev != CloudChoice::Claude
                    && prev != CloudChoice::LocalOnly
                    && self.cloud_api_key.take().is_some();
                self.cloud_url = anthropic::API_URL.to_owned();
                if !self.cloud_model.starts_with("claude-") {
                    self.cloud_model = anthropic::DEFAULT_MODEL.to_owned();
                }
                if !self.research_model.starts_with("claude-") {
                    self.research_model = anthropic::DEFAULT_MODEL.to_owned();
                }
                if prev != CloudChoice::Claude && self.cloud_fallbacks.is_empty() {
                    self.cloud_fallbacks = anthropic::DEFAULT_FALLBACKS
                        .iter()
                        .map(|m| (*m).to_owned())
                        .collect();
                }
                let msg = if cleared {
                    "Switched to Anthropic Claude API (previous service key cleared). Paste your Claude key below."
                } else {
                    "Switched to Anthropic Claude API. Select 'Cloud API Key' below to paste your key."
                };
                self.set_status(msg, false);
            }
            CloudChoice::OpenRouter => {
                let cleared = prev != CloudChoice::OpenRouter
                    && prev != CloudChoice::LocalOnly
                    && self.cloud_api_key.take().is_some();
                let defaults = AiSettings::default();
                if anthropic::is_claude_api(&self.cloud_url) || self.cloud_url.trim().is_empty() {
                    self.cloud_url = defaults.cloud_url;
                }
                if self.cloud_model.starts_with("claude-") {
                    self.cloud_model = defaults.cloud_model;
                }
                if self.research_model.starts_with("claude-") {
                    self.research_model = defaults.research_model;
                }
                self.cloud_fallbacks.clear();
                let msg = if cleared {
                    "Switched to OpenRouter / OpenAI-compatible API (previous service key cleared). Paste your key below."
                } else {
                    "Switched to OpenRouter / OpenAI-compatible API. Select 'Cloud API Key' to paste your key."
                };
                self.set_status(msg, false);
            }
        }
    }

    fn start_edit(&mut self, field: EditField) {
        let initial = match field {
            EditField::LocalUrl => self.local_url.clone(),
            EditField::LocalModel => self.local_model.clone(),
            // Secret fields start empty so pasting a new key replaces cleanly
            // without ever loading existing secret bytes into an edit buffer
            // unless needed; Ctrl-U + Enter clears.
            EditField::CloudApiKey | EditField::NvdApiKey => String::new(),
            EditField::CloudUrl => self.cloud_url.clone(),
            EditField::CloudModel => self.cloud_model.clone(),
            EditField::ResearchModel => self.research_model.clone(),
            EditField::Fallbacks => self.cloud_fallbacks.join(", "),
            EditField::WorkspaceName => self.launch_workspace.clone(),
        };
        self.editing = Some(EditState {
            field,
            buffer: initial,
            paste_hint: false,
        });
    }

    fn commit_edit(&mut self) {
        let Some(edit) = self.editing.take() else {
            return;
        };
        let trimmed = edit.buffer.trim();
        match edit.field {
            EditField::LocalUrl => match setup::checked_url(trimmed) {
                Ok(url) => {
                    self.local_url = url.clone();
                    self.set_status(format!("Local AI server set to {url}"), false);
                }
                Err(err) => {
                    self.set_status(format!("{err:#}"), true);
                    self.editing = Some(edit);
                }
            },
            EditField::LocalModel => {
                self.local_model = sanitize(trimmed, 120);
                let shown = if self.local_model.is_empty() {
                    "chosen by the server".to_owned()
                } else {
                    self.local_model.clone()
                };
                self.set_status(format!("Local AI model: {shown}"), false);
            }
            EditField::CloudApiKey => {
                if trimmed.is_empty() {
                    self.cloud_api_key = None;
                    self.set_status("Cloud API key cleared.", false);
                } else if trimmed.len() > 512 || trimmed.chars().any(char::is_control) {
                    self.set_status(
                        "API key must be at most 512 bytes and contain no control characters.",
                        true,
                    );
                } else {
                    let key = trimmed.to_owned();
                    if key.starts_with("sk-ant-") {
                        if self.cloud_choice != CloudChoice::Claude {
                            self.select_cloud_choice(CloudChoice::Claude);
                        }
                    } else if self.cloud_choice == CloudChoice::LocalOnly {
                        self.select_cloud_choice(CloudChoice::OpenRouter);
                    }
                    let summary = setup::masked(&key);
                    self.cloud_api_key = Some(key);
                    self.set_status(format!("Cloud API key {summary} (kept hidden)"), false);
                }
            }
            EditField::CloudUrl => match ai::validate_cloud_url(trimmed) {
                Ok(url) => {
                    let host_of = |raw: &str| {
                        reqwest::Url::parse(raw)
                            .ok()
                            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                            .unwrap_or_default()
                    };
                    let old_host = host_of(&self.cloud_url);
                    let new_host = host_of(&url);
                    let mut cleared = false;
                    if !old_host.is_empty() && old_host != new_host {
                        cleared = self.cloud_api_key.take().is_some();
                    }
                    if anthropic::is_claude_api(&url) {
                        self.select_cloud_choice(CloudChoice::Claude);
                    } else if self.cloud_choice != CloudChoice::OpenRouter {
                        self.select_cloud_choice(CloudChoice::OpenRouter);
                    }
                    self.cloud_url = url.clone();
                    let note = if cleared {
                        " (previous host's API key cleared)"
                    } else {
                        ""
                    };
                    self.set_status(format!("Cloud service URL set to {url}{note}"), false);
                }
                Err(err) => {
                    self.set_status(format!("{err:#}"), true);
                    self.editing = Some(edit);
                }
            },
            EditField::CloudModel => {
                if !trimmed.is_empty() {
                    self.cloud_model = sanitize(trimmed, 120);
                    self.set_status(format!("[C] triage model: {}", self.cloud_model), false);
                }
            }
            EditField::ResearchModel => {
                if !trimmed.is_empty() {
                    self.research_model = sanitize(trimmed, 120);
                    self.set_status(
                        format!("[R] research model: {}", self.research_model),
                        false,
                    );
                }
            }
            EditField::Fallbacks => {
                self.cloud_fallbacks = setup::parse_chain(trimmed)
                    .into_iter()
                    .map(|m| sanitize(&m, 120))
                    .collect();
                let desc = if self.cloud_fallbacks.is_empty() {
                    "left to the Claude API".to_owned()
                } else {
                    self.cloud_fallbacks.join(" -> ")
                };
                self.set_status(format!("Fallback chain: {desc}"), false);
            }
            EditField::NvdApiKey => {
                if trimmed.is_empty() {
                    self.nvd_api_key = None;
                    self.set_status("NVD API key cleared (6.5s anonymous pacing).", false);
                } else if trimmed.len() > 512 || trimmed.chars().any(char::is_control) {
                    self.set_status(
                        "NVD API key must be at most 512 bytes and contain no control characters.",
                        true,
                    );
                } else {
                    let summary = setup::masked(trimmed);
                    self.nvd_api_key = Some(trimmed.to_owned());
                    self.set_status(format!("NVD API key {summary} (0.7s fast pacing)"), false);
                }
            }
            EditField::WorkspaceName => {
                if trimmed.is_empty() {
                    self.launch_workspace.clear();
                    self.set_status(
                        "No initial workspace selected; saving will finish cleanly.",
                        false,
                    );
                } else {
                    match validate_launch_workspace(trimmed) {
                        Ok(valid) => {
                            self.launch_workspace = valid.clone();
                            self.set_status(
                                format!("Will launch session '{valid}' right after saving!"),
                                false,
                            );
                        }
                        Err(reason) => {
                            self.set_status(format!("Invalid workspace name: {reason}"), true);
                            self.editing = Some(edit);
                        }
                    }
                }
            }
        }
    }

    /// Handles pasted text (such as pasting an API key or URL).
    pub fn on_paste(&mut self, text: &str) {
        if let Some(edit) = &mut self.editing {
            let remaining = MAX_EDIT_CHARS.saturating_sub(edit.buffer.chars().count());
            let cleaned: String = text
                .chars()
                .filter(|c| !matches!(c, '\r' | '\n') && !c.is_control())
                .take(remaining)
                .collect();
            edit.buffer.push_str(&cleaned);
        }
    }

    /// Handles a key press and returns any requested I/O action.
    pub fn on_key(&mut self, key: KeyEvent) -> WizardAction {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return WizardAction::Quit;
        }

        if let Some(edit) = &mut self.editing {
            let mut paste_hint = false;
            match key.code {
                KeyCode::Esc => {
                    self.editing = None;
                    self.set_status("Edit cancelled.", false);
                }
                KeyCode::Enter => self.commit_edit(),
                KeyCode::Backspace => {
                    edit.buffer.pop();
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    edit.buffer.clear();
                }
                KeyCode::Delete => {
                    edit.buffer.clear();
                }
                // In a terminal Ctrl+V sends a control key, not the
                // clipboard: say how to paste instead of typing a "v".
                KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    edit.paste_hint = true;
                    paste_hint = true;
                }
                KeyCode::Char(_)
                    if key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {}
                KeyCode::Char(ch)
                    if !ch.is_control() && edit.buffer.chars().count() < MAX_EDIT_CHARS =>
                {
                    edit.buffer.push(ch);
                }
                _ => {}
            }
            if paste_hint {
                self.set_status(setup::PASTE_HINT, true);
            }
            return WizardAction::None;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => WizardAction::Quit,
            KeyCode::Char('s') => self.request_save(),
            KeyCode::Char('p') => WizardAction::ProbeLocal,
            KeyCode::Char('t') => WizardAction::TestConnections,
            KeyCode::Char('r') if self.step == Step::Toolkit => {
                self.rescan_tools();
                WizardAction::None
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                self.step = self.step.next();
                self.clamp_cursor();
                WizardAction::None
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                self.step = self.step.prev();
                self.clamp_cursor();
                WizardAction::None
            }
            KeyCode::Char('1') => {
                self.step = Step::Mode;
                WizardAction::None
            }
            KeyCode::Char('2') => {
                self.step = Step::LocalAi;
                WizardAction::None
            }
            KeyCode::Char('3') => {
                self.step = Step::CloudAi;
                WizardAction::None
            }
            KeyCode::Char('4') => {
                self.step = Step::Toolkit;
                WizardAction::None
            }
            KeyCode::Char('5') => {
                self.step = Step::Launch;
                WizardAction::None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_cursor(-1);
                WizardAction::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_cursor(1);
                WizardAction::None
            }
            KeyCode::Char(' ') => self.activate_row(false),
            KeyCode::Enter => self.activate_row(true),
            _ => WizardAction::None,
        }
    }

    fn request_save(&mut self) -> WizardAction {
        if !self.launch_workspace.is_empty() {
            if let Err(reason) = validate_launch_workspace(&self.launch_workspace) {
                self.set_status(format!("Invalid workspace name: {reason}"), true);
                self.step = Step::Launch;
                return WizardAction::None;
            }
        }
        WizardAction::Save
    }

    fn activate_row(&mut self, advance_on_mode: bool) -> WizardAction {
        let row = self.cursor();
        match self.step {
            Step::Mode => {
                self.default_mode = match row {
                    0 => Mode::Light,
                    1 => Mode::Mild,
                    _ => Mode::Aggressive,
                };
                self.set_status(
                    format!("Default mode set to '{}'.", self.default_mode),
                    false,
                );
                if advance_on_mode {
                    self.step = Step::LocalAi;
                }
                WizardAction::None
            }
            Step::LocalAi => match row {
                0..=2 => {
                    let (url, name) = setup::LOCAL_SERVERS[row];
                    self.local_url = url.to_owned();
                    self.set_status(
                        format!("Selected {name} ({url}). Press 'p' to sniff models!"),
                        false,
                    );
                    WizardAction::None
                }
                3 => {
                    self.start_edit(EditField::LocalUrl);
                    WizardAction::None
                }
                4 => {
                    self.start_edit(EditField::LocalModel);
                    WizardAction::None
                }
                5 => WizardAction::ProbeLocal,
                idx => {
                    if let Some(found) = self.discovered_local.get(idx - 6).cloned() {
                        self.local_url = found.url.clone();
                        self.local_model = found.model.clone();
                        self.set_status(
                            format!(
                                "Selected {} on {} ({})",
                                found.model, found.server_name, found.url
                            ),
                            false,
                        );
                    }
                    WizardAction::None
                }
            },
            Step::CloudAi => match row {
                0 => {
                    self.select_cloud_choice(CloudChoice::LocalOnly);
                    WizardAction::None
                }
                1 => {
                    self.select_cloud_choice(CloudChoice::Claude);
                    WizardAction::None
                }
                2 => {
                    self.select_cloud_choice(CloudChoice::OpenRouter);
                    WizardAction::None
                }
                3 => {
                    self.start_edit(EditField::CloudApiKey);
                    WizardAction::None
                }
                4 => {
                    self.start_edit(EditField::CloudUrl);
                    WizardAction::None
                }
                5 => {
                    self.start_edit(EditField::CloudModel);
                    WizardAction::None
                }
                6 => {
                    self.start_edit(EditField::ResearchModel);
                    WizardAction::None
                }
                _ => {
                    if self.cloud_choice == CloudChoice::Claude {
                        self.start_edit(EditField::Fallbacks);
                    } else {
                        self.set_status(
                            "Refusal fallback chains apply when using the Anthropic Claude API.",
                            false,
                        );
                    }
                    WizardAction::None
                }
            },
            Step::Toolkit => match row {
                0 => {
                    self.cve_enabled = !self.cve_enabled;
                    self.set_status(
                        format!(
                            "Live CVE grounding {}.",
                            if self.cve_enabled {
                                "enabled"
                            } else {
                                "disabled"
                            }
                        ),
                        false,
                    );
                    WizardAction::None
                }
                1 => {
                    self.start_edit(EditField::NvdApiKey);
                    WizardAction::None
                }
                2 => {
                    self.location_enabled = !self.location_enabled;
                    self.set_status(
                        format!(
                            "Public IP location lookup {}.",
                            if self.location_enabled {
                                "enabled (skipped automatically when VPN is active)"
                            } else {
                                "disabled (local GeoIP only)"
                            }
                        ),
                        false,
                    );
                    WizardAction::None
                }
                3 => {
                    self.location_map = !self.location_map;
                    self.set_status(
                        format!(
                            "Satellite map tiles {}.",
                            if self.location_map {
                                "enabled"
                            } else {
                                "disabled"
                            }
                        ),
                        false,
                    );
                    WizardAction::None
                }
                _ => {
                    self.rescan_tools();
                    WizardAction::None
                }
            },
            Step::Launch => match row {
                0 => {
                    self.start_edit(EditField::WorkspaceName);
                    WizardAction::None
                }
                1 => self.request_save(),
                2 => WizardAction::TestConnections,
                _ => WizardAction::Quit,
            },
        }
    }

    pub fn rescan_tools(&mut self) {
        let Some(root) = self.config_file.parent() else {
            return;
        };
        if let Ok(home) = MeowHome::at(root) {
            let mut cfg = read_private_bounded(&self.config_file, MAX_WIZARD_CONFIG_BYTES)
                .ok()
                .and_then(|t| crate::workspace::parse_toml::<Config>(&t, &self.config_file).ok())
                .unwrap_or_default();
            cfg.recon.wordlist_dir = Some(home.root().join("wordlists"));
            self.tools = scan_tools(&cfg, &home);
            let ready = self.tools.iter().filter(|t| t.found.is_some()).count();
            self.set_status(
                format!(
                    "Re-scanned local toolkit: {ready}/{} items ready.",
                    self.tools.len()
                ),
                false,
            );
        }
    }

    /// Probes local model servers and updates discovered models.
    pub fn probe_local(&mut self) {
        match setup::probe_local_servers(&self.local_url) {
            Ok(servers) => {
                let mut models = Vec::new();
                for (url, name, list) in servers {
                    if list.is_empty() {
                        models.push(DiscoveredModel {
                            server_name: sanitize(&name, 40),
                            url: sanitize(&url, 120),
                            model: String::new(),
                        });
                    } else {
                        for m in list.into_iter().take(12) {
                            models.push(DiscoveredModel {
                                server_name: sanitize(&name, 40),
                                url: sanitize(&url, 120),
                                model: sanitize(&m, 120),
                            });
                        }
                    }
                }
                if models.is_empty() {
                    self.discovered_local.clear();
                    self.clamp_cursor();
                    self.set_status(
                        "No local model server answered on :1234, :11434, or :8080. Start Ollama or LM Studio first!",
                        true,
                    );
                } else {
                    let count = models.len();
                    if let Some(first) = models.first() {
                        self.local_url = first.url.clone();
                        if self.local_model.is_empty() && !first.model.is_empty() {
                            self.local_model = first.model.clone();
                        }
                    }
                    self.discovered_local = models;
                    self.step = Step::LocalAi;
                    self.clamp_cursor();
                    self.set_status(
                        format!(
                            "Purr! Found {count} local model option(s). Pick one from the list!"
                        ),
                        false,
                    );
                }
            }
            Err(err) => {
                self.set_status(
                    format!(
                        "Could not probe local ports: {}",
                        sanitize(&format!("{err:#}"), 160)
                    ),
                    true,
                );
            }
        }
    }

    /// Builds an in-memory `AiOverrides` representing the wizard's choices.
    pub fn build_ai_overrides(&self) -> AiOverrides {
        let disable_cloud = self.cloud_choice == CloudChoice::LocalOnly;
        let (provider, url, fallbacks, api_key) = match self.cloud_choice {
            CloudChoice::LocalOnly => (None, None, None, None),
            CloudChoice::Claude => (
                Some(CloudProvider::Anthropic),
                Some(self.cloud_url.clone()),
                Some(self.cloud_fallbacks.clone()),
                self.cloud_api_key.clone(),
            ),
            CloudChoice::OpenRouter => (
                Some(CloudProvider::OpenAi),
                Some(self.cloud_url.clone()),
                None,
                self.cloud_api_key.clone(),
            ),
        };
        AiOverrides {
            local_url: Some(self.local_url.clone()),
            local_model: Some(self.local_model.clone()),
            cloud_url: url,
            cloud_model: Some(self.cloud_model.clone()),
            research_model: Some(self.research_model.clone()),
            cloud_provider: provider,
            cloud_fallbacks: fallbacks,
            api_key,
            disable_cloud,
        }
    }

    /// Runs live connection checks against the currently configured `[L]` and `[C]`.
    pub fn test_connections(&mut self) {
        let local_only = self.cloud_choice == CloudChoice::LocalOnly;
        let preview = AiSettings {
            local_url: self.local_url.clone(),
            local_model: self.local_model.clone(),
            cloud_url: self.cloud_url.clone(),
            cloud_model: self.cloud_model.clone(),
            research_model: self.research_model.clone(),
            cloud_provider: match self.cloud_choice {
                CloudChoice::Claude => Some(CloudProvider::Anthropic),
                CloudChoice::OpenRouter | CloudChoice::LocalOnly => Some(CloudProvider::OpenAi),
            },
            cloud_fallbacks: (self.cloud_choice == CloudChoice::Claude)
                .then(|| self.cloud_fallbacks.clone()),
            openrouter_api_key: (!local_only).then(|| self.cloud_api_key.clone()).flatten(),
            disable_cloud: local_only,
            user_file: None,
            ..AiSettings::default()
        };
        let mut buf = Vec::new();
        match setup::check(&preview, &mut buf) {
            Ok(ok) => {
                let text = String::from_utf8_lossy(&buf);
                self.test_results = text.lines().map(|line| sanitize(line, 200)).collect();
                self.step = Step::Launch;
                self.set_status(
                    if ok {
                        "All configured AI endpoints responded cleanly!"
                    } else {
                        "Some endpoints did not answer -- see check results on the right."
                    },
                    !ok,
                );
            }
            Err(err) => {
                self.set_status(
                    format!(
                        "Connection test error: {}",
                        sanitize(&format!("{err:#}"), 160)
                    ),
                    true,
                );
            }
        }
    }

    /// Atomically persists `config.toml` and `ai.toml` with `0600` permissions.
    pub fn save(&self, home: &MeowHome) -> Result<WizardOutcome> {
        Config::save_setup_preferences_with_location(
            home,
            self.default_mode,
            self.cve_enabled,
            self.nvd_api_key.as_deref(),
            Some((self.location_enabled, self.location_map)),
        )?;
        let overrides = self.build_ai_overrides();
        overrides.save(&home.ai_path())?;
        let launch_workspace = (!self.launch_workspace.trim().is_empty())
            .then(|| self.launch_workspace.trim().to_owned());
        Ok(WizardOutcome::Saved { launch_workspace })
    }
}

// ---------------------------------------------------------------------------
// Local toolkit detection
// ---------------------------------------------------------------------------

/// Rejects CLI subcommand names so `meow <name>` opens a workspace session
/// rather than dispatching to a subcommand.
fn validate_launch_workspace(raw: &str) -> Result<String, String> {
    validate_name(raw)
}

fn tool_hint(name: &str) -> &'static str {
    if cfg!(target_os = "macos") {
        match name {
            "nmap" => "brew install nmap",
            "katana" => "brew install katana",
            "feroxbuster" => "brew install feroxbuster",
            "geoip" => "run `meow tools` or ./install.sh --tools-only",
            _ => "run ./install.sh or place a .txt wordlist in ~/.meow/wordlists",
        }
    } else if cfg!(target_os = "windows") {
        match name {
            "nmap" => "winget install Insecure.Nmap",
            "katana" => "go install github.com/projectdiscovery/katana/cmd/katana@v1.1.2",
            "feroxbuster" => "cargo install feroxbuster --locked",
            "geoip" => "run `meow tools` or .\\install.ps1 -ToolsOnly",
            _ => "run .\\install.ps1 or place a .txt wordlist in ~/.meow/wordlists",
        }
    } else {
        match name {
            "nmap" => "install nmap with your package manager (or ./install.sh)",
            "katana" => "go install github.com/projectdiscovery/katana/cmd/katana@v1.1.2",
            "feroxbuster" => "cargo install feroxbuster --locked (or ./install.sh)",
            "geoip" => "run `meow tools` or ./install.sh --tools-only",
            _ => "run ./install.sh or place a .txt wordlist in ~/.meow/wordlists",
        }
    }
}

fn scan_tools(config: &Config, home: &MeowHome) -> Vec<ToolCheck> {
    let mut out = Vec::new();
    for (label, bin) in [
        (
            "nmap (port & service inventory)",
            config.recon.nmap.as_str(),
        ),
        (
            "katana (web link & JS crawler)",
            config.recon.katana.as_str(),
        ),
        (
            "feroxbuster (directory discovery)",
            config.recon.feroxbuster.as_str(),
        ),
    ] {
        let short = label.split_whitespace().next().unwrap_or(bin);
        let found = tools::find_program(bin).map(|p| sanitize(&p.display().to_string(), 120));
        out.push(ToolCheck {
            name: label.to_owned(),
            found,
            hint: tool_hint(short).to_owned(),
        });
    }
    let wordlist = queue::find_wordlist(
        config.recon.wordlist_path.as_deref(),
        Some(&home.root().join("wordlists")),
    )
    .map(|p| sanitize(&p.display().to_string(), 120));
    out.push(ToolCheck {
        name: "web wordlist (SecLists common.txt)".to_owned(),
        found: wordlist,
        hint: tool_hint("wordlist").to_owned(),
    });
    let geo_path = {
        let raw = config.location.database.trim();
        let base = if raw.is_empty() {
            home.root().join(crate::geoip::DIR)
        } else {
            let db = Path::new(raw);
            if db.is_absolute() {
                db.to_path_buf()
            } else {
                home.root().join(db)
            }
        };
        if base.extension().and_then(|e| e.to_str()) == Some("mmdb") {
            base
        } else {
            base.join(crate::geoip::CITY_FILE)
        }
    };
    let geo_found = std::fs::symlink_metadata(&geo_path)
        .ok()
        .filter(|m| m.is_file() && !m.file_type().is_symlink())
        .map(|_| sanitize(&geo_path.display().to_string(), 120));
    out.push(ToolCheck {
        name: "GeoIP database (DB-IP City Lite)".to_owned(),
        found: geo_found,
        hint: tool_hint("geoip").to_owned(),
    });
    out
}

// ---------------------------------------------------------------------------
// Rendering (Ratatui)
// ---------------------------------------------------------------------------

const DIM: Style = Style::new().fg(Color::DarkGray);
const GOOD: Style = Style::new().fg(Color::Green);
const WARN: Style = Style::new().fg(Color::Yellow);
const ACCENT: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
const PURR: Style = Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD);
const SELECTED: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD);

fn card(title: &str, focused: bool) -> Block<'_> {
    let border = if focused {
        Style::new().fg(Color::Cyan)
    } else {
        DIM
    };
    Block::bordered()
        .title(Span::styled(format!(" {title} "), ACCENT))
        .border_style(border)
}

struct CatBanner {
    art: [&'static str; 3],
    art_style: Style,
    headline: &'static str,
    subline: &'static str,
}

fn cat_banner(wizard: &Wizard) -> CatBanner {
    match wizard.step {
        Step::Mode => match wizard.previewed_mode() {
            Mode::Light => CatBanner {
                art: [
                    "   |\\__/,|   (`\\  ",
                    " _.| -.- |_   ) ) ",
                    "-(((---(((--------",
                ],
                art_style: GOOD.add_modifier(Modifier::BOLD),
                headline: "=^..^=  PROWL MODE :: SLEEPING & LISTENING (LIGHT)",
                subline: "Zero outbound target packets! Passively maps local interfaces, VPNs & routes.",
            },
            Mode::Mild => CatBanner {
                art: [
                    "   /\\_/\\     _    ",
                    "  ( o.o )  _//    ",
                    "   > ^ <  (_/     ",
                ],
                art_style: WARN.add_modifier(Modifier::BOLD),
                headline: "=^..^=  PROWL MODE :: CURIOUS WHISKERS (MILD)",
                subline: "Polite active recon: rate-limited Nmap, Katana crawl & gentle directory checks.",
            },
            Mode::Aggressive => CatBanner {
                art: [
                    "  /\\___/\\   /     ",
                    " ( >'w'< ) //     ",
                    "  /     \\ V       ",
                ],
                art_style: Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                headline: "=^..^=  PROWL MODE :: FULL POUNCE (AGGRESSIVE)",
                subline: "Fast Nmap (-T4) + auto-tuned Feroxbuster. Use on dedicated labs & cleared targets!",
            },
        },
        Step::LocalAi => CatBanner {
            art: [
                "   /\\_/\\   [o_o]  ",
                "  ( ^.^ )  /| |\\  ",
                "   > ~ <  (_|_|_) ",
            ],
            art_style: ACCENT,
            headline: "=^..^=  LOCAL PURR-CESSOR [L] :: $0.00 ON-DEVICE AI",
            subline: "100% private on this machine. Press 'p' to sniff LM Studio, Ollama & llama.cpp!",
        },
        Step::CloudAi => CatBanner {
            art: [
                "   /\\_/\\    .~.   ",
                "  ( o.O )  (   )  ",
                "   > ^ <    `~'   ",
            ],
            art_style: PURR,
            headline: "=^..^=  CLOUD WHISKERS [C]/[R] :: VAULTED TRIAGE & RESEARCH",
            subline: "Optional! Every IP, hostname, path & secret is vaulted into <<HOST_01>> tokens first.",
        },
        Step::Toolkit => CatBanner {
            art: [
                "   /\\_/\\   _===_  ",
                "  ( 0.0 )  (o o)  ",
                "   > ^ <    \\_/   ",
            ],
            art_style: WARN.add_modifier(Modifier::BOLD),
            headline: "=^..^=  CLAWS & CVE RADAR :: SCANNERS & LIVE ADVISORIES",
            subline: "Free NIST NVD + OSV.dev + CISA KEV grounding ($0 AI) & local scanner readiness.",
        },
        Step::Launch => CatBanner {
            art: [
                "   /\\_/\\    *  *  ",
                "  ( ^w^ )  purrr~ ",
                "  (\")_(\")~~~~~~~~ ",
            ],
            art_style: GOOD.add_modifier(Modifier::BOLD),
            headline: "=^..^=  READY TO POUNCE! :: REVIEW, TEST & SAVE",
            subline: "Saved privately (0600). Press 't' to test AI endpoints or 's' / Enter to finish!",
        },
    }
}

fn secret_summary(secret: Option<&str>, env_source: Option<&str>) -> String {
    match (secret, env_source) {
        (Some(key), _) if !key.trim().is_empty() => format!("{} (setup file)", setup::masked(key)),
        (None, Some(src)) => format!("from {src}"),
        _ => "not set".to_owned(),
    }
}

/// Renders the entire Interactive Cat Setup GUI into `frame`.
pub fn draw(frame: &mut Frame, wizard: &Wizard) {
    let area = frame.area();
    if area.width < 12 || area.height < 6 {
        frame.render_widget(Paragraph::new("=^..^= meow setup"), area);
        return;
    }

    let footer_height = if wizard.editing.is_some() { 4 } else { 2 };
    let [header_area, tabs_area, body_area, footer_area] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(2),
        Constraint::Min(4),
        Constraint::Length(footer_height),
    ])
    .areas(area);

    draw_cat_header(frame, header_area, wizard);
    draw_step_bar(frame, tabs_area, wizard);
    draw_body(frame, body_area, wizard);
    draw_footer(frame, footer_area, wizard);
}

fn draw_cat_header(frame: &mut Frame, area: Rect, wizard: &Wizard) {
    let banner = cat_banner(wizard);
    let title = if wizard.first_run {
        "MEOW :: INTERACTIVE FIRST-TIME SETUP"
    } else {
        "MEOW :: INTERACTIVE SETUP WIZARD"
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(banner.art[0], banner.art_style),
            Span::raw("  "),
            Span::styled(banner.headline, banner.art_style),
        ]),
        Line::from(vec![
            Span::styled(banner.art[1], banner.art_style),
            Span::raw("  "),
            Span::raw(banner.subline),
        ]),
        Line::from(vec![
            Span::styled(banner.art[2], banner.art_style),
            Span::raw("  "),
            Span::styled(
                "Private 0700/0600 storage -- API keys are masked & never echoed.",
                DIM,
            ),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines).block(card(title, true)), area);
}

fn draw_step_bar(frame: &mut Frame, area: Rect, wizard: &Wizard) {
    let mut spans = vec![Span::raw(" ")];
    for (idx, step) in Step::ALL.iter().copied().enumerate() {
        if idx > 0 {
            spans.push(Span::styled("  >  ", DIM));
        }
        if step == wizard.step {
            spans.push(Span::styled(
                format!(" [{}] ", step.short_title()),
                SELECTED,
            ));
        } else {
            spans.push(Span::styled(format!(" {} ", step.short_title()), ACCENT));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_body(frame: &mut Frame, area: Rect, wizard: &Wizard) {
    let [left, right] = if area.width >= 90 {
        Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)]).areas(area)
    } else {
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(area)
    };

    let (left_title, items) = step_items(wizard);
    let mut state = ListState::default();
    state.select(Some(wizard.cursor()));
    let list = List::new(items)
        .block(card(left_title, wizard.editing.is_none()))
        .highlight_style(SELECTED)
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, left, &mut state);

    let (right_title, details) = step_details(wizard);
    frame.render_widget(
        Paragraph::new(details)
            .wrap(Wrap { trim: false })
            .block(card(right_title, false)),
        right,
    );
}

fn radio(chosen: bool) -> &'static str {
    if chosen {
        "(o)"
    } else {
        "( )"
    }
}

fn checkbox(enabled: bool) -> &'static str {
    if enabled {
        "[x]"
    } else {
        "[ ]"
    }
}

fn step_items(wizard: &Wizard) -> (&'static str, Vec<ListItem<'static>>) {
    match wizard.step {
        Step::Mode => {
            let items = vec![
                ListItem::new(format!(
                    "{} Light       Passive only (0 packets sent -- recommended)",
                    radio(wizard.default_mode == Mode::Light)
                )),
                ListItem::new(format!(
                    "{} Mild        Polite rate-limited Nmap + web crawl",
                    radio(wizard.default_mode == Mode::Mild)
                )),
                ListItem::new(format!(
                    "{} Aggressive  Fast lab-speed Nmap (-T4) + auto-tune",
                    radio(wizard.default_mode == Mode::Aggressive)
                )),
            ];
            ("Choose Default Discovery Mode (Enter selects)", items)
        }
        Step::LocalAi => {
            let model_label = if wizard.local_model.is_empty() {
                "chosen by server".to_owned()
            } else {
                wizard.local_model.clone()
            };
            let mut items = vec![
                ListItem::new(format!(
                    "{} Preset: LM Studio   http://localhost:1234/v1",
                    radio(wizard.local_url == "http://localhost:1234/v1")
                )),
                ListItem::new(format!(
                    "{} Preset: Ollama      http://localhost:11434/v1",
                    radio(wizard.local_url == "http://localhost:11434/v1")
                )),
                ListItem::new(format!(
                    "{} Preset: llama.cpp   http://localhost:8080/v1",
                    radio(wizard.local_url == "http://localhost:8080/v1")
                )),
                ListItem::new(format!("Edit Server URL:     {}", wizard.local_url)),
                ListItem::new(format!("Edit Model Name:     {model_label}")),
                ListItem::new("[Sniff Local Ports for Running Models (p)]".to_owned()),
            ];
            for d in &wizard.discovered_local {
                let label = if d.model.is_empty() {
                    format!("Found server: {} ({})", d.server_name, d.url)
                } else {
                    format!("Found model:  {}  @ {}", d.model, d.server_name)
                };
                items.push(ListItem::new(label));
            }
            ("Local AI [L] -- Free & Private", items)
        }
        Step::CloudAi => {
            let key_desc = secret_summary(
                wizard.cloud_api_key.as_deref(),
                wizard.env_key_source.as_deref(),
            );
            let chain_desc = if wizard.cloud_choice != CloudChoice::Claude {
                "n/a (Claude API only)".to_owned()
            } else if wizard.cloud_fallbacks.is_empty() {
                "left to Claude API".to_owned()
            } else {
                wizard.cloud_fallbacks.join(", ")
            };
            let items = vec![
                ListItem::new(format!(
                    "{} Local Only ($0.00 -- No Cloud API Key)",
                    radio(wizard.cloud_choice == CloudChoice::LocalOnly)
                )),
                ListItem::new(format!(
                    "{} Anthropic Claude API (native Claude key)",
                    radio(wizard.cloud_choice == CloudChoice::Claude)
                )),
                ListItem::new(format!(
                    "{} OpenRouter / OpenAI-Compatible Service",
                    radio(wizard.cloud_choice == CloudChoice::OpenRouter)
                )),
                ListItem::new(format!("Cloud API Key:       {key_desc}")),
                ListItem::new(format!("Cloud Service URL:   {}", wizard.cloud_url)),
                ListItem::new(format!("[C] Triage Model:    {}", wizard.cloud_model)),
                ListItem::new(format!("[R] Research Model:  {}", wizard.research_model)),
                ListItem::new(format!("Refusal Fallbacks:   {chain_desc}")),
            ];
            ("Cloud AI [C]/[R] -- Vaulted & Capped", items)
        }
        Step::Toolkit => {
            let nvd_desc = match wizard.nvd_api_key.as_deref() {
                Some(k) => format!("{} (0.7s fast pace)", setup::masked(k)),
                None => "not set (6.5s anonymous pace)".to_owned(),
            };
            let items = vec![
                ListItem::new(format!(
                    "{} Live CVE Grounding (NIST NVD + OSV.dev + CISA KEV)",
                    checkbox(wizard.cve_enabled)
                )),
                ListItem::new(format!("NVD API Key (opt):   {nvd_desc}")),
                ListItem::new(format!(
                    "{} Public IP Location Lookup (auto-disabled on VPN)",
                    checkbox(wizard.location_enabled)
                )),
                ListItem::new(format!(
                    "{} Satellite Map Tiles (EOX Sentinel-2 cloudless)",
                    checkbox(wizard.location_map)
                )),
                ListItem::new("[Re-scan Local Scanners & Wordlists (r)]".to_owned()),
            ];
            ("CVE Radar, Location & Toolkit", items)
        }
        Step::Launch => {
            let ws_label = if wizard.first_run {
                "First Workspace:  "
            } else {
                "Launch Workspace: "
            };
            let ws = if wizard.launch_workspace.is_empty() {
                "(optional -- press Enter to name e.g. 'homelab')".to_owned()
            } else {
                format!("{}  (will open session on save!)", wizard.launch_workspace)
            };
            let save_label = if !wizard.launch_workspace.is_empty() {
                "[ Save Setup & Launch Workspace! (s) ]"
            } else if wizard.first_run {
                "[ Save Setup & Finish (s) ]"
            } else {
                "[ Save Setup & Exit (s) ]"
            };
            let items = vec![
                ListItem::new(format!("{ws_label}{ws}")),
                ListItem::new(save_label.to_owned()),
                ListItem::new("[ Test AI Connections Now (t) ]".to_owned()),
                ListItem::new("[ Quit Without Saving (q) ]".to_owned()),
            ];
            ("Launchpad & Connection Check", items)
        }
    }
}

fn step_details(wizard: &Wizard) -> (&'static str, Vec<Line<'static>>) {
    match wizard.step {
        Step::Mode => {
            let mode = wizard.previewed_mode();
            let mut lines = vec![
                Line::styled(format!("Highlighted mode: {mode}"), ACCENT),
                Line::raw(""),
            ];
            match mode {
                Mode::Light => {
                    lines.push(Line::styled("Zero outbound network packets.", GOOD));
                    lines.push(Line::raw(
                        "Reads local OS routing, interface, VPN (utun/tun) and ARP tables passively without sudo.",
                    ));
                    lines.push(Line::raw(""));
                    lines.push(Line::raw(
                        "Active `meow recon` scans are refused until you switch to mild or aggressive (`meow mode mild`).",
                    ));
                }
                Mode::Mild => {
                    lines.push(Line::styled("Polite, rate-capped inventory.", WARN));
                    lines.push(Line::raw(
                        "Runs 1-at-a-time queued Nmap (-T3) + Katana host-scoped crawl + rate-limited Feroxbuster.",
                    ));
                    lines.push(Line::raw(""));
                    lines.push(Line::raw(
                        "Automatically swaps -sS for -sT when running unprivileged.",
                    ));
                }
                Mode::Aggressive => {
                    lines.push(Line::styled(
                        "High-speed lab & CTF profile.",
                        Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ));
                    lines.push(Line::raw(
                        "Uses Nmap -T4 and auto-tuned Feroxbuster without rate caps.",
                    ));
                    lines.push(Line::raw(""));
                    lines.push(Line::raw(
                        "Only select as default if you exclusively work against isolated lab environments.",
                    ));
                }
            }
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "Tip: Change mode anytime per workspace with `meow mode` or keys 1/2/3 in `meow hud`.",
                DIM,
            ));
            ("How Prowl Modes Work", lines)
        }
        Step::LocalAi => {
            let model_desc = if wizard.local_model.is_empty() {
                "chosen automatically by server".to_owned()
            } else {
                wizard.local_model.clone()
            };
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("Server: ", DIM),
                    Span::styled(wizard.local_url.clone(), GOOD),
                ]),
                Line::from(vec![
                    Span::styled("Model:  ", DIM),
                    Span::raw(model_desc),
                ]),
                Line::raw(""),
                Line::raw(
                    "Press [L] inside `meow hud` to triage a selected host using your local model at $0.00 cost.",
                ),
                Line::raw(""),
                Line::styled("Quick Start:", ACCENT),
                Line::raw("  * Ollama:    run `ollama serve` (:11434)"),
                Line::raw("  * LM Studio: Developer > Start Server (:1234)"),
                Line::raw("  * Press 'p' right now to auto-detect running models!"),
            ];
            if !wizard.discovered_local.is_empty() {
                lines.push(Line::raw(""));
                lines.push(Line::styled(
                    format!(
                        "Sniffed {} local option(s) -- select one on the left!",
                        wizard.discovered_local.len()
                    ),
                    GOOD,
                ));
            }
            ("On-Device Purr-cessor Details", lines)
        }
        Step::CloudAi => {
            let provider_desc = match wizard.cloud_choice {
                CloudChoice::LocalOnly => "Disabled ($0.00 local-only)",
                CloudChoice::Claude => "Anthropic Claude API",
                CloudChoice::OpenRouter => "OpenRouter / OpenAI-compatible",
            };
            let key_desc = if wizard.cloud_choice == CloudChoice::LocalOnly {
                "disabled (local-only mode overrides environment keys)".to_owned()
            } else {
                secret_summary(
                    wizard.cloud_api_key.as_deref(),
                    wizard.env_key_source.as_deref(),
                )
            };
            let lines = vec![
                Line::from(vec![
                    Span::styled("Mode:     ", DIM),
                    Span::styled(provider_desc, ACCENT),
                ]),
                Line::from(vec![
                    Span::styled("API Key:  ", DIM),
                    Span::styled(
                        key_desc,
                        if wizard.cloud_choice != CloudChoice::LocalOnly
                            && (wizard.cloud_api_key.is_some() || wizard.env_key_source.is_some())
                        {
                            GOOD
                        } else {
                            WARN
                        },
                    ),
                ]),
                Line::raw(""),
                Line::styled("Bidirectional Privacy Vault:", ACCENT),
                Line::raw(
                    "Before any cloud prompt leaves this machine, meow replaces IPs, domains/SANs, URL paths, usernames, JWTs & keys with placeholders like <<HOST_01>> and <<SEC_01>>, unmasking replies locally.",
                ),
                Line::raw(""),
                Line::styled(
                    "No cloud key? No problem! [C] automatically falls back to your local [L] model.",
                    DIM,
                ),
            ];
            ("Privacy Vault & Cloud Safety", lines)
        }
        Step::Toolkit => {
            let mut lines = vec![Line::styled("Local Scanner & Wordlist Status:", ACCENT)];
            for item in &wizard.tools {
                match &item.found {
                    Some(path) => {
                        lines.push(Line::from(vec![
                            Span::styled(" [x] ", GOOD),
                            Span::raw(format!("{} ", item.name)),
                        ]));
                        lines.push(Line::styled(format!("     {path}"), DIM));
                    }
                    None => {
                        lines.push(Line::from(vec![
                            Span::styled(" [ ] ", WARN),
                            Span::raw(item.name.clone()),
                        ]));
                        lines.push(Line::styled(format!("     add via: {}", item.hint), DIM));
                    }
                }
            }
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "CVE lookups send only public CPE / package versions -- never host IPs or paths.",
                DIM,
            ));
            ("System Readiness", lines)
        }
        Step::Launch => {
            let cloud_summary = match wizard.cloud_choice {
                CloudChoice::LocalOnly => "Local-only ($0.00 -- cloud key not used)".to_owned(),
                CloudChoice::Claude => format!("Claude API ({})", wizard.cloud_model),
                CloudChoice::OpenRouter => {
                    format!("{} ({})", wizard.cloud_url, wizard.cloud_model)
                }
            };
            let local_model = if wizard.local_model.is_empty() {
                "server default"
            } else {
                wizard.local_model.as_str()
            };
            let key_summary = if wizard.cloud_choice == CloudChoice::LocalOnly {
                "disabled (local-only mode)".to_owned()
            } else {
                secret_summary(
                    wizard.cloud_api_key.as_deref(),
                    wizard.env_key_source.as_deref(),
                )
            };
            let loc_summary = match (wizard.location_enabled, wizard.location_map) {
                (true, true) => "enabled + satellite map tiles",
                (true, false) => "enabled (map tiles off)",
                (false, _) => "disabled (offline GeoIP only)",
            };
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("Default mode:  ", DIM),
                    Span::styled(wizard.default_mode.as_str(), ACCENT),
                ]),
                Line::from(vec![
                    Span::styled("[L] Local AI:  ", DIM),
                    Span::raw(format!("{} ({local_model})", wizard.local_url)),
                ]),
                Line::from(vec![
                    Span::styled("[C] Cloud AI:  ", DIM),
                    Span::raw(cloud_summary),
                ]),
                Line::from(vec![
                    Span::styled("Cloud API key: ", DIM),
                    Span::raw(key_summary),
                ]),
                Line::from(vec![
                    Span::styled("CVE grounding: ", DIM),
                    Span::raw(if wizard.cve_enabled {
                        "enabled (NVD + OSV.dev + CISA KEV)"
                    } else {
                        "disabled"
                    }),
                ]),
                Line::from(vec![
                    Span::styled("Location/map:  ", DIM),
                    Span::raw(loc_summary),
                ]),
                Line::from(vec![
                    Span::styled("Config files:  ", DIM),
                    Span::styled(
                        format!(
                            "{} & ai.toml (0600)",
                            sanitize(&wizard.config_file.display().to_string(), 80)
                        ),
                        DIM,
                    ),
                ]),
            ];
            if !wizard.test_results.is_empty() {
                lines.push(Line::raw(""));
                lines.push(Line::styled("Live Connection Check:", ACCENT));
                for line in &wizard.test_results {
                    let style = if line.starts_with("[+]") { GOOD } else { WARN };
                    lines.push(Line::styled(format!("  {line}"), style));
                }
            }
            ("Summary & Verification", lines)
        }
    }
}

fn draw_footer(frame: &mut Frame, area: Rect, wizard: &Wizard) {
    if let Some(edit) = &wizard.editing {
        let shown = if edit.field.is_secret() {
            let count = edit.buffer.chars().count();
            let stars = "*".repeat(count.min(36));
            format!("{stars}_  ({count} chars, hidden)")
        } else {
            format!("{}_", sanitize(&edit.buffer, 200))
        };
        let help = if edit.paste_hint {
            Line::styled(format!(" {}", setup::PASTE_HINT), WARN)
        } else {
            Line::styled(
                " Paste: Ctrl+Shift+V or right-click  |  Enter: confirm  |  Ctrl-U: clear  |  Esc: cancel",
                DIM,
            )
        };
        let lines = vec![
            Line::from(vec![Span::styled(" > ", ACCENT), Span::raw(shown)]),
            help,
        ];
        frame.render_widget(
            Paragraph::new(lines).block(card(edit.field.label(), true)),
            area,
        );
        return;
    }

    let status_style = if wizard.status_warn { WARN } else { GOOD };
    let lines = vec![
        Line::from(vec![
            Span::styled(" =^..^= ", ACCENT),
            Span::styled(sanitize(&wizard.status, 220), status_style),
        ]),
        Line::styled(
            " Tab/Left/Right or 1-5: tab  |  Up/Down: select  |  Enter: edit/pick  |  p: sniff local AI  |  t: test  |  s: save  |  q: quit",
            DIM,
        ),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

// ---------------------------------------------------------------------------
// Terminal lifecycle & main-thread runner
// ---------------------------------------------------------------------------

struct WizardTerminalGuard;

impl Drop for WizardTerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(std::io::stdout(), DisableBracketedPaste);
        let _ = std::io::stdout()
            .write_all(b"\x1b[?2004l\x1b[?1000l\x1b[?25h")
            .and_then(|()| std::io::stdout().flush());
        ratatui::restore();
    }
}

/// True when the current process can display an interactive full-screen TUI.
pub fn can_run_tui() -> bool {
    std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && env::var("TERM").ok().as_deref() != Some("dumb")
}

fn run_loop(home: &MeowHome, first_run: bool) -> Result<WizardOutcome> {
    if !can_run_tui() {
        anyhow::bail!("cannot open the interactive setup GUI (requires a TTY)");
    }
    let mut wizard = Wizard::load(home, first_run)?;
    let mut terminal =
        ratatui::try_init().context("cannot initialize terminal for meow setup GUI")?;
    let _guard = WizardTerminalGuard;
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);

    loop {
        terminal
            .draw(|frame| draw(frame, &wizard))
            .context("cannot draw setup GUI")?;

        let ev = event::read().context("cannot read terminal input")?;
        match ev {
            Event::Paste(text) => wizard.on_paste(&text),
            Event::Key(key) if key.kind == KeyEventKind::Press => match wizard.on_key(key) {
                WizardAction::None => {}
                WizardAction::ProbeLocal => {
                    wizard.set_status(
                        "Sniffing local ports (:1234, :11434, :8080) for models ...",
                        false,
                    );
                    let _ = terminal.draw(|frame| draw(frame, &wizard));
                    wizard.probe_local();
                }
                WizardAction::TestConnections => {
                    wizard.set_status("Testing [L] and [C] AI connections ...", false);
                    let _ = terminal.draw(|frame| draw(frame, &wizard));
                    wizard.test_connections();
                }
                WizardAction::Save => match wizard.save(home) {
                    Ok(outcome) => return Ok(outcome),
                    Err(err) => wizard.set_status(
                        format!(
                            "Could not save setup: {}",
                            sanitize(&format!("{err:#}"), 180)
                        ),
                        true,
                    ),
                },
                WizardAction::Quit => return Ok(WizardOutcome::Cancelled),
            },
            _ => {}
        }
    }
}

/// Launches the Interactive First-Time Setup GUI (called on bare `meow` when
/// `~/.meow` has not been configured yet).
pub fn run_first_time(home: &MeowHome) -> Result<WizardOutcome> {
    run_loop(home, true)
}

/// Launches the Interactive Setup GUI for `meow setup`.
pub fn run_setup(home: &MeowHome) -> Result<WizardOutcome> {
    run_loop(home, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn render(wizard: &Wizard, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, wizard)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn every_step_renders_its_own_cat_ascii_header_and_mode_reactions() {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let mut wiz = Wizard::load(&home, true).unwrap();

        // Step 1: Light (sleeping cat), Mild (curious cat), Aggressive (pouncing cat)
        let light_screen = render(&wiz, 120, 32);
        assert!(
            light_screen.contains("MEOW :: INTERACTIVE FIRST-TIME SETUP"),
            "{light_screen}"
        );
        assert!(light_screen.contains("_.| -.- |_"), "{light_screen}");
        assert!(
            light_screen.contains("SLEEPING & LISTENING (LIGHT)"),
            "{light_screen}"
        );

        wiz.on_key(key(KeyCode::Down));
        let mild_screen = render(&wiz, 120, 32);
        assert!(mild_screen.contains("( o.o )  _//"), "{mild_screen}");
        assert!(
            mild_screen.contains("CURIOUS WHISKERS (MILD)"),
            "{mild_screen}"
        );

        wiz.on_key(key(KeyCode::Down));
        let agg_screen = render(&wiz, 120, 32);
        assert!(agg_screen.contains("( >'w'< ) //"), "{agg_screen}");
        assert!(
            agg_screen.contains("FULL POUNCE (AGGRESSIVE)"),
            "{agg_screen}"
        );

        // Step 2..5 each display distinct cat headers
        wiz.on_key(key(KeyCode::Char('2')));
        let s2 = render(&wiz, 120, 32);
        assert!(s2.contains("( ^.^ )  /| |\\"), "{s2}");
        assert!(s2.contains("LOCAL PURR-CESSOR [L]"), "{s2}");

        wiz.on_key(key(KeyCode::Char('3')));
        let s3 = render(&wiz, 120, 32);
        assert!(s3.contains("( o.O )  (   )"), "{s3}");
        assert!(s3.contains("CLOUD WHISKERS [C]/[R]"), "{s3}");

        wiz.on_key(key(KeyCode::Char('4')));
        let s4 = render(&wiz, 120, 32);
        assert!(s4.contains("( 0.0 )  (o o)"), "{s4}");
        assert!(s4.contains("CLAWS & CVE RADAR"), "{s4}");

        wiz.on_key(key(KeyCode::Char('5')));
        let s5 = render(&wiz, 120, 32);
        assert!(s5.contains("( ^w^ )  purrr~"), "{s5}");
        assert!(s5.contains("READY TO POUNCE!"), "{s5}");
    }

    #[test]
    fn secrets_never_appear_in_rendered_frames_and_save_writes_private_files() {
        const SECRET_AI: &str = "sk-ant-wizard-super-secret-8899";
        const SECRET_NVD: &str = "nvd-secret-token-4455";

        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let mut wiz = Wizard::load(&home, true).unwrap();
        assert!(
            !home.root().exists(),
            "loading the wizard must not create ~/.meow before saving"
        );

        // Pick Mild on Step 1 and advance with Enter
        wiz.on_key(key(KeyCode::Down));
        assert_eq!(wiz.on_key(key(KeyCode::Enter)), WizardAction::None);
        assert_eq!(wiz.default_mode, Mode::Mild);
        assert_eq!(wiz.step, Step::LocalAi);

        // Jump to Step 3 (Cloud AI), open Cloud API Key editor (row 3)
        wiz.on_key(key(KeyCode::Char('3')));
        wiz.cursors[Step::CloudAi.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        // Ctrl+V is not a paste in a terminal: a hint, and no "v" typed.
        wiz.on_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL));
        assert_eq!(wiz.editing.as_ref().unwrap().buffer, "");
        assert!(
            render(&wiz, 120, 32).contains("Ctrl+V does not paste in a terminal"),
            "{}",
            render(&wiz, 120, 32)
        );
        wiz.on_paste(SECRET_AI);

        // While editing, only '*' bullets appear -- NEVER the secret!
        let editing_frame = render(&wiz, 120, 32);
        assert!(
            !editing_frame.contains(SECRET_AI) && !editing_frame.contains("sk-ant"),
            "{editing_frame}"
        );
        assert!(editing_frame.contains("chars, hidden"), "{editing_frame}");

        wiz.on_key(key(KeyCode::Enter));
        // Auto-detected sk-ant- -> switched to Claude!
        assert_eq!(wiz.cloud_choice, CloudChoice::Claude);
        let after_commit = render(&wiz, 120, 32);
        assert!(
            !after_commit.contains(SECRET_AI) && !after_commit.contains("sk-ant"),
            "{after_commit}"
        );
        assert!(
            after_commit.contains("ends in 8899"),
            "masked tail should be shown: {after_commit}"
        );

        // Step 4: enter NVD API key (row 1), verify hidden
        wiz.on_key(key(KeyCode::Char('4')));
        wiz.cursors[Step::Toolkit.index()] = 1;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste(SECRET_NVD);
        let nvd_edit_frame = render(&wiz, 120, 32);
        assert!(!nvd_edit_frame.contains(SECRET_NVD), "{nvd_edit_frame}");
        wiz.on_key(key(KeyCode::Enter));

        // Step 5: enter first workspace name "homelab" (row 0), then save!
        wiz.on_key(key(KeyCode::Char('5')));
        wiz.cursors[Step::Launch.index()] = 0;
        wiz.on_key(key(KeyCode::Enter));
        for ch in "homelab".chars() {
            wiz.on_key(key(KeyCode::Char(ch)));
        }
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.launch_workspace, "homelab");

        assert_eq!(wiz.on_key(key(KeyCode::Char('s'))), WizardAction::Save);
        let outcome = wiz.save(&home).unwrap();
        assert_eq!(
            outcome,
            WizardOutcome::Saved {
                launch_workspace: Some("homelab".into())
            }
        );

        let cfg = Config::load_or_create(&home).unwrap();
        assert_eq!(cfg.default_mode, Mode::Mild);
        assert_eq!(cfg.cve.nvd_api_key.as_deref(), Some(SECRET_NVD));
        let eff = cfg.ai.effective();
        assert_eq!(eff.provider(), CloudProvider::Anthropic);
        assert_eq!(eff.api_key().as_deref(), Some(SECRET_AI));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [home.config_path(), home.ai_path()] {
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{} must be 0600", path.display());
            }
        }
    }

    #[test]
    fn tiny_and_large_screens_render_without_panicking() {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let mut wiz = Wizard::load(&home, true).unwrap();
        for step in Step::ALL {
            wiz.step = step;
            for (w, h) in [(1, 1), (10, 4), (20, 8), (80, 24), (160, 50)] {
                let _ = render(&wiz, w, h);
            }
        }
    }

    #[test]
    fn session_headers_reflect_each_mode_and_sanitize_names() {
        let light = session_header("acme\x1b]2;pwn\x07", Mode::Light, true);
        assert!(!light.contains('\x1b') && !light.contains('\x07'));
        assert!(light.contains("_.| -.- |_"));
        let mild = session_header("lab", Mode::Mild, false);
        assert!(mild.contains("( o.o )"));
        let agg = session_header("ctf", Mode::Aggressive, false);
        assert!(agg.contains("( >'w'< )"));
        assert!(validate_launch_workspace("update").is_err());
        assert!(validate_launch_workspace("setup").is_err());
        assert!(validate_launch_workspace("tools").is_err());
        assert_eq!(validate_launch_workspace("catlab").unwrap(), "catlab");
    }

    #[test]
    fn local_only_location_toggles_and_edit_caps_persist_across_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let mut wiz = Wizard::load(&home, false).unwrap();

        // Select LocalOnly explicitly and toggle both [location] preferences off.
        wiz.on_key(key(KeyCode::Char('3')));
        wiz.cursors[Step::CloudAi.index()] = 0;
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_choice, CloudChoice::LocalOnly);

        wiz.on_key(key(KeyCode::Char('4')));
        wiz.cursors[Step::Toolkit.index()] = 2;
        wiz.on_key(key(KeyCode::Enter));
        wiz.cursors[Step::Toolkit.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        assert!(!wiz.location_enabled);
        assert!(!wiz.location_map);

        // Paste cap at MAX_EDIT_CHARS and workspace launch on non-first-run setup.
        wiz.on_key(key(KeyCode::Char('5')));
        wiz.cursors[Step::Launch.index()] = 0;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste(&"a".repeat(6_000));
        assert_eq!(wiz.editing.as_ref().unwrap().buffer.len(), MAX_EDIT_CHARS);
        wiz.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        wiz.on_paste("recheck-lab");
        wiz.on_key(key(KeyCode::Enter));

        let outcome = wiz.save(&home).unwrap();
        assert_eq!(
            outcome,
            WizardOutcome::Saved {
                launch_workspace: Some("recheck-lab".into())
            }
        );

        let cfg = Config::load_or_create(&home).unwrap();
        assert!(!cfg.location.enabled);
        assert!(!cfg.location.map);
        let eff = cfg.ai.effective();
        assert!(eff.disable_cloud);
        assert_eq!(eff.api_key(), None);

        let reloaded = Wizard::load(&home, false).unwrap();
        assert_eq!(reloaded.cloud_choice, CloudChoice::LocalOnly);
        assert!(!reloaded.location_enabled);
        assert!(!reloaded.location_map);
    }

    #[test]
    fn switching_cloud_provider_or_host_clears_key_and_broken_config_hides_secrets() {
        const CLAUDE_KEY: &str = "sk-ant-never-leak-to-other-host-7711";
        const NVD_SECRET: &str = "nvd-secret-in-broken-toml-9922";

        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let mut wiz = Wizard::load(&home, false).unwrap();

        // Enter a Claude key on Step 3 -> auto-selects Claude.
        wiz.on_key(key(KeyCode::Char('3')));
        wiz.cursors[Step::CloudAi.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste(CLAUDE_KEY);
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_choice, CloudChoice::Claude);
        assert_eq!(wiz.cloud_api_key.as_deref(), Some(CLAUDE_KEY));

        // Switching provider from Claude to OpenRouter clears the Claude key!
        wiz.cursors[Step::CloudAi.index()] = 2;
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_choice, CloudChoice::OpenRouter);
        assert_eq!(wiz.cloud_api_key, None);
        assert_eq!(wiz.build_ai_overrides().api_key, None);

        // Set an OpenRouter key, then change CloudUrl to a different host -> clears key!
        wiz.cursors[Step::CloudAi.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste("sk-or-v1-host-bound-key-5544");
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(
            wiz.cloud_api_key.as_deref(),
            Some("sk-or-v1-host-bound-key-5544")
        );

        wiz.cursors[Step::CloudAi.index()] = 4;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        wiz.on_paste("https://api.together.xyz/v1");
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_url, "https://api.together.xyz/v1");
        assert_eq!(wiz.cloud_api_key, None);

        // Oversized (> 512 bytes) keys are rejected.
        wiz.cursors[Step::CloudAi.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste(&"k".repeat(513));
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_api_key, None);

        // Broken config.toml with an NVD secret fails Wizard::load without echoing the secret.
        Config::load_or_create(&home).unwrap();
        crate::workspace::write_private_atomic(
            &home.config_path(),
            format!("[cve]\nnvd_api_key = \"{NVD_SECRET}\" broken_syntax\n").as_bytes(),
        )
        .unwrap();
        let err = match Wizard::load(&home, false) {
            Ok(_) => panic!("broken config.toml must fail Wizard::load"),
            Err(err) => format!("{err:#}"),
        };
        assert!(
            !err.contains(NVD_SECRET),
            "parse error leaked config secret: {err}"
        );
    }
}

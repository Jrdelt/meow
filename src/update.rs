//! `meow update`: for a meow installed from a GitHub Release, downloads the
//! newest release (`release.rs`). Otherwise pulls the latest meow from
//! GitHub into the folder it was built from, then runs that folder's `install.sh`, which rebuilds meow and
//! adds any tool it now needs. Nothing is pulled while the folder has local
//! changes, and only fast-forward pulls are made.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use anyhow::{bail, Context, Result};

use crate::evidence::{sanitize, sanitize_block};

/// The folder `cargo install --path .` was run in.
const BUILT_FROM: &str = env!("CARGO_MANIFEST_DIR");
/// The commit this binary was built from; empty when not known.
const BUILT_COMMIT: &str = env!("MEOW_BUILD_COMMIT");
/// Overrides the folder to update.
pub const SOURCE_ENV: &str = "MEOW_SOURCE";

pub struct UpdateArgs {
    /// Only say what would change.
    pub check: bool,
    /// The meow checkout to update, instead of the one meow was built from.
    pub source: Option<PathBuf>,
}

fn source_dir(arg: Option<&Path>) -> PathBuf {
    arg.map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os(SOURCE_ENV)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(BUILT_FROM))
}

fn read_manifest_bounded(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > 1024 * 1024 {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(1024 * 1024).read_to_string(&mut text).ok()?;
    Some(text)
}

fn is_meow_checkout(dir: &Path) -> bool {
    let git_dir = dir.join(".git");
    let git_is_real_dir = std::fs::symlink_metadata(&git_dir)
        .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir());
    git_is_real_dir
        && read_manifest_bounded(&dir.join("Cargo.toml"))
            .is_some_and(|manifest| manifest.lines().any(|l| l.trim() == "name = \"meow\""))
}

fn is_ephemeral_tmp_path(dir: &Path) -> bool {
    let sys_tmp = std::env::temp_dir();
    let sys_tmp_canon = std::fs::canonicalize(&sys_tmp).ok();
    let check = |p: &Path| {
        p.starts_with("/tmp")
            || p.starts_with("/var/tmp")
            || p.starts_with("/private/tmp")
            || p.starts_with("/private/var/tmp")
            || p.starts_with("/var/folders")
            || p.starts_with("/private/var/folders")
            || p.starts_with(&sys_tmp)
            || sys_tmp_canon.as_ref().is_some_and(|c| p.starts_with(c))
    };
    check(dir) || std::fs::canonicalize(dir).is_ok_and(|canon| check(&canon))
}

fn verify_checkout_security(dir: &Path, explicit_source: bool) -> Result<()> {
    let safe_dir = sanitize(&dir.display().to_string(), 400);
    if !explicit_source && is_ephemeral_tmp_path(dir) {
        bail!(
            "{safe_dir} is a temporary build folder (for example from Homebrew) that no longer exists. \
             Upgrade with `brew update && brew upgrade meow` (or `brew uninstall meow && brew install --HEAD meow` for the latest main branch), \
             or pass `--source <folder>` with a meow git checkout."
        );
    }
    for ancestor in dir.ancestors().skip(1) {
        let Ok(meta) = std::fs::symlink_metadata(ancestor) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            let safe_anc = sanitize(&ancestor.display().to_string(), 400);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.uid() != 0 {
                    bail!("refusing to update {safe_dir}: parent {safe_anc} is a user-owned symbolic link");
                }
            }
            #[cfg(not(unix))]
            {
                bail!("refusing to update {safe_dir}: parent {safe_anc} is a symbolic link");
            }
        }
    }
    for path in [
        dir.to_path_buf(),
        dir.join("Cargo.toml"),
        dir.join("build.rs"),
        dir.join("src"),
        dir.join(".git"),
        dir.join(".git").join("config"),
        dir.join("install.sh"),
        dir.join("install.ps1"),
        dir.join(".cargo"),
    ] {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            bail!(
                "refusing to update {safe_dir}: {} is a symbolic link",
                sanitize(&path.display().to_string(), 400)
            );
        }
    }
    Ok(())
}

/// git, and then the folder's `install.sh`, are run in `dir`: it must be
/// this user's own. A folder (or critical build/config file inside it) that
/// another account owns or can write to could make both run that account's code.
#[cfg(unix)]
fn ensure_own_checkout(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: these calls have no preconditions and cannot fail.
    let (me, my_group) = unsafe { (libc::geteuid(), libc::getegid()) };
    for (path, must_exist) in [
        (dir.to_path_buf(), true),
        (dir.join(".git"), true),
        (dir.join(".git").join("config"), false),
        (dir.join("Cargo.toml"), true),
        (dir.join("build.rs"), false),
        (dir.join("src"), false),
        (dir.join("install.sh"), false),
        (dir.join("install.ps1"), false),
        (dir.join(".cargo"), false),
    ] {
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(_) if !must_exist => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "cannot inspect {}",
                        sanitize(&path.display().to_string(), 400)
                    )
                })
            }
        };
        let problem = if meta.file_type().is_symlink() {
            "is a symbolic link"
        } else if meta.uid() != me {
            "belongs to another user"
        } else if meta.mode() & 0o002 != 0 || (meta.mode() & 0o020 != 0 && meta.gid() != my_group) {
            "can be changed by other users"
        } else {
            continue;
        };
        bail!(
            "{} {problem}, so nothing is run in it. Update from a meow folder of your own \
             (clone it again and run ./install.sh there), or pass --source <folder>",
            sanitize(&path.display().to_string(), 400)
        );
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_own_checkout(dir: &Path) -> Result<()> {
    for (path, must_exist) in [
        (dir.to_path_buf(), true),
        (dir.join(".git"), true),
        (dir.join("Cargo.toml"), true),
        (dir.join("src"), false),
        (dir.join("install.ps1"), false),
        (dir.join(".cargo"), false),
    ] {
        if !must_exist && std::fs::symlink_metadata(&path).is_err() {
            continue;
        }
        crate::workspace::verify_windows_owner(&path).with_context(|| {
            format!(
                "refusing untrusted checkout path {}",
                sanitize(&path.display().to_string(), 400)
            )
        })?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_own_checkout(_dir: &Path) -> Result<()> {
    Ok(())
}

fn audit_untracked_build_overrides(dir: &Path) -> Result<()> {
    const OVERRIDES: [&str; 4] = [
        ".cargo/config",
        ".cargo/config.toml",
        "rust-toolchain",
        "rust-toolchain.toml",
    ];
    let safe_dir = sanitize(&dir.display().to_string(), 400);
    for rel in OVERRIDES {
        let candidate = dir.join(rel);
        let Ok(meta) = std::fs::symlink_metadata(&candidate) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            bail!(
                "refusing to update {safe_dir}: {} is a symbolic link",
                sanitize(&candidate.display().to_string(), 400)
            );
        }
        if git(dir, &["ls-files", "--error-unmatch", "--", rel]).is_err() {
            bail!("refusing to build {safe_dir}: untracked '{rel}' could override Cargo or rustc settings");
        }
    }
    // Cargo and rustup also walk parent directories above the checkout; allow
    // the user's own private `~/.cargo/config.toml`, but refuse any parent
    // override file owned or writable by another account.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (me, my_group) = unsafe { (libc::geteuid(), libc::getegid()) };
        for ancestor in dir.ancestors().skip(1) {
            for rel in OVERRIDES {
                let candidate = ancestor.join(rel);
                let Ok(meta) = std::fs::symlink_metadata(&candidate) else {
                    continue;
                };
                let untrusted = meta.file_type().is_symlink()
                    || (meta.uid() != me && meta.uid() != 0)
                    || meta.mode() & 0o002 != 0
                    || (meta.mode() & 0o020 != 0 && meta.gid() != my_group);
                if untrusted {
                    bail!(
                        "refusing to build {safe_dir}: untrusted parent override {}",
                        sanitize(&candidate.display().to_string(), 400)
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
const TRUSTED_GIT_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/run/current-system/sw/bin",
];

#[cfg(windows)]
fn trusted_windows_dir(raw: &std::ffi::OsStr) -> Option<PathBuf> {
    use std::path::{Component, Prefix};
    let path = PathBuf::from(raw);
    let mut comps = path.components();
    let Some(Component::Prefix(prefix)) = comps.next() else {
        return None;
    };
    if !matches!(prefix.kind(), Prefix::Disk(_)) {
        return None;
    }
    if !matches!(comps.next(), Some(Component::RootDir)) {
        return None;
    }
    if comps.any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    Some(path)
}

fn resolve_git() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        for dir in TRUSTED_GIT_DIRS {
            let candidate = Path::new(dir).join("git");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        bail!("cannot find git in trusted system directories (/usr/bin, /bin, /opt/homebrew/bin, /usr/local/bin)")
    }
    #[cfg(windows)]
    {
        let mut dirs = Vec::new();
        if let Some(root) = std::env::var_os("SystemRoot").and_then(|v| trusted_windows_dir(&v)) {
            dirs.push(root.join("System32"));
        }
        for env_key in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(base) = std::env::var_os(env_key).and_then(|v| trusted_windows_dir(&v)) {
                dirs.push(base.join("Git").join("cmd"));
                dirs.push(base.join("Git").join("bin"));
            }
        }
        dirs.push(PathBuf::from(r"C:\Program Files\Git\cmd"));
        dirs.push(PathBuf::from(r"C:\Program Files\Git\bin"));
        for dir in dirs {
            let candidate = dir.join("git.exe");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        bail!("cannot find git.exe in trusted system directories (C:\\Program Files\\Git\\cmd)")
    }
}

fn resolve_sh() -> PathBuf {
    for candidate in ["/bin/sh", "/usr/bin/sh"] {
        let path = Path::new(candidate);
        if path.is_file() {
            return path.to_path_buf();
        }
    }
    PathBuf::from("/bin/sh")
}

fn sanitized_path_env() -> Option<std::ffi::OsString> {
    let raw = std::env::var_os("PATH")?;
    let clean: Vec<PathBuf> = std::env::split_paths(&raw)
        .filter(|dir| !dir.as_os_str().is_empty() && dir.is_absolute())
        .collect();
    std::env::join_paths(clean).ok()
}

fn is_scp_git_url(url: &str) -> bool {
    if url.contains("://") || url.contains("::") {
        return false;
    }
    let Some((user_host, path)) = url.split_once(':') else {
        return false;
    };
    let Some((user, host)) = user_host.split_once('@') else {
        return false;
    };
    !user.is_empty()
        && !host.is_empty()
        && !path.is_empty()
        && !user.starts_with('-')
        && !host.starts_with('-')
        && !path.starts_with('-')
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn validate_remote_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('-')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("refusing unsafe git remote name '{}'", sanitize(name, 64));
    }
    Ok(())
}

/// Validates the upstream git remote URL before fetching. Returns `Ok(true)`
/// if it is a verified local directory (allowed only with explicit `--source`).
fn validate_remote_url(dir: &Path, remote_url: &str, allow_local: bool) -> Result<bool> {
    let url = remote_url.trim();
    if url.is_empty() || url.starts_with('-') {
        bail!("refusing unsafe git remote URL '{}'", sanitize(url, 120));
    }
    if url.starts_with("https://") || url.starts_with("ssh://") {
        let parsed = url::Url::parse(url).map_err(|_| {
            anyhow::anyhow!("refusing invalid git remote URL '{}'", sanitize(url, 120))
        })?;
        let Some(host) = parsed.host_str() else {
            bail!(
                "refusing git remote URL without host '{}'",
                sanitize(url, 120)
            );
        };
        if host.is_empty()
            || host.starts_with('-')
            || parsed.username().starts_with('-')
            || parsed.path().is_empty()
            || parsed.path() == "/"
        {
            bail!("refusing unsafe git remote URL '{}'", sanitize(url, 120));
        }
        return Ok(false);
    }
    if is_scp_git_url(url) {
        return Ok(false);
    }
    if allow_local
        && !url.contains("://")
        && !url.contains("::")
        && (Path::new(url).is_dir() || dir.join(url).is_dir())
    {
        return Ok(true);
    }
    bail!(
        "refusing untrusted git remote URL '{}' (must use https:// or ssh://)",
        sanitize(url, 120)
    )
}

fn is_unsafe_local_git_config_key(key: &str) -> bool {
    let k = key.trim().to_ascii_lowercase();
    let http_tail = k
        .strip_prefix("http.")
        .map(|rest| rest.rsplit_once('.').map_or(rest, |(_, leaf)| leaf));
    matches!(
        k.as_str(),
        "core.fsmonitor"
            | "core.alternaterefscommand"
            | "core.sshcommand"
            | "core.askpass"
            | "core.gitproxy"
            | "core.pager"
            | "core.editor"
            | "core.hookspath"
            | "core.worktree"
            | "credential.helper"
            | "protocol.allow"
            | "https.proxy"
            | "diff.external"
            | "interactive.difffilter"
            | "ssh.variant"
            | "include.path"
            | "fetch.recursesubmodules"
    ) || http_tail.is_some_and(|leaf| {
        leaf == "proxy"
            || leaf == "extraheader"
            || leaf.starts_with("ssl")
            || leaf.starts_with("curlopt")
            || leaf == "followredirects"
    }) || k.starts_with("credential.") && k.ends_with(".helper")
        || k.starts_with("protocol.") && k.ends_with(".allow")
        || k.starts_with("remote.")
            && (k.ends_with(".uploadpack")
                || k.ends_with(".receivepack")
                || k.ends_with(".proxy")
                || k.ends_with(".vcs"))
        || k.starts_with("submodule.")
        || k.starts_with("uploadpack.")
        || k.starts_with("receivepack.")
        || k.starts_with("filter.")
        || k.starts_with("diff.") && (k.ends_with(".command") || k.ends_with(".textconv"))
        || k.starts_with("difftool.")
        || k.starts_with("mergetool.")
        || k.starts_with("merge.") && k.ends_with(".driver")
        || k.starts_with("man.") && k.ends_with(".cmd")
        || k.starts_with("gpg.")
        || k.starts_with("pager.")
        || k.starts_with("extensions.")
        || k.starts_with("alias.")
        || k.starts_with("includeif.")
        || k.starts_with("url.") && (k.ends_with(".insteadof") || k.ends_with(".pushinsteadof"))
}

fn audit_local_git_config(dir: &Path) -> Result<()> {
    let safe_dir = sanitize(&dir.display().to_string(), 400);
    let keys = git(dir, &["config", "--local", "--name-only", "--list"])
        .with_context(|| format!("cannot audit local .git/config in {safe_dir}"))?;
    for key in keys.lines() {
        if is_unsafe_local_git_config_key(key) {
            bail!(
                "refusing unsafe local .git/config setting '{}' in {safe_dir}",
                sanitize(key.trim(), 80),
            );
        }
    }
    Ok(())
}

const GIT_ENV_SCRUB: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_SSL_NO_VERIFY",
    "GIT_PROXY_COMMAND",
    "GIT_ALLOW_PROTOCOL",
    "GIT_TEMPLATE_DIR",
];

fn configure_git_command(cmd: &mut Command, hooks_dir: &Path) {
    for var in GIT_ENV_SCRUB {
        cmd.env_remove(var);
    }
    if let Some(path) = sanitized_path_env() {
        cmd.env("PATH", path);
    } else {
        cmd.env_remove("PATH");
    }
    cmd.arg("-c")
        .arg(format!("core.hooksPath={}", hooks_dir.display()))
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("submodule.recurse=false")
        .arg("-c")
        .arg("fetch.recurseSubmodules=false")
        .arg("-c")
        .arg("protocol.ext.allow=never")
        .arg("-c")
        .arg("protocol.http.allow=never")
        .arg("-c")
        .arg("protocol.git.allow=never");
}

/// Runs git in `dir` with hooks and fsmonitor disabled and returns its trimmed standard output.
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    #[cfg(windows)]
    let empty_hooks = tempfile::tempdir().context("cannot create temporary hooks folder")?;
    #[cfg(windows)]
    let hooks_path = empty_hooks.path();
    #[cfg(not(windows))]
    let hooks_path = Path::new("/dev/null");

    let mut cmd = Command::new(resolve_git()?);
    configure_git_command(&mut cmd, hooks_path);
    let output = cmd
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .context("cannot run git; install it and try again")?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            sanitize_block(&String::from_utf8_lossy(&output.stderr), 2000)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Like [`git`], but git talks to the terminal (credential prompts,
/// progress) and nothing is captured.
fn git_live(dir: &Path, local_remote: bool, args: &[&str]) -> Result<()> {
    #[cfg(windows)]
    let empty_hooks = tempfile::tempdir().context("cannot create temporary hooks folder")?;
    #[cfg(windows)]
    let hooks_path = empty_hooks.path();
    #[cfg(not(windows))]
    let hooks_path = Path::new("/dev/null");

    let file_policy = if local_remote {
        "protocol.file.allow=always"
    } else {
        "protocol.file.allow=never"
    };
    let mut cmd = Command::new(resolve_git()?);
    configure_git_command(&mut cmd, hooks_path);
    let status = cmd
        .arg("-c")
        .arg(file_policy)
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .context("cannot run git; install it and try again")?;
    if !status.success() {
        bail!("git {} failed (see the messages above)", args.join(" "));
    }
    Ok(())
}

fn short(commit: &str) -> &str {
    commit.get(..7).unwrap_or(commit)
}

#[cfg(any(unix, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct HomebrewInstall {
    prefix: PathBuf,
    formula: String,
    keg_version: String,
    is_head: bool,
}

/// Recognizes a binary installed inside a Homebrew Cellar:
/// `<prefix>/Cellar/<formula>/<keg_version>/bin/<exe>`.
#[cfg(any(unix, test))]
fn parse_homebrew_cellar_exe(canon_exe: &Path) -> Option<HomebrewInstall> {
    if !canon_exe.is_absolute() {
        return None;
    }
    let bin_dir = canon_exe.parent()?;
    if bin_dir.file_name()?.to_str()? != "bin" {
        return None;
    }
    let keg_dir = bin_dir.parent()?;
    let keg_version = keg_dir.file_name()?.to_str()?.to_owned();
    if keg_version.is_empty() || keg_version.starts_with('-') {
        return None;
    }
    let formula_dir = keg_dir.parent()?;
    let formula = formula_dir.file_name()?.to_str()?.to_owned();
    if formula.is_empty()
        || formula.starts_with('-')
        || !formula
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
    {
        return None;
    }
    let cellar_dir = formula_dir.parent()?;
    if cellar_dir.file_name()?.to_str()? != "Cellar" {
        return None;
    }
    let prefix = cellar_dir.parent()?.to_path_buf();
    if prefix.as_os_str().is_empty() {
        return None;
    }
    let is_head = keg_version.starts_with("HEAD");
    Some(HomebrewInstall {
        prefix,
        formula,
        keg_version,
        is_head,
    })
}

#[cfg(unix)]
fn detect_homebrew_install() -> Option<(HomebrewInstall, PathBuf)> {
    use std::os::unix::fs::MetadataExt;
    let exe = std::env::current_exe().ok()?;
    let canon = std::fs::canonicalize(&exe).ok()?;
    let hb = parse_homebrew_cellar_exe(&canon)?;
    if is_ephemeral_tmp_path(&hb.prefix) {
        return None;
    }
    let brew = hb.prefix.join("bin").join("brew");
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    let link_meta = std::fs::symlink_metadata(&brew).ok()?;
    if link_meta.uid() != me && link_meta.uid() != 0 {
        return None;
    }
    let target_meta = std::fs::metadata(&brew).ok()?;
    if !target_meta.is_file()
        || (target_meta.uid() != me && target_meta.uid() != 0)
        || target_meta.mode() & 0o002 != 0
    {
        return None;
    }
    Some((hb, brew))
}

#[cfg(unix)]
fn brew_command(brew_bin: &Path) -> Command {
    let mut cmd = Command::new(brew_bin);
    for var in GIT_ENV_SCRUB {
        cmd.env_remove(var);
    }
    if let Some(path) = sanitized_path_env() {
        cmd.env("PATH", path);
    } else {
        cmd.env_remove("PATH");
    }
    cmd
}

#[cfg(unix)]
fn run_homebrew_update(hb: &HomebrewInstall, brew_bin: &Path, check: bool) -> Result<ExitCode> {
    let safe_formula = sanitize(&hb.formula, 64);
    let safe_ver = sanitize(&hb.keg_version, 64);
    if check {
        println!("[+] Installed via Homebrew ({safe_formula} {safe_ver}). Checking with brew...");
        let mut cmd = brew_command(brew_bin);
        cmd.arg("outdated").arg("--quiet");
        if hb.is_head {
            cmd.arg("--fetch-HEAD");
        }
        let out = cmd
            .arg(&hb.formula)
            .stdin(Stdio::null())
            .output()
            .context("cannot run brew outdated")?;
        if !out.status.success() {
            bail!(
                "brew outdated failed: {}",
                sanitize_block(&String::from_utf8_lossy(&out.stderr), 1000)
            );
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.trim().is_empty() {
            println!("[+] Already up to date in Homebrew ({safe_formula} {safe_ver}).");
            if !hb.is_head {
                println!(
                    "[+] Note: Homebrew stable tracks tagged releases; run `brew uninstall {safe_formula} && brew install --HEAD {safe_formula}` to track the latest main branch."
                );
            }
        } else {
            let head_flag = if hb.is_head { " --fetch-HEAD" } else { "" };
            println!(
                "[+] Update available in Homebrew: {}",
                sanitize(stdout.trim(), 120)
            );
            println!(
                "[+] Run `meow update` (or `brew upgrade{head_flag} {safe_formula}`) to install it."
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    println!("[+] Installed via Homebrew ({safe_formula} {safe_ver}) — running brew update...");
    let status = brew_command(brew_bin)
        .arg("update")
        .status()
        .context("cannot run brew update")?;
    if !status.success() {
        bail!("brew update failed (see the messages above)");
    }

    println!("[+] Running brew upgrade for {safe_formula}...");
    let mut up = brew_command(brew_bin);
    up.env("HOMEBREW_NO_AUTO_UPDATE", "1").arg("upgrade");
    if hb.is_head {
        up.arg("--fetch-HEAD");
    }
    let status = up
        .arg(&hb.formula)
        .status()
        .context("cannot run brew upgrade")?;
    if !status.success() {
        bail!("brew upgrade failed (see the messages above)");
    }
    println!(
        "[+] Homebrew update finished. Sessions that are open keep the old version until you close and reopen them."
    );
    Ok(ExitCode::SUCCESS)
}

pub fn run(args: &UpdateArgs) -> Result<ExitCode> {
    // Installed from a GitHub Release: download the newest release instead,
    // unless a checkout to update was named.
    let explicit_source =
        args.source.is_some() || std::env::var_os(SOURCE_ENV).is_some_and(|v| !v.is_empty());
    if crate::release::BUILD.is_some() && !explicit_source {
        return crate::release::run(args.check);
    }
    #[cfg(unix)]
    if !explicit_source {
        if let Some((hb, brew_bin)) = detect_homebrew_install() {
            return run_homebrew_update(&hb, &brew_bin, args.check);
        }
    }
    let dir = source_dir(args.source.as_deref());
    let safe_dir = sanitize(&dir.display().to_string(), 400);
    verify_checkout_security(&dir, explicit_source)?;
    if !is_meow_checkout(&dir) {
        bail!(
            "{safe_dir} is not a meow git checkout, so there is nothing to pull into. \
             Clone the repository again, run ./install.sh in it, and `meow update` \
             will use that folder from then on (or pass --source <folder>)."
        );
    }
    ensure_own_checkout(&dir)?;
    audit_local_git_config(&dir)?;
    audit_untracked_build_overrides(&dir)?;
    println!("[+] meow source: {safe_dir}");

    let changed = git(&dir, &["status", "--porcelain", "--untracked-files=no"])?;
    if !changed.is_empty() {
        bail!(
            "{safe_dir} has local changes, so nothing was pulled. Commit or discard them first:\n{}",
            sanitize_block(&changed, 1000)
        );
    }
    let upstream = git(
        &dir,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
    )
    .context("the checked-out branch does not track a branch on GitHub")?;
    let remote_name = upstream.split('/').next().unwrap_or("origin");
    validate_remote_name(remote_name)?;
    let remote_urls = git(
        &dir,
        &["config", "--get-all", &format!("remote.{remote_name}.url")],
    )
    .with_context(|| format!("cannot read remote URL for {}", sanitize(remote_name, 64)))?;
    let mut local_remote = false;
    let mut saw_url = false;
    for raw_url in remote_urls.lines().filter(|l| !l.trim().is_empty()) {
        saw_url = true;
        local_remote |= validate_remote_url(&dir, raw_url, explicit_source)?;
    }
    if !saw_url {
        bail!("cannot read remote URL for {}", sanitize(remote_name, 64));
    }
    // The address git will really use, after its own rewriting rules.
    let effective_url =
        git(&dir, &["ls-remote", "--get-url", "--", remote_name]).with_context(|| {
            format!(
                "cannot resolve remote URL for {}",
                sanitize(remote_name, 64)
            )
        })?;
    local_remote |= validate_remote_url(&dir, &effective_url, explicit_source)?;

    let safe_upstream = sanitize(&upstream, 120);
    println!("[+] Checking {safe_upstream} for changes");
    git_live(&dir, local_remote, &["fetch", "--quiet", "--", remote_name])?;
    let incoming = git(&dir, &["log", "--oneline", "--no-decorate", "HEAD..@{u}"])?;
    let head = git(&dir, &["rev-parse", "HEAD"])?;
    let behind_checkout = !BUILT_COMMIT.is_empty() && BUILT_COMMIT != head;

    if incoming.is_empty() && !behind_checkout {
        println!(
            "[+] Already up to date ({} on {safe_upstream})",
            sanitize(short(&head), 16)
        );
        return Ok(ExitCode::SUCCESS);
    }
    if incoming.is_empty() {
        println!(
            "[+] Nothing new on GitHub, but this meow was built from {} and the folder is at {}",
            sanitize(short(BUILT_COMMIT), 16),
            sanitize(short(&head), 16)
        );
    } else {
        let lines: Vec<&str> = incoming.lines().collect();
        println!("[+] {} new on {safe_upstream}:", lines.len());
        // A commit's subject is whatever its author typed: shown as text.
        for line in lines.iter().take(20) {
            println!("    {}", sanitize(line, 200));
        }
        if lines.len() > 20 {
            println!("    ... and {} more", lines.len() - 20);
        }
    }
    if args.check {
        println!("[+] Run `meow update` to install it.");
        return Ok(ExitCode::SUCCESS);
    }

    if !incoming.is_empty() {
        git_live(&dir, local_remote, &["pull", "--ff-only", "--quiet"])
            .context("the pull could not fast-forward; the folder's branch has its own commits")?;
    }

    verify_checkout_security(&dir, explicit_source)?;
    ensure_own_checkout(&dir)?;
    audit_local_git_config(&dir)?;
    audit_untracked_build_overrides(&dir)?;
    if cfg!(windows) {
        // A running program cannot be replaced on Windows.
        println!(
            "[+] Pulled. Close meow, then run in PowerShell: & \"{safe_dir}\\install.ps1\" -Yes  (or: cargo install --path \"{safe_dir}\" --locked)"
        );
        return Ok(ExitCode::SUCCESS);
    }
    println!("[+] Rebuilding with install.sh");
    let mut cmd = Command::new(resolve_sh());
    if let Some(path) = sanitized_path_env() {
        cmd.env("PATH", path);
    } else {
        cmd.env_remove("PATH");
    }
    let status = cmd
        .arg("install.sh")
        .arg("--yes")
        .env("MEOW_NO_SUDO", "1")
        .current_dir(&dir)
        .status()
        .context("cannot run install.sh")?;
    if !status.success() {
        bail!("install.sh failed (see the messages above); the pulled code is in place, so it can be run again");
    }
    println!(
        "[+] Updated. Sessions that are open keep the old version until you close and reopen them."
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_remote_urls_and_local_config_keys_are_audited() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            !validate_remote_url(tmp.path(), "https://github.com/Jrdelt/meow.git", false).unwrap()
        );
        assert!(!validate_remote_url(tmp.path(), "git@github.com:Jrdelt/meow.git", false).unwrap());
        assert!(
            !validate_remote_url(tmp.path(), "ssh://git@github.com/Jrdelt/meow.git", false)
                .unwrap()
        );
        for bad in [
            "",
            "http://example.com/meow.git",
            "git://github.com/Jrdelt/meow.git",
            "ext::sh -c touch% /tmp/pwn",
            "-oProxyCommand=sh",
            "git@-oProxyCommand=sh:Jrdelt/meow.git",
            "ssh://-oProxyCommand=sh/Jrdelt/meow.git",
            "https://",
            "https://github.com/",
        ] {
            assert!(
                validate_remote_url(tmp.path(), bad, true).is_err(),
                "expected rejection for {bad}"
            );
        }

        for unsafe_key in [
            "core.fsmonitor",
            "core.alternaterefscommand",
            "core.sshcommand",
            "core.hookspath",
            "http.sslverify",
            "http.sslcainfo",
            "http.https://github.com/.sslcainfo",
            "http.curloptresolve",
            "http.https://github.com/.curloptresolve",
            "http.followredirects",
            "credential.helper",
            "protocol.ext.allow",
            "remote.origin.uploadpack",
            "filter.lfs.clean",
            "difftool.evil.cmd",
            "merge.evil.driver",
            "url.https://evil.example/.insteadof",
            "include.path",
            "includeif.gitdir:~/x.path",
            "fetch.recursesubmodules",
            "submodule.evil.url",
            "submodule.evil.update",
        ] {
            assert!(
                is_unsafe_local_git_config_key(unsafe_key),
                "expected {unsafe_key} to be flagged unsafe"
            );
        }
        for benign_key in [
            "core.repositoryformatversion",
            "core.filemode",
            "core.bare",
            "core.logallrefupdates",
            "remote.origin.url",
            "remote.origin.fetch",
            "branch.main.remote",
            "branch.main.merge",
        ] {
            assert!(
                !is_unsafe_local_git_config_key(benign_key),
                "expected {benign_key} to be allowed"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn checkout_update_enforces_ownership_hooks_remotes_and_clean_tree() {
        use std::os::unix::fs::PermissionsExt;

        fn test_git(dir: &Path, args: &[&str]) {
            let out = Command::new("git")
                .arg("-C")
                .arg(dir)
                .args([
                    "-c",
                    "user.name=meow-test",
                    "-c",
                    "user.email=test@example.invalid",
                    "-c",
                    "init.defaultBranch=main",
                    "-c",
                    "advice.detachedHead=false",
                ])
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        let tmp = tempfile::tempdir().unwrap();
        let install_log = tmp.path().join("install.log");
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        test_git(&work, &["init", "-q"]);
        std::fs::write(work.join("Cargo.toml"), "[package]\nname = \"meow\"\n").unwrap();
        std::fs::write(
            work.join("install.sh"),
            format!("echo \"ran $*\" >> '{}'\n", install_log.display()),
        )
        .unwrap();
        test_git(&work, &["add", "."]);
        test_git(&work, &["commit", "-qm", "initial"]);
        test_git(tmp.path(), &["clone", "-q", "--bare", "work", "origin.git"]);
        test_git(&work, &["remote", "add", "origin", "../origin.git"]);
        test_git(&work, &["fetch", "-q", "origin"]);
        test_git(&work, &["branch", "-q", "--set-upstream-to=origin/main"]);
        test_git(tmp.path(), &["clone", "-q", "origin.git", "clone"]);
        let clone = tmp.path().join("clone");
        // Container environments with `umask 0000` create world-writable files
        // during `git clone`; normalize the test checkout to private modes first.
        fn tighten_tree(path: &Path) {
            let meta = std::fs::symlink_metadata(path).unwrap();
            if meta.is_dir() {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
                for entry in std::fs::read_dir(path).unwrap() {
                    tighten_tree(&entry.unwrap().path());
                }
            } else if meta.is_file() {
                let mode = if meta.permissions().mode() & 0o111 != 0 {
                    0o755
                } else {
                    0o644
                };
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        tighten_tree(&clone);

        // Push a new commit with terminal control bytes in the subject.
        std::fs::write(work.join("feat.txt"), "ok").unwrap();
        test_git(&work, &["add", "."]);
        test_git(
            &work,
            &["commit", "-qm", "feat: add\u{1b}]0;pwn\u{7} support"],
        );
        test_git(&work, &["push", "-q", "origin", "HEAD:main"]);

        // Non-checkout folder is refused.
        let err = run(&UpdateArgs {
            check: true,
            source: Some(tmp.path().join("missing")),
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("is not a meow git checkout"));

        // World-writable checkout folder is refused before git runs.
        std::fs::set_permissions(&clone, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = run(&UpdateArgs {
            check: false,
            source: Some(clone.clone()),
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("can be changed by other users"));
        std::fs::set_permissions(&clone, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Plant a post-merge git hook; hooksPath=/dev/null prevents execution.
        let hooks = clone.join(".git/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        let hook_marker = tmp.path().join("hook-ran");
        let hook = hooks.join("post-merge");
        std::fs::write(
            &hook,
            format!("#!/bin/sh\necho pwn > '{}'\n", hook_marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        // --check changes nothing; full update pulls and runs install.sh without running hooks.
        let _ = run(&UpdateArgs {
            check: true,
            source: Some(clone.clone()),
        })
        .unwrap();
        assert!(!clone.join("feat.txt").exists());
        assert!(!install_log.exists());

        let _ = run(&UpdateArgs {
            check: false,
            source: Some(clone.clone()),
        })
        .unwrap();
        assert!(clone.join("feat.txt").exists());
        assert!(!hook_marker.exists());
        assert_eq!(
            std::fs::read_to_string(&install_log).unwrap().trim(),
            "ran --yes"
        );

        // Local modifications refuse pulling.
        std::fs::write(clone.join("install.sh"), "echo dirty\n").unwrap();
        let err = run(&UpdateArgs {
            check: false,
            source: Some(clone.clone()),
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("has local changes"));
        test_git(&clone, &["checkout", "--", "install.sh"]);

        // Multi-URL remote smuggling (first bad, second good) is refused.
        let origin_path = tmp.path().join("origin.git");
        test_git(
            &clone,
            &["remote", "set-url", "--", "origin", "ext::sh -c pwn"],
        );
        test_git(
            &clone,
            &[
                "config",
                "--add",
                "remote.origin.url",
                origin_path.to_str().unwrap(),
            ],
        );
        tighten_tree(&clone);
        let err = run(&UpdateArgs {
            check: true,
            source: Some(clone.clone()),
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("git remote URL"), "{err:#}");
    }

    #[test]
    fn homebrew_cellar_paths_are_recognized_and_sanitized() {
        let root = if cfg!(windows) {
            r"C:\opt\homebrew"
        } else {
            "/opt/homebrew"
        };
        let stable = PathBuf::from(root)
            .join("Cellar")
            .join("meow")
            .join("0.2.0")
            .join("bin")
            .join("meow");
        let parsed = parse_homebrew_cellar_exe(&stable).expect("stable cellar path");
        assert_eq!(parsed.prefix, PathBuf::from(root));
        assert_eq!(parsed.formula, "meow");
        assert_eq!(parsed.keg_version, "0.2.0");
        assert!(!parsed.is_head);

        let head = PathBuf::from(root)
            .join("Cellar")
            .join("meow")
            .join("HEAD-cccc85c_1")
            .join("bin")
            .join("meow");
        let parsed_head = parse_homebrew_cellar_exe(&head).expect("HEAD cellar path");
        assert!(parsed_head.is_head);
        assert_eq!(parsed_head.keg_version, "HEAD-cccc85c_1");

        // Reject flag-like formula names and non-Cellar paths.
        let bad_formula = PathBuf::from(root)
            .join("Cellar")
            .join("-evil")
            .join("0.2.0")
            .join("bin")
            .join("meow");
        assert!(parse_homebrew_cellar_exe(&bad_formula).is_none());
        let plain_bin = PathBuf::from(root).join("bin").join("meow");
        assert!(parse_homebrew_cellar_exe(&plain_bin).is_none());
    }
}

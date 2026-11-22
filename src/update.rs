//! `meow update`: for a meow installed from a GitHub Release, downloads the
//! newest release (`release.rs`). Otherwise pulls the latest meow from
//! GitHub into the folder it was built from, then runs that folder's `install.sh`, which rebuilds meow and
//! adds any tool it now needs. Nothing is pulled while the folder has local
//! changes, and only fast-forward pulls are made.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

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

/// Why `path` (whose metadata is `meta`) is not this user's alone, if it
/// is not: a link, another account's, or one others can change, also
/// through a shared group or an access list.
#[cfg(unix)]
fn not_own(path: &Path, meta: &std::fs::Metadata) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: this call has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    if meta.file_type().is_symlink() {
        Some("is a symbolic link")
    } else if meta.uid() != me {
        Some("belongs to another user")
    } else if crate::perms::others_can_change(path, meta) {
        Some("can be changed by other users")
    } else {
        None
    }
}

/// [`not_own`] on Windows, read from the owner and access list: a folder
/// made under `C:\` lets every account change what is in it.
#[cfg(windows)]
fn not_own(path: &Path, meta: &std::fs::Metadata) -> Option<&'static str> {
    use crate::perms::Foreign;
    if meta.file_type().is_symlink() {
        return Some("is a symbolic link");
    }
    match crate::perms::foreign(path) {
        Ok(None) => None,
        Ok(Some(Foreign::Owner)) => Some("belongs to another account"),
        Ok(Some(Foreign::Writable)) => Some("can be changed by other accounts"),
        Err(_) => Some("cannot be checked"),
    }
}

/// What to do about a checkout that is not the user's alone.
#[cfg(unix)]
const USE_OWN_CHECKOUT: &str = "Update from a meow folder of your own \
     (clone it again and run ./install.sh there), or pass --source <folder>";
#[cfg(windows)]
const USE_OWN_CHECKOUT: &str =
    "Clone meow into your user folder and run .\\install.ps1 there, or pass --source <folder>";

/// git, and then the folder's installer, are run in `dir`: it must be this
/// user's own. A folder (or any file git tracks in it, or what git keeps
/// of its history) that another account owns or can write to ([`not_own`])
/// could make both run that account's code. Its git settings are vetted
/// ([`vet_git_folder`]) before git first reads it.
#[cfg(any(unix, windows))]
fn ensure_own_checkout(dir: &Path) -> Result<()> {
    let check = |path: &Path, meta: &std::fs::Metadata| -> Result<()> {
        let Some(problem) = not_own(path, meta) else {
            return Ok(());
        };
        bail!(
            "{} {problem}, so nothing is run in it. {USE_OWN_CHECKOUT}",
            sanitize(&path.display().to_string(), 400)
        );
    };
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
        check(&path, &meta)?;
    }
    // The entries above are this user's alone, and once its settings are
    // those of a plain clone, git can be asked which files it tracks.
    vet_git_folder(dir)?;
    for path in checkout_paths(dir)? {
        // One deleted here is refused later, as a local change.
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            check(&path, &meta)?;
        }
    }
    Ok(())
}

/// More entries than a meow checkout has; past this, nothing is run.
#[cfg(any(unix, windows))]
const MAX_CHECKOUT_ENTRIES: usize = 500_000;

/// A file name as `git ls-files -z` gives it, as a path.
#[cfg(unix)]
fn tracked_path(name: &[u8]) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(name)))
}

/// A file name as `git ls-files -z` gives it (UTF-8, with `/`), as a
/// path: with `\`, which a `\\?\` path needs.
#[cfg(windows)]
fn tracked_path(name: &[u8]) -> Result<PathBuf> {
    let name = std::str::from_utf8(name).context("git lists a file name that is not UTF-8")?;
    Ok(PathBuf::from(name.replace('/', "\\")))
}

/// Every file git tracks in `dir` and the folders they are in, and what
/// git keeps that decides what is checked out: its index, `HEAD`,
/// `packed-refs`, and everything under `refs` and `objects`.
#[cfg(any(unix, windows))]
fn checkout_paths(dir: &Path) -> Result<Vec<PathBuf>> {
    use std::collections::BTreeSet;
    let listed = git_output(dir, &["ls-files", "-z"])?;
    let mut paths = BTreeSet::new();
    for name in listed
        .split(|&byte| byte == 0)
        .filter(|name| !name.is_empty())
    {
        let path = dir.join(tracked_path(name)?);
        paths.extend(
            path.ancestors()
                .take_while(|above| above.starts_with(dir) && *above != dir)
                .map(Path::to_path_buf),
        );
        if paths.len() > MAX_CHECKOUT_ENTRIES {
            bail!(
                "{} holds too many files to check",
                sanitize(&dir.display().to_string(), 400)
            );
        }
    }
    let git_dir = dir.join(".git");
    for name in ["index", "HEAD", "packed-refs"] {
        paths.insert(git_dir.join(name));
    }
    let mut folders = vec![git_dir.join("refs"), git_dir.join("objects")];
    while let Some(folder) = folders.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        paths.insert(folder);
        for entry in entries {
            let entry = entry.context("cannot read the git folder")?;
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                folders.push(entry.path());
            } else {
                paths.insert(entry.path());
            }
            if paths.len() > MAX_CHECKOUT_ENTRIES {
                bail!(
                    "{} holds too many files to check",
                    sanitize(&dir.display().to_string(), 400)
                );
            }
        }
    }
    Ok(paths.into_iter().collect())
}

#[cfg(not(any(unix, windows)))]
fn ensure_own_checkout(dir: &Path) -> Result<()> {
    vet_git_folder(dir)
}

/// What git reads first, checked before git reads the checkout: a `.git`
/// that takes its settings from another folder is refused, and so is any
/// setting a plain clone lacks (a promisor remote with a `core.sshCommand`
/// would otherwise run as soon as git lists the files).
fn vet_git_folder(dir: &Path) -> Result<()> {
    refuse_shared_git_dir(dir)?;
    audit_local_git_config(dir)
}

fn audit_untracked_build_overrides(dir: &Path) -> Result<()> {
    const OVERRIDES: [&str; 4] = [
        ".cargo/config",
        ".cargo/config.toml",
        "rust-toolchain",
        "rust-toolchain.toml",
    ];
    let safe_dir = sanitize(&dir.display().to_string(), 400);
    // `rel` as a path of this system (`.cargo\config.toml` on Windows).
    let native = |base: &Path, rel: &str| rel.split('/').fold(base.to_path_buf(), |p, c| p.join(c));
    for rel in OVERRIDES {
        let candidate = native(dir, rel);
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
    // override file owned or writable by another account, and a `.cargo`
    // folder another account could put one in. On Windows any account may
    // make `C:\.cargo`. A checkout whose manifest is no workspace of its
    // own would also take a `Cargo.toml` (its `[patch]`) and `Cargo.lock`
    // from above.
    #[cfg(any(unix, windows))]
    {
        let manifests: &[&str] = if is_own_workspace(dir) {
            &[]
        } else {
            &["Cargo.toml", "Cargo.lock"]
        };
        for ancestor in dir.ancestors().skip(1) {
            for &rel in [".cargo"].iter().chain(&OVERRIDES).chain(manifests) {
                let candidate = native(ancestor, rel);
                let Ok(meta) = std::fs::symlink_metadata(&candidate) else {
                    continue;
                };
                if let Some(problem) = untrusted_override(&candidate, &meta, rel == ".cargo") {
                    bail!(
                        "refusing to build {safe_dir}: {} {problem}, and cargo would use it",
                        sanitize(&candidate.display().to_string(), 400)
                    );
                }
            }
        }
    }
    Ok(())
}

/// Whether the checkout's `Cargo.toml` makes it a workspace of its own,
/// so cargo looks for no manifest above it.
#[cfg(any(unix, windows))]
fn is_own_workspace(dir: &Path) -> bool {
    read_manifest_bounded(&dir.join("Cargo.toml"))
        .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
        .is_some_and(|manifest| manifest.contains_key("workspace"))
}

/// Why cargo or rustup must not take settings from `path`, above the
/// checkout, if they must not: a link, or what an account other than
/// this user (or root, SYSTEM, Administrators) owns or can change. A
/// `.cargo` folder (`cargo_dir`) may be a link the user keeps on another
/// disk: one of the user's own, to a folder that passes.
#[cfg(any(unix, windows))]
fn untrusted_override(path: &Path, meta: &std::fs::Metadata, cargo_dir: bool) -> Option<String> {
    if !(cargo_dir && meta.file_type().is_symlink()) {
        return override_problem(path, meta).map(str::to_owned);
    }
    if let Some(problem) = link_problem(path, meta) {
        return Some(problem.to_owned());
    }
    let Some((target, target_meta)) = std::fs::canonicalize(path).ok().and_then(|target| {
        let meta = std::fs::symlink_metadata(&target).ok()?;
        Some((target, meta))
    }) else {
        return Some("is a link that leads nowhere".to_owned());
    };
    let problem = override_problem(&target, &target_meta)?;
    Some(format!(
        "leads to {}, which {problem}",
        sanitize(&git_path(&target).display().to_string(), 400)
    ))
}

/// What keeps `path` from being a place cargo may take settings from: a
/// link, another account's (root's is fine), or one others can change.
#[cfg(unix)]
fn override_problem(path: &Path, meta: &std::fs::Metadata) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: this call has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    if meta.file_type().is_symlink() {
        Some("is a symbolic link")
    } else if meta.uid() != me && meta.uid() != 0 {
        Some("belongs to another user")
    } else if crate::perms::others_can_change(path, meta) {
        Some("can be changed by other users")
    } else {
        None
    }
}

/// [`override_problem`] on Windows: SYSTEM, Administrators and
/// TrustedInstaller count as the user ([`not_own`]).
#[cfg(windows)]
fn override_problem(path: &Path, meta: &std::fs::Metadata) -> Option<&'static str> {
    not_own(path, meta)
}

/// What keeps the link `path` itself from being the user's own. Nobody
/// can change where a link points on Unix, only replace the link.
#[cfg(unix)]
fn link_problem(_path: &Path, meta: &std::fs::Metadata) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: this call has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    (meta.uid() != me && meta.uid() != 0).then_some("is a link that belongs to another user")
}

/// [`link_problem`] on Windows, read from the link's own owner and access
/// list: whoever may change a link (a junction too) may point it elsewhere.
#[cfg(windows)]
fn link_problem(path: &Path, _meta: &std::fs::Metadata) -> Option<&'static str> {
    use crate::perms::Foreign;
    match crate::perms::foreign(path) {
        Ok(None) => None,
        Ok(Some(Foreign::Owner)) => Some("is a link that belongs to another account"),
        Ok(Some(Foreign::Writable)) => Some("is a link other accounts can change"),
        Err(_) => Some("is a link that cannot be checked"),
    }
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

#[cfg(unix)]
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

/// Whether `key`, from the checkout's own `.git/config`, is one that a plain
/// clone has (on macOS and Windows too) or that a user sets by hand without
/// harm. Every other key is refused: many make git run a program or write a
/// file (`gc.recentObjectsHook`, `http.cookieFile`, `filter.*`, ...), and
/// git keeps adding more.
fn is_allowed_local_git_config_key(key: &str) -> bool {
    let key = key.trim().to_ascii_lowercase();
    let (section, rest) = key.split_once('.').unwrap_or((key.as_str(), ""));
    // `branch.<name>.merge`: the name may hold dots, the leaf cannot.
    let (name, leaf) = match rest.rsplit_once('.') {
        Some((name, leaf)) => (Some(name).filter(|name| !name.is_empty()), leaf),
        None => (None, rest),
    };
    match (section, name) {
        ("core", None) => matches!(
            leaf,
            "repositoryformatversion"
                | "filemode"
                | "bare"
                | "logallrefupdates"
                | "ignorecase"
                | "precomposeunicode"
                | "symlinks"
        ),
        // Written by `git clone` with newer defaults (reftable, SHA-256).
        ("extensions", None) => matches!(leaf, "objectformat" | "refstorage"),
        ("remote", Some(_)) => matches!(leaf, "url" | "fetch" | "tagopt"),
        ("branch", Some(_)) => matches!(leaf, "remote" | "merge" | "rebase"),
        ("user", None) => matches!(leaf, "name" | "email"),
        // meow never pulls; git's own advice has users set these.
        ("pull", None) => matches!(leaf, "rebase" | "ff"),
        // meow passes `-c gc.auto=0` itself.
        ("gc", None) => leaf == "auto",
        // Written by `git maintenance register` (or `start`): meow passes
        // `-c maintenance.auto=false` itself and never runs maintenance.
        ("maintenance", None) => matches!(leaf, "auto" | "strategy"),
        _ => false,
    }
}

fn audit_local_git_config(dir: &Path) -> Result<()> {
    let safe_dir = sanitize(&dir.display().to_string(), 400);
    // Read as a file: `.git/config` alone, its includes not followed.
    let keys = git(
        dir,
        &[
            "config",
            "--file",
            ".git/config",
            "--no-includes",
            "--name-only",
            "--list",
        ],
    )
    .with_context(|| format!("cannot audit local .git/config in {safe_dir}"))?;
    for key in keys.lines() {
        if !is_allowed_local_git_config_key(key) {
            bail!(
                "refusing unsafe local .git/config setting '{}' in {safe_dir}: \
                 meow allows only the settings a plain clone has",
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

/// `-c` settings that keep git from reaching a remote. A promisor remote
/// is otherwise fetched from as soon as an object is missing (a sparse
/// index with a tree left out is enough), with the repository's
/// `core.sshCommand` or credential helper. A repository's
/// `protocol.<name>.allow` beats `protocol.allow`, so each name git knows
/// is named; [`NO_TRANSPORT`] covers the rest.
const NO_REMOTES: &[&str] = &[
    "protocol.allow=never",
    "protocol.file.allow=never",
    "protocol.ssh.allow=never",
    "protocol.https.allow=never",
    "protocol.http.allow=never",
    "protocol.ftp.allow=never",
    "protocol.ftps.allow=never",
    "protocol.git.allow=never",
    "protocol.ext.allow=never",
    "protocol.fd.allow=never",
    "core.sshCommand=",
    "credential.helper=",
];

/// `GIT_ALLOW_PROTOCOL` for a git that must reach no remote: it allows
/// only the transports it names, and no transport has this name. It beats
/// every `protocol.<name>.allow`, also that of a remote helper
/// (`<name>::<url>` runs `git-remote-<name>`, whatever the name), and every
/// git has it, also one too old for `GIT_NO_LAZY_FETCH`.
const NO_TRANSPORT: &str = "/";

/// Keeps the git of `cmd` from reaching any remote, whatever the
/// repository's own config says.
fn reach_no_remote(cmd: &mut Command) {
    cmd.env("GIT_ALLOW_PROTOCOL", NO_TRANSPORT);
    for setting in NO_REMOTES {
        cmd.arg("-c").arg(setting);
    }
}

fn configure_git_command(cmd: &mut Command, hooks_dir: &Path) {
    for var in GIT_ENV_SCRUB {
        cmd.env_remove(var);
    }
    if let Some(path) = sanitized_path_env() {
        cmd.env("PATH", path);
    } else {
        cmd.env_remove("PATH");
    }
    // No object is fetched unasked (see `NO_REMOTES`), and git never asks
    // for a password on the terminal.
    cmd.env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
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
        .arg("protocol.git.allow=never")
        // `git fetch` and `git merge` would otherwise start `git maintenance`
        // and `git gc`, which run commands from the config. These win over
        // the checkout's keys of the same name, but not over a URL-scoped
        // `http.<url>.cookieFile`: git picks the closest URL first. The
        // allow-list, which takes no `http.*` key, is what blocks those.
        .arg("-c")
        .arg("maintenance.auto=false")
        .arg("-c")
        .arg("gc.auto=0")
        .arg("-c")
        .arg("http.saveCookies=false")
        .arg("-c")
        .arg("http.cookieFile=");
}

/// Runs git in `dir` with hooks and fsmonitor disabled and returns its trimmed standard output.
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = git_output(dir, args)?;
    Ok(String::from_utf8_lossy(&output).trim().to_owned())
}

/// [`git`], returning the standard output as git wrote it.
pub(crate) fn git_output(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    let empty_hooks = tempfile::tempdir().context("cannot create temporary hooks folder")?;
    #[cfg(windows)]
    let hooks_path = empty_hooks.path();
    #[cfg(not(windows))]
    let hooks_path = Path::new("/dev/null");

    let mut cmd = Command::new(resolve_git()?);
    configure_git_command(&mut cmd, hooks_path);
    // Every call made this way reads only what is on disk.
    reach_no_remote(&mut cmd);
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
    Ok(output.stdout)
}

/// Why [`git_output_pinned`] has no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoAnswer {
    /// git is not there, or was not started: the session is closing.
    NotStarted,
    /// git failed, or was killed as the session closed.
    Failed,
    /// git ran past its time, and was killed with what it started.
    TimedOut,
}

/// Where [`git_output_pinned`] runs git.
#[derive(Clone, Copy)]
pub(crate) enum GitRuns<'a> {
    /// As a tree of its own in a session's tracker: killed with what it
    /// started at its time, or when the tracker closes.
    Tracked(&'a crate::procs::Tracker),
    /// For a check made while meow itself waits in the terminal: a Ctrl-C
    /// there ends git with meow. On Unix git is in meow's own process
    /// group (one of its own would not get the Ctrl-C, and would outlive
    /// meow), and is killed alone at its time: run this way, with no hook,
    /// fsmonitor or transport, it starts no program. On Windows it is a
    /// job of its own, which ends with meow.
    Foreground,
}

/// The git variables that change how a pathspec is read: meow's pathspecs
/// say how they are to be read themselves.
const PATHSPEC_ENV: &[&str] = &[
    "GIT_LITERAL_PATHSPECS",
    "GIT_GLOB_PATHSPECS",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
];

/// [`git_output`] in the work tree `top` of a repository meow did not vet
/// (the folder a session is saved in): git is pointed at `top/.git` and
/// `top` itself, so no repository in a folder below can stand in for it,
/// it reaches no remote ([`reach_no_remote`]) and takes no bare repository
/// it was not pointed at. It runs as `runs` says, and is killed at
/// `until`. Paths in `args` are relative to `top`. `read` is given what
/// git prints, as git prints it, on a thread of its own; its result is
/// the answer, if git ends well by `until`.
pub(crate) fn git_output_pinned<T: Send + 'static>(
    top: &Path,
    args: &[&str],
    until: Instant,
    runs: GitRuns<'_>,
    read: impl FnOnce(&mut dyn Read) -> std::io::Result<T> + Send + 'static,
) -> Result<T, NoAnswer> {
    #[cfg(windows)]
    let empty_hooks = tempfile::tempdir().map_err(|_| NoAnswer::NotStarted)?;
    #[cfg(windows)]
    let hooks_path = empty_hooks.path();
    #[cfg(not(windows))]
    let hooks_path = Path::new("/dev/null");

    let top = git_path(top);
    let mut git_dir = std::ffi::OsString::from("--git-dir=");
    git_dir.push(top.join(".git"));
    let mut work_tree = std::ffi::OsString::from("--work-tree=");
    work_tree.push(&top);
    let mut cmd = Command::new(resolve_git().map_err(|_| NoAnswer::NotStarted)?);
    configure_git_command(&mut cmd, hooks_path);
    for var in PATHSPEC_ENV {
        cmd.env_remove(var);
    }
    reach_no_remote(&mut cmd);
    cmd.arg("-c").arg("safe.bareRepository=explicit");
    cmd.arg("-C")
        .arg(&top)
        .arg(git_dir)
        .arg(work_tree)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    output_until(&mut cmd, until, runs, read)
}

/// Starts `cmd` as `runs` says: the child, and the tree it leads when it
/// has one.
fn start_pinned(
    cmd: &mut Command,
    runs: GitRuns<'_>,
) -> std::io::Result<(std::process::Child, Option<crate::procs::Group>)> {
    match runs {
        GitRuns::Tracked(tracker) => tracker
            .spawn_std(cmd)
            .map(|(child, group)| (child, Some(group))),
        #[cfg(windows)]
        GitRuns::Foreground => crate::procs::Tracker::new()
            .spawn_std(cmd)
            .map(|(child, group)| (child, Some(group))),
        #[cfg(not(windows))]
        GitRuns::Foreground => cmd.spawn().map(|child| (child, None)),
    }
}

/// Runs `cmd` as `runs` says and gives what it prints to `read`; its
/// result, if `cmd` ends well by `until`. Otherwise `cmd` is killed, with
/// its tree when it has one.
fn output_until<T: Send + 'static>(
    cmd: &mut Command,
    until: Instant,
    runs: GitRuns<'_>,
    read: impl FnOnce(&mut dyn Read) -> std::io::Result<T> + Send + 'static,
) -> Result<T, NoAnswer> {
    let (mut child, group) = start_pinned(cmd, runs).map_err(|_| NoAnswer::NotStarted)?;
    let (sent, printed) = std::sync::mpsc::channel();
    if let Some(mut stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let _ = sent.send(read(&mut stdout));
        });
    }
    let ended = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => break Err(NoAnswer::TimedOut),
            Err(_) => break Err(NoAnswer::Failed),
        }
    };
    if ended.is_err() {
        if let Some(group) = &group {
            group.kill();
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    // What it started and left running goes with it, and so does the
    // last holder of its output.
    drop(group);
    let status = ended?;
    let wait = until
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(200));
    let answer = match printed.recv_timeout(wait) {
        Ok(Ok(answer)) => answer,
        Ok(Err(_)) => return Err(NoAnswer::Failed),
        Err(_) => return Err(NoAnswer::TimedOut),
    };
    if !status.success() {
        return Err(NoAnswer::Failed);
    }
    Ok(answer)
}

/// `path` as git reads it: on Windows without the `\\?\` that
/// `fs::canonicalize` puts before a drive letter.
fn git_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let mut components = path.components();
        if let Some(Component::Prefix(prefix)) = components.next() {
            if let Prefix::VerbatimDisk(drive) = prefix.kind() {
                let mut plain = std::ffi::OsString::from(format!("{}:", char::from(drive)));
                plain.push(components.as_path());
                return PathBuf::from(plain);
            }
        }
    }
    path.to_path_buf()
}

/// Like [`git`], but git talks to the terminal (progress, what ssh asks;
/// git itself asks for no password) and nothing is captured.
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

/// meow's own folder for cargo to build updates in, `build` in meow's
/// folder (`~/.meow`): kept from one update to the next, so each builds
/// only what changed, and on the user's own disk (a temporary folder may
/// run no programs, may be memory, and was left full when an update was
/// stopped). cargo links what it finds there into meow, so it and meow's
/// folder must be this user's alone ([`not_own`]), checked each time.
#[cfg(unix)]
fn build_dir(home: &crate::workspace::MeowHome) -> Result<PathBuf> {
    let dir = home.root().join("build");
    crate::workspace::create_private_dir(&dir).context("cannot make a folder to build in")?;
    // meow's folder as it really is: it may be a link the user made.
    let root = std::fs::canonicalize(home.root())
        .with_context(|| format!("cannot resolve {}", home.root().display()))?;
    for path in [root.clone(), root.join("build")] {
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect {}", path.display()))?;
        if let Some(problem) = not_own(&path, &meta) {
            bail!(
                "{} {problem}, so meow does not build in it",
                sanitize(&path.display().to_string(), 400)
            );
        }
    }
    Ok(root.join("build"))
}

/// Whether `name` is that of a build folder older meow versions made in
/// the system's temporary folder: `meow-build-` and six letters or digits.
#[cfg(any(unix, test))]
fn is_old_build_dir_name(name: &str) -> bool {
    name.strip_prefix("meow-build-")
        .is_some_and(|rest| rest.len() == 6 && rest.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Removes from `tmp` the build folders older meow versions left there when
/// an update was stopped: only real folders named as they named them
/// ([`is_old_build_dir_name`]), this user's and private (`0700`) as they
/// made them. Links are never followed, and what cannot be removed stays.
#[cfg(unix)]
fn remove_old_build_dirs(tmp: &Path) {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: this call has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    let Ok(entries) = std::fs::read_dir(tmp) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_str()
            .is_some_and(is_old_build_dir_name)
        {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_dir() && meta.uid() == me && meta.mode() & 0o7777 == 0o700 {
            // Does not follow links inside either.
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// `sh install.sh --yes` in `dir`, with cargo building in `target`: a
/// `--path` install otherwise builds in the folder's own `./target`, which
/// git does not track, so no check covers it, and a shared group can
/// write to it (a planted build output would be linked into meow).
#[cfg(unix)]
fn install_command(dir: &Path, target: &Path) -> Command {
    let mut cmd = Command::new(resolve_sh());
    if let Some(path) = sanitized_path_env() {
        cmd.env("PATH", path);
    } else {
        cmd.env_remove("PATH");
    }
    cmd.arg("install.sh")
        .arg("--yes")
        .env("MEOW_NO_SUDO", "1")
        .env("CARGO_TARGET_DIR", target)
        .env_remove("CARGO_BUILD_TARGET_DIR")
        .current_dir(dir);
    cmd
}

/// Lists local changes. Nested repositories are left alone: `git status`
/// would run their own git config.
const LOCAL_CHANGES: &[&str] = &[
    "status",
    "--porcelain",
    "--untracked-files=no",
    "--ignore-submodules=all",
];

/// A submodule has a git config of its own that is never audited, and `git
/// status` in the checkout runs it. meow's tree has none. Other repositories
/// below the top (no gitlink), such as `git worktree add` folders, are fine:
/// no git call here reads their config.
fn refuse_submodules(dir: &Path) -> Result<()> {
    let safe_dir = sanitize(&dir.display().to_string(), 400);
    let index = git(dir, &["ls-files", "--stage"])?;
    if let Some(line) = index.lines().find(|line| line.starts_with("160000 ")) {
        let path = line.split_once('\t').map_or("", |(_, path)| path);
        bail!(
            "refusing to update {safe_dir}: it has a submodule at '{}'",
            sanitize(path, 200)
        );
    }
    Ok(())
}

/// With `.git/commondir`, git takes the config, objects and refs from the
/// folder it names, which the ownership checks never see. A plain clone
/// has none.
fn refuse_shared_git_dir(dir: &Path) -> Result<()> {
    if std::fs::symlink_metadata(dir.join(".git").join("commondir")).is_ok() {
        bail!(
            "refusing to update {}: its .git/commondir makes git use another folder's settings",
            sanitize(&dir.display().to_string(), 400)
        );
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
    update(
        args,
        crate::workspace::MeowHome::from_env,
        &std::env::temp_dir(),
    )
}

/// [`run`], with meow's own folder given by `home` once a build needs it,
/// and `tmp` the temporary folder older versions built in.
fn update(
    args: &UpdateArgs,
    home: impl FnOnce() -> Result<crate::workspace::MeowHome>,
    tmp: &Path,
) -> Result<ExitCode> {
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
    refuse_submodules(&dir)?;
    audit_untracked_build_overrides(&dir)?;
    println!("[+] meow source: {safe_dir}");

    let changed = git(&dir, LOCAL_CHANGES)?;
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
    // The remote the branch is configured to pull from. Taking it from the
    // tracking ref's name ("origin/main") would let a branch whose remote is
    // another one, with a refspec that writes to origin's refs, be checked
    // as origin and fetched from elsewhere.
    let branch = git(&dir, &["symbolic-ref", "--quiet", "--short", "HEAD"])
        .context("the folder is not on a branch")?;
    let remote_owned = git(
        &dir,
        &[
            "for-each-ref",
            "--format=%(upstream:remotename)",
            "--",
            &format!("refs/heads/{branch}"),
        ],
    )?;
    let remote_name = remote_owned.trim();
    if remote_name.is_empty() || !upstream.starts_with(&format!("{remote_name}/")) {
        bail!(
            "the branch's remote does not match its upstream {}; check `git remote -v` and the branch's settings",
            sanitize(&upstream, 120)
        );
    }
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
        // What was fetched and checked above, merged without contacting
        // anything again: a `git pull` would fetch once more, from whatever
        // remote the branch's settings name.
        git(&dir, &["merge", "--ff-only", "--quiet", "@{u}"]).context(
            "the update could not fast-forward; the folder's branch has its own commits",
        )?;
    }

    verify_checkout_security(&dir, explicit_source)?;
    // build.rs runs git as well.
    ensure_own_checkout(&dir)?;
    audit_untracked_build_overrides(&dir)?;
    install_pulled(&dir, &safe_dir, home, tmp)
}

/// Windows: a running program cannot be replaced, so the user runs the
/// installer once meow is closed.
#[cfg(windows)]
fn install_pulled(
    _dir: &Path,
    safe_dir: &str,
    _home: impl FnOnce() -> Result<crate::workspace::MeowHome>,
    _tmp: &Path,
) -> Result<ExitCode> {
    println!(
        "[+] Pulled. Close meow, then run in PowerShell: & \"{safe_dir}\\install.ps1\" -Yes  (or: cargo install --path \"{safe_dir}\" --locked)"
    );
    Ok(ExitCode::SUCCESS)
}

/// Runs the pulled checkout's `install.sh`, which builds meow in meow's
/// own build folder ([`build_dir`]) and installs it.
#[cfg(unix)]
fn install_pulled(
    dir: &Path,
    _safe_dir: &str,
    home: impl FnOnce() -> Result<crate::workspace::MeowHome>,
    tmp: &Path,
) -> Result<ExitCode> {
    let build = build_dir(&home()?)?;
    remove_old_build_dirs(tmp);
    println!("[+] Rebuilding with install.sh");
    let status = install_command(dir, &build)
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

#[cfg(not(any(unix, windows)))]
fn install_pulled(
    _dir: &Path,
    safe_dir: &str,
    _home: impl FnOnce() -> Result<crate::workspace::MeowHome>,
    _tmp: &Path,
) -> Result<ExitCode> {
    bail!("meow cannot rebuild itself here; run install.sh in {safe_dir}")
}

/// Repositories prepared to make git run a program of theirs, for tests.
#[cfg(all(test, unix))]
pub(crate) mod git_traps {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// git for a test, without system or global config: its standard
    /// output.
    pub(crate) fn git(dir: &Path, args: &[&str]) -> String {
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
                "commit.gpgsign=false",
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
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// Makes `dir` a repository (`top/f` and `c/d/f` committed, with
    /// whatever else is in it) whose index is a sparse index without the
    /// tree of `c`, and which takes missing objects from a promisor remote
    /// over ssh, through a `core.sshCommand` that adds a line to `marker`.
    /// Plain `git ls-files` there runs that command.
    pub(crate) fn lazy_fetch_trap(dir: &Path, marker: &Path) {
        std::fs::create_dir_all(dir.join("top")).unwrap();
        std::fs::create_dir_all(dir.join("c").join("d")).unwrap();
        std::fs::write(dir.join("top").join("f"), "t\n").unwrap();
        std::fs::write(dir.join("c").join("d").join("f"), "x\n").unwrap();
        git(dir, &["init", "-q"]);
        git(dir, &["add", "."]);
        git(dir, &["commit", "-qm", "trap"]);
        git(
            dir,
            &["sparse-checkout", "set", "--cone", "--sparse-index", "top"],
        );
        let tree = git(dir, &["rev-parse", "HEAD:c"]);
        let object = dir
            .join(".git")
            .join("objects")
            .join(&tree[..2])
            .join(&tree[2..]);
        std::fs::remove_file(object).unwrap();
        let command = format!("echo ran >> '{}'; false", marker.display());
        for (key, value) in [
            ("core.repositoryformatversion", "1"),
            ("extensions.partialclone", "origin"),
            ("remote.origin.url", "ssh://example.invalid/x.git"),
            ("remote.origin.promisor", "true"),
            // Beats `protocol.allow=never`.
            ("protocol.ssh.allow", "always"),
            ("core.sshCommand", &command),
        ] {
            git(dir, &["config", key, value]);
        }
    }

    /// Puts in the work tree `dir` a folder `evil` shaped as a bare
    /// repository, with the config and index of a [`lazy_fetch_trap`] and
    /// no objects, as a clone of a hostile repository brings it. Run inside
    /// it, plain git takes it for the repository. Returns it.
    pub(crate) fn embedded_bare_trap(dir: &Path, marker: &Path) -> PathBuf {
        let source = dir.with_extension("source");
        lazy_fetch_trap(&source, marker);
        let evil = dir.join("evil");
        for folder in ["objects", "refs/heads"] {
            std::fs::create_dir_all(evil.join(folder)).unwrap();
            std::fs::write(evil.join(folder).join(".keep"), "").unwrap();
        }
        std::fs::write(evil.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        for name in ["config", "index"] {
            std::fs::copy(source.join(".git").join(name), evil.join(name)).unwrap();
        }
        evil
    }

    /// [`git`] with `input` on its standard input.
    pub(crate) fn git_with_input(dir: &Path, args: &[&str], input: &str) {
        use std::io::Write;
        let mut child = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success(), "git {args:?}");
    }

    /// Makes a FIFO at `path`.
    pub(crate) fn fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a plain system call on a valid C string.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    /// Makes the `core.excludesFile` of the repository in `dir` a FIFO no
    /// one writes to: git listing untracked files waits on it for good.
    /// Returns the FIFO.
    pub(crate) fn blocking_excludes(dir: &Path) -> PathBuf {
        let fifo = dir.join(".git").join("excludes");
        self::fifo(&fifo);
        git(
            dir,
            &["config", "core.excludesFile", fifo.to_str().unwrap()],
        );
        fifo
    }

    /// The process group of a git that runs on the work tree `top`, as
    /// `ps` lists it.
    pub(crate) fn group_of_git_in(top: &Path) -> Option<libc::pid_t> {
        let out = Command::new("ps")
            .args(["-A", "-ww", "-o", "pgid=,args="])
            .output()
            .ok()?;
        let work_tree = format!("--work-tree={}", top.display());
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find(|line| line.contains(&work_tree) && line.contains("ls-files"))
            .and_then(|line| line.split_whitespace().next()?.parse().ok())
    }

    /// Whether a process still has the FIFO `fifo` open to read.
    pub(crate) fn fifo_has_reader(fifo: &Path) -> bool {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(fifo)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`run`], with meow's own folder (`meow-home`) and the temporary
    /// folder older versions built in next to the checkout, in the test's
    /// own folder.
    #[cfg(unix)]
    fn run_here(args: &UpdateArgs) -> Result<ExitCode> {
        let source = args.source.clone().expect("a test names its checkout");
        let tmp = source.parent().unwrap().to_path_buf();
        let home = tmp.join("meow-home");
        update(args, move || crate::workspace::MeowHome::at(home), &tmp)
    }

    /// cargo builds the update in meow's own private folder, never in the
    /// checkout's own `./target`, and the same one each time.
    #[cfg(unix)]
    #[test]
    fn install_sh_builds_in_a_private_folder_of_its_own() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let checkout = tmp.path().join("clone");
        std::fs::create_dir(&checkout).unwrap();
        std::fs::write(
            checkout.join("install.sh"),
            "printf '%s' \"$CARGO_TARGET_DIR\" > built-in\n",
        )
        .unwrap();
        let home = crate::workspace::MeowHome::at(tmp.path().join("meow-home")).unwrap();
        let build = build_dir(&home).unwrap();
        let real_home = std::fs::canonicalize(home.root()).unwrap();
        assert_eq!(build, real_home.join("build"));
        let mode = std::fs::metadata(&build).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let mut command = install_command(&checkout, &build);
        // A target folder from the user's settings does not apply either.
        assert!(command
            .get_envs()
            .any(|(key, value)| key == "CARGO_BUILD_TARGET_DIR" && value.is_none()));
        assert!(command.status().unwrap().success());
        let built_in = std::fs::read_to_string(checkout.join("built-in")).unwrap();
        assert_eq!(built_in, build.display().to_string());
        // What a build left is kept for the next one.
        std::fs::write(build.join("kept"), "x").unwrap();
        assert_eq!(build_dir(&home).unwrap(), build);
        assert!(build.join("kept").exists());
    }

    /// PoC (SUP-4): the build folder was made in the system's temporary
    /// folder and left there, full, when the update was stopped. A folder
    /// others can change, or that is a link, is not built in.
    #[cfg(unix)]
    #[test]
    fn the_build_folder_must_be_the_users_alone() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("meow-home");
        let home = crate::workspace::MeowHome::at(&root).unwrap();
        let build = build_dir(&home).unwrap();
        // Made private again when it is not.
        std::fs::set_permissions(&build, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(build_dir(&home).is_ok());
        let mode = std::fs::metadata(&build).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        // meow's folder that others can change: not built in.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = build_dir(&home).unwrap_err();
        assert!(
            format!("{err:#}")
                .contains("can be changed by other users, so meow does not build in it"),
            "{err:#}"
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A link in place of the build folder: refused, never followed.
        std::fs::remove_dir(&build).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &build).unwrap();
        assert!(build_dir(&home).is_err());
        // meow's folder may be a link the user made to a folder of theirs.
        std::fs::remove_file(&build).unwrap();
        let linked = tmp.path().join("linked-home");
        std::os::unix::fs::symlink(&root, &linked).unwrap();
        let through_link = crate::workspace::MeowHome::at(&linked).unwrap();
        assert_eq!(
            build_dir(&through_link).unwrap(),
            std::fs::canonicalize(&root).unwrap().join("build")
        );
    }

    #[test]
    fn old_build_folders_are_known_by_their_name() {
        for name in [
            "meow-build-EeBX4p",
            "meow-build-O0efPZ",
            "meow-build-abc123",
        ] {
            assert!(is_old_build_dir_name(name), "{name}");
        }
        for name in [
            "meow-build-",
            "meow-build-abc12",
            "meow-build-abc1234",
            "meow-build-abc-12",
            "meow-build-abc.12",
            "meow-build-ab\u{e9}12",
            "xmeow-build-abc123",
            "meow-builds-abc123",
            "build",
        ] {
            assert!(!is_old_build_dir_name(name), "{name}");
        }
    }

    /// Only the user's own private folders named as older versions named
    /// them are removed; links are not followed.
    #[cfg(unix)]
    #[test]
    fn old_build_folders_in_the_temporary_folder_are_removed() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let make = |name: &str, mode: u32| {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(dir.join("release").join("deps")).unwrap();
            std::fs::write(dir.join("release").join("deps").join("libbig.rlib"), "x").unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            dir
        };
        let left = make("meow-build-EeBX4p", 0o700);
        let shared = make("meow-build-Shared", 0o755);
        let other_name = make("meow-build-toolong1", 0o700);
        let not_meow = make("cargo-build-AbC123", 0o700);
        // A link named like one, to a folder of the user's.
        let keep = make("keep", 0o700);
        let link = tmp.path().join("meow-build-Lnk123");
        std::os::unix::fs::symlink(&keep, &link).unwrap();
        // A file named like one.
        let file = tmp.path().join("meow-build-File12");
        std::fs::write(&file, "x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();

        remove_old_build_dirs(tmp.path());
        assert!(!left.exists());
        for kept in [&shared, &other_name, &not_meow, &file] {
            assert!(kept.exists(), "{}", kept.display());
        }
        assert!(std::fs::symlink_metadata(&link).is_ok());
        assert!(keep
            .join("release")
            .join("deps")
            .join("libbig.rlib")
            .exists());
    }

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
            // Not on the old list of refused keys: they run a program,
            // write or read a file, or reach the network.
            "gc.recentobjectshook",
            "gc.autopacklimit",
            "maintenance.repo",
            "maintenance.gc.enabled",
            "maintenance.main.auto",
            "http.cookiefile",
            "http.savecookies",
            "http.https://github.com/.cookiefile",
            "http.lowspeedlimit",
            "http.proxysslcert",
            "fetch.bundleuri",
            "transfer.bundleuri",
            "bundle.list.uri",
            "core.sharedrepository",
            "core.splitindex",
            "extensions.worktreeconfig",
            "extensions.partialclone",
            "remote.origin.promisor",
            "remote.origin.pushurl",
            "branch.main.mergeoptions",
            "user.signingkey",
            // Leaves that are allowed elsewhere, in the wrong place.
            "core",
            "core.url",
            "core.origin.bare",
            "remote.url",
            "remote..url",
            "branch.merge",
            "user.main.name",
        ] {
            assert!(
                !is_allowed_local_git_config_key(unsafe_key),
                "expected {unsafe_key} to be refused"
            );
        }
        for benign_key in [
            "core.repositoryformatversion",
            "core.filemode",
            "core.bare",
            "core.logallrefupdates",
            "core.ignorecase",
            "core.precomposeunicode",
            "core.symlinks",
            "extensions.objectformat",
            "extensions.refstorage",
            "remote.origin.url",
            "remote.origin.fetch",
            "remote.origin.tagopt",
            "remote.my.fork.url",
            "branch.main.remote",
            "branch.main.merge",
            "branch.main.rebase",
            "branch.release/1.0.merge",
            "branch.Feature.remote",
            "user.name",
            "user.email",
            "pull.rebase",
            "pull.ff",
            "gc.auto",
            "maintenance.auto",
            "maintenance.strategy",
        ] {
            assert!(
                is_allowed_local_git_config_key(benign_key),
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
        std::fs::create_dir_all(work.join("src").join("parsers")).unwrap();
        std::fs::write(work.join("src").join("parsers").join("mod.rs"), "\n").unwrap();
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
        let err = run_here(&UpdateArgs {
            check: true,
            source: Some(tmp.path().join("missing")),
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("is not a meow git checkout"));

        // World-writable checkout folder is refused before git runs.
        std::fs::set_permissions(&clone, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = run_here(&UpdateArgs {
            check: false,
            source: Some(clone.clone()),
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("can be changed by other users"));
        std::fs::set_permissions(&clone, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Group write counts unless the group is the user's alone (on
        // macOS every user's group is staff), and so does every file git
        // tracks, every folder it is in, and what git keeps.
        let check_only = || {
            run_here(&UpdateArgs {
                check: true,
                source: Some(clone.clone()),
            })
        };
        let set_mode = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let refused = |what: &Path| {
            let err = check_only().unwrap_err();
            let expected = format!("{} can be changed by other users", what.display());
            assert!(format!("{err:#}").contains(&expected), "{err:#}");
        };
        set_mode(&clone.join("install.sh"), 0o664);
        crate::perms::with_private_group(false, || refused(&clone.join("install.sh")));
        crate::perms::with_private_group(true, || assert!(check_only().is_ok()));
        tighten_tree(&clone);
        let nested = clone.join("src").join("parsers");
        for (path, mode) in [
            (nested.join("mod.rs"), 0o666),
            (nested.clone(), 0o777),
            (clone.join(".git").join("refs").join("heads"), 0o777),
            (clone.join(".git").join("objects"), 0o777),
            (clone.join(".git").join("index"), 0o666),
        ] {
            set_mode(&path, mode);
            refused(&path);
            tighten_tree(&clone);
        }
        let object_folder = std::fs::read_dir(clone.join(".git").join("objects"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.file_name().unwrap().len() == 2)
            .unwrap();
        crate::perms::with_private_group(false, || {
            set_mode(&object_folder, 0o775);
            refused(&object_folder);
        });
        tighten_tree(&clone);

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
        let _ = run_here(&UpdateArgs {
            check: true,
            source: Some(clone.clone()),
        })
        .unwrap();
        assert!(!clone.join("feat.txt").exists());
        assert!(!install_log.exists());

        let _ = run_here(&UpdateArgs {
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

        // The branch pulls from another remote whose refspec writes to
        // origin's refs: `@{u}` still reads origin/main. The update must
        // not take origin's word for it, nor contact the other remote.
        std::fs::write(work.join("feat2.txt"), "ok").unwrap();
        test_git(&work, &["add", "."]);
        test_git(&work, &["commit", "-qm", "feat: two"]);
        test_git(&work, &["push", "-q", "origin", "HEAD:main"]);
        test_git(
            &clone,
            &["remote", "add", "evil", "ftp://127.0.0.1:9/evil.git"],
        );
        test_git(
            &clone,
            &[
                "config",
                "remote.evil.fetch",
                "+refs/heads/*:refs/remotes/origin/*",
            ],
        );
        test_git(&clone, &["config", "branch.main.remote", "evil"]);
        tighten_tree(&clone);
        let err = run_here(&UpdateArgs {
            check: false,
            source: Some(clone.clone()),
        })
        .unwrap_err();
        let said = format!("{err:#}");
        assert!(
            said.contains("does not match its upstream")
                || said.contains("git remote URL")
                || said.contains("ftp"),
            "{said}"
        );
        assert!(!clone.join("feat2.txt").exists(), "nothing was merged");
        test_git(&clone, &["config", "branch.main.remote", "origin"]);
        test_git(&clone, &["remote", "remove", "evil"]);
        tighten_tree(&clone);
        // Back to normal, the checked fetch is merged without a second one.
        let _ = run_here(&UpdateArgs {
            check: false,
            source: Some(clone.clone()),
        })
        .unwrap();
        assert!(clone.join("feat2.txt").exists());

        // Local modifications refuse pulling.
        std::fs::write(clone.join("install.sh"), "echo dirty\n").unwrap();
        let err = run_here(&UpdateArgs {
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
        let err = run_here(&UpdateArgs {
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

    /// Runs git for a test, without system or global config.
    #[cfg(unix)]
    fn repo_git(dir: &Path, args: &[&str]) -> String {
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
                "commit.gpgsign=false",
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
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// Only the owner may write anything under `path`, whatever the umask.
    #[cfg(unix)]
    fn private_tree(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(path).unwrap();
        let mode = meta.permissions().mode();
        if meta.is_dir() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            for entry in std::fs::read_dir(path).unwrap() {
                private_tree(&entry.unwrap().path());
            }
        } else if meta.is_file() {
            let mode = (mode & 0o755) | 0o400;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    /// A bare `origin.git` and `clone`, the checkout to update, which is one
    /// commit behind it. `prepare` runs in the first commit's work tree.
    #[cfg(unix)]
    fn sample_checkout(tmp: &Path, prepare: impl FnOnce(&Path)) -> PathBuf {
        let work = tmp.join("work");
        std::fs::create_dir(&work).unwrap();
        repo_git(&work, &["init", "-q"]);
        std::fs::write(work.join("Cargo.toml"), "[package]\nname = \"meow\"\n").unwrap();
        std::fs::write(work.join("install.sh"), "exit 0\n").unwrap();
        repo_git(&work, &["add", "Cargo.toml", "install.sh"]);
        prepare(&work);
        repo_git(&work, &["commit", "-qm", "initial"]);
        repo_git(tmp, &["clone", "-q", "--bare", "work", "origin.git"]);
        repo_git(tmp, &["clone", "-q", "origin.git", "clone"]);
        std::fs::write(work.join("new.txt"), "new").unwrap();
        repo_git(&work, &["add", "new.txt"]);
        repo_git(&work, &["commit", "-qm", "new"]);
        repo_git(&work, &["push", "-q", "../origin.git", "HEAD:main"]);
        let clone = tmp.join("clone");
        private_tree(&clone);
        clone
    }

    #[cfg(unix)]
    fn set_old_mtime(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000))
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn checkout_config_keys_a_plain_clone_lacks_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let clone = sample_checkout(tmp.path(), |_| {});
        let marker = tmp.path().join("hook-ran");
        let hook = format!("sh -c 'echo ran > \"{}\"; true'", marker.display());
        let victim = tmp.path().join("victim");
        let victim = victim.to_str().unwrap();
        for (key, value) in [
            ("gc.recentObjectsHook", hook.as_str()),
            ("gc.autoPackLimit", "1"),
            ("http.cookieFile", victim),
            ("http.saveCookies", "true"),
            ("http.https://example.invalid/.cookieFile", victim),
            ("http.https://example.invalid/.saveCookies", "true"),
            ("maintenance.repo", "/dev/null"),
            ("core.sharedRepository", "0666"),
            ("branch.main.mergeOptions", "--no-ff"),
        ] {
            repo_git(&clone, &["config", key, value]);
            private_tree(&clone);
            let err = run_here(&UpdateArgs {
                check: true,
                source: Some(clone.clone()),
            })
            .unwrap_err();
            let said = format!("{err:#}");
            // git lists the keys in lower case.
            let shown = key.to_ascii_lowercase();
            assert!(
                said.contains(&format!(
                    "refusing unsafe local .git/config setting '{shown}'"
                )),
                "{key}: {said}"
            );
            repo_git(&clone, &["config", "--unset", key]);
        }
        assert!(!marker.exists());
        assert!(!clone.join("new.txt").exists());

        // What git writes on a clone on macOS and Windows, and the name and
        // address a user may give: the update goes ahead.
        for (key, value) in [
            ("core.ignorecase", "true"),
            ("core.precomposeunicode", "true"),
            ("core.symlinks", "false"),
            ("user.name", "meow-test"),
            ("user.email", "test@example.invalid"),
            ("branch.main.rebase", "false"),
            ("gc.auto", "0"),
            // What `git maintenance register` writes.
            ("maintenance.auto", "false"),
            ("maintenance.strategy", "incremental"),
        ] {
            repo_git(&clone, &["config", key, value]);
        }
        private_tree(&clone);
        let _ = run_here(&UpdateArgs {
            check: true,
            source: Some(clone.clone()),
        })
        .unwrap();
    }

    /// PoC: a checkout's gc.recentObjectsHook ran during `meow update
    /// --check`, through the automatic maintenance `git fetch` and `git
    /// merge` start. And libcurl wrote the cookie jar http.cookieFile names.
    #[cfg(unix)]
    #[test]
    fn git_calls_run_no_automatic_maintenance_and_save_no_cookies() {
        let tmp = tempfile::tempdir().unwrap();
        let clone = sample_checkout(tmp.path(), |_| {});
        // Packs for `gc --auto` to merge, and an old unreachable object.
        for name in ["b.txt", "c.txt"] {
            std::fs::write(clone.join(name), name).unwrap();
            repo_git(&clone, &["add", name]);
            repo_git(&clone, &["commit", "-qm", name]);
            repo_git(&clone, &["repack", "-q"]);
        }
        repo_git(&clone, &["reset", "-q", "--hard", "HEAD~2"]);
        repo_git(&clone, &["reflog", "expire", "--expire=now", "--all"]);
        std::fs::write(tmp.path().join("dangling"), "dangling").unwrap();
        let blob = repo_git(&clone, &["hash-object", "-w", "../dangling"]);
        set_old_mtime(&clone.join(".git/objects").join(&blob[..2]).join(&blob[2..]));
        let marker = tmp.path().join("hook-ran");
        for (key, value) in [
            ("gc.autoPackLimit", "1"),
            ("gc.autoDetach", "false"),
            (
                "gc.recentObjectsHook",
                &format!("sh -c 'echo ran > \"{}\"; true'", marker.display()),
            ),
        ] {
            repo_git(&clone, &["config", key, value]);
        }

        git_live(&clone, true, &["fetch", "--quiet", "--", "origin"]).unwrap();
        assert!(!marker.exists(), "git fetch ran automatic maintenance");
        git(&clone, &["merge", "--ff-only", "--quiet", "@{u}"]).unwrap();
        assert!(!marker.exists(), "git merge ran automatic maintenance");
        assert!(clone.join("new.txt").exists());

        // The settings meow gives git win over the checkout's own.
        for (key, own, forced) in [("gc.auto", "1", "0"), ("maintenance.auto", "true", "false")] {
            repo_git(&clone, &["config", key, own]);
            assert_eq!(git(&clone, &["config", "--get", key]).unwrap(), forced);
        }
        // For http keys git picks the closest URL first, so these win only
        // over the checkout's generic keys. The allow-list refuses all of
        // them, URL-scoped ones included.
        let url = "https://example.invalid/meow.git";
        for (leaf, own, forced) in [
            ("savecookies", "true", "false"),
            ("cookiefile", "/dev/null", ""),
        ] {
            let key = format!("http.{leaf}");
            repo_git(&clone, &["config", &key, own]);
            let used = git(&clone, &["config", "--get-urlmatch", &key, url]).unwrap();
            assert_eq!(used, forced);
            assert!(!is_allowed_local_git_config_key(&key));
            let scoped = format!("http.https://example.invalid/.{leaf}");
            assert!(!is_allowed_local_git_config_key(&scoped));
        }
    }

    /// PoC: a nested repository at a gitlink of the checkout carried its own
    /// config, and `git status` in the checkout ran its clean filter.
    #[cfg(unix)]
    #[test]
    fn a_checkout_with_a_submodule_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("filter-ran");
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        repo_git(&sub, &["init", "-q"]);
        std::fs::write(sub.join(".gitattributes"), "* filter=x\n").unwrap();
        std::fs::write(sub.join("f.txt"), "data\n").unwrap();
        repo_git(&sub, &["add", "."]);
        repo_git(&sub, &["commit", "-qm", "sub"]);
        let sub_head = repo_git(&sub, &["rev-parse", "HEAD"]);
        let clone = sample_checkout(tmp.path(), |work| {
            let gitlink = format!("160000,{sub_head},sub");
            repo_git(work, &["update-index", "--add", "--cacheinfo", &gitlink]);
        });
        // The nested repository where the gitlink is, with a clean filter
        // in its own config and a file git has to filter again.
        repo_git(tmp.path(), &["clone", "-q", "sub", "clone/sub"]);
        let filter = format!("sh -c 'echo ran > \"{}\"; cat'", marker.display());
        repo_git(&clone.join("sub"), &["config", "filter.x.clean", &filter]);
        set_old_mtime(&clone.join("sub/f.txt"));
        private_tree(&clone);

        let err = run_here(&UpdateArgs {
            check: true,
            source: Some(clone.clone()),
        })
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("has a submodule at 'sub'"),
            "{err:#}"
        );
        assert!(!marker.exists(), "the nested repository's filter ran");

        // Should the check be passed, `git status` leaves it alone too.
        git(&clone, LOCAL_CHANGES).unwrap();
        assert!(!marker.exists(), "the nested repository's filter ran");
        // (Without it, git does run the filter: the test is a real one.)
        let unguarded = &LOCAL_CHANGES[..3];
        git(&clone, &[unguarded, &["--ignore-submodules=none"]].concat()).unwrap();
        assert!(marker.exists());
    }

    /// A linked worktree (`git worktree add`, as Claude Code makes under
    /// .claude/worktrees) or another repository below the top, with no
    /// gitlink, is fine: git never reads its config.
    #[cfg(unix)]
    #[test]
    fn repositories_inside_the_checkout_without_a_gitlink_are_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("filter-ran");
        let clone = sample_checkout(tmp.path(), |work| {
            std::fs::create_dir(work.join("docs")).unwrap();
            std::fs::write(work.join("docs/a.md"), "a\n").unwrap();
            repo_git(work, &["add", "docs/a.md"]);
        });
        repo_git(
            &clone,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "feature",
                ".claude/worktrees/feature",
            ],
        );
        // In a tracked folder and in an untracked one: a repository with a
        // clean filter in its own config and a file git would filter again.
        for inner in ["docs", "scratch/inner"] {
            let inner = clone.join(inner);
            std::fs::create_dir_all(&inner).unwrap();
            repo_git(&inner, &["init", "-q"]);
            std::fs::write(inner.join(".gitattributes"), "* filter=x\n").unwrap();
            std::fs::write(inner.join("f.txt"), "data\n").unwrap();
            repo_git(&inner, &["add", ".gitattributes", "f.txt"]);
            repo_git(&inner, &["commit", "-qm", "inner"]);
            let filter = format!("sh -c 'echo ran > \"{}\"; cat'", marker.display());
            repo_git(&inner, &["config", "filter.x.clean", &filter]);
            set_old_mtime(&inner.join("f.txt"));
        }
        set_old_mtime(&clone.join("docs/a.md"));
        private_tree(&clone);

        let _ = run_here(&UpdateArgs {
            check: true,
            source: Some(clone.clone()),
        })
        .unwrap();
        assert!(!marker.exists(), "an inner repository's filter ran");
    }

    /// PoC: with `.git/commondir`, git took the checkout's config, objects
    /// and refs from another folder, which the ownership checks never saw.
    #[cfg(unix)]
    #[test]
    fn a_checkout_whose_git_folder_points_elsewhere_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let clone = sample_checkout(tmp.path(), |_| {});
        let shared = tmp.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        for name in [
            "config",
            "objects",
            "refs",
            "info",
            "hooks",
            "logs",
            "packed-refs",
        ] {
            let from = clone.join(".git").join(name);
            if from.exists() {
                std::fs::rename(&from, shared.join(name)).unwrap();
            }
        }
        std::fs::create_dir(clone.join(".git/refs")).unwrap();
        std::fs::write(clone.join(".git/commondir"), "../../shared\n").unwrap();
        // git does use the other folder's config.
        repo_git(&clone, &["config", "meow.test", "shared"]);
        assert!(std::fs::read_to_string(shared.join("config"))
            .unwrap()
            .contains("test = shared"));
        repo_git(&clone, &["config", "--unset", "meow.test"]);
        private_tree(&clone);
        private_tree(&shared);

        let err = run_here(&UpdateArgs {
            check: true,
            source: Some(clone.clone()),
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains(".git/commondir"), "{err:#}");
    }

    /// PoC (SUP-1): with a promisor remote over ssh and a sparse index
    /// without one of its trees, listing the files made git fetch that
    /// tree with the repository's own `core.sshCommand`. And (its review)
    /// a git too old for `GIT_NO_LAZY_FETCH` still fetched over ftp, or
    /// through a remote helper of any name, that the repository allowed.
    #[cfg(unix)]
    #[test]
    fn git_calls_fetch_nothing_and_run_no_ssh_command() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let marker = tmp.path().join("ran");
        git_traps::lazy_fetch_trap(&repo, &marker);
        let listed = git_output(&repo, &["ls-files", "-z", "--cached"]).unwrap();
        assert!(
            !marker.exists(),
            "meow's git ran the repository's ssh command"
        );
        assert!(String::from_utf8_lossy(&listed).contains("top/f"));
        // A remote helper on PATH, as one a tool installs.
        let bin = tmp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let helper = bin.join("git-remote-meowtrap");
        let script = format!("#!/bin/sh\necho helper >> '{}'\nexit 1\n", marker.display());
        std::fs::write(&helper, script).unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        )))
        .unwrap();
        // meow's settings with lazy fetch left on, as a git older than
        // GIT_NO_LAZY_FETCH has it.
        let plain = |locked: bool| {
            let mut cmd = Command::new("git");
            if locked {
                reach_no_remote(&mut cmd);
            } else {
                cmd.env_remove("GIT_ALLOW_PROTOCOL");
            }
            cmd.arg("-C")
                .arg(&repo)
                .args(["ls-files", "--cached"])
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("PATH", &path)
                .env_remove("GIT_NO_LAZY_FETCH")
                .output()
                .unwrap();
        };
        for (url, transport) in [
            ("ssh://example.invalid/x.git", "ssh"),
            ("ftp://192.0.2.1/x.git", "ftp"),
            ("meowtrap::example.invalid/x", "meowtrap"),
        ] {
            git_traps::git(&repo, &["config", "remote.origin.url", url]);
            let allow = format!("protocol.{transport}.allow");
            git_traps::git(&repo, &["config", &allow, "always"]);
            plain(true);
            assert!(!marker.exists(), "{url}: git reached the remote");
        }
        // Without them git does run the helper: the test is a real one.
        plain(false);
        assert!(marker.exists());
    }

    /// PoC (SUP-V1): git run in a folder below the top of a work tree took
    /// a folder there shaped as a bare repository for the repository, with
    /// its config. Pinned, git asks the top repository only.
    #[cfg(unix)]
    #[test]
    fn pinned_git_uses_the_top_repository_only() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().join("clone");
        let marker = tmp.path().join("ran");
        std::fs::create_dir(&top).unwrap();
        git_traps::git(&top, &["init", "-q"]);
        let evil = git_traps::embedded_bare_trap(&top, &marker);
        std::fs::create_dir_all(evil.join("meow [x]")).unwrap();
        std::fs::write(evil.join("meow [x]").join("f"), "f").unwrap();
        git_traps::git(&top, &["add", "evil/meow [x]/f"]);
        let until = Instant::now() + Duration::from_secs(10);
        let listed = git_output_pinned(
            &top,
            &[
                "--literal-pathspecs",
                "ls-files",
                "-z",
                "--cached",
                "--",
                "evil/meow [x]",
            ],
            until,
            GitRuns::Tracked(&crate::procs::Tracker::new()),
            read_all,
        )
        .unwrap();
        assert_eq!(listed, b"evil/meow [x]/f\0");
        assert!(!marker.exists(), "git used the planted repository");
        // Plain git in the folder does use it: the test is a real one.
        let _ = Command::new("git")
            .arg("-C")
            .arg(&evil)
            .args(["ls-files", "--cached"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(marker.exists());
    }

    /// PoC (SUP-1): with a FIFO as `core.excludesFile`, `git ls-files
    /// --others` waited for good. Pinned, git is killed at its time.
    #[cfg(unix)]
    #[test]
    fn pinned_git_is_killed_at_its_time() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().join("repo");
        std::fs::create_dir(&top).unwrap();
        git_traps::git(&top, &["init", "-q"]);
        let fifo = git_traps::blocking_excludes(&top);
        let tracker = crate::procs::Tracker::new();
        for runs in [GitRuns::Tracked(&tracker), GitRuns::Foreground] {
            let start = Instant::now();
            let got = git_output_pinned(
                &top,
                &["ls-files", "-z", "--others", "--exclude-standard"],
                start + Duration::from_millis(500),
                runs,
                read_all,
            );
            assert_eq!(got, Err(NoAnswer::TimedOut));
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "{:?}",
                start.elapsed()
            );
            assert!(!git_traps::fifo_has_reader(&fifo), "git still runs");
        }
        // A session that ends kills the git it still waits for.
        let tracker = crate::procs::Tracker::new();
        let waiting = {
            let (top, tracker) = (top.clone(), tracker.clone());
            std::thread::spawn(move || {
                git_output_pinned(
                    &top,
                    &["ls-files", "-z", "--others", "--exclude-standard"],
                    Instant::now() + Duration::from_secs(60),
                    GitRuns::Tracked(&tracker),
                    read_all,
                )
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        let start = Instant::now();
        tracker.close();
        assert_eq!(waiting.join().unwrap(), Err(NoAnswer::Failed));
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
        assert!(!git_traps::fifo_has_reader(&fifo), "git still runs");
        // A git that answers in time is not cut short.
        git_traps::git(&top, &["config", "--unset", "core.excludesFile"]);
        std::fs::write(top.join("new"), "x").unwrap();
        let tracker = crate::procs::Tracker::new();
        for runs in [GitRuns::Tracked(&tracker), GitRuns::Foreground] {
            let listed = git_output_pinned(
                &top,
                &["ls-files", "-z", "--others", "--exclude-standard"],
                Instant::now() + Duration::from_secs(10),
                runs,
                read_all,
            );
            assert_eq!(listed, Ok(b"new\0".to_vec()));
        }
    }

    /// PoC (review of SUP-1): run from the terminal before a session
    /// opens, git was a process group of its own, so a Ctrl-C there ended
    /// meow and left git waiting for good. From the terminal it is in
    /// meow's group; in a session, a group of its own.
    #[cfg(unix)]
    #[test]
    fn pinned_git_from_the_terminal_is_in_meows_process_group() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().join("repo");
        std::fs::create_dir(&top).unwrap();
        git_traps::git(&top, &["init", "-q"]);
        // git's own group, read while it waits on the FIFO.
        let group_of = |runs: GitRuns<'_>| {
            let fifo = git_traps::blocking_excludes(&top);
            let watcher = {
                let top = top.clone();
                std::thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let mut found = None;
                    while found.is_none() && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(50));
                        found = git_traps::group_of_git_in(&top);
                    }
                    found
                })
            };
            let got = git_output_pinned(
                &top,
                &["ls-files", "-z", "--others", "--exclude-standard"],
                Instant::now() + Duration::from_millis(1500),
                runs,
                read_all,
            );
            let found = watcher.join().unwrap();
            git_traps::git(&top, &["config", "--unset", "core.excludesFile"]);
            std::fs::remove_file(&fifo).unwrap();
            assert_eq!(got, Err(NoAnswer::TimedOut));
            found.expect("git was not seen waiting")
        };
        // SAFETY: a plain system call about this process.
        let ours = unsafe { libc::getpgid(0) };
        assert_eq!(group_of(GitRuns::Foreground), ours);
        let tracker = crate::procs::Tracker::new();
        assert_ne!(group_of(GitRuns::Tracked(&tracker)), ours);
    }

    #[cfg(unix)]
    fn read_all(out: &mut dyn Read) -> std::io::Result<Vec<u8>> {
        let mut all = Vec::new();
        out.read_to_end(&mut all)?;
        Ok(all)
    }

    /// PoC (SUP-2): `meow update --check` listed the checkout's files with
    /// git before it vetted the checkout's config, so a promisor remote's
    /// `core.sshCommand` ran first. The config is vetted before git reads
    /// anything else.
    #[cfg(unix)]
    #[test]
    fn a_checkouts_config_is_vetted_before_git_lists_its_files() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let clone = tmp.path().join("clone");
        let marker = tmp.path().join("ran");
        std::fs::create_dir(&clone).unwrap();
        std::fs::write(clone.join("Cargo.toml"), "[package]\nname = \"meow\"\n").unwrap();
        git_traps::lazy_fetch_trap(&clone, &marker);
        private_tree(&clone);
        // A tracked file others can change: refused only once git has
        // listed it.
        let shared = clone.join("top").join("f");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = run_here(&UpdateArgs {
            check: true,
            source: Some(clone.clone()),
        })
        .unwrap_err();
        let said = format!("{err:#}");
        assert!(
            said.contains("refusing unsafe local .git/config setting"),
            "{said}"
        );
        assert!(!marker.exists(), "git ran the checkout's ssh command");
    }

    /// cargo and rustup take settings from every folder above the
    /// checkout: one another account owns or can change is refused, and so
    /// is a `.cargo` folder it could put one in.
    #[cfg(unix)]
    #[test]
    fn parent_cargo_settings_others_can_change_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let clone = tmp.path().join("src").join("clone");
        std::fs::create_dir_all(&clone).unwrap();
        let cargo = tmp.path().join(".cargo");
        std::fs::create_dir(&cargo).unwrap();
        let config = cargo.join("config.toml");
        std::fs::write(&config, "").unwrap();
        let set_mode = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        set_mode(&cargo, 0o755);
        set_mode(&config, 0o644);
        audit_untracked_build_overrides(&clone).unwrap();
        for (path, mode, back) in [(&config, 0o666, 0o644), (&cargo, 0o777, 0o755)] {
            set_mode(path, mode);
            let err = audit_untracked_build_overrides(&clone).unwrap_err();
            let expected = format!("{} can be changed by other users", path.display());
            assert!(format!("{err:#}").contains(&expected), "{err:#}");
            set_mode(path, back);
        }
        audit_untracked_build_overrides(&clone).unwrap();
    }

    /// Review (SUP-V2): a `~/.cargo` the user keeps on another disk
    /// through a link of their own stopped every update. Such a link is
    /// taken when what it leads to passes; the settings in it, a link
    /// another user owns, and a link that leads nowhere are still refused.
    #[cfg(unix)]
    #[test]
    fn a_cargo_folder_the_user_links_elsewhere_is_accepted() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let clone = tmp.path().join("home").join("meow");
        std::fs::create_dir_all(&clone).unwrap();
        let target = tmp.path().join("disk").join("cargo-home");
        std::fs::create_dir_all(&target).unwrap();
        let config = target.join("config.toml");
        std::fs::write(&config, "").unwrap();
        let set_mode = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        set_mode(&target, 0o755);
        set_mode(&config, 0o644);
        let link = tmp.path().join("home").join(".cargo");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        audit_untracked_build_overrides(&clone).unwrap();
        let refused = |expected: &str| {
            let said = format!("{:#}", audit_untracked_build_overrides(&clone).unwrap_err());
            assert!(said.contains(expected), "{said}");
        };
        // What the link leads to, and the settings in it.
        set_mode(&target, 0o777);
        let real = std::fs::canonicalize(&target).unwrap();
        refused(&format!(
            "{} leads to {}, which can be changed by other users",
            link.display(),
            real.display()
        ));
        set_mode(&target, 0o755);
        set_mode(&config, 0o666);
        refused(&format!(
            "{} can be changed by other users",
            link.join("config.toml").display()
        ));
        set_mode(&config, 0o644);
        audit_untracked_build_overrides(&clone).unwrap();
        // Only the `.cargo` folder may be a link.
        let elsewhere = tmp.path().join("disk").join("config.toml");
        std::fs::write(&elsewhere, "").unwrap();
        std::fs::remove_file(&config).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &config).unwrap();
        refused(&format!(
            "{} is a symbolic link",
            link.join("config.toml").display()
        ));
        std::fs::remove_file(&config).unwrap();
        audit_untracked_build_overrides(&clone).unwrap();
        // A link another user owns (root may make one here).
        // SAFETY: this call has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::CString::new(link.as_os_str().as_bytes()).unwrap();
            // SAFETY: a plain system call on a valid C string.
            assert_eq!(unsafe { libc::lchown(path.as_ptr(), 4242, 4242) }, 0);
            refused(&format!(
                "{} is a link that belongs to another user",
                link.display()
            ));
        }
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("missing"), &link).unwrap();
        refused(&format!("{} is a link that leads nowhere", link.display()));
    }

    /// Review (SUP-V2): cargo took the workspace, its `[patch]` and its
    /// `Cargo.lock` from a `Cargo.toml` above a checkout whose manifest
    /// has no `[workspace]`. meow's own manifest has one; for one without,
    /// a manifest above that another user can change is refused.
    #[cfg(unix)]
    #[test]
    fn a_manifest_above_counts_only_for_a_checkout_without_its_own_workspace() {
        use std::os::unix::fs::PermissionsExt;
        assert!(is_own_workspace(Path::new(env!("CARGO_MANIFEST_DIR"))));
        let tmp = tempfile::tempdir().unwrap();
        let clone = tmp.path().join("shared").join("meow");
        std::fs::create_dir_all(&clone).unwrap();
        std::fs::write(clone.join("Cargo.toml"), "[package]\nname = \"meow\"\n").unwrap();
        assert!(!is_own_workspace(&clone));
        for name in ["Cargo.toml", "Cargo.lock"] {
            let above = tmp.path().join("shared").join(name);
            std::fs::write(&above, "[workspace]\nmembers = [\"meow\"]\n").unwrap();
            std::fs::set_permissions(&above, std::fs::Permissions::from_mode(0o644)).unwrap();
            audit_untracked_build_overrides(&clone).unwrap();
            std::fs::set_permissions(&above, std::fs::Permissions::from_mode(0o666)).unwrap();
            let said = format!("{:#}", audit_untracked_build_overrides(&clone).unwrap_err());
            let expected = format!("{} can be changed by other users", above.display());
            assert!(said.contains(&expected), "{said}");
            std::fs::set_permissions(&above, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let above = tmp.path().join("shared").join("Cargo.toml");
        std::fs::set_permissions(&above, std::fs::Permissions::from_mode(0o666)).unwrap();
        std::fs::write(
            clone.join("Cargo.toml"),
            "[package]\nname = \"meow\"\n\n[workspace]\n",
        )
        .unwrap();
        assert!(is_own_workspace(&clone));
        audit_untracked_build_overrides(&clone).unwrap();
    }

    /// meow's manifest is a workspace of its own, so cargo takes no
    /// `Cargo.toml`, `Cargo.lock` or `[patch]` from a folder above.
    #[test]
    fn meows_manifest_is_a_workspace_of_its_own() {
        let manifest: toml::Table = toml::from_str(include_str!("../Cargo.toml")).unwrap();
        assert!(manifest.contains_key("workspace"));
    }

    /// Runs icacls (`System32`) on `path` with `args`.
    #[cfg(windows)]
    fn icacls(path: &Path, args: &[&str]) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        let status = Command::new(Path::new(&root).join("System32").join("icacls.exe"))
            .arg(path)
            .args(args)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "icacls {args:?}");
    }

    /// git for a Windows test, without the system's settings.
    #[cfg(windows)]
    fn windows_git(dir: &Path, args: &[&str]) {
        let status = Command::new(resolve_git().unwrap())
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
                "commit.gpgsign=false",
            ])
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    /// PoC (SUP-3): on Windows only the owner of six paths was checked. A
    /// clone under `C:\` lets every account change `.git\config` and any
    /// tracked file while the owner stays the user, and meow then fetched
    /// from the address that account chose.
    #[cfg(windows)]
    #[test]
    fn on_windows_a_checkout_other_accounts_can_change_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let clone = tmp.path().join("clone");
        std::fs::create_dir_all(clone.join("src")).unwrap();
        windows_git(&clone, &["init", "-q"]);
        std::fs::write(clone.join("Cargo.toml"), "[package]\nname = \"meow\"\n").unwrap();
        std::fs::write(clone.join("src").join("main.rs"), "fn main() {}\n").unwrap();
        windows_git(&clone, &["add", "."]);
        windows_git(&clone, &["commit", "-qm", "initial"]);
        ensure_own_checkout(&clone).unwrap();
        let refused = |path: &Path| {
            let said = format!("{:#}", ensure_own_checkout(&clone).unwrap_err());
            let expected = format!("{} can be changed by other accounts", path.display());
            assert!(said.contains(&expected), "{said}");
            assert!(
                said.contains("Clone meow into your user folder and run .\\install.ps1 there"),
                "{said}"
            );
        };
        // A tracked file, and the git settings that name where to fetch.
        let main = clone.join("src").join("main.rs");
        let config = clone.join(".git").join("config");
        for path in [&main, &config] {
            icacls(path, &["/grant", "*S-1-1-0:(M)"]);
            refused(path);
            icacls(path, &["/remove:g", "*S-1-1-0"]);
            ensure_own_checkout(&clone).unwrap();
        }
        // As under C:\: what is in the folder inherits Authenticated
        // Users: Modify, which does not apply to the folder itself.
        icacls(&clone, &["/grant", "*S-1-5-11:(OI)(CI)(IO)(M)"]);
        assert!(ensure_own_checkout(&clone).is_err());
        icacls(&clone, &["/remove:g", "*S-1-5-11"]);
        ensure_own_checkout(&clone).unwrap();
    }

    /// PoC (SUP-V2): any account may make `C:\.cargo\config.toml`, which
    /// `cargo install --path` reads from every folder above the checkout.
    #[cfg(windows)]
    #[test]
    fn on_windows_parent_cargo_settings_other_accounts_can_change_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let clone = tmp.path().join("src").join("clone");
        std::fs::create_dir_all(&clone).unwrap();
        let cargo = tmp.path().join(".cargo");
        std::fs::create_dir(&cargo).unwrap();
        let config = cargo.join("config.toml");
        std::fs::write(&config, "").unwrap();
        audit_untracked_build_overrides(&clone).unwrap();
        for path in [&config, &cargo] {
            icacls(path, &["/grant", "*S-1-5-11:(M)"]);
            let said = format!("{:#}", audit_untracked_build_overrides(&clone).unwrap_err());
            let expected = format!("{} can be changed by other accounts", path.display());
            assert!(said.contains(&expected), "{said}");
            icacls(path, &["/remove:g", "*S-1-5-11"]);
        }
        audit_untracked_build_overrides(&clone).unwrap();
    }

    /// Review (SUP-V2): a `.cargo` the user keeps on another disk through
    /// a junction of their own (`mklink /J`) stopped every update. It is
    /// taken while what it leads to is the user's alone.
    #[cfg(windows)]
    #[test]
    fn on_windows_a_cargo_folder_the_user_links_elsewhere_is_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let clone = tmp.path().join("home").join("meow");
        std::fs::create_dir_all(&clone).unwrap();
        let target = tmp.path().join("disk").join("cargo-home");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("config.toml"), "").unwrap();
        let link = tmp.path().join("home").join(".cargo");
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        let status = Command::new(Path::new(&root).join("System32").join("cmd.exe"))
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J");
        audit_untracked_build_overrides(&clone).unwrap();
        icacls(&target, &["/grant", "*S-1-5-11:(M)"]);
        let said = format!("{:#}", audit_untracked_build_overrides(&clone).unwrap_err());
        assert!(
            said.contains(&format!("{} leads to ", link.display())),
            "{said}"
        );
        assert!(said.contains("can be changed by other accounts"), "{said}");
        icacls(&target, &["/remove:g", "*S-1-5-11"]);
        audit_untracked_build_overrides(&clone).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn on_windows_git_file_names_become_paths() {
        assert_eq!(
            tracked_path(b"src/parsers/mod.rs").unwrap(),
            PathBuf::from(r"src\parsers\mod.rs")
        );
        assert!(tracked_path(b"src/\xff.rs").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn git_is_given_paths_without_the_verbatim_prefix() {
        assert_eq!(
            git_path(Path::new(r"\\?\C:\Users\me\repo")),
            PathBuf::from(r"C:\Users\me\repo")
        );
        assert_eq!(
            git_path(Path::new(r"C:\Users\me\repo")),
            PathBuf::from(r"C:\Users\me\repo")
        );
    }
}

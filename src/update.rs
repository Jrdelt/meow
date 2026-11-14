//! `meow update`: for a meow installed from a GitHub Release, downloads the
//! newest release (`release.rs`). Otherwise pulls the latest meow from
//! GitHub into the folder it was built from, then runs that folder's `install.sh`, which rebuilds meow and
//! adds any tool it now needs. Nothing is pulled while the folder has local
//! changes, and only fast-forward pulls are made.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use anyhow::{bail, Context, Result};

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

fn is_meow_checkout(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("Cargo.toml"))
        .is_ok_and(|manifest| manifest.lines().any(|l| l.trim() == "name = \"meow\""))
        && dir.join(".git").exists()
}

#[cfg(unix)]
const TRUSTED_GIT_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/run/current-system/sw/bin",
];

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
        if let Some(root) = std::env::var_os("SystemRoot") {
            dirs.push(PathBuf::from(root).join("System32"));
        }
        dirs.push(PathBuf::from(r"C:\Program Files\Git\cmd"));
        dirs.push(PathBuf::from(r"C:\Program Files\Git\bin"));
        for dir in dirs {
            let candidate = dir.join("git.exe");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Ok(PathBuf::from("git.exe"))
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
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Validates the upstream git remote URL before fetching. Returns `Ok(true)`
/// if it is a verified local directory (allowed only with explicit `--source`).
fn validate_remote_url(dir: &Path, remote_url: &str, allow_local: bool) -> Result<bool> {
    let url = remote_url.trim();
    if url.is_empty() || url.starts_with('-') {
        bail!("refusing unsafe git remote URL '{url}'");
    }
    if url.starts_with("https://") || url.starts_with("ssh://") || is_scp_git_url(url) {
        return Ok(false);
    }
    if allow_local
        && !url.contains("://")
        && !url.contains("::")
        && (Path::new(url).is_dir() || dir.join(url).is_dir())
    {
        return Ok(true);
    }
    bail!("refusing untrusted git remote URL '{url}' (must use https:// or ssh://)")
}

/// Runs git in `dir` with hooks disabled and returns its trimmed standard output.
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(resolve_git()?)
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("protocol.ext.allow=never")
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
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Like [`git`], but git talks to the terminal (credential prompts,
/// progress) and nothing is captured.
fn git_live(dir: &Path, local_remote: bool, args: &[&str]) -> Result<()> {
    let file_policy = if local_remote {
        "protocol.file.allow=always"
    } else {
        "protocol.file.allow=never"
    };
    let status = Command::new(resolve_git()?)
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("protocol.ext.allow=never")
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

pub fn run(args: &UpdateArgs) -> Result<ExitCode> {
    // Installed from a GitHub Release: download the newest release instead,
    // unless a checkout to update was named.
    let named =
        args.source.is_some() || std::env::var_os(SOURCE_ENV).is_some_and(|v| !v.is_empty());
    if crate::release::BUILD.is_some() && !named {
        return crate::release::run(args.check);
    }
    let dir = source_dir(args.source.as_deref());
    if !is_meow_checkout(&dir) {
        bail!(
            "{} is not a meow git checkout, so there is nothing to pull into. \
             Clone the repository again, run ./install.sh in it, and `meow update` \
             will use that folder from then on (or pass --source <folder>).",
            dir.display()
        );
    }
    println!("[+] meow source: {}", dir.display());

    let changed = git(&dir, &["status", "--porcelain", "--untracked-files=no"])?;
    if !changed.is_empty() {
        bail!(
            "{} has local changes, so nothing was pulled. Commit or discard them first:\n{changed}",
            dir.display()
        );
    }
    let upstream = git(
        &dir,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
    )
    .context("the checked-out branch does not track a branch on GitHub")?;
    let remote_name = upstream.split('/').next().unwrap_or("origin");
    let remote_url = git(
        &dir,
        &["config", "--get", &format!("remote.{remote_name}.url")],
    )
    .with_context(|| format!("cannot read remote URL for {remote_name}"))?;
    let local_remote = validate_remote_url(&dir, &remote_url, args.source.is_some())?;

    println!("[+] Checking {upstream} for changes");
    git_live(&dir, local_remote, &["fetch", "--quiet"])?;
    let incoming = git(&dir, &["log", "--oneline", "--no-decorate", "HEAD..@{u}"])?;
    let head = git(&dir, &["rev-parse", "HEAD"])?;
    let behind_checkout = !BUILT_COMMIT.is_empty() && BUILT_COMMIT != head;

    if incoming.is_empty() && !behind_checkout {
        println!("[+] Already up to date ({} on {upstream})", short(&head));
        return Ok(ExitCode::SUCCESS);
    }
    if incoming.is_empty() {
        println!(
            "[+] Nothing new on GitHub, but this meow was built from {} and the folder is at {}",
            short(BUILT_COMMIT),
            short(&head)
        );
    } else {
        let lines: Vec<&str> = incoming.lines().collect();
        println!("[+] {} new on {upstream}:", lines.len());
        for line in lines.iter().take(20) {
            println!("    {line}");
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

    if cfg!(windows) {
        // A running program cannot be replaced on Windows.
        println!(
            "[+] Pulled. Close meow, then run in PowerShell: & \"{}\\install.ps1\" -Yes  (or: cargo install --path \"{}\" --locked)",
            dir.display(),
            dir.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    println!("[+] Rebuilding with install.sh");
    let status = Command::new(resolve_sh())
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

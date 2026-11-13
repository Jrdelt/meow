//! `meow update`: pulls the latest meow from GitHub into the folder it was
//! built from, then runs that folder's `install.sh`, which rebuilds meow and
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

/// Runs git in `dir` and returns its trimmed standard output.
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
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
fn git_live(dir: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
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

    println!("[+] Checking {upstream} for changes");
    git_live(&dir, &["fetch", "--quiet"])?;
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
        git_live(&dir, &["pull", "--ff-only", "--quiet"])
            .context("the pull could not fast-forward; the folder's branch has its own commits")?;
    }

    if cfg!(windows) {
        // A running program cannot be replaced on Windows.
        println!(
            "[+] Pulled. Close meow, then run: cargo install --path \"{}\" --locked",
            dir.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    println!("[+] Rebuilding with install.sh");
    let status = Command::new("sh")
        .arg("install.sh")
        .arg("--yes")
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

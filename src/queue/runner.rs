//! Running one tool: in its own process group, with `stdin` closed, under a
//! wall-clock limit and an output cap, and stopped when the mode changes or
//! the session closes.

use super::progress::OutputWatch;
use super::*;
use crate::procs::Tracker;

pub use super::progress::OutputKind;

// ---------------------------------------------------------------------------
// Running one tool
// ---------------------------------------------------------------------------

/// How the private folder a tool runs in is named, in the workspace's
/// `tmp/`.
pub(super) const RUN_DIR_PREFIX: &str = "run-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    pub timeout: Duration,
    pub cap_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// The tool exited by itself with this code (`None`: killed by a signal).
    Exited(Option<i32>),
    TimedOut,
    OutputCapExceeded,
    NotInstalled,
    Failed(String),
    /// Stopped by meow because it may no longer run (the mode changed or
    /// the session closed).
    Stopped,
}

/// Environment variables that hold credentials or dangerous dynamic-linker /
/// TLS / shell injection hooks: API keys, tokens, and loader overrides are no
/// business of an external scanner.
pub(super) fn is_secret_variable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL"]
        .iter()
        .any(|word| upper.contains(word))
    {
        return true;
    }
    matches!(
        upper.as_str(),
        "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "LD_AUDIT"
            | "OPENSSL_CONF"
            | "OPENSSL_ENGINES"
            | "OPENSSL_MODULES"
            | "SSL_CERT_FILE"
            | "SSL_CERT_DIR"
            | "NODE_OPTIONS"
            | "GIT_SSH_COMMAND"
            | "BASH_ENV"
            | "ENV"
    ) || upper.starts_with("DYLD_")
}

/// Runs one tool to completion, or stops it at the time or size limit.
///
/// The tool runs in an empty private folder made for this run, not where
/// the session was started: feroxbuster, nmap and katana all read settings
/// or data files from their working directory, and that directory may be
/// one the user did not write (a cloned repository). Variables that look
/// like credentials are not passed on.
pub async fn run_tool(command: &ToolCommand, limits: RunLimits) -> RunOutcome {
    run_tool_while(command, limits, || true).await
}

/// [`run_tool`], stopping the tool (and everything it started) as soon as
/// `may_run` says no. It is asked before the start and every [`CAP_POLL`].
pub async fn run_tool_while(
    command: &ToolCommand,
    limits: RunLimits,
    may_run: impl Fn() -> bool,
) -> RunOutcome {
    let alone = Tracker::new();
    run_tool_watched(command, limits, &alone, may_run, OutputKind::Other, |_| {}).await
}

/// [`run_tool_while`] for a session: the tool is one of `tools`, so it ends
/// with the session however that ends, and `report` is told how far the
/// tool is whenever its output file says something new.
pub async fn run_tool_watched(
    command: &ToolCommand,
    limits: RunLimits,
    tools: &Tracker,
    may_run: impl Fn() -> bool,
    output: OutputKind,
    report: impl Fn(Progress),
) -> RunOutcome {
    if !may_run() {
        return RunOutcome::Stopped;
    }
    // Whatever already sits where the output goes is never written through.
    match std::fs::symlink_metadata(&command.output) {
        Ok(meta) if meta.file_type().is_file() => {
            let _ = std::fs::remove_file(&command.output);
        }
        Ok(_) => {
            return RunOutcome::Failed(format!(
                "{} exists and is not a regular file; refusing to write {}'s output there",
                command.output.display(),
                command.program
            ))
        }
        Err(_) => {}
    }
    let scratch = command.output.parent().and_then(|dir| {
        let mut builder = tempfile::Builder::new();
        builder.prefix(RUN_DIR_PREFIX);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        builder.tempdir_in(dir).ok()
    });
    let Some(scratch) = scratch else {
        return RunOutcome::Failed(format!(
            "cannot make a private folder to run {} in",
            command.program
        ));
    };
    // A configured relative path names a program where meow was started;
    // bare names resolve strictly through absolute `PATH` entries (never a
    // relative `PATH` entry or Windows's parent working directory).
    let program_candidate = if Path::new(&command.program).components().count() > 1
        && Path::new(&command.program).is_relative()
    {
        std::path::absolute(&command.program)
            .ok()
            .and_then(|p| p.to_str().map(str::to_owned))
            .unwrap_or_else(|| command.program.clone())
    } else {
        command.program.clone()
    };
    let Some(program) = crate::tools::find_program(&program_candidate) else {
        return RunOutcome::NotInstalled;
    };
    let mut process = tokio::process::Command::new(program);
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(is_secret_variable) {
            process.env_remove(&name);
        }
    }
    process
        .current_dir(scratch.path())
        .args(&command.args)
        // No terminal input: a tool that asks a question gets EOF instead of
        // hanging the queue.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    // In a group of its own, which is killed whole when `group` is dropped
    // (a cancelled stage) or the session closes.
    let (mut child, group) = match tools.spawn(&mut process) {
        Ok(started) => started,
        Err(_) if tools.is_closed() => return RunOutcome::Stopped,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RunOutcome::NotInstalled
        }
        Err(error) => {
            return RunOutcome::Failed(format!("cannot start {}: {error}", command.program))
        }
    };

    let deadline = tokio::time::sleep(limits.timeout);
    tokio::pin!(deadline);
    let mut poll = tokio::time::interval(CAP_POLL);
    let mut watch = OutputWatch::new(output);
    let size_now = || async {
        tokio::fs::metadata(&command.output)
            .await
            .map(|m| m.len())
            .unwrap_or(0)
    };
    let outcome = loop {
        tokio::select! {
            status = child.wait() => break match status {
                Ok(status) => RunOutcome::Exited(status.code()),
                Err(error) => RunOutcome::Failed(error.to_string()),
            },
            () = &mut deadline => break RunOutcome::TimedOut,
            _ = poll.tick() => {
                if !may_run() {
                    break RunOutcome::Stopped;
                }
                let size = size_now().await;
                if size > limits.cap_bytes {
                    break RunOutcome::OutputCapExceeded;
                }
                if let Some(progress) = watch.look(&command.output, size) {
                    report(progress);
                }
            }
        }
    };
    // A session that closed killed the tool: how it ended says nothing.
    let outcome = if tools.is_closed() {
        RunOutcome::Stopped
    } else {
        outcome
    };
    if !matches!(outcome, RunOutcome::Exited(_)) {
        group.kill();
        let _ = child.kill().await;
    }
    // What the tool wrote between the last look and its end.
    if let Some(progress) = watch.look(&command.output, size_now().await) {
        report(progress);
    }
    outcome
}

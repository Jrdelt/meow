//! Running one tool: in its own process group, with `stdin` closed, under a
//! wall-clock limit and an output cap, and stopped when the mode changes.

use super::*;

// ---------------------------------------------------------------------------
// Running one tool
// ---------------------------------------------------------------------------

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
    /// Stopped by meow because it may no longer run (the mode changed).
    Stopped,
}

/// Kills the whole process group when dropped, so a cancelled stage or a
/// closing session never leaves scanners running.
#[cfg(unix)]
struct GroupGuard(Option<u32>);

#[cfg(unix)]
impl GroupGuard {
    fn kill_all(&self) {
        if let Some(pid) = self.0 {
            // SAFETY: plain syscall; the child was started as the leader of
            // its own process group, so this cannot signal our own group.
            unsafe {
                libc::killpg(pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

#[cfg(unix)]
impl Drop for GroupGuard {
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// A Job Object with kill-on-close: closing the handle ends every process
/// the tool started.
#[cfg(windows)]
struct GroupGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
// SAFETY: a job handle may be used and closed from any thread.
unsafe impl Send for GroupGuard {}

#[cfg(windows)]
impl GroupGuard {
    fn attach(process: std::os::windows::io::RawHandle) -> Option<Self> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        // SAFETY: all pointers are valid for the duration of each call and
        // the structure is plain data that may be zero-initialised.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) != 0;
            if !configured || AssignProcessToJobObject(job, process as _) == 0 {
                CloseHandle(job);
                return None;
            }
            Some(Self(job))
        }
    }

    fn kill_all(&self) {
        // SAFETY: self.0 is a valid Job Object handle owned by this guard.
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0, 1);
        }
    }
}

#[cfg(windows)]
impl Drop for GroupGuard {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this guard and closed exactly once.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
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
        builder.prefix("run-");
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
    #[cfg(unix)]
    process.process_group(0);

    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RunOutcome::NotInstalled
        }
        Err(error) => {
            return RunOutcome::Failed(format!("cannot start {}: {error}", command.program))
        }
    };
    #[cfg(unix)]
    let _group = GroupGuard(child.id());
    #[cfg(windows)]
    let _group = child.raw_handle().and_then(GroupGuard::attach);

    let deadline = tokio::time::sleep(limits.timeout);
    tokio::pin!(deadline);
    let mut poll = tokio::time::interval(CAP_POLL);
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
                let size = tokio::fs::metadata(&command.output).await.map(|m| m.len()).unwrap_or(0);
                if size > limits.cap_bytes {
                    break RunOutcome::OutputCapExceeded;
                }
            }
        }
    };
    if !matches!(outcome, RunOutcome::Exited(_)) {
        #[cfg(unix)]
        _group.kill_all();
        #[cfg(windows)]
        if let Some(group) = &_group {
            group.kill_all();
        }
        let _ = child.kill().await;
    }
    outcome
}

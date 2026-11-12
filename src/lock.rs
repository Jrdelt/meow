//! Crash-safe session lock.
//!
//! One `meow <name>` session owns a workspace at a time. Ownership is an OS
//! kernel advisory lock (`flock` on Unix, `LockFileEx` on Windows) on
//! `session.lock`, so a crash, `kill -9` or power loss releases it
//! automatically: there is no stale lock file to clean up.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use fd_lock::RwLock;

use crate::workspace::private_open_options;

/// Holds the workspace lock until dropped (or until the process dies).
#[derive(Debug)]
pub struct SessionLock {
    /// The kernel lock belongs to this open file and ends when it closes.
    file: RwLock<File>,
}

impl Drop for SessionLock {
    /// Unlocks explicitly instead of relying on the file closing: a child
    /// process forked while the lock was held briefly shares the open file,
    /// which would otherwise keep the lock alive until that child execs.
    fn drop(&mut self) {
        // Re-taking a lock this file already holds succeeds on Unix, and
        // dropping the guard unlocks. On Windows the attempt fails and the
        // lock is released when the handle closes.
        if let Ok(guard) = self.file.try_write() {
            drop(guard);
        }
    }
}

#[derive(Debug)]
pub enum LockError {
    /// Another live process holds the lock. `pid` is best effort: it is
    /// unreadable on Windows while the file is locked.
    Held {
        pid: Option<u32>,
    },
    Io(io::Error),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::Held { pid: Some(pid) } => {
                write!(f, "already open in another meow session (pid {pid})")
            }
            LockError::Held { pid: None } => {
                write!(f, "already open in another meow session")
            }
            LockError::Io(error) => write!(f, "cannot lock the workspace: {error}"),
        }
    }
}

impl std::error::Error for LockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LockError::Io(error) => Some(error),
            LockError::Held { .. } => None,
        }
    }
}

impl SessionLock {
    /// Takes the exclusive lock on `path` without blocking and records this
    /// process id in the file for diagnostics.
    pub fn acquire(path: &Path) -> Result<Self, LockError> {
        let file = private_open_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(LockError::Io)?;
        let mut lock = RwLock::new(file);

        match lock.try_write() {
            Ok(mut guard) => {
                let written = guard
                    .set_len(0)
                    .and_then(|()| writeln!(guard, "{}", std::process::id()))
                    .and_then(|()| guard.flush());
                // Dropping the guard would unlock. Forgetting it keeps the
                // lock tied to the open file, which `SessionLock` now owns.
                std::mem::forget(guard);
                written.map_err(LockError::Io)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(LockError::Held {
                    pid: read_pid(path),
                });
            }
            Err(error) => return Err(LockError::Io(error)),
        }
        Ok(Self { file: lock })
    }
}

fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    const CHILD_LOCK_ENV: &str = "MEOW_TEST_LOCK_FILE";
    const CHILD_TEST: &str = "lock::tests::child_process_holds_the_lock";

    fn lock_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.lock");
        (dir, path)
    }

    #[test]
    fn second_acquire_is_refused_and_names_the_holder() {
        let (_dir, path) = lock_file();
        let held = SessionLock::acquire(&path).unwrap();
        assert_eq!(read_pid(&path), Some(std::process::id()));

        match SessionLock::acquire(&path) {
            Err(LockError::Held { pid }) => {
                // Windows cannot read the locked file, so the pid is optional.
                assert!(pid.is_none() || pid == Some(std::process::id()));
                #[cfg(unix)]
                assert_eq!(pid, Some(std::process::id()));
            }
            other => panic!("expected Held, got {other:?}"),
        }
        drop(held);
    }

    #[test]
    fn dropping_the_lock_releases_it() {
        let (_dir, path) = lock_file();
        for _ in 0..3 {
            let lock = SessionLock::acquire(&path).unwrap();
            assert!(SessionLock::acquire(&path).is_err());
            drop(lock);
        }
        assert!(SessionLock::acquire(&path).is_ok());
    }

    #[test]
    fn leftover_lock_file_from_a_dead_session_is_not_a_lock() {
        let (_dir, path) = lock_file();
        fs::write(&path, "4242\n").unwrap();
        let _lock = SessionLock::acquire(&path).unwrap();
        assert_eq!(read_pid(&path), Some(std::process::id()));
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = lock_file();
        let _lock = SessionLock::acquire(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn errors_read_as_plain_sentences() {
        assert_eq!(
            LockError::Held { pid: Some(7) }.to_string(),
            "already open in another meow session (pid 7)"
        );
        assert_eq!(
            LockError::Held { pid: None }.to_string(),
            "already open in another meow session"
        );
        let (dir, _) = lock_file();
        let missing = dir.path().join("no-such-dir").join("session.lock");
        assert!(matches!(
            SessionLock::acquire(&missing),
            Err(LockError::Io(_))
        ));
    }

    /// Not a test of its own: `killed_holder_releases_the_lock` re-runs this
    /// test binary with `CHILD_LOCK_ENV` set so a separate process holds the
    /// lock. Without the variable it does nothing.
    #[test]
    #[ignore = "helper process for killed_holder_releases_the_lock"]
    fn child_process_holds_the_lock() {
        let Some(path) = std::env::var_os(CHILD_LOCK_ENV) else {
            return;
        };
        let _lock = SessionLock::acquire(Path::new(&path)).unwrap();
        println!("locked");
        std::thread::sleep(Duration::from_secs(60));
    }

    #[test]
    fn killed_holder_releases_the_lock() {
        let (_dir, path) = lock_file();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", CHILD_TEST, "--nocapture"])
            .env(CHILD_LOCK_ENV, &path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let stdout = BufReader::new(child.stdout.take().unwrap());
        let ready = stdout
            .lines()
            .map_while(Result::ok)
            .any(|line| line.contains("locked"));
        assert!(ready, "child never took the lock");

        match SessionLock::acquire(&path) {
            Err(LockError::Held { pid }) => {
                assert!(pid.is_none() || pid == Some(child.id()));
            }
            other => panic!("expected Held while the child lives, got {other:?}"),
        }

        // Hard kill: no destructor runs in the child, the kernel unlocks.
        child.kill().unwrap();
        child.wait().unwrap();
        let _lock = SessionLock::acquire(&path).expect("lock survived its dead holder");
        assert_eq!(read_pid(&path), Some(std::process::id()));
    }
}

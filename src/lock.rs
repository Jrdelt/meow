//! Crash-safe session lock.
//!
//! One `meow <name>` session owns a workspace at a time. Ownership is an OS
//! kernel advisory lock (`flock` on Unix, `LockFileEx` on Windows) on
//! `session.lock`, so a crash, `kill -9` or power loss releases it
//! automatically: there is no stale lock file to clean up.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
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
    /// Another live process holds the lock. `pid` is best effort.
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

fn refused_lock(path: &Path, what: &str) -> LockError {
    LockError::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{} {what}; refusing to use it as a lock file",
            path.display()
        ),
    ))
}

fn refuse_lock_symlink(path: &Path) -> Result<bool, LockError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(refused_lock(path, "is a symbolic link")),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(LockError::Io(error)),
    }
}

fn open_readonly_lock(path: &Path) -> Result<Option<File>, LockError> {
    if !refuse_lock_symlink(path)? {
        return Ok(None);
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Never follow a symbolic link and never wait on a FIFO/device node.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(LockError::Io(error)),
    };
    let meta = file.metadata().map_err(LockError::Io)?;
    if !meta.is_file() {
        return Err(refused_lock(path, "is not a regular file"));
    }
    Ok(Some(file))
}

fn read_pid_from_file(file: &mut File) -> Option<u32> {
    let mut buf = String::new();
    let _ = file.seek(SeekFrom::Start(0));
    if (&*file).take(32).read_to_string(&mut buf).is_err() || buf.trim().is_empty() {
        // On Windows fd-lock holds a mandatory byte-range lock on [0, 1);
        // seeking to byte 1 reads the ASCII PID written past byte 0.
        buf.clear();
        file.seek(SeekFrom::Start(1)).ok()?;
        (&*file).take(32).read_to_string(&mut buf).ok()?;
    }
    buf.trim().parse().ok().filter(|&pid| pid != 0)
}

impl SessionLock {
    /// Takes the exclusive lock on `path` without blocking and records this
    /// process id in the file for diagnostics.
    pub fn acquire(path: &Path) -> Result<Self, LockError> {
        // The file is truncated and written below, so a link in its place
        // (a workspace folder someone else prepared) is never followed: not
        // a symbolic link, and not a second hard link to another file.
        let _ = refuse_lock_symlink(path)?;
        let mut options = private_open_options();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path).map_err(LockError::Io)?;
        let meta = file.metadata().map_err(LockError::Io)?;
        if !meta.is_file() {
            return Err(refused_lock(path, "is not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() > 1 {
                return Err(refused_lock(path, "has a second hard link"));
            }
        }
        let mut lock = RwLock::new(file);
        let mut acquired = false;

        for attempt in 0..3 {
            match lock.try_write() {
                Ok(mut guard) => {
                    // Leading space at byte 0 keeps the ASCII PID outside
                    // fd-lock's mandatory [0, 1) byte-range lock on Windows,
                    // written in a single call so readers never see partial bytes.
                    let line = format!(" {}\n", std::process::id());
                    let written = guard
                        .set_len(0)
                        .and_then(|()| guard.seek(SeekFrom::Start(0)).map(|_| ()))
                        .and_then(|()| guard.write_all(line.as_bytes()))
                        .and_then(|()| guard.flush());
                    if let Err(error) = written {
                        drop(guard);
                        return Err(LockError::Io(error));
                    }
                    // Dropping the guard would unlock. Forgetting it keeps the
                    // lock tied to the open file, which `SessionLock` now owns.
                    std::mem::forget(guard);
                    acquired = true;
                    break;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    if attempt < 2 {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
                Err(error) => return Err(LockError::Io(error)),
            }
        }
        if !acquired {
            let mut file = lock.into_inner();
            return Err(LockError::Held {
                pid: read_pid_from_file(&mut file),
            });
        }
        Ok(Self { file: lock })
    }

    /// True when an exclusive `SessionLock` is currently held on `path`.
    /// Read-only: never creates, truncates or modifies `path`.
    pub fn is_held(path: &Path) -> bool {
        matches!(Self::check_free(path), Err(LockError::Held { .. }))
    }

    /// Fails with [`LockError::Held`] when an exclusive lock is held on `path`,
    /// or [`LockError::Io`] if `path` is a symbolic link or non-regular file.
    /// Never creates, truncates, or writes `path`.
    pub fn check_free(path: &Path) -> Result<(), LockError> {
        let Some(file) = open_readonly_lock(path)? else {
            return Ok(());
        };
        let lock = RwLock::new(file);
        for attempt in 0..3 {
            match lock.try_read() {
                Ok(guard) => {
                    drop(guard);
                    return Ok(());
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    if attempt < 2 {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
                Err(error) => return Err(LockError::Io(error)),
            }
        }
        let mut file = lock.into_inner();
        Err(LockError::Held {
            pid: read_pid_from_file(&mut file),
        })
    }

    /// Reads the PID recorded in a held `session.lock` file, if any.
    pub fn holder_pid(path: &Path) -> Option<u32> {
        match Self::check_free(path) {
            Err(LockError::Held { pid }) => pid,
            _ => None,
        }
    }
}

/// The process id written into the lock file at `path` by whoever took the
/// lock last. Reads past byte 0 so Windows mandatory `[0, 1)` byte-range locks
/// do not block reading the holder PID.
pub fn holder_pid(path: &Path) -> Option<u32> {
    read_pid(path)
}

fn read_pid(path: &Path) -> Option<u32> {
    let mut file = open_readonly_lock(path).ok()??;
    read_pid_from_file(&mut file)
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
        assert!(!SessionLock::is_held(&path));
        assert!(
            !path.exists(),
            "is_held must not create a missing lock file"
        );
        fs::write(&path, "4242\n").unwrap();
        assert!(!SessionLock::is_held(&path));
        let held = SessionLock::acquire(&path).unwrap();
        assert!(SessionLock::is_held(&path));
        assert_eq!(read_pid(&path), Some(std::process::id()));
        drop(held);
        assert!(!SessionLock::is_held(&path));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_in_place_of_the_lock_file_is_never_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.txt");
        fs::write(&outside, "keep me").unwrap();

        // A symbolic link: refused, the file it names keeps its content.
        let path = dir.path().join("session.lock");
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(matches!(SessionLock::acquire(&path), Err(LockError::Io(_))));
        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep me");
        assert!(!SessionLock::is_held(&path));
        fs::remove_file(&path).unwrap();

        // A second hard link to another file: refused before truncating.
        fs::hard_link(&outside, &path).unwrap();
        assert!(matches!(SessionLock::acquire(&path), Err(LockError::Io(_))));
        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep me");
        fs::remove_file(&path).unwrap();

        // An ordinary lock file still works.
        let lock = SessionLock::acquire(&path).unwrap();
        assert!(SessionLock::is_held(&path));
        drop(lock);
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
        assert_eq!(holder_pid(&path), Some(std::process::id()));
        assert_eq!(SessionLock::holder_pid(&path), Some(std::process::id()));
    }

    #[test]
    fn pid_is_written_past_byte_zero_and_zero_pid_is_ignored() {
        let (_dir, path) = lock_file();
        let held = SessionLock::acquire(&path).unwrap();
        // Read past byte 0 while the lock is held, as other processes do.
        assert_eq!(holder_pid(&path), Some(std::process::id()));
        drop(held);
        // The whole file can be read once the lock is gone: on Windows the
        // held lock covers byte 0, so it is checked here, not before.
        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            raw.starts_with(' '),
            "byte 0 must be a space outside Windows [0, 1) lock range: {raw:?}"
        );
        assert_eq!(raw.trim(), std::process::id().to_string());

        fs::write(&path, " 0\n").unwrap();
        assert_eq!(holder_pid(&path), None);
    }

    #[cfg(unix)]
    #[test]
    fn fifo_at_lock_path_never_blocks_acquire_or_checks() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("session.lock");
        let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        assert!(matches!(SessionLock::acquire(&fifo), Err(LockError::Io(_))));
        assert!(matches!(
            SessionLock::check_free(&fifo),
            Err(LockError::Io(_))
        ));
        assert!(!SessionLock::is_held(&fifo));
        assert_eq!(holder_pid(&fifo), None);
        assert_eq!(SessionLock::holder_pid(&fifo), None);
    }
}

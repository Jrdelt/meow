//! The day's cloud AI use of every meow session of this user.
//!
//! The daily caps (`max_daily_usd`, `max_daily_calls`) hold for the user,
//! not for one session folder: each cloud call of any session is set
//! aside in `~/.meow/ai-usage` before it is made (the most it can cost)
//! and settled after (what it cost). What a call set aside is marked with
//! the process that makes it: should that process end first (killed, a
//! crash), the next use of the file settles the call at its input. A day
//! is a calendar day where the user is. The file is private and changed
//! under a lock; when it cannot be read or written, no cloud call is
//! made. Each session's own record (`ai_usage` in its `state.db`) stays,
//! for its reports.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::lock::{LockError, UpdateLock};
use crate::workspace::{read_private_bounded, write_private_atomic};

/// The file's name in meow's own folder.
pub const FILE: &str = "ai-usage";
/// The most the file holds: one day's figures and the calls running.
const MAX_BYTES: u64 = 16 * 1024;
/// The most calls the file marks as running at once.
pub const MAX_HELD: usize = 32;
/// How long a change waits for another meow changing the file. Each one
/// holds it for a read and a write.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// What a day's cloud calls cost, or may still cost, and how many there
/// were.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Day {
    /// `2026-11-21`, where the user is.
    pub day: String,
    /// What the day's calls cost, with what running calls set aside.
    pub usd: f64,
    pub calls: u32,
    /// The calls still running, and what each set aside (in `usd`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held: Vec<Hold>,
}

impl Day {
    /// What running calls have set aside.
    pub fn held_usd(&self) -> f64 {
        self.held.iter().fold(0.0, |sum, hold| sum + hold.usd)
    }

    /// Settles each call whose process has ended at what it is known to
    /// cost: a call cannot go on without it.
    fn release_ended(&mut self) {
        let (ended, running): (Vec<Hold>, Vec<Hold>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|hold| hold.owner.ended());
        self.held = running;
        for hold in ended {
            self.usd = (self.usd - hold.usd + hold.floor.min(hold.usd)).max(0.0);
        }
    }
}

/// What one running request has set aside.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hold {
    /// The request, as its process numbers them.
    pub id: u64,
    /// The process that makes it.
    pub owner: Owner,
    /// What it has cost so far and the most its call can add.
    pub usd: f64,
    /// What it is settled at should its process end first: what it cost
    /// before its call, and that call's input.
    pub floor: f64,
}

/// A process as the record names it: its id, when it started (in the
/// system's own unit, 0 where that is not known), the system start that
/// counts from (Linux) and the set of process ids it is in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    pub pid: u32,
    pub start: u64,
    #[serde(default)]
    pub boot: String,
    #[serde(default)]
    pub space: String,
}

static THIS_PROCESS: LazyLock<Owner> = LazyLock::new(process::this);

impl Owner {
    /// This process.
    pub fn this() -> Owner {
        THIS_PROCESS.clone()
    }

    /// Whether the process has ended, or its id names another one now.
    /// `false` where that cannot be told: what it set aside then stays.
    pub fn ended(&self) -> bool {
        let known = |a: &str, b: &str| !a.is_empty() && a != "-" && !b.is_empty() && b != "-";
        let this = &*THIS_PROCESS;
        if known(&self.space, &this.space) && self.space != this.space {
            return false;
        }
        if known(&self.boot, &this.boot) && self.boot != this.boot {
            return true;
        }
        process::ended(self)
    }
}

/// The day-wide record, kept at one path.
#[derive(Debug, Clone)]
pub struct Ledger {
    path: PathBuf,
}

impl Ledger {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Today's use so far, by every session. Calls whose process has
    /// ended count at what they are known to cost.
    pub fn today(&self) -> Result<Day> {
        let mut day = self.read(&today_local())?;
        day.release_ended();
        Ok(day)
    }

    /// Changes today's record under the lock. `change` gets today's use as
    /// it stands, with the calls whose process has ended settled; what it
    /// leaves there is written back.
    pub fn update<T>(&self, change: impl FnOnce(&mut Day) -> T) -> Result<T> {
        let _lock = self.lock()?;
        let mut day = self.read(&today_local())?;
        let before = day.clone();
        day.release_ended();
        let out = change(&mut day);
        if day != before {
            if !valid(&day) {
                bail!(
                    "refusing to write an invalid amount to {}",
                    self.path.display()
                );
            }
            let text = serde_json::to_string(&day)?;
            write_private_atomic(&self.path, format!("{text}\n").as_bytes())?;
        }
        Ok(out)
    }

    /// The record as it stands, for `today`: a record of another day, or
    /// none yet, is a day with nothing used.
    fn read(&self, today: &str) -> Result<Day> {
        let fresh = || Day {
            day: today.to_owned(),
            ..Day::default()
        };
        match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(fresh()),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", self.path.display()))
            }
            Ok(_) => {}
        }
        let text = read_private_bounded(&self.path, MAX_BYTES)?;
        let day: Day = serde_json::from_str(&text)
            .map_err(|_| anyhow!("{} is not a usage record", self.path.display()))?;
        if !valid(&day) {
            bail!("{} holds an invalid amount", self.path.display());
        }
        Ok(if day.day == today { day } else { fresh() })
    }

    fn lock(&self) -> Result<UpdateLock> {
        let mut name = self
            .path
            .file_name()
            .map(|name| name.to_os_string())
            .unwrap_or_else(|| FILE.into());
        name.push(".lock");
        let path = self.path.with_file_name(name);
        UpdateLock::acquire(&path, LOCK_WAIT).map_err(|error| match error {
            LockError::Held { .. } => anyhow!(
                "another meow is still changing {}; try again",
                self.path.display()
            ),
            LockError::Io(error) => {
                anyhow!(error).context(format!("cannot lock {}", path.display()))
            }
        })
    }
}

/// Whether every amount of a record is a number, none below 0, and no
/// more calls are marked running than [`MAX_HELD`].
fn valid(day: &Day) -> bool {
    let amount = |usd: f64| usd.is_finite() && usd >= 0.0;
    amount(day.usd)
        && day.held.len() <= MAX_HELD
        && day
            .held
            .iter()
            .all(|hold| amount(hold.usd) && amount(hold.floor))
}

/// Which process this is, and whether another has ended.
#[cfg(unix)]
mod process {
    use super::Owner;
    use crate::procs::identity;

    pub fn this() -> Owner {
        let pid = std::process::id();
        Owner {
            pid,
            start: libc::pid_t::try_from(pid)
                .ok()
                .and_then(identity::seen)
                .map_or(0, |seen| seen.start),
            boot: identity::boot(),
            space: space(),
        }
    }

    /// The set of process ids this one is in (a container has its own):
    /// an id in a record of another set names no process here.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn space() -> String {
        std::fs::read_link("/proc/self/ns/pid")
            .map(|link| link.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn space() -> String {
        String::new()
    }

    pub fn ended(owner: &Owner) -> bool {
        let Ok(pid) = libc::pid_t::try_from(owner.pid) else {
            return false;
        };
        if pid <= 0 {
            return false;
        }
        // SAFETY: signal 0 sends nothing; it asks whether the process is
        // there.
        if unsafe { libc::kill(pid, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            return true;
        }
        if owner.start == 0 {
            return false;
        }
        match identity::seen(pid) {
            Some(seen) => seen.start != owner.start,
            // Ended, and not yet collected by its parent.
            None => identity::ended(pid).is_some(),
        }
    }
}

/// Which process this is, and whether another has ended.
#[cfg(windows)]
mod process {
    use super::Owner;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, STILL_ACTIVE,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// When a process was made, in the system's time.
    fn made_at(process: HANDLE) -> Option<u64> {
        let mut made = FILETIME::default();
        let (mut ended, mut kernel, mut user) = (made, made, made);
        // SAFETY: `process` is an open process handle with the right to
        // ask this, or the pseudo handle of this process; the four are
        // valid places for the times the call writes.
        let read =
            unsafe { GetProcessTimes(process, &mut made, &mut ended, &mut kernel, &mut user) };
        (read != 0).then(|| (u64::from(made.dwHighDateTime) << 32) | u64::from(made.dwLowDateTime))
    }

    pub fn this() -> Owner {
        Owner {
            pid: std::process::id(),
            // SAFETY: the pseudo handle of this process needs no closing.
            start: made_at(unsafe { GetCurrentProcess() }).unwrap_or(0),
            boot: String::new(),
            space: String::new(),
        }
    }

    pub fn ended(owner: &Owner) -> bool {
        // SAFETY: a plain call; the handle it opens is closed below.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, owner.pid) };
        if process.is_null() {
            // SAFETY: reads this thread's last error. No process has that
            // id; any other failure (no right to ask) cannot tell.
            return unsafe { GetLastError() } == ERROR_INVALID_PARAMETER;
        }
        let made = made_at(process);
        let mut code = 0u32;
        // SAFETY: `process` is open with the right to ask this; `code` is
        // a valid place for the exit code.
        let read = unsafe { GetExitCodeProcess(process, &mut code) };
        // SAFETY: `process` was opened above and is closed once.
        unsafe { CloseHandle(process) };
        (owner.start != 0 && made.is_some_and(|made| made != owner.start))
            || (read != 0 && code != STILL_ACTIVE as u32)
    }
}

/// Elsewhere nothing says whether a process runs: what a call set aside
/// stays until the day ends.
#[cfg(not(any(unix, windows)))]
mod process {
    use super::Owner;

    pub fn this() -> Owner {
        Owner {
            pid: std::process::id(),
            start: 0,
            boot: String::new(),
            space: String::new(),
        }
    }

    pub fn ended(_owner: &Owner) -> bool {
        false
    }
}

/// Today's date where the user is (`2026-11-21`), as the daily caps
/// count days.
pub fn today_local() -> String {
    let now = crate::timeutil::unix_seconds(SystemTime::now());
    local_date(now).unwrap_or_else(crate::timeutil::today_utc)
}

/// The local date at `utc` (seconds since 1970).
#[cfg(unix)]
fn local_date(utc: u64) -> Option<String> {
    let time = libc::time_t::try_from(utc).ok()?;
    // SAFETY: an all-zero `tm` is a valid value of this plain C struct.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are to live values of the right types;
    // `localtime_r` only writes `tm`.
    if unsafe { libc::localtime_r(&time, &mut tm) }.is_null() {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02}",
        i64::from(tm.tm_year) + 1900,
        tm.tm_mon + 1,
        tm.tm_mday
    ))
}

/// The local date at `utc` (seconds since 1970).
#[cfg(windows)]
fn local_date(utc: u64) -> Option<String> {
    let local = local_seconds(utc)?;
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(local);
    Some(crate::timeutil::format_rfc3339(time)[..10].to_owned())
}

/// `utc` (seconds since 1970) as the local clock shows it, counted the
/// same way.
#[cfg(windows)]
fn local_seconds(utc: u64) -> Option<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::Storage::FileSystem::FileTimeToLocalFileTime;
    /// From 1601-01-01 to 1970-01-01, in seconds.
    const EPOCH_GAP: u64 = 11_644_473_600;
    const TICKS: u64 = 10_000_000;
    let ticks = (utc + EPOCH_GAP).checked_mul(TICKS)?;
    let file_time = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut local = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: both pointers are to live FILETIME values; the call only
    // writes `local`.
    if unsafe { FileTimeToLocalFileTime(&file_time, &mut local) } == 0 {
        return None;
    }
    let local = (u64::from(local.dwHighDateTime) << 32) | u64::from(local.dwLowDateTime);
    (local / TICKS).checked_sub(EPOCH_GAP)
}

#[cfg(not(any(unix, windows)))]
fn local_date(_utc: u64) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_record_is_a_day_with_nothing_used() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::at(dir.path().join(FILE));
        let day = ledger.today().unwrap();
        assert_eq!((day.usd, day.calls), (0.0, 0));
        assert_eq!(day.day, today_local());
        assert!(!ledger.path().exists(), "reading writes nothing");
    }

    #[test]
    fn changes_are_kept_for_today_and_forgotten_the_next_day() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::at(dir.path().join(FILE));
        ledger
            .update(|day| {
                day.usd += 0.25;
                day.calls += 2;
            })
            .unwrap();
        let day = ledger.today().unwrap();
        assert_eq!((day.usd, day.calls), (0.25, 2));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(ledger.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Yesterday's record counts for nothing today.
        std::fs::write(
            ledger.path(),
            r#"{"day":"2000-01-01","usd":0.99,"calls":19}"#,
        )
        .unwrap();
        let day = ledger.today().unwrap();
        assert_eq!((day.usd, day.calls), (0.0, 0));
    }

    #[test]
    fn a_record_that_cannot_be_read_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::at(dir.path().join(FILE));
        for text in ["not json", r#"{"day":"x","usd":-1.0,"calls":0}"#] {
            std::fs::write(ledger.path(), text).unwrap();
            assert!(ledger.today().is_err(), "{text}");
            assert!(ledger.update(|day| day.calls += 1).is_err(), "{text}");
        }
        std::fs::remove_file(ledger.path()).unwrap();
        std::fs::create_dir(ledger.path()).unwrap();
        assert!(ledger.today().is_err());
        #[cfg(unix)]
        {
            std::fs::remove_dir(ledger.path()).unwrap();
            let target = dir.path().join("elsewhere");
            std::fs::write(&target, r#"{"day":"x","usd":0.0,"calls":0}"#).unwrap();
            std::os::unix::fs::symlink(&target, ledger.path()).unwrap();
            assert!(ledger.today().is_err(), "a link is not followed");
        }
    }

    /// What a call of `owner` set aside: `usd` in all, `floor` of it
    /// known to be spent.
    fn held_by(owner: Owner, usd: f64, floor: f64) -> Hold {
        Hold {
            id: 7,
            owner,
            usd,
            floor,
        }
    }

    /// A process that has ended, and been collected.
    fn ended_process() -> Owner {
        #[cfg(unix)]
        let mut child = std::process::Command::new("true").spawn().unwrap();
        #[cfg(windows)]
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();
        Owner {
            pid,
            ..Owner::this()
        }
    }

    /// v0.2.6 review AI-4: a call whose process was killed is settled at
    /// what it is known to cost the next time the record is used; one of a
    /// process that runs, or that cannot be told, stays set aside.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn a_call_whose_process_ended_is_settled_at_its_input() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::at(dir.path().join(FILE));
        let this = Owner::this();
        assert!(this.start > 0, "{this:?}");
        assert!(!this.ended());
        let reused = Owner {
            start: this.start + 1,
            ..this.clone()
        };
        // Its start not known: whether it runs cannot be told.
        let unknown = Owner {
            start: 0,
            ..this.clone()
        };
        let mut held = vec![
            held_by(ended_process(), 0.33, 0.01),
            held_by(reused, 0.58, 0.04),
            held_by(this.clone(), 0.20, 0.02),
            held_by(unknown, 0.30, 0.03),
        ];
        // An id of another set of process ids names no process here.
        if cfg!(target_os = "linux") {
            let elsewhere = Owner {
                space: "pid:[1]".into(),
                ..ended_process()
            };
            held.push(held_by(elsewhere, 0.25, 0.05));
        }
        let kept: Vec<Hold> = held[2..].to_vec();
        let record = Day {
            day: today_local(),
            // 0.10 spent by calls that ended, and the calls running.
            usd: 0.10 + held.iter().map(|hold| hold.usd).sum::<f64>(),
            calls: 5,
            held,
        };
        let text = serde_json::to_string(&record).unwrap();
        crate::workspace::write_private_atomic(ledger.path(), text.as_bytes()).unwrap();
        let day = ledger.today().unwrap();
        let kept_usd: f64 = kept.iter().map(|hold| hold.usd).sum();
        assert!(
            (day.usd - (0.10 + 0.01 + 0.04 + kept_usd)).abs() < 1e-9,
            "{day:?}"
        );
        assert_eq!(day.calls, 5);
        assert_eq!(day.held, kept, "{day:?}");
        assert!((day.held_usd() - kept_usd).abs() < 1e-9);
        // Reading changes nothing; the next change writes it.
        assert_eq!(std::fs::read_to_string(ledger.path()).unwrap(), text);
        ledger.update(|_| ()).unwrap();
        let written: Day =
            serde_json::from_str(&std::fs::read_to_string(ledger.path()).unwrap()).unwrap();
        assert_eq!(written, day);
    }

    #[test]
    fn a_record_without_running_calls_reads_as_before() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::at(dir.path().join(FILE));
        let old = format!(r#"{{"day":"{}","usd":0.25,"calls":2}}"#, today_local());
        std::fs::write(ledger.path(), &old).unwrap();
        let day = ledger.today().unwrap();
        assert_eq!((day.usd, day.calls, day.held.len()), (0.25, 2, 0));
        ledger.update(|day| day.calls += 1).unwrap();
        let text = std::fs::read_to_string(ledger.path()).unwrap();
        assert!(!text.contains("held"), "{text}");
        // A running call with an amount that is no number is refused.
        let bad = format!(
            r#"{{"day":"{}","usd":0.25,"calls":2,"held":[{{"id":1,"owner":{{"pid":1,"start":1}},"usd":-1.0,"floor":0.0}}]}}"#,
            today_local()
        );
        std::fs::write(ledger.path(), bad).unwrap();
        assert!(ledger.today().is_err());
    }

    #[test]
    fn today_is_the_local_date_within_a_day_of_utc() {
        let day = |date: &str| {
            crate::timeutil::parse_rfc3339(&format!("{date}T00:00:00Z"))
                .map(crate::timeutil::unix_seconds)
                .unwrap()
        };
        let local = today_local();
        let utc = crate::timeutil::today_utc();
        assert!(day(&local).abs_diff(day(&utc)) <= 86_400, "{local} {utc}");
    }

    #[cfg(windows)]
    #[test]
    fn local_time_on_windows_is_within_a_day_of_utc() {
        let now = crate::timeutil::unix_seconds(SystemTime::now());
        let local = local_seconds(now).unwrap();
        assert!(local.abs_diff(now) <= 14 * 3600, "{local} vs {now}");
    }
}

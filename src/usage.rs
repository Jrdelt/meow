//! The day's cloud AI use of every meow session of this user.
//!
//! The daily caps (`max_daily_usd`, `max_daily_calls`) hold for the user,
//! not for one session folder: each cloud call of any session is set
//! aside in `~/.meow/ai-usage` before it is made (the most it can cost)
//! and settled after (what it cost). A day is a calendar day where the
//! user is. The file is private and changed under a lock; when it cannot
//! be read or written, no cloud call is made. Each session's own record
//! (`ai_usage` in its `state.db`) stays, for its reports.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::lock::{LockError, UpdateLock};
use crate::workspace::{read_private_bounded, write_private_atomic};

/// The file's name in meow's own folder.
pub const FILE: &str = "ai-usage";
/// The most the file holds: one day's figures.
const MAX_BYTES: u64 = 4096;
/// How long a change waits for another meow changing the file. Each one
/// holds it for a read and a write.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// What a day's cloud calls cost, or may still cost, and how many there
/// were.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Day {
    /// `2026-11-21`, where the user is.
    pub day: String,
    pub usd: f64,
    pub calls: u32,
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

    /// Today's use so far, by every session.
    pub fn today(&self) -> Result<Day> {
        self.read(&today_local())
    }

    /// Changes today's record under the lock. `change` gets today's use as
    /// it stands; what it leaves there is written back.
    pub fn update<T>(&self, change: impl FnOnce(&mut Day) -> T) -> Result<T> {
        let _lock = self.lock()?;
        let mut day = self.read(&today_local())?;
        let before = day.clone();
        let out = change(&mut day);
        if day != before {
            if !(day.usd.is_finite() && day.usd >= 0.0) {
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
        if !(day.usd.is_finite() && day.usd >= 0.0) {
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

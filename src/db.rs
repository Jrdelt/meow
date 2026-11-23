//! `state.db`: the workspace's SQLite database.
//!
//! Opened in WAL mode with `synchronous=NORMAL` and a 5 s busy timeout, so
//! the session coordinator and helper subcommands can use it side by side.
//! The schema version lives in `PRAGMA user_version`; each entry of
//! [`MIGRATIONS`] upgrades the database by exactly one version.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rusqlite::{config::DbConfig, Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::workspace::private_open_options;

pub(crate) const BUSY_TIMEOUT: Duration = Duration::from_millis(5000);
const MAX_CVE_CACHE_ROWS: i64 = 4096;

/// Append-only: never edit or reorder an entry that has shipped.
const MIGRATIONS: &[&str] = &[
    // 1: generic key/value settings.
    "CREATE TABLE meta (
         key   TEXT PRIMARY KEY,
         value TEXT NOT NULL
     ) WITHOUT ROWID;",
    // 2: cached CVE lookups (NVD / OSV responses, CISA KEV catalog).
    "CREATE TABLE cve_cache (
         key         TEXT PRIMARY KEY,
         fetched_utc TEXT NOT NULL,
         body        TEXT NOT NULL
     ) WITHOUT ROWID;",
    // 3: background recon queue.
    "CREATE TABLE tasks (
         id          INTEGER PRIMARY KEY AUTOINCREMENT,
         target      TEXT NOT NULL,
         mode        TEXT NOT NULL,
         extra_flags TEXT NOT NULL DEFAULT '[]',
         created_utc TEXT NOT NULL
     );
     CREATE TABLE task_stages (
         task_id      INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
         stage        TEXT NOT NULL,
         position     INTEGER NOT NULL,
         status       TEXT NOT NULL
                      CHECK (status IN ('pending','running','interrupted','done','skipped','failed')),
         detail       TEXT NOT NULL DEFAULT '',
         started_utc  TEXT,
         finished_utc TEXT,
         PRIMARY KEY (task_id, stage)
     ) WITHOUT ROWID;",
    // 4: privacy vault (placeholder <-> real value) and AI accounting.
    "CREATE TABLE vault (
         token    TEXT PRIMARY KEY,
         kind     TEXT NOT NULL,
         value    TEXT NOT NULL UNIQUE,
         exposed  INTEGER NOT NULL DEFAULT 0,
         first_seen_utc TEXT NOT NULL
     ) WITHOUT ROWID;
     CREATE TABLE ai_usage (
         id          INTEGER PRIMARY KEY AUTOINCREMENT,
         day_utc     TEXT NOT NULL,
         tier        TEXT NOT NULL,
         model       TEXT NOT NULL,
         cost_usd    REAL NOT NULL DEFAULT 0,
         web_search_requests INTEGER NOT NULL DEFAULT 0,
         prompt_tokens     INTEGER NOT NULL DEFAULT 0,
         completion_tokens INTEGER NOT NULL DEFAULT 0,
         created_utc TEXT NOT NULL
     );
     CREATE INDEX ai_usage_day ON ai_usage(day_utc);
     CREATE TABLE prompt_cache (
         sha256      TEXT PRIMARY KEY,
         tier        TEXT NOT NULL,
         response    TEXT NOT NULL,
         created_utc TEXT NOT NULL
     ) WITHOUT ROWID;",
    // 5: what each recon stage's own tool reported, for the stages after it.
    "ALTER TABLE task_stages ADD COLUMN found TEXT NOT NULL DEFAULT '';",
    // 6: index for fast unfinished-task and active-stage lookups.
    "CREATE INDEX IF NOT EXISTS idx_task_stages_status ON task_stages(status, task_id);",
];

fn inspect_sqlite_entry(candidate: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(candidate) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("cannot inspect {}", candidate.display()));
        }
    };
    let kind = meta.file_type();
    if kind.is_symlink() {
        bail!(
            "{} is a symbolic link; refusing to open SQLite database",
            candidate.display()
        );
    }
    if !kind.is_file() {
        bail!(
            "{} is not a regular file; refusing to open SQLite database",
            candidate.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            bail!(
                "{} belongs to another user (uid {}); refusing to open SQLite database",
                candidate.display(),
                meta.uid()
            );
        }
        if meta.nlink() > 1 {
            bail!(
                "{} has multiple hard links; refusing to open SQLite database",
                candidate.display()
            );
        }
    }
    Ok(())
}

/// Refuses symbolic links, non-regular files, multi-hardlink files, and
/// foreign-owned files on `path` and its SQLite `-wal`, `-shm`, and `-journal`
/// sidecars.
pub(crate) fn refuse_sqlite_symlinks(path: &Path) -> Result<()> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut raw: OsString = path.as_os_str().to_owned();
        raw.push(suffix);
        inspect_sqlite_entry(&PathBuf::from(raw))?;
    }
    Ok(())
}

/// Applies defensive SQLite flags so untrusted schema objects (triggers/views)
/// cannot invoke unsafe functions or mutate shadow tables.
pub(crate) fn harden_connection(conn: &Connection) -> rusqlite::Result<()> {
    harden(conn)?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(())
}

pub struct Db {
    conn: Connection,
}

/// Settings for a database file that may not be the one meow wrote (a
/// workspace folder can be copied or handed on). meow's schema has no views
/// and no triggers, so neither runs: a file that adds some cannot attach
/// its own statements to meow's, or make a plain count run for ever. The
/// schema itself is not trusted to call functions with side effects.
pub fn harden(conn: &Connection) -> rusqlite::Result<()> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    Ok(())
}

impl Db {
    /// Opens (creating if needed) the database at `path` and migrates it to
    /// the current schema.
    pub fn open(path: &Path) -> Result<Self> {
        refuse_sqlite_symlinks(path)?;
        // Create the file ourselves so it is 0600 from the first byte;
        // SQLite gives the -wal and -shm files the same mode.
        let file = private_open_options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        let meta = file
            .metadata()
            .with_context(|| format!("cannot inspect {}", path.display()))?;
        if !meta.is_file() {
            bail!(
                "{} is not a regular file; refusing to open SQLite database",
                path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // SAFETY: `geteuid` has no preconditions and cannot fail.
            let euid = unsafe { libc::geteuid() };
            if meta.uid() != euid {
                bail!(
                    "{} belongs to another user (uid {}); refusing to open SQLite database",
                    path.display(),
                    meta.uid()
                );
            }
            if meta.nlink() > 1 {
                bail!(
                    "{} has multiple hard links; refusing to open SQLite database",
                    path.display()
                );
            }
            // Operate on the open descriptor (`fchmod`) rather than the path so
            // a concurrent rename cannot redirect the permission change.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("cannot set permissions on {}", path.display()))?;
        }
        drop(file);
        refuse_sqlite_symlinks(path)?;
        let conn =
            Connection::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        Self::init(conn).with_context(|| format!("cannot initialise {}", path.display()))
    }

    /// A private in-memory database, for tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        harden_connection(&conn)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // `journal_mode` returns the resulting mode as a row.
        conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&mut self) -> Result<()> {
        let initial = self.schema_version()? as usize;
        if initial > MIGRATIONS.len() {
            bail!(
                "database schema version {initial} is newer than this build of meow ({})",
                MIGRATIONS.len()
            );
        }
        if initial == MIGRATIONS.len() {
            return Ok(());
        }
        let tx = Transaction::new(&mut self.conn, TransactionBehavior::Immediate)?;
        let current: usize =
            tx.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))? as usize;
        if current > MIGRATIONS.len() {
            bail!(
                "database schema version {current} is newer than this build of meow ({})",
                MIGRATIONS.len()
            );
        }
        for (index, sql) in MIGRATIONS.iter().enumerate().skip(current) {
            tx.execute_batch(sql)
                .with_context(|| format!("migration {} failed", index + 1))?;
            tx.pragma_update(None, "user_version", i64::try_from(index + 1)?)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn schema_version(&self) -> Result<u32> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Cached body for `key`. With `max_age`, only an entry younger than
    /// that is returned; without, any entry (a stale fallback).
    pub fn cache_get(&self, key: &str, max_age: Option<Duration>) -> Result<Option<String>> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT fetched_utc, body FROM cve_cache WHERE key = ?1",
                [key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((fetched, body)) = row else {
            return Ok(None);
        };
        let fresh = match max_age {
            None => true,
            Some(max_age) => crate::timeutil::parse_rfc3339(&fetched)
                .and_then(|at| at.elapsed().ok())
                .is_some_and(|age| age <= max_age),
        };
        Ok(fresh.then_some(body))
    }

    pub fn cache_put(&self, key: &str, body: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO cve_cache (key, fetched_utc, body) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET fetched_utc = excluded.fetched_utc, body = excluded.body",
            [key, &crate::timeutil::now_rfc3339(), body],
        )?;
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM cve_cache", [], |row| row.get(0))?;
        if count > MAX_CVE_CACHE_ROWS {
            let excess = count - MAX_CVE_CACHE_ROWS;
            self.conn.execute(
                "DELETE FROM cve_cache WHERE key IN (
                     SELECT key FROM cve_cache ORDER BY fetched_utc ASC LIMIT ?1
                 )",
                [excess],
            )?;
        }
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pragma(db: &Db, name: &str) -> String {
        db.conn()
            .query_row(&format!("PRAGMA {name}"), [], |row| {
                row.get::<_, rusqlite::types::Value>(0)
            })
            .map(|value| match value {
                rusqlite::types::Value::Integer(i) => i.to_string(),
                rusqlite::types::Value::Text(t) => t,
                other => format!("{other:?}"),
            })
            .unwrap()
    }

    #[test]
    fn opens_with_wal_normal_sync_and_busy_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("state.db")).unwrap();
        assert_eq!(pragma(&db, "journal_mode"), "wal");
        assert_eq!(pragma(&db, "synchronous"), "1"); // NORMAL
        assert_eq!(pragma(&db, "busy_timeout"), "5000");
        assert_eq!(pragma(&db, "foreign_keys"), "1");
        assert_eq!(db.schema_version().unwrap() as usize, MIGRATIONS.len());
    }

    #[test]
    fn reopening_keeps_data_and_does_not_rerun_migrations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let db = Db::open(&path).unwrap();
            assert_eq!(db.get_meta("k").unwrap(), None);
            db.set_meta("k", "one").unwrap();
            db.set_meta("k", "two").unwrap();
        }
        let db = Db::open(&path).unwrap();
        assert_eq!(db.get_meta("k").unwrap().as_deref(), Some("two"));
        assert_eq!(db.schema_version().unwrap() as usize, MIGRATIONS.len());
    }

    #[test]
    fn two_connections_share_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let coordinator = Db::open(&path).unwrap();
        let helper = Db::open(&path).unwrap();
        coordinator.set_meta("mode", "mild").unwrap();
        assert_eq!(helper.get_meta("mode").unwrap().as_deref(), Some("mild"));
        helper.set_meta("mode", "light").unwrap();
        assert_eq!(
            coordinator.get_meta("mode").unwrap().as_deref(),
            Some("light")
        );
    }

    #[test]
    fn cache_entries_expire_but_stay_available_as_stale() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.cache_get("k", None).unwrap(), None);
        db.cache_put("k", "one").unwrap();
        db.cache_put("k", "two").unwrap();
        let hour = Some(Duration::from_secs(3600));
        assert_eq!(db.cache_get("k", hour).unwrap().as_deref(), Some("two"));
        db.conn()
            .execute(
                "UPDATE cve_cache SET fetched_utc = '2020-01-01T00:00:00Z'",
                [],
            )
            .unwrap();
        assert_eq!(db.cache_get("k", hour).unwrap(), None);
        assert_eq!(db.cache_get("k", None).unwrap().as_deref(), Some("two"));
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        Db::open(&path)
            .unwrap()
            .conn()
            .pragma_update(None, "user_version", 9999)
            .unwrap();
        let error = Db::open(&path).err().unwrap();
        assert!(format!("{error:#}").contains("newer than this build"));
    }

    #[test]
    fn stage_status_is_constrained() {
        let db = Db::open_in_memory().unwrap();
        db.conn()
            .execute(
                "INSERT INTO tasks (target, mode, created_utc) VALUES ('t', 'mild', 'now')",
                [],
            )
            .unwrap();
        let insert = |status: &str| {
            db.conn().execute(
                "INSERT INTO task_stages (task_id, stage, position, status)
                 VALUES (1, ?1, 0, ?1)",
                [status],
            )
        };
        for status in ["pending", "running", "interrupted", "done"] {
            insert(status).unwrap();
        }
        assert!(insert("bogus").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn database_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let db = Db::open(&path).unwrap();
        db.set_meta("k", "v").unwrap();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o600, "{}", path.display());
        }
    }

    #[test]
    fn hardened_connections_disable_views_triggers_and_trusted_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let db = Db::open(&path).unwrap();
            assert_eq!(pragma(&db, "trusted_schema"), "0");
            // Both `found` column (migration 5) and status index (migration 6) exist.
            let found_default: String = db
                .conn()
                .query_row(
                    "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_task_stages_status'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(found_default, "idx_task_stages_status");
            db.conn()
                .execute(
                    "INSERT INTO tasks (target, mode, created_utc) VALUES ('t', 'mild', 'now')",
                    [],
                )
                .unwrap();
            db.conn()
                .execute(
                    "INSERT INTO task_stages (task_id, stage, position, status, found)
                     VALUES (1, 'ports', 0, 'done', '22/tcp')",
                    [],
                )
                .unwrap();
        }
        // Inject a hostile trigger using an unhardened connection; a hardened
        // connection must refuse to fire it or query views.
        {
            let raw = Connection::open(&path).unwrap();
            raw.execute_batch(
                "CREATE TRIGGER trap AFTER INSERT ON meta BEGIN
                     INSERT INTO cve_cache (key, fetched_utc, body) VALUES ('pwn', 'now', 'x');
                 END;
                 CREATE VIEW trap_view AS SELECT 'view';",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        db.set_meta("safe", "1").unwrap();
        assert_eq!(db.cache_get("pwn", None).unwrap(), None);
        assert!(db
            .conn()
            .query_row("SELECT * FROM trap_view", [], |_| Ok(()))
            .is_err());
    }

    #[test]
    fn non_regular_and_linked_sqlite_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let as_dir = dir.path().join("dir.db");
        std::fs::create_dir(&as_dir).unwrap();
        assert!(Db::open(&as_dir).is_err());

        #[cfg(unix)]
        {
            let outside = dir.path().join("outside");
            std::fs::write(&outside, "keep me").unwrap();
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let db_path = dir.path().join(format!("sym{suffix}_test.db"));
                let sidecar = PathBuf::from(format!("{}{suffix}", db_path.display()));
                std::os::unix::fs::symlink(&outside, &sidecar).unwrap();
                assert!(Db::open(&db_path).is_err(), "accepted symlink {suffix}");
                std::fs::remove_file(&sidecar).unwrap();
            }

            let hard = dir.path().join("hard.db");
            std::fs::hard_link(&outside, &hard).unwrap();
            assert!(Db::open(&hard).is_err(), "accepted hard-linked db");
            std::fs::remove_file(&hard).unwrap();
            assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep me");
        }
    }
}

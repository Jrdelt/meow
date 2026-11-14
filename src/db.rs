//! `state.db`: the workspace's SQLite database.
//!
//! Opened in WAL mode with `synchronous=NORMAL` and a 5 s busy timeout, so
//! the session coordinator and helper subcommands can use it side by side.
//! The schema version lives in `PRAGMA user_version`; each entry of
//! [`MIGRATIONS`] upgrades the database by exactly one version.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OptionalExtension};

use crate::workspace::private_open_options;

const BUSY_TIMEOUT: Duration = Duration::from_millis(5000);

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
];

pub struct Db {
    conn: Connection,
}

impl Db {
    /// Opens (creating if needed) the database at `path` and migrates it to
    /// the current schema.
    pub fn open(path: &Path) -> Result<Self> {
        // Create the file ourselves so it is 0600 from the first byte;
        // SQLite gives the -wal and -shm files the same mode.
        private_open_options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        let conn =
            Connection::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        Self::init(conn).with_context(|| format!("cannot initialise {}", path.display()))
    }

    /// A private in-memory database, for tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
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
        let current = self.schema_version()? as usize;
        if current > MIGRATIONS.len() {
            bail!(
                "database schema version {current} is newer than this build of meow ({})",
                MIGRATIONS.len()
            );
        }
        for (index, sql) in MIGRATIONS.iter().enumerate().skip(current) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)
                .with_context(|| format!("migration {} failed", index + 1))?;
            tx.pragma_update(None, "user_version", i64::try_from(index + 1)?)?;
            tx.commit()?;
        }
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

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
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
}

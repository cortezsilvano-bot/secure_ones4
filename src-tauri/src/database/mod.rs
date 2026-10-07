//! Local SQLite store. Nothing here ever leaves the machine.

mod migrations;

use std::path::Path;

use parking_lot::Mutex;
use rusqlite::Connection;

pub use migrations::MigrationError;

/// Owns the single write connection.
///
/// SQLite tolerates one writer; funnelling every statement through one mutex is
/// simpler than a pool and fast enough for scan-rate traffic.
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Open (creating if needed) the store at `path` and bring it to the latest
    /// schema version. Fails loudly rather than starting on a half-migrated file.
    pub fn open(path: &Path) -> Result<Self, MigrationError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(MigrationError::Io)?;
        }

        let conn = Connection::open(path)?;

        // WAL keeps background collectors from blocking UI reads.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        migrations::run(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory store. Used by tests.
    pub fn open_in_memory() -> Result<Self, MigrationError> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrations::run(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Run `f` against the connection while holding the write lock.
    pub fn with<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let conn = self.conn.lock();
        f(&conn)
    }

    pub fn schema_version(&self) -> rusqlite::Result<i32> {
        self.with(migrations::current_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_and_migrates_to_latest() {
        let db = Database::open_in_memory().expect("open");
        assert_eq!(db.schema_version().unwrap(), migrations::LATEST_VERSION);
    }

    #[test]
    fn core_tables_exist() {
        let db = Database::open_in_memory().expect("open");
        for table in [
            "scan_runs",
            "security_facts",
            "findings",
            "events",
            "settings",
        ] {
            let found: i64 = db
                .with(|c| {
                    c.query_row(
                        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                        [table],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            assert_eq!(found, 1, "missing table {table}");
        }
    }

    #[test]
    fn reopening_a_file_store_is_a_no_op() {
        let dir = std::env::temp_dir().join(format!("sentry-test-{}", std::process::id()));
        let path = dir.join("sentry.db");
        let _ = std::fs::remove_file(&path);

        let first = Database::open(&path).expect("first open");
        assert_eq!(first.schema_version().unwrap(), migrations::LATEST_VERSION);
        drop(first);

        // Opening again must re-run the migration pass harmlessly.
        let second = Database::open(&path).expect("second open");
        assert_eq!(second.schema_version().unwrap(), migrations::LATEST_VERSION);
        drop(second);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

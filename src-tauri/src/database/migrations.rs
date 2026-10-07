//! Forward-only schema migrations, tracked in SQLite's `user_version`.
//!
//! Deliberately hand-rolled rather than pulled from a migration crate: every
//! such crate pins its own `rusqlite` version, and a mismatch there is a
//! dependency deadlock we would have to resolve on someone else's release
//! schedule. This is forty lines and owes nothing to anyone.
//!
//! Rules: migrations are append-only and never edited once released, each runs
//! inside a transaction, and a failure aborts startup rather than leaving a
//! half-migrated store behind.

use rusqlite::Connection;

/// Ordered list of (version, SQL). Index + 1 is the resulting `user_version`.
const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("../../migrations/001_core.sql")),
    (2, include_str!("../../migrations/002_vulnerabilities.sql")),
    (3, include_str!("../../migrations/003_network.sql")),
    (
        4,
        include_str!("../../migrations/004_software_identity.sql"),
    ),
    (5, include_str!("../../migrations/005_remediation.sql")),
];

pub const LATEST_VERSION: i32 = MIGRATIONS.len() as i32;

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("filesystem error: {0}")]
    Io(std::io::Error),

    #[error(
        "database schema is version {found}, newer than this build understands ({supported}). \
         It was probably written by a later version of SENTRY."
    )]
    FromTheFuture { found: i32, supported: i32 },
}

pub fn current_version(conn: &Connection) -> rusqlite::Result<i32> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
}

/// Apply every migration newer than the store's current version.
pub fn run(conn: &Connection) -> Result<(), MigrationError> {
    let current = current_version(conn)?;

    // Refuse to touch a store written by a newer build: downgrading silently
    // would corrupt data we do not understand.
    if current > LATEST_VERSION {
        return Err(MigrationError::FromTheFuture {
            found: current,
            supported: LATEST_VERSION,
        });
    }

    for (version, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > current) {
        log::info!("applying schema migration {version}");
        conn.execute_batch(&format!(
            "BEGIN; {sql} PRAGMA user_version = {version}; COMMIT;"
        ))
        .map_err(|e| {
            log::error!("migration {version} failed: {e}");
            // execute_batch aborts mid-batch on error; roll back explicitly so
            // the connection is not left inside an open transaction.
            let _ = conn.execute_batch("ROLLBACK;");
            e
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_database_reaches_latest() {
        let conn = Connection::open_in_memory().unwrap();
        run(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), LATEST_VERSION);
    }

    #[test]
    fn rerunning_applies_nothing() {
        let conn = Connection::open_in_memory().unwrap();
        run(&conn).unwrap();
        // A second run must not attempt to recreate tables, which would error.
        run(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), LATEST_VERSION);
    }

    #[test]
    fn refuses_a_newer_schema() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", LATEST_VERSION + 5)
            .unwrap();
        assert!(matches!(
            run(&conn),
            Err(MigrationError::FromTheFuture { .. })
        ));
    }

    #[test]
    fn versions_are_sequential_from_one() {
        for (i, (version, _)) in MIGRATIONS.iter().enumerate() {
            assert_eq!(*version, i as i32 + 1, "migration list has a gap");
        }
    }
}

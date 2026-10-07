//! Save a standalone router observation without changing unrelated findings or scores.
use super::report::RouterReport;
use crate::{database::Database, security::Known};
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedRouterReport {
    pub id: i64,
    pub saved_at: String,
    pub report: Known<RouterReport>,
}

/// Historical data only: never refreshes a router or re-evaluates old findings.
pub fn list(db: &Database, limit: u32) -> rusqlite::Result<Vec<SavedRouterReport>> {
    db.with(|c| {
        let mut stmt = c.prepare("SELECT r.id, r.started_at, f.value_json FROM scan_runs r
            JOIN security_facts f ON f.scan_run_id = r.id
            WHERE r.scan_type = 'router' AND f.collector = 'network.router' AND f.fact_key = 'router_snapshot'
            ORDER BY r.id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit.clamp(1, 60)], |row| {
            let raw: String = row.get(2)?;
            #[derive(Deserialize)]
            struct Snapshot { generation: u64, facts: Known<super::RouterFacts>, findings: Vec<crate::findings::Finding> }
            let report = match serde_json::from_str::<Snapshot>(&raw) {
                Ok(snapshot) => match snapshot.facts {
                    Known::Known(facts) if facts.target.as_ref().map(|t| t.network_generation) == Some(snapshot.generation) =>
                        Known::Known(RouterReport { facts, findings: snapshot.findings, history_error: None }),
                    _ => Known::Unavailable("Saved router context is incomplete.".into()),
                },
                Err(_) => Known::Unavailable("This saved router report could not be read.".into()),
            };
            Ok(SavedRouterReport { id: row.get(0)?, saved_at: row.get(1)?, report })
        })?;
        rows.collect()
    })
}

/// Caller holds the coordinator generation guard during this transaction.
pub fn record(db: &Database, report: &RouterReport, generation: u64) -> rusqlite::Result<()> {
    if report
        .facts
        .target
        .as_ref()
        .map(|target| target.network_generation)
        != Some(generation)
    {
        return Err(rusqlite::Error::InvalidParameterName(
            "Stale router report".into(),
        ));
    }
    let now = chrono::Utc::now().to_rfc3339();
    let snapshot = serde_json::json!({
        "generation": generation,
        "facts": Known::Known(&report.facts),
        "findings": &report.findings,
    })
    .to_string();
    db.with(|connection| {
        let tx = connection.unchecked_transaction()?;
        // Router checks do not constitute a complete system scan or a score.
        tx.execute("INSERT INTO scan_runs (scan_type, started_at, finished_at, status) VALUES ('router', ?1, ?1, 'partial')", [&now])?;
        let id = tx.last_insert_rowid();
        tx.execute("INSERT INTO security_facts (scan_run_id, collector, fact_key, state, value_json, collected_at)
            VALUES (?1, 'network.router', 'router_snapshot', 'known', ?2, ?3)", params![id, snapshot, report.facts.collected_at])?;
        tx.execute("INSERT INTO events (occurred_at, kind, subject, detail_json) VALUES (?1, 'scan_completed', 'router', ?2)",
            params![now, serde_json::json!({"scanType": "router", "findings": report.findings.len(), "generation": generation}).to_string()])?;
        tx.commit()
    })
}

#[cfg(test)]
mod tests {
    use super::super::{report, target, RouterFacts};
    use super::*;

    fn fixture() -> RouterReport {
        let facts = RouterFacts {
            target: Some(target::candidates(&target::fixture(), 4).remove(0)),
            collected_at: "2026-01-02T00:00:00Z".into(),
            ..Default::default()
        };
        report::from_snapshot(Known::Known(facts), 4)
            .value()
            .unwrap()
            .clone()
    }

    #[test]
    fn historical_reader_preserves_saved_data_and_handles_corruption() {
        let db = Database::open_in_memory().unwrap();
        record(&db, &fixture(), 4).unwrap();
        let saved = list(&db, 60).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(
            saved[0].report.value().unwrap().facts.collected_at,
            "2026-01-02T00:00:00Z"
        );
        db.with(|c| c.execute("UPDATE security_facts SET value_json = 'broken'", []))
            .unwrap();
        assert!(matches!(
            list(&db, 60).unwrap()[0].report,
            Known::Unavailable(_)
        ));
    }

    #[test]
    fn saves_router_snapshot_without_system_score_or_finding_mutation() {
        let db = Database::open_in_memory().unwrap();
        record(&db, &fixture(), 4).unwrap();
        db.with(|c| {
            let (kind, status): (String, String) =
                c.query_row("SELECT scan_type, status FROM scan_runs", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            assert_eq!((kind.as_str(), status.as_str()), ("router", "partial"));
            let raw: String = c.query_row(
                "SELECT value_json FROM security_facts WHERE fact_key = 'router_snapshot'",
                [],
                |r| r.get(0),
            )?;
            let snapshot: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(snapshot["generation"], 4);
            assert!(snapshot["findings"].is_array());
            let scores: i64 = c.query_row(
                "SELECT count(*) FROM security_facts WHERE fact_key = 'security_score'",
                [],
                |r| r.get(0),
            )?;
            let findings: i64 = c.query_row("SELECT count(*) FROM findings", [], |r| r.get(0))?;
            assert_eq!((scores, findings), (0, 0));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn rejects_stale_reports_without_creating_history() {
        let db = Database::open_in_memory().unwrap();
        assert!(record(&db, &fixture(), 5).is_err());
        let count: i64 = db
            .with(|c| c.query_row("SELECT count(*) FROM scan_runs", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn storage_failure_rolls_back_the_whole_scan() {
        let db = Database::open_in_memory().unwrap();
        db.with(|c| c.execute_batch("CREATE TRIGGER fail_router_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;")).unwrap();
        assert!(record(&db, &fixture(), 4).is_err());
        db.with(|c| {
            for table in ["scan_runs", "security_facts"] {
                let count: i64 =
                    c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
                assert_eq!(count, 0);
            }
            Ok(())
        })
        .unwrap();
    }
}

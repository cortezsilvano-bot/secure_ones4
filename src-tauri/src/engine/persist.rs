//! Writing scan results to the local store.
//!
//! Findings are upserted rather than replaced, because a finding's identity is
//! stable across scans (see `Finding::id_for`). That is what makes history
//! possible: `first_seen` records when a problem appeared, `last_seen` when it
//! was last observed, and a user's decision to dismiss it survives a re-scan.

use rusqlite::params;

use crate::database::Database;
use crate::engine::Dashboard;

/// Record what this PC is currently listening on.
///
/// Upserted on (port, protocol, address) with `first_seen` preserved, so the
/// store answers "when did this service first appear?" rather than only "what
/// is listening right now".
pub fn record_listeners(
    db: &Database,
    listeners: &[crate::collectors::network::local_ports::Listener],
) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();

    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO local_listeners (port, protocol, local_address, scope,
                        process_name, process_path, service, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
                 ON CONFLICT (port, protocol, local_address) DO UPDATE SET
                    scope = ?4, process_name = ?5, process_path = ?6,
                    service = ?7, last_seen = ?8",
            )?;

            for l in listeners {
                stmt.execute(params![
                    l.port,
                    l.protocol,
                    l.local_address,
                    l.scope.as_str(),
                    l.process_name,
                    l.process_path,
                    l.well_known_service,
                    now,
                ])?;
            }
        }
        tx.commit()
    })
}

/// Record a completed scan and its findings.
pub fn record(db: &Database, dashboard: &Dashboard) -> rusqlite::Result<()> {
    let now = &dashboard.scanned_at;

    // Coverage decides the recorded status: a scan where several modules could
    // not report is "partial", not "complete".
    let status = match dashboard.score.coverage {
        crate::security::score::Coverage::Complete => "complete",
        crate::security::score::Coverage::Partial => "partial",
        crate::security::score::Coverage::Incomplete => "incomplete",
    };

    db.with(|c| {
        let tx = c.unchecked_transaction()?;

        tx.execute(
            "INSERT INTO scan_runs (scan_type, started_at, finished_at, status)
             VALUES ('standard', ?1, ?1, ?2)",
            params![now, status],
        )?;
        let scan_run_id = tx.last_insert_rowid();

        {
            let mut stmt = tx.prepare(
                "INSERT INTO findings (id, rule_id, category, severity, confidence, title,
                        what_happened, why_it_matters, affected_asset, remediation, auto_fix,
                        auto_fix_risk, evidence_json, references_json, first_seen, last_seen,
                        status, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15, ?16, ?17)
                 ON CONFLICT (id) DO UPDATE SET
                    severity = ?4, confidence = ?5, title = ?6, what_happened = ?7,
                    why_it_matters = ?8, remediation = ?10, evidence_json = ?13,
                    references_json = ?14, last_seen = ?15",
            )?;

            for f in &dashboard.findings {
                stmt.execute(params![
                    f.id,
                    f.rule_id,
                    f.category,
                    format!("{:?}", f.severity),
                    f.confidence.as_f32(),
                    f.title,
                    f.what_happened,
                    f.why_it_matters,
                    f.affected_asset,
                    f.remediation,
                    f.auto_fix as i32,
                    f.auto_fix_risk.map(|r| format!("{r:?}").to_lowercase()),
                    serde_json::to_string(&f.evidence).unwrap_or_else(|_| "[]".into()),
                    serde_json::to_string(&f.references).unwrap_or_else(|_| "[]".into()),
                    now,
                    // The user's own status is never overwritten by a re-scan,
                    // so this value only applies on first insert.
                    "open",
                    f.source,
                ])?;
            }
        }

        // Findings that were open but did not reappear have been resolved.
        // Only those SENTRY itself opened are touched; a dismissal stands.
        {
            let ids: Vec<String> = dashboard.findings.iter().map(|f| f.id.clone()).collect();
            let placeholders = if ids.is_empty() {
                "''".to_string()
            } else {
                ids.iter().map(|_| "?").collect::<Vec<_>>().join(",")
            };

            let sql = format!(
                "UPDATE findings SET status = 'resolved'
                 WHERE status = 'open' AND id NOT IN ({placeholders})"
            );
            let refs: Vec<&dyn rusqlite::ToSql> =
                ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
            tx.execute(&sql, refs.as_slice())?;
        }

        // The score is part of the run's record, so history can show it moving.
        tx.execute(
            "INSERT INTO security_facts (scan_run_id, collector, fact_key, state, value_json, collected_at)
             VALUES (?1, 'engine', 'security_score', 'known', ?2, ?3)",
            params![
                scan_run_id,
                serde_json::to_string(&dashboard.score).unwrap_or_else(|_| "null".into()),
                now
            ],
        )?;

        tx.execute(
            "INSERT INTO events (occurred_at, kind, subject, detail_json) VALUES (?1, 'scan_completed', ?2, ?3)",
            params![
                now,
                status,
                serde_json::json!({
                    "findings": dashboard.findings.len(),
                    "score": dashboard.score.score,
                    "modulesReporting": dashboard.score.modules_reporting,
                    "modulesTotal": dashboard.score.modules_total,
                })
                .to_string()
            ],
        )?;

        tx.commit()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{FindingBuilder, Severity};
    use crate::security::score;

    fn dashboard(findings: Vec<crate::findings::Finding>) -> Dashboard {
        Dashboard {
            score: score::compute(&findings, 5, 9, vec!["Network".into()]),
            tiles: vec![],
            findings,
            scanned_at: chrono::Utc::now().to_rfc3339(),
            programs_installed: Some(48),
        }
    }

    fn finding(rule: &str, title: &str) -> crate::findings::Finding {
        FindingBuilder::new(rule, "Test", Severity::Warning, title)
            .what("w")
            .why("y")
            .evidence(["e".to_string()])
            .source("test")
            .build()
    }

    #[test]
    fn listeners_are_recorded_with_a_stable_first_seen() {
        use crate::collectors::network::local_ports::{BindScope, Listener};

        let db = Database::open_in_memory().unwrap();
        let listener = Listener {
            port: 445,
            protocol: "tcp".into(),
            local_address: "0.0.0.0".into(),
            scope: BindScope::AllInterfaces,
            pid: 4,
            process_path: None,
            process_name: Some("System".into()),
            well_known_service: Some("Windows file sharing (SMB)".into()),
        };

        record_listeners(&db, std::slice::from_ref(&listener)).unwrap();
        let first: String = db
            .with(|c| c.query_row("SELECT first_seen FROM local_listeners", [], |r| r.get(0)))
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        record_listeners(&db, std::slice::from_ref(&listener)).unwrap();

        let (again, count, scope): (String, i64, String) = db
            .with(|c| {
                c.query_row(
                    "SELECT first_seen, (SELECT count(*) FROM local_listeners), scope FROM local_listeners",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
            })
            .unwrap();

        assert_eq!(count, 1, "the same socket must not duplicate");
        assert_eq!(first, again, "first_seen answers when the service appeared");
        assert_eq!(scope, "all_interfaces");
    }

    #[test]
    fn records_a_run_its_findings_and_an_event() {
        let db = Database::open_in_memory().unwrap();
        record(
            &db,
            &dashboard(vec![finding("A", "One"), finding("B", "Two")]),
        )
        .unwrap();

        let (runs, found, events): (i64, i64, i64) = db
            .with(|c| {
                c.query_row(
                    "SELECT (SELECT count(*) FROM scan_runs),
                            (SELECT count(*) FROM findings),
                            (SELECT count(*) FROM events)",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
            })
            .unwrap();

        assert_eq!(runs, 1);
        assert_eq!(found, 2);
        assert_eq!(events, 1);
    }

    #[test]
    fn a_recurring_finding_keeps_its_first_seen() {
        let db = Database::open_in_memory().unwrap();

        record(&db, &dashboard(vec![finding("A", "One")])).unwrap();
        let first: String = db
            .with(|c| c.query_row("SELECT first_seen FROM findings", [], |r| r.get(0)))
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        record(&db, &dashboard(vec![finding("A", "One")])).unwrap();

        let (again, last, count): (String, String, i64) = db
            .with(|c| {
                c.query_row(
                    "SELECT first_seen, last_seen, (SELECT count(*) FROM findings) FROM findings",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
            })
            .unwrap();

        assert_eq!(count, 1, "a recurring finding must not duplicate");
        assert_eq!(
            first, again,
            "first_seen must record when the problem appeared"
        );
        assert!(last >= first, "last_seen must move forward");
    }

    #[test]
    fn a_finding_that_stops_appearing_is_resolved() {
        let db = Database::open_in_memory().unwrap();

        record(
            &db,
            &dashboard(vec![finding("A", "One"), finding("B", "Two")]),
        )
        .unwrap();
        // Second scan: only A is still present.
        record(&db, &dashboard(vec![finding("A", "One")])).unwrap();

        let statuses: Vec<(String, String)> = db
            .with(|c| {
                let mut stmt =
                    c.prepare("SELECT rule_id, status FROM findings ORDER BY rule_id")?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect()
            })
            .unwrap();

        assert_eq!(statuses[0], ("A".to_string(), "open".to_string()));
        assert_eq!(
            statuses[1],
            ("B".to_string(), "resolved".to_string()),
            "a problem that no longer appears has been fixed"
        );
    }

    #[test]
    fn a_dismissed_finding_stays_dismissed_after_a_rescan() {
        // The user's judgement must outlast the scanner's.
        let db = Database::open_in_memory().unwrap();
        record(&db, &dashboard(vec![finding("A", "One")])).unwrap();

        db.with(|c| {
            c.execute("UPDATE findings SET status = 'dismissed'", [])?;
            Ok(())
        })
        .unwrap();

        record(&db, &dashboard(vec![finding("A", "One")])).unwrap();

        let status: String = db
            .with(|c| c.query_row("SELECT status FROM findings", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(status, "dismissed");
    }

    #[test]
    fn a_clean_scan_resolves_everything_outstanding() {
        let db = Database::open_in_memory().unwrap();
        record(&db, &dashboard(vec![finding("A", "One")])).unwrap();
        record(&db, &dashboard(vec![])).unwrap();

        let open: i64 = db
            .with(|c| {
                c.query_row(
                    "SELECT count(*) FROM findings WHERE status = 'open'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(open, 0);
    }

    #[test]
    fn the_score_is_recorded_with_the_run() {
        let db = Database::open_in_memory().unwrap();
        record(&db, &dashboard(vec![finding("A", "One")])).unwrap();

        let json: String = db
            .with(|c| {
                c.query_row(
                    "SELECT value_json FROM security_facts WHERE fact_key = 'security_score'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(json.contains("coverage"));
    }
}

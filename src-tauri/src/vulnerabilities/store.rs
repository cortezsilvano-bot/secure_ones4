//! Persistence for the vulnerability feeds.
//!
//! Feed data is cached so that a scan is an offline operation. Refreshing is a
//! separate, deliberate act; scanning reads only what is already on disk. That
//! keeps scans fast, keeps them working without a network, and means the
//! machine's software list is never the trigger for an outbound request during
//! a scan.

use rusqlite::{params, OptionalExtension};

use crate::collectors::software::InstalledSoftware;
use crate::database::Database;
use crate::vulnerabilities::feeds::epss::EpssScore;
use crate::vulnerabilities::feeds::kev::{KevEntry, KevSnapshot};
use crate::vulnerabilities::feeds::nvd::CveRecord;
use crate::vulnerabilities::feeds::oui::OuiEntry;
use crate::vulnerabilities::version::VersionRange;

/// How each feed last fared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedState {
    pub feed: String,
    pub last_attempt: Option<String>,
    pub last_success: Option<String>,
    pub record_count: i64,
    pub version: Option<String>,
    pub last_error: Option<String>,
}

impl FeedState {
    /// Days since the last successful refresh, if there has ever been one.
    pub fn age_days(&self) -> Option<i64> {
        let raw = self.last_success.as_ref()?;
        let parsed = chrono::DateTime::parse_from_rfc3339(raw).ok()?;
        Some(
            chrono::Utc::now()
                .signed_duration_since(parsed.with_timezone(&chrono::Utc))
                .num_days(),
        )
    }
}

// --- Feed bookkeeping -------------------------------------------------------

pub fn record_attempt(db: &Database, feed: &str) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    db.with(|c| {
        c.execute(
            "INSERT INTO feed_state (feed, last_attempt) VALUES (?1, ?2)
             ON CONFLICT (feed) DO UPDATE SET last_attempt = ?2",
            params![feed, now],
        )?;
        Ok(())
    })
}

pub fn record_success(
    db: &Database,
    feed: &str,
    record_count: i64,
    version: Option<&str>,
) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    db.with(|c| {
        c.execute(
            "INSERT INTO feed_state (feed, last_attempt, last_success, record_count, version, last_error)
             VALUES (?1, ?2, ?2, ?3, ?4, NULL)
             ON CONFLICT (feed) DO UPDATE SET
                last_attempt = ?2, last_success = ?2, record_count = ?3,
                version = ?4, last_error = NULL",
            params![feed, now, record_count, version],
        )?;
        Ok(())
    })
}

pub fn record_failure(db: &Database, feed: &str, error: &str) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    db.with(|c| {
        c.execute(
            "INSERT INTO feed_state (feed, last_attempt, last_error) VALUES (?1, ?2, ?3)
             ON CONFLICT (feed) DO UPDATE SET last_attempt = ?2, last_error = ?3",
            params![feed, now, error],
        )?;
        Ok(())
    })
}

pub fn feed_state(db: &Database, feed: &str) -> rusqlite::Result<Option<FeedState>> {
    db.with(|c| {
        c.query_row(
            "SELECT feed, last_attempt, last_success, record_count, version, last_error
             FROM feed_state WHERE feed = ?1",
            [feed],
            |r| {
                Ok(FeedState {
                    feed: r.get(0)?,
                    last_attempt: r.get(1)?,
                    last_success: r.get(2)?,
                    record_count: r.get(3)?,
                    version: r.get(4)?,
                    last_error: r.get(5)?,
                })
            },
        )
        .optional()
    })
}

// --- KEV --------------------------------------------------------------------

/// Replace the cached catalogue wholesale.
///
/// KEV is only ever published complete, and entries are occasionally withdrawn.
/// Merging would leave a withdrawn CVE marked as actively exploited forever, so
/// the table is replaced inside one transaction instead.
pub fn save_kev(db: &Database, snapshot: &KevSnapshot) -> rusqlite::Result<()> {
    db.with(|c| {
        let tx = c.unchecked_transaction()?;

        tx.execute("DELETE FROM kev", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO kev (cve_id, vendor_project, product, vulnerability_name,
                                  date_added, short_description, required_action, due_date,
                                  known_ransomware_use)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for e in &snapshot.entries {
                stmt.execute(params![
                    e.cve_id,
                    e.vendor_project,
                    e.product,
                    e.vulnerability_name,
                    e.date_added,
                    e.short_description,
                    e.required_action,
                    e.due_date,
                    e.used_in_ransomware() as i32,
                ])?;
            }
        }

        tx.commit()
    })
}

pub fn kev_entry(db: &Database, cve_id: &str) -> rusqlite::Result<Option<KevEntry>> {
    db.with(|c| {
        c.query_row(
            "SELECT cve_id, vendor_project, product, vulnerability_name, date_added,
                    short_description, required_action, due_date, known_ransomware_use
             FROM kev WHERE cve_id = ?1",
            [cve_id.to_ascii_uppercase()],
            |r| {
                Ok(KevEntry {
                    cve_id: r.get(0)?,
                    vendor_project: r.get(1)?,
                    product: r.get(2)?,
                    vulnerability_name: r.get(3)?,
                    date_added: r.get(4)?,
                    short_description: r.get(5)?,
                    required_action: r.get(6)?,
                    due_date: r.get(7)?,
                    known_ransomware_use: if r.get::<_, i32>(8)? != 0 {
                        "Known".to_string()
                    } else {
                        "Unknown".to_string()
                    },
                })
            },
        )
        .optional()
    })
}

pub fn kev_count(db: &Database) -> rusqlite::Result<i64> {
    db.with(|c| c.query_row("SELECT count(*) FROM kev", [], |r| r.get(0)))
}

// --- MAC vendor registry ----------------------------------------------------

/// Replace the cached IEEE registry.
///
/// Replaced wholesale rather than merged: prefixes are occasionally reassigned,
/// and a stale entry would attribute a device to the wrong manufacturer, which
/// is worse than attributing it to none.
pub fn save_oui(db: &Database, entries: &[OuiEntry]) -> rusqlite::Result<()> {
    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        tx.execute("DELETE FROM oui", [])?;
        {
            let mut stmt =
                tx.prepare("INSERT OR REPLACE INTO oui (prefix, organization) VALUES (?1, ?2)")?;
            for e in entries {
                stmt.execute(params![e.prefix, e.organization])?;
            }
        }
        tx.commit()
    })
}

pub fn oui_count(db: &Database) -> rusqlite::Result<i64> {
    db.with(|c| c.query_row("SELECT count(*) FROM oui", [], |r| r.get(0)))
}

// --- EPSS -------------------------------------------------------------------

pub fn save_epss(db: &Database, scores: &[(String, EpssScore)]) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO epss (cve_id, epss, percentile, fetched_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (cve_id) DO UPDATE SET
                    epss = ?2, percentile = ?3, fetched_at = ?4",
            )?;
            for (id, score) in scores {
                stmt.execute(params![id, score.epss, score.percentile, now])?;
            }
        }
        tx.commit()
    })
}

pub fn epss_score(db: &Database, cve_id: &str) -> rusqlite::Result<Option<EpssScore>> {
    db.with(|c| {
        c.query_row(
            "SELECT epss, percentile FROM epss WHERE cve_id = ?1",
            [cve_id.to_ascii_uppercase()],
            |r| {
                Ok(EpssScore {
                    epss: r.get(0)?,
                    percentile: r.get(1)?,
                })
            },
        )
        .optional()
    })
}

// --- CVEs -------------------------------------------------------------------

pub fn save_cves(db: &Database, keyword: &str, records: &[CveRecord]) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();

    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        {
            let mut cve_stmt = tx.prepare(
                "INSERT INTO cve (cve_id, description, published, last_modified,
                                  cvss_score, cvss_severity, cvss_vector, fetched_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (cve_id) DO UPDATE SET
                    description = ?2, published = ?3, last_modified = ?4,
                    cvss_score = ?5, cvss_severity = ?6, cvss_vector = ?7, fetched_at = ?8",
            )?;
            let mut clear_stmt = tx.prepare("DELETE FROM cve_cpe_match WHERE cve_id = ?1")?;
            let mut match_stmt = tx.prepare(
                "INSERT INTO cve_cpe_match (cve_id, criteria, vulnerable,
                        version_start_including, version_start_excluding,
                        version_end_including, version_end_excluding)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            let mut link_stmt =
                tx.prepare("INSERT OR IGNORE INTO product_cve (keyword, cve_id) VALUES (?1, ?2)")?;

            for record in records {
                cve_stmt.execute(params![
                    record.id,
                    record.description,
                    record.published,
                    record.last_modified,
                    record.cvss_score,
                    record.cvss_severity,
                    record.cvss_vector,
                    now,
                ])?;

                // Replace rather than accumulate: NVD revises match rules, and
                // a stale rule would keep matching a version that is no longer
                // considered affected.
                clear_stmt.execute([&record.id])?;
                for m in &record.matches {
                    match_stmt.execute(params![
                        record.id,
                        m.criteria,
                        m.vulnerable as i32,
                        m.range.start_including,
                        m.range.start_excluding,
                        m.range.end_including,
                        m.range.end_excluding,
                    ])?;
                }

                link_stmt.execute(params![keyword, record.id])?;
            }
        }
        tx.commit()
    })
}

/// Every cached CVE linked to a product keyword, with its match rules.
pub fn cves_for_keyword(db: &Database, keyword: &str) -> rusqlite::Result<Vec<CveRecord>> {
    use crate::vulnerabilities::feeds::nvd::CpeMatch;

    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT v.cve_id, v.description, v.published, v.last_modified,
                    v.cvss_score, v.cvss_severity, v.cvss_vector
             FROM cve v
             JOIN product_cve p ON p.cve_id = v.cve_id
             WHERE p.keyword = ?1",
        )?;

        let rows = stmt.query_map([keyword], |r| {
            Ok(CveRecord {
                id: r.get(0)?,
                description: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                published: r.get(2)?,
                last_modified: r.get(3)?,
                cvss_score: r.get(4)?,
                cvss_severity: r.get(5)?,
                cvss_vector: r.get(6)?,
                matches: Vec::new(),
            })
        })?;

        let mut records: Vec<CveRecord> = rows.collect::<rusqlite::Result<_>>()?;

        let mut match_stmt = c.prepare(
            "SELECT criteria, vulnerable, version_start_including, version_start_excluding,
                    version_end_including, version_end_excluding
             FROM cve_cpe_match WHERE cve_id = ?1",
        )?;

        for record in &mut records {
            let matches = match_stmt.query_map([&record.id], |r| {
                Ok(CpeMatch {
                    criteria: r.get(0)?,
                    vulnerable: r.get::<_, i32>(1)? != 0,
                    range: VersionRange {
                        start_including: r.get(2)?,
                        start_excluding: r.get(3)?,
                        end_including: r.get(4)?,
                        end_excluding: r.get(5)?,
                    },
                })
            })?;
            record.matches = matches.collect::<rusqlite::Result<_>>()?;
        }

        Ok(records)
    })
}

// --- Product lookups --------------------------------------------------------

/// When a keyword was last successfully looked up, if ever.
pub fn lookup_age_days(db: &Database, keyword: &str) -> rusqlite::Result<Option<i64>> {
    let last: Option<String> = db.with(|c| {
        c.query_row(
            "SELECT last_success FROM product_lookup WHERE keyword = ?1",
            [keyword],
            |r| r.get(0),
        )
        .optional()
        .map(|o| o.flatten())
    })?;

    Ok(last.and_then(|raw| {
        chrono::DateTime::parse_from_rfc3339(&raw).ok().map(|t| {
            chrono::Utc::now()
                .signed_duration_since(t.with_timezone(&chrono::Utc))
                .num_days()
        })
    }))
}

pub fn record_lookup_success(db: &Database, keyword: &str, cve_count: i64) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    db.with(|c| {
        c.execute(
            "INSERT INTO product_lookup (keyword, last_attempt, last_success, cve_count, last_error)
             VALUES (?1, ?2, ?2, ?3, NULL)
             ON CONFLICT (keyword) DO UPDATE SET
                last_attempt = ?2, last_success = ?2, cve_count = ?3, last_error = NULL",
            params![keyword, now, cve_count],
        )?;
        Ok(())
    })
}

pub fn record_lookup_failure(db: &Database, keyword: &str, error: &str) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    db.with(|c| {
        c.execute(
            "INSERT INTO product_lookup (keyword, last_attempt, last_error) VALUES (?1, ?2, ?3)
             ON CONFLICT (keyword) DO UPDATE SET last_attempt = ?2, last_error = ?3",
            params![keyword, now, error],
        )?;
        Ok(())
    })
}

// --- Software inventory -----------------------------------------------------

/// Upsert the inventory, preserving `first_seen` for programs already known.
pub fn save_software(db: &Database, programs: &[InstalledSoftware]) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO software (name, version, publisher, scope, registry_key,
                                       install_location, install_date, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
                 ON CONFLICT (name, version, scope) DO UPDATE SET
                    publisher = ?3, registry_key = ?5, install_location = ?6,
                    install_date = ?7, last_seen = ?8",
            )?;
            for p in programs {
                stmt.execute(params![
                    p.name,
                    // Empty string, never NULL: a NULL here would never match
                    // the UNIQUE constraint and would insert a new row on every
                    // scan. See migration 004.
                    p.version.as_deref().unwrap_or(""),
                    p.publisher,
                    p.scope,
                    p.registry_key,
                    p.install_location,
                    p.install_date,
                    now,
                ])?;
            }
        }
        tx.commit()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::feeds::nvd::CpeMatch;

    fn db() -> Database {
        Database::open_in_memory().expect("in-memory store")
    }

    fn kev_snapshot() -> KevSnapshot {
        KevSnapshot {
            catalog_version: Some("2026.09.17".into()),
            date_released: None,
            entries: vec![
                KevEntry {
                    cve_id: "CVE-2021-44228".into(),
                    vendor_project: "Apache".into(),
                    product: "Log4j2".into(),
                    vulnerability_name: "Log4Shell".into(),
                    date_added: "2021-12-10".into(),
                    short_description: "RCE".into(),
                    required_action: "Patch".into(),
                    due_date: "2021-12-24".into(),
                    known_ransomware_use: "Known".into(),
                },
                KevEntry {
                    cve_id: "CVE-2017-0144".into(),
                    vendor_project: "Microsoft".into(),
                    product: "SMBv1".into(),
                    vulnerability_name: "EternalBlue".into(),
                    date_added: "2022-03-03".into(),
                    short_description: "RCE".into(),
                    required_action: "Patch".into(),
                    due_date: "2022-03-24".into(),
                    known_ransomware_use: "Unknown".into(),
                },
            ],
        }
    }

    #[test]
    fn kev_round_trips() {
        let db = db();
        save_kev(&db, &kev_snapshot()).expect("save");

        assert_eq!(kev_count(&db).unwrap(), 2);

        let entry = kev_entry(&db, "CVE-2021-44228").unwrap().expect("found");
        assert_eq!(entry.product, "Log4j2");
        assert!(entry.used_in_ransomware());

        let other = kev_entry(&db, "CVE-2017-0144").unwrap().unwrap();
        assert!(!other.used_in_ransomware());
    }

    #[test]
    fn kev_lookup_is_case_insensitive() {
        let db = db();
        save_kev(&db, &kev_snapshot()).unwrap();
        assert!(kev_entry(&db, "cve-2021-44228").unwrap().is_some());
    }

    #[test]
    fn an_absent_kev_entry_is_none_not_an_error() {
        let db = db();
        save_kev(&db, &kev_snapshot()).unwrap();
        assert!(kev_entry(&db, "CVE-1999-9999").unwrap().is_none());
    }

    #[test]
    fn saving_kev_replaces_rather_than_merges() {
        // A withdrawn entry must disappear. Merging would leave it marked
        // actively exploited forever.
        let db = db();
        save_kev(&db, &kev_snapshot()).unwrap();

        let mut smaller = kev_snapshot();
        smaller.entries.truncate(1);
        save_kev(&db, &smaller).unwrap();

        assert_eq!(kev_count(&db).unwrap(), 1);
        assert!(kev_entry(&db, "CVE-2017-0144").unwrap().is_none());
    }

    #[test]
    fn oui_round_trips_and_replaces() {
        let db = db();
        save_oui(
            &db,
            &[
                OuiEntry {
                    prefix: "2462AB".into(),
                    organization: "Espressif Inc.".into(),
                },
                OuiEntry {
                    prefix: "F0D1A9".into(),
                    organization: "Apple  Inc.".into(),
                },
            ],
        )
        .unwrap();
        assert_eq!(oui_count(&db).unwrap(), 2);

        // A reassigned prefix must not leave the old manufacturer behind.
        save_oui(
            &db,
            &[OuiEntry {
                prefix: "2462AB".into(),
                organization: "Somebody Else".into(),
            }],
        )
        .unwrap();
        assert_eq!(oui_count(&db).unwrap(), 1);

        let org: String = db
            .with(|c| {
                c.query_row(
                    "SELECT organization FROM oui WHERE prefix = '2462AB'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(org, "Somebody Else");
    }

    #[test]
    fn epss_round_trips_and_updates() {
        let db = db();
        save_epss(
            &db,
            &[(
                "CVE-2021-44228".into(),
                EpssScore {
                    epss: 0.94,
                    percentile: 0.99,
                },
            )],
        )
        .unwrap();

        let score = epss_score(&db, "CVE-2021-44228").unwrap().unwrap();
        assert!((score.epss - 0.94).abs() < 1e-9);

        // A later fetch must overwrite, not duplicate.
        save_epss(
            &db,
            &[(
                "CVE-2021-44228".into(),
                EpssScore {
                    epss: 0.50,
                    percentile: 0.90,
                },
            )],
        )
        .unwrap();
        let updated = epss_score(&db, "CVE-2021-44228").unwrap().unwrap();
        assert!((updated.epss - 0.50).abs() < 1e-9);
    }

    fn cve(id: &str, end_excluding: &str) -> CveRecord {
        CveRecord {
            id: id.into(),
            description: "test".into(),
            published: Some("2023-05-05T21:15:10".into()),
            last_modified: None,
            cvss_score: Some(7.8),
            cvss_severity: Some("HIGH".into()),
            cvss_vector: Some("CVSS:3.1/AV:L".into()),
            matches: vec![CpeMatch {
                criteria: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*".into(),
                vulnerable: true,
                range: VersionRange {
                    end_excluding: Some(end_excluding.into()),
                    ..Default::default()
                },
            }],
        }
    }

    #[test]
    fn cves_round_trip_with_their_match_rules() {
        let db = db();
        save_cves(&db, "7zip", &[cve("CVE-2023-31102", "22.00")]).unwrap();

        let loaded = cves_for_keyword(&db, "7zip").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].cvss_score, Some(7.8));
        assert_eq!(loaded[0].matches.len(), 1);
        assert_eq!(
            loaded[0].matches[0].range.end_excluding.as_deref(),
            Some("22.00")
        );
    }

    #[test]
    fn re_saving_a_cve_replaces_its_match_rules() {
        // NVD revises ranges; an accumulated stale rule would keep flagging a
        // version that is no longer considered affected.
        let db = db();
        save_cves(&db, "7zip", &[cve("CVE-2023-31102", "22.00")]).unwrap();
        save_cves(&db, "7zip", &[cve("CVE-2023-31102", "21.00")]).unwrap();

        let loaded = cves_for_keyword(&db, "7zip").unwrap();
        assert_eq!(
            loaded[0].matches.len(),
            1,
            "match rules must not accumulate"
        );
        assert_eq!(
            loaded[0].matches[0].range.end_excluding.as_deref(),
            Some("21.00")
        );
    }

    #[test]
    fn an_unknown_keyword_returns_nothing() {
        let db = db();
        assert!(cves_for_keyword(&db, "nothing-here").unwrap().is_empty());
    }

    #[test]
    fn feed_state_tracks_success_and_failure() {
        let db = db();
        assert!(feed_state(&db, "kev").unwrap().is_none());

        record_attempt(&db, "kev").unwrap();
        let attempted = feed_state(&db, "kev").unwrap().unwrap();
        assert!(attempted.last_attempt.is_some());
        assert!(attempted.last_success.is_none());

        record_success(&db, "kev", 1400, Some("2026.09.17")).unwrap();
        let ok = feed_state(&db, "kev").unwrap().unwrap();
        assert_eq!(ok.record_count, 1400);
        assert_eq!(ok.version.as_deref(), Some("2026.09.17"));
        assert!(ok.last_error.is_none());
        assert_eq!(ok.age_days(), Some(0));

        record_failure(&db, "kev", "network down").unwrap();
        let failed = feed_state(&db, "kev").unwrap().unwrap();
        assert_eq!(failed.last_error.as_deref(), Some("network down"));
        // A failure must not erase the last good refresh.
        assert!(failed.last_success.is_some());
    }

    #[test]
    fn a_never_refreshed_feed_has_no_age() {
        let state = FeedState {
            feed: "kev".into(),
            last_attempt: Some(chrono::Utc::now().to_rfc3339()),
            last_success: None,
            record_count: 0,
            version: None,
            last_error: None,
        };
        assert_eq!(state.age_days(), None);
    }

    #[test]
    fn a_program_with_no_version_does_not_duplicate_across_scans() {
        // The regression this guards: NULL never equals NULL, so the upsert's
        // conflict target never matched and every scan inserted a fresh row.
        let db = db();
        let program = InstalledSoftware {
            name: "EPSON ET-3830 Series Printer Uninstall".into(),
            version: None,
            publisher: None,
            scope: "HKLM32".into(),
            registry_key: "epson".into(),
            install_location: None,
            install_date: None,
        };

        for _ in 0..5 {
            save_software(&db, std::slice::from_ref(&program)).unwrap();
        }

        let count: i64 = db
            .with(|c| c.query_row("SELECT count(*) FROM software", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(
            count, 1,
            "a version-less program must not duplicate per scan"
        );
    }

    #[test]
    fn different_versions_of_one_program_remain_separate() {
        let db = db();
        let base = InstalledSoftware {
            name: "7-Zip".into(),
            version: Some("23.01".into()),
            publisher: None,
            scope: "HKLM64".into(),
            registry_key: "7-Zip".into(),
            install_location: None,
            install_date: None,
        };
        let newer = InstalledSoftware {
            version: Some("25.00".into()),
            ..base.clone()
        };

        save_software(&db, &[base, newer]).unwrap();

        let count: i64 = db
            .with(|c| c.query_row("SELECT count(*) FROM software", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn software_inventory_preserves_first_seen() {
        let db = db();
        let program = InstalledSoftware {
            name: "7-Zip".into(),
            version: Some("23.01".into()),
            publisher: Some("Igor Pavlov".into()),
            scope: "HKLM64".into(),
            registry_key: "7-Zip".into(),
            install_location: None,
            install_date: None,
        };

        save_software(&db, std::slice::from_ref(&program)).unwrap();
        let first: String = db
            .with(|c| c.query_row("SELECT first_seen FROM software", [], |r| r.get(0)))
            .unwrap();

        save_software(&db, std::slice::from_ref(&program)).unwrap();
        let (again, count): (String, i64) = db
            .with(|c| {
                c.query_row(
                    "SELECT first_seen, (SELECT count(*) FROM software) FROM software",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .unwrap();

        assert_eq!(count, 1, "re-scanning must not duplicate a program");
        assert_eq!(first, again, "first_seen must survive a re-scan");
    }

    #[test]
    fn lookup_age_is_none_until_a_success() {
        let db = db();
        assert_eq!(lookup_age_days(&db, "7zip").unwrap(), None);

        record_lookup_failure(&db, "7zip", "rate limited").unwrap();
        assert_eq!(
            lookup_age_days(&db, "7zip").unwrap(),
            None,
            "a failed attempt must not count as a lookup"
        );

        record_lookup_success(&db, "7zip", 3).unwrap();
        assert_eq!(lookup_age_days(&db, "7zip").unwrap(), Some(0));
    }
}

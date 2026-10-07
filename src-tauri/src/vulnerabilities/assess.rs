//! Assessing installed software against the cached feeds.
//!
//! Entirely offline. If the feeds have never been downloaded, this returns an
//! error rather than an empty result -- "no vulnerabilities found" and "we have
//! no vulnerability data" are different statements, and only the second is true
//! before a refresh.

use serde::{Deserialize, Serialize};

use crate::collectors::software::InstalledSoftware;
use crate::database::Database;
use crate::security::CollectorError;
use crate::vulnerabilities::matcher::{self, Enrichment, Verdict, VulnerabilityMatch};
use crate::vulnerabilities::store;

/// Beyond this, cached feed data is old enough that results must be labelled
/// as possibly stale rather than presented as current.
const STALE_FEED_DAYS: i64 = 14;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VulnerabilityFacts {
    /// Programs found to be affected, worst first.
    pub vulnerable: Vec<VulnerabilityMatch>,
    /// Programs that match a CVE but whose version could not be settled.
    pub undetermined: Vec<VulnerabilityMatch>,
    pub programs_total: usize,
    /// Programs with no version in the registry, which can never be confirmed
    /// either way. Reported so the coverage figure is honest.
    pub programs_without_version: usize,
    /// Programs never looked up against NVD, so nothing is known about them.
    pub programs_never_checked: usize,
    pub kev_entries: i64,
    pub feed_age_days: Option<i64>,
    pub feed_is_stale: bool,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl VulnerabilityFacts {
    /// Programs actually covered by the assessment.
    pub fn programs_checked(&self) -> usize {
        self.programs_total
            .saturating_sub(self.programs_never_checked)
    }
}

/// Assess `programs` against the cached feeds.
pub fn assess(
    db: &Database,
    programs: &[InstalledSoftware],
) -> Result<VulnerabilityFacts, CollectorError> {
    // Without feed data there is nothing to say. Returning empty facts here
    // would render as "no vulnerabilities", which would be a lie.
    let kev_state = store::feed_state(db, "kev")
        .map_err(|e| CollectorError::Unavailable(format!("Could not read feed state: {e}")))?;

    let nvd_state = store::feed_state(db, "nvd")
        .map_err(|e| CollectorError::Unavailable(format!("Could not read feed state: {e}")))?;

    let ever_refreshed = kev_state.as_ref().is_some_and(|s| s.last_success.is_some())
        || nvd_state.as_ref().is_some_and(|s| s.last_success.is_some());

    if !ever_refreshed {
        return Err(CollectorError::Unavailable(
            "Vulnerability data has not been downloaded yet. Until it is, SENTRY has nothing to \
             check your software against -- this is not the same as finding nothing."
                .into(),
        ));
    }

    let feed_age_days = nvd_state
        .as_ref()
        .and_then(|s| s.age_days())
        .or_else(|| kev_state.as_ref().and_then(|s| s.age_days()));

    let kev_entries = store::kev_count(db).unwrap_or(0);

    let mut facts = VulnerabilityFacts {
        programs_total: programs.len(),
        kev_entries,
        feed_age_days,
        feed_is_stale: feed_age_days.is_some_and(|d| d >= STALE_FEED_DAYS),
        collected_at: chrono::Utc::now().to_rfc3339(),
        ..Default::default()
    };

    facts.evidence.push(format!(
        "Feeds: NVD (CVE API 2.0), CISA KEV ({kev_entries} entries), FIRST EPSS"
    ));
    if let Some(age) = feed_age_days {
        facts
            .evidence
            .push(format!("Feed data last refreshed {age} day(s) ago"));
    }

    for program in programs {
        if program.version.is_none() {
            facts.programs_without_version += 1;
        }

        let Some(keyword) = matcher::lookup_keyword(program) else {
            facts.programs_never_checked += 1;
            continue;
        };

        // A keyword never successfully looked up tells us nothing about this
        // program, which is different from telling us it is clean.
        match store::lookup_age_days(db, &keyword) {
            Ok(Some(_)) => {}
            _ => {
                facts.programs_never_checked += 1;
                continue;
            }
        }

        let cves = match store::cves_for_keyword(db, &keyword) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("could not read cached CVEs for {keyword}: {e}");
                facts.programs_never_checked += 1;
                continue;
            }
        };

        for cve in &cves {
            let kev = store::kev_entry(db, &cve.id).ok().flatten();
            let epss = store::epss_score(db, &cve.id).ok().flatten();

            let Some(m) = matcher::match_one(
                program,
                cve,
                Enrichment {
                    kev: kev.as_ref(),
                    epss,
                },
            ) else {
                continue;
            };

            match m.verdict {
                Verdict::Vulnerable => facts.vulnerable.push(m),
                Verdict::Undetermined => facts.undetermined.push(m),
                Verdict::NotVulnerable => {}
            }
        }
    }

    // Worst first: exploited-in-the-wild outranks everything, then CVSS.
    facts.vulnerable.sort_by(|a, b| {
        b.kev
            .is_some()
            .cmp(&a.kev.is_some())
            .then(
                b.cvss_score
                    .unwrap_or(0.0)
                    .partial_cmp(&a.cvss_score.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(a.cve_id.cmp(&b.cve_id))
    });

    facts.evidence.push(format!(
        "Programs: {} total, {} checked, {} never looked up, {} with no version recorded",
        facts.programs_total,
        facts.programs_checked(),
        facts.programs_never_checked,
        facts.programs_without_version,
    ));

    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::feeds::kev::{KevEntry, KevSnapshot};
    use crate::vulnerabilities::feeds::nvd::{CpeMatch, CveRecord};
    use crate::vulnerabilities::version::VersionRange;

    fn db() -> Database {
        Database::open_in_memory().unwrap()
    }

    fn program(name: &str, version: Option<&str>) -> InstalledSoftware {
        InstalledSoftware {
            name: name.to_string(),
            version: version.map(str::to_string),
            publisher: Some("Igor Pavlov".into()),
            scope: "HKLM64".into(),
            registry_key: name.to_string(),
            install_location: None,
            install_date: None,
        }
    }

    fn seed_feeds(db: &Database) {
        store::save_kev(
            db,
            &KevSnapshot {
                catalog_version: Some("2026.09.17".into()),
                date_released: None,
                entries: vec![KevEntry {
                    cve_id: "CVE-2023-31102".into(),
                    vendor_project: "7-Zip".into(),
                    product: "7-Zip".into(),
                    vulnerability_name: "n".into(),
                    date_added: "2024-01-15".into(),
                    short_description: "d".into(),
                    required_action: "Apply updates".into(),
                    due_date: "2024-02-05".into(),
                    known_ransomware_use: "Known".into(),
                }],
            },
        )
        .unwrap();
        store::record_success(db, "kev", 1, Some("2026.09.17")).unwrap();

        store::save_cves(
            db,
            "7-zip",
            &[CveRecord {
                id: "CVE-2023-31102".into(),
                description: "An integer underflow in 7-Zip before 22.00.".into(),
                published: Some("2023-05-05".into()),
                last_modified: None,
                cvss_score: Some(7.8),
                cvss_severity: Some("HIGH".into()),
                cvss_vector: None,
                matches: vec![CpeMatch {
                    criteria: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*".into(),
                    vulnerable: true,
                    range: VersionRange {
                        end_excluding: Some("22.00".into()),
                        ..Default::default()
                    },
                }],
            }],
        )
        .unwrap();
        store::record_lookup_success(db, "7-zip", 1).unwrap();
        store::record_success(db, "nvd", 1, None).unwrap();
    }

    #[test]
    fn without_a_refresh_it_refuses_rather_than_reporting_clean() {
        // The single most important behaviour in this module.
        let db = db();
        let err = assess(&db, &[program("7-Zip", Some("21.07"))]).unwrap_err();
        assert!(matches!(err, CollectorError::Unavailable(_)));
        assert!(
            err.to_string().contains("not the same as finding nothing"),
            "the message must distinguish no-data from no-findings"
        );
    }

    #[test]
    fn finds_a_vulnerable_program() {
        let db = db();
        seed_feeds(&db);

        let facts = assess(&db, &[program("7-Zip", Some("21.07"))]).unwrap();
        assert_eq!(facts.vulnerable.len(), 1);
        assert_eq!(facts.vulnerable[0].cve_id, "CVE-2023-31102");
        assert!(
            facts.vulnerable[0].kev.is_some(),
            "KEV enrichment should be attached"
        );
    }

    #[test]
    fn a_patched_program_produces_no_finding() {
        let db = db();
        seed_feeds(&db);

        let facts = assess(&db, &[program("7-Zip", Some("23.01"))]).unwrap();
        assert!(facts.vulnerable.is_empty());
        assert!(facts.undetermined.is_empty());
    }

    #[test]
    fn a_program_without_a_version_is_undetermined_and_counted() {
        let db = db();
        seed_feeds(&db);

        let facts = assess(&db, &[program("7-Zip", None)]).unwrap();
        assert!(
            facts.vulnerable.is_empty(),
            "a version-less program cannot be confirmed"
        );
        assert_eq!(facts.undetermined.len(), 1);
        assert_eq!(facts.programs_without_version, 1);
    }

    #[test]
    fn a_never_looked_up_program_is_counted_as_unchecked() {
        let db = db();
        seed_feeds(&db);

        let facts = assess(
            &db,
            &[
                program("7-Zip", Some("21.07")),
                program("Some Obscure Tool", Some("1.0")),
            ],
        )
        .unwrap();

        assert_eq!(facts.programs_total, 2);
        assert_eq!(facts.programs_never_checked, 1);
        assert_eq!(facts.programs_checked(), 1);
    }

    #[test]
    fn exploited_vulnerabilities_sort_first() {
        let db = db();
        seed_feeds(&db);

        // A higher-scoring CVE that is *not* in KEV must still rank below the
        // KEV one: known exploitation outranks a bigger number.
        store::save_cves(
            &db,
            "7-zip",
            &[CveRecord {
                id: "CVE-2024-99999".into(),
                description: "Worse on paper.".into(),
                published: None,
                last_modified: None,
                cvss_score: Some(9.8),
                cvss_severity: Some("CRITICAL".into()),
                cvss_vector: None,
                matches: vec![CpeMatch {
                    criteria: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*".into(),
                    vulnerable: true,
                    range: VersionRange {
                        end_excluding: Some("22.00".into()),
                        ..Default::default()
                    },
                }],
            }],
        )
        .unwrap();

        let facts = assess(&db, &[program("7-Zip", Some("21.07"))]).unwrap();
        assert_eq!(facts.vulnerable.len(), 2);
        assert_eq!(
            facts.vulnerable[0].cve_id, "CVE-2023-31102",
            "the KEV-listed CVE must rank above the higher CVSS one"
        );
    }

    #[test]
    fn stale_feeds_are_flagged() {
        let db = db();
        seed_feeds(&db);

        // Backdate the NVD refresh well past the staleness threshold.
        let old = (chrono::Utc::now() - chrono::Duration::days(STALE_FEED_DAYS + 10)).to_rfc3339();
        db.with(|c| {
            c.execute(
                "UPDATE feed_state SET last_success = ?1 WHERE feed = 'nvd'",
                [&old],
            )?;
            Ok(())
        })
        .unwrap();

        let facts = assess(&db, &[program("7-Zip", Some("21.07"))]).unwrap();
        assert!(facts.feed_is_stale);
        assert!(facts.feed_age_days.unwrap() >= STALE_FEED_DAYS);
    }

    #[test]
    fn evidence_records_coverage_not_just_findings() {
        let db = db();
        seed_feeds(&db);

        let facts = assess(&db, &[program("7-Zip", Some("21.07"))]).unwrap();
        assert!(facts.evidence.iter().any(|e| e.contains("CISA KEV")));
        assert!(facts.evidence.iter().any(|e| e.contains("never looked up")));
    }
}

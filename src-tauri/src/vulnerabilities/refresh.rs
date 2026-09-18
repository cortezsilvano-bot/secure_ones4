//! Refreshing the feed caches.
//!
//! This is the only part of SENTRY that reaches the network, and it is never
//! triggered by a scan. A scan reads the cache; refreshing it is a separate,
//! explicit act with visible progress.
//!
//! The pacing is set by NVD, which permits 5 requests per rolling 30 seconds
//! without an API key. Refreshing fifty products therefore takes minutes, not
//! seconds, so the work is incremental and resumable: products already looked
//! up recently are skipped, and a run that is cancelled or rate-limited leaves
//! everything it did manage to fetch in the cache.

use std::time::Instant;

use crate::collectors::software::InstalledSoftware;
use crate::database::Database;
use crate::security::CollectorError;
use crate::vulnerabilities::feeds::{epss, kev, nvd, oui};
use crate::vulnerabilities::matcher;
use crate::vulnerabilities::store;

/// How long a product lookup stays fresh. NVD publishes continuously, but
/// re-querying every product daily would spend the entire rate-limit budget on
/// software that has not changed.
const LOOKUP_TTL_DAYS: i64 = 7;

// At six seconds a request, a shorter TTL would mean re-spending the whole
// budget every time. Enforced at compile time so it cannot be lowered casually.
const _: () = assert!(LOOKUP_TTL_DAYS >= 7);

/// Progress reported as a refresh runs.
#[derive(Debug, Clone)]
pub struct RefreshProgress {
    pub stage: String,
    pub completed: usize,
    pub total: usize,
    pub detail: String,
}

/// What a refresh achieved. Partial success is normal and is reported as such
/// rather than as failure.
#[derive(Debug, Clone, Default)]
pub struct RefreshOutcome {
    pub kev_entries: usize,
    pub products_looked_up: usize,
    pub products_skipped: usize,
    pub cves_cached: usize,
    pub epss_scored: usize,
    pub oui_entries: usize,
    /// Non-fatal problems, each naming what could not be refreshed.
    pub problems: Vec<String>,
}

/// Refresh every feed.
///
/// `cancelled` is polled between requests so a long run can be stopped
/// promptly; `progress` is called as each stage advances.
pub fn refresh_all(
    db: &Database,
    programs: &[InstalledSoftware],
    api_key: Option<&str>,
    cancelled: &dyn Fn() -> bool,
    progress: &mut dyn FnMut(RefreshProgress),
) -> RefreshOutcome {
    let mut outcome = RefreshOutcome::default();

    // --- KEV: one request, always worth doing first -------------------------
    progress(RefreshProgress {
        stage: "kev".into(),
        completed: 0,
        total: 1,
        detail: "Downloading the CISA exploited-vulnerability catalogue".into(),
    });

    store::record_attempt(db, "kev").ok();
    match kev::fetch() {
        Ok(snapshot) => {
            let count = snapshot.entries.len();
            if let Err(e) = store::save_kev(db, &snapshot) {
                outcome
                    .problems
                    .push(format!("Could not store the KEV catalogue: {e}"));
                store::record_failure(db, "kev", &e.to_string()).ok();
            } else {
                outcome.kev_entries = count;
                store::record_success(db, "kev", count as i64, snapshot.catalog_version.as_deref())
                    .ok();
            }
        }
        Err(e) => {
            outcome.problems.push(format!("Could not refresh KEV: {e}"));
            store::record_failure(db, "kev", &e.to_string()).ok();
        }
    }

    if cancelled() {
        outcome.problems.push("Refresh was cancelled.".into());
        return outcome;
    }

    // --- IEEE MAC registry: one request, turns MACs into manufacturer names --
    progress(RefreshProgress {
        stage: "oui".into(),
        completed: 0,
        total: 1,
        detail: "Downloading the MAC manufacturer registry".into(),
    });

    store::record_attempt(db, "oui").ok();
    match oui::fetch() {
        Ok(entries) => {
            let count = entries.len();
            if let Err(e) = store::save_oui(db, &entries) {
                outcome
                    .problems
                    .push(format!("Could not store the MAC registry: {e}"));
                store::record_failure(db, "oui", &e.to_string()).ok();
            } else {
                outcome.oui_entries = count;
                store::record_success(db, "oui", count as i64, None).ok();
            }
        }
        Err(e) => {
            outcome.problems.push(format!(
                "Could not refresh the MAC manufacturer registry: {e}"
            ));
            store::record_failure(db, "oui", &e.to_string()).ok();
        }
    }

    if cancelled() {
        outcome.problems.push("Refresh was cancelled.".into());
        return outcome;
    }

    // --- NVD: one request per distinct product keyword ----------------------
    // Collapse the inventory to distinct keywords first; several programs from
    // one vendor commonly share one.
    let mut keywords: Vec<String> = programs
        .iter()
        .filter_map(matcher::lookup_keyword)
        .collect();
    keywords.sort();
    keywords.dedup();

    let total = keywords.len();
    let mut last_request: Option<Instant> = None;

    // An API key raises NVD's limit from 5 requests per 30 seconds to 50.
    let interval = nvd::request_interval(api_key);

    for (i, keyword) in keywords.iter().enumerate() {
        if cancelled() {
            outcome
                .problems
                .push("Refresh was cancelled before it finished.".into());
            return outcome;
        }

        // Skip anything looked up recently enough to still be current.
        match store::lookup_age_days(db, keyword) {
            Ok(Some(age)) if age < LOOKUP_TTL_DAYS => {
                outcome.products_skipped += 1;
                continue;
            }
            _ => {}
        }

        progress(RefreshProgress {
            stage: "nvd".into(),
            completed: i,
            total,
            detail: format!("Checking {keyword}"),
        });

        // Respect NVD's documented pacing, measuring from the last request
        // rather than sleeping blindly after each one.
        if let Some(previous) = last_request {
            let elapsed = previous.elapsed();
            if elapsed < interval {
                std::thread::sleep(interval - elapsed);
            }
        }
        last_request = Some(Instant::now());

        store::record_attempt(db, "nvd").ok();
        match nvd::search_by_keyword(keyword, api_key) {
            Ok(records) => {
                outcome.products_looked_up += 1;
                outcome.cves_cached += records.len();

                if let Err(e) = store::save_cves(db, keyword, &records) {
                    outcome
                        .problems
                        .push(format!("Could not store CVEs for {keyword}: {e}"));
                } else {
                    store::record_lookup_success(db, keyword, records.len() as i64).ok();
                }
            }
            Err(e) => {
                let message = e.to_string();
                store::record_lookup_failure(db, keyword, &message).ok();

                // Rate limiting means the budget is spent; continuing would
                // just collect more refusals. Stop and keep what we have.
                if message.contains("rate limiting") {
                    outcome.problems.push(
                        "NVD is rate limiting us. The products checked so far have been saved; \
                         run the refresh again later to continue."
                            .into(),
                    );
                    break;
                }

                outcome
                    .problems
                    .push(format!("Could not check {keyword}: {message}"));
            }
        }
    }

    store::record_success(db, "nvd", outcome.cves_cached as i64, None).ok();

    if cancelled() {
        return outcome;
    }

    // --- EPSS: batched, for the CVEs we now hold ----------------------------
    progress(RefreshProgress {
        stage: "epss".into(),
        completed: 0,
        total: 1,
        detail: "Fetching exploitation-likelihood scores".into(),
    });

    match cached_cve_ids(db) {
        Ok(ids) if !ids.is_empty() => {
            store::record_attempt(db, "epss").ok();
            match epss::fetch(&ids) {
                Ok(scores) => {
                    outcome.epss_scored = scores.len();
                    if let Err(e) = store::save_epss(db, &scores) {
                        outcome
                            .problems
                            .push(format!("Could not store EPSS scores: {e}"));
                    } else {
                        store::record_success(db, "epss", scores.len() as i64, None).ok();
                    }
                }
                Err(e) => {
                    outcome
                        .problems
                        .push(format!("Could not refresh EPSS: {e}"));
                    store::record_failure(db, "epss", &e.to_string()).ok();
                }
            }
        }
        Ok(_) => {}
        Err(e) => outcome
            .problems
            .push(format!("Could not list cached CVEs: {e}")),
    }

    outcome
}

/// Refresh only KEV. One request, so it is cheap enough to run often.
pub fn refresh_kev(db: &Database) -> Result<usize, CollectorError> {
    store::record_attempt(db, "kev").ok();

    let snapshot = kev::fetch().inspect_err(|e| {
        store::record_failure(db, "kev", &e.to_string()).ok();
    })?;

    let count = snapshot.entries.len();
    store::save_kev(db, &snapshot).map_err(|e| {
        store::record_failure(db, "kev", &e.to_string()).ok();
        CollectorError::Unavailable(format!("Could not store the KEV catalogue: {e}"))
    })?;

    store::record_success(db, "kev", count as i64, snapshot.catalog_version.as_deref()).ok();
    Ok(count)
}

fn cached_cve_ids(db: &Database) -> rusqlite::Result<Vec<String>> {
    db.with(|c| {
        let mut stmt = c.prepare("SELECT cve_id FROM cve")?;
        let ids = stmt.query_map([], |r| r.get::<_, String>(0))?;
        ids.collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn program(name: &str) -> InstalledSoftware {
        InstalledSoftware {
            name: name.to_string(),
            version: Some("1.0".into()),
            publisher: None,
            scope: "HKLM64".into(),
            registry_key: name.to_string(),
            install_location: None,
            install_date: None,
        }
    }

    #[test]
    fn cancelling_before_any_work_returns_immediately() {
        let db = Database::open_in_memory().unwrap();
        let mut seen = Vec::new();

        let outcome = refresh_all(
            &db,
            &[program("7-Zip")],
            None,
            &|| true, // cancelled from the outset
            &mut |p| seen.push(p.stage),
        );

        // KEV is attempted first and the cancel is checked straight after, so
        // no NVD lookups may have run.
        assert_eq!(outcome.products_looked_up, 0);
        assert!(outcome.problems.iter().any(|p| p.contains("cancelled")));
    }

    #[test]
    fn keywords_are_deduplicated_before_any_request() {
        // Two versions of one product must not spend two of five requests.
        let programs = [
            program("Mozilla Firefox 140.0 (x64 en-US)"),
            program("Mozilla Firefox 141.0 (x64 en-US)"),
        ];
        let mut keywords: Vec<String> = programs
            .iter()
            .filter_map(matcher::lookup_keyword)
            .collect();
        keywords.sort();
        keywords.dedup();

        assert_eq!(keywords, vec!["mozilla firefox"]);
    }

    #[test]
    fn cached_cve_ids_starts_empty() {
        let db = Database::open_in_memory().unwrap();
        assert!(cached_cve_ids(&db).unwrap().is_empty());
    }

    #[test]
    fn the_request_pacing_matches_nvds_documented_limit() {
        // The TTL floor is a compile-time assertion above. NVD's own guidance
        // is roughly six seconds between unauthenticated requests.
        assert!(nvd::UNKEYED_REQUEST_INTERVAL >= Duration::from_secs(6));
    }
}

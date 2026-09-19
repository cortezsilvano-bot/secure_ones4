//! Commands for the vulnerability feeds.
//!
//! Refreshing is the only user-facing action in SENTRY that reaches the
//! internet, so it is always explicit: the user asks for it, sees what it is
//! downloading, and can stop it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, State};

use crate::collectors::software;
use crate::vulnerabilities::{refresh, store};
use crate::AppState;

/// Progress event emitted as a refresh runs. Mirrors `RefreshProgress`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshProgressEvent {
    pub stage: String,
    pub completed: usize,
    pub total: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshSummary {
    pub kev_entries: usize,
    pub products_looked_up: usize,
    pub products_skipped: usize,
    pub cves_cached: usize,
    pub epss_scored: usize,
    /// Non-fatal problems. A refresh that hits NVD's rate limit still counts
    /// as a success for everything it did manage to fetch.
    pub problems: Vec<String>,
}

/// One feed's cache state, for the UI to show how current the data is.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedStatus {
    pub feed: String,
    pub last_success: Option<String>,
    pub age_days: Option<i64>,
    pub record_count: i64,
    pub version: Option<String>,
    pub last_error: Option<String>,
}

/// Cancellation flag shared with a running refresh.
#[derive(Default)]
pub struct RefreshControl {
    cancelled: AtomicBool,
    running: AtomicBool,
}

impl RefreshControl {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn begin(&self) -> bool {
        // Two concurrent refreshes would double-spend the rate-limit budget.
        if self.running.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.cancelled.store(false, Ordering::SeqCst);
        true
    }

    fn end(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Download the latest vulnerability data.
///
/// Long-running: NVD's unauthenticated rate limit means one request every six
/// seconds, so a full refresh over a typical machine takes minutes. Progress is
/// emitted as `vuln-refresh-progress` and the run can be cancelled.
#[tauri::command]
pub async fn refresh_vulnerability_data(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<RefreshSummary, String> {
    let db = state.db.clone();
    let control = state.refresh.clone();

    // The user's own NVD key, when they have supplied one: it raises their
    // rate limit from 5 requests per 30 seconds to 50.
    let api_key = crate::ipc::settings::nvd_api_key(&state);

    if !control.begin() {
        return Err("A vulnerability refresh is already running.".to_string());
    }

    let result = tauri::async_runtime::spawn_blocking(move || {
        // Refresh against the software actually installed, so the rate-limit
        // budget is spent only on programs this machine has.
        let programs = match software::collect() {
            Ok(facts) => facts.programs,
            Err(e) => {
                log::warn!("could not read the software inventory before refreshing: {e}");
                Vec::new()
            }
        };

        let cancelled = {
            let control = control.clone();
            move || control.is_cancelled()
        };

        let mut emit = |p: refresh::RefreshProgress| {
            let _ = app.emit(
                "vuln-refresh-progress",
                RefreshProgressEvent {
                    stage: p.stage,
                    completed: p.completed,
                    total: p.total,
                    detail: p.detail,
                },
            );
        };

        let outcome =
            refresh::refresh_all(&db, &programs, api_key.as_deref(), &cancelled, &mut emit);
        control.end();
        outcome
    })
    .await;

    match result {
        Ok(outcome) => Ok(RefreshSummary {
            kev_entries: outcome.kev_entries,
            products_looked_up: outcome.products_looked_up,
            products_skipped: outcome.products_skipped,
            cves_cached: outcome.cves_cached,
            epss_scored: outcome.epss_scored,
            problems: outcome.problems,
        }),
        Err(e) => {
            log::error!("refresh task failed: {e}");
            Err("The refresh stopped unexpectedly. See the application log for details.".into())
        }
    }
}

/// Stop a running refresh. Whatever was fetched before the stop is kept.
#[tauri::command]
pub fn cancel_vulnerability_refresh(state: State<'_, AppState>) {
    state.refresh.cancel();
}

/// How current each feed's cached data is.
#[tauri::command]
pub fn get_feed_status(state: State<'_, AppState>) -> Vec<FeedStatus> {
    ["kev", "nvd", "epss"]
        .iter()
        .map(|feed| match store::feed_state(&state.db, feed) {
            Ok(Some(s)) => FeedStatus {
                age_days: s.age_days(),
                feed: s.feed,
                last_success: s.last_success,
                record_count: s.record_count,
                version: s.version,
                last_error: s.last_error,
            },
            // Never refreshed, or unreadable: either way there is no data, and
            // the UI must show that rather than an empty-but-fine row.
            _ => FeedStatus {
                feed: (*feed).to_string(),
                last_success: None,
                age_days: None,
                record_count: 0,
                version: None,
                last_error: None,
            },
        })
        .collect()
}

pub type SharedRefreshControl = Arc<RefreshControl>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_refresh_cannot_start_while_one_is_running() {
        // Two concurrent runs would double-spend NVD's rate-limit budget.
        let control = RefreshControl::default();
        assert!(control.begin());
        assert!(!control.begin(), "a second refresh must be refused");

        control.end();
        assert!(
            control.begin(),
            "a refresh may start once the previous one ends"
        );
    }

    #[test]
    fn beginning_a_refresh_clears_a_previous_cancellation() {
        let control = RefreshControl::default();
        assert!(control.begin());
        control.cancel();
        assert!(control.is_cancelled());

        control.end();
        assert!(control.begin());
        assert!(
            !control.is_cancelled(),
            "a stale cancel must not immediately stop the next run"
        );
    }
}

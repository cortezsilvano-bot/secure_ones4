//! Commands backing the main dashboard.

use tauri::State;

use crate::engine::{self, Dashboard};
use crate::AppState;

/// Run a scan and return everything the dashboard renders.
///
/// Returns the payload directly rather than wrapped in `Known`: the scan itself
/// always succeeds, because every individual module's failure is already
/// represented inside the payload as that module's own not-determined state.
#[tauri::command]
pub async fn run_scan(state: State<'_, AppState>) -> Result<Dashboard, String> {
    let db = state.db.clone();
    let router = state.router.clone();
    let check = router.clone();

    let dashboard =
        tauri::async_runtime::spawn_blocking(move || engine::scan_with_router(&db, &router))
            .await
            .map_err(|e| {
                log::error!("scan task failed: {e}");
                "The scan stopped unexpectedly. See the application log for details.".to_string()
            })?;
    if dashboard.router_generation != check.generation() {
        return Err("The network or selected router changed. Run a new scan.".into());
    }
    Ok(dashboard)
}

//! Commands for the router view.

use tauri::State;

use crate::collectors::network::{interfaces, router};
use crate::security::Known;
use crate::AppState;

/// What SENTRY established about the router, and what it could not.
#[tauri::command]
pub async fn get_router_status(
    _state: State<'_, AppState>,
) -> Result<Known<router::RouterFacts>, String> {
    let result = tauri::async_runtime::spawn_blocking(|| {
        let ifaces = interfaces::collect()?;
        router::collect(&ifaces)
    })
    .await;

    match result {
        Ok(facts) => Ok(facts.into()),
        Err(e) => {
            log::error!("router inspection failed: {e}");
            Err("The router check stopped unexpectedly. See the application log.".into())
        }
    }
}

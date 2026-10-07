//! Router commands accept only backend-issued target IDs and generations, never URLs.
use crate::{
    collectors::network::router::{
        coordinator::RouterEnvironment,
        report::{self, RouterReport},
    },
    security::Known,
    AppState,
};
use tauri::{Emitter, State};

#[tauri::command]
pub fn get_router_history(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<crate::collectors::network::router::history::SavedRouterReport>, String> {
    crate::collectors::network::router::history::list(&state.db, limit.unwrap_or(20))
        .map_err(|_| "Saved router reports could not be read.".into())
}

#[tauri::command]
pub async fn get_router_environment(
    state: State<'_, AppState>,
) -> Result<RouterEnvironment, String> {
    let coordinator = state.router.clone();
    tauri::async_runtime::spawn_blocking(move || coordinator.refresh_network())
        .await
        .map_err(|_| "Network discovery stopped unexpectedly.".into())
}

#[tauri::command]
pub async fn get_router_status(
    state: State<'_, AppState>,
    generation: u64,
) -> Result<Known<RouterReport>, String> {
    let coordinator = state.router.clone();
    tauri::async_runtime::spawn_blocking(move || {
        coordinator.refresh_network();
        report::from_snapshot(coordinator.cached(generation), generation)
    })
    .await
    .map_err(|_| "Router inspection stopped unexpectedly.".into())
}

#[tauri::command]
pub async fn scan_router(
    state: State<'_, AppState>,
    generation: u64,
    confirmed: Option<bool>,
) -> Result<Known<RouterReport>, String> {
    run_scan(state, generation, confirmed.unwrap_or(false), None).await
}

#[tauri::command]
pub async fn scan_asus_router(
    state: State<'_, AppState>,
    generation: u64,
    confirmed: Option<bool>,
    options: crate::collectors::network::router::asus_session::LoginOptions,
) -> Result<Known<RouterReport>, String> {
    run_scan(state, generation, confirmed.unwrap_or(false), Some(options)).await
}

async fn run_scan(
    state: State<'_, AppState>,
    generation: u64,
    confirmed: bool,
    options: Option<crate::collectors::network::router::asus_session::LoginOptions>,
) -> Result<Known<RouterReport>, String> {
    let coordinator = state.router.clone();
    let db = state.db.clone();
    tauri::async_runtime::spawn_blocking(move || {
        coordinator.refresh_network();
        let mut result = report::from_snapshot(
            match options {
                Some(options) => coordinator.scan_asus_confirmed(generation, confirmed, options),
                None => coordinator.scan_confirmed(generation, confirmed),
            },
            generation,
        );
        if let Known::Known(report) = &mut result {
            match coordinator.if_current(generation, || {
                crate::collectors::network::router::history::record(&db, report, generation)
            }) {
                Some(Ok(())) => {}
                Some(Err(_)) => report.history_error = Some(
                    "Router results are available, but saving this scan to local history failed."
                        .into(),
                ),
                None => {
                    return Known::Unavailable(
                        "The router changed before its results could be saved.".into(),
                    )
                }
            }
        }
        result
    })
    .await
    .map_err(|_| "Router inspection stopped unexpectedly.".into())
}

#[tauri::command]
pub async fn select_router(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    target_id: String,
    generation: u64,
) -> Result<RouterEnvironment, String> {
    let coordinator = state.router.clone();
    let env = tauri::async_runtime::spawn_blocking(move || {
        coordinator.refresh_network();
        coordinator.select(&target_id, generation)
    })
    .await
    .map_err(|_| "Router selection stopped unexpectedly.".to_string())??;
    let _ = app.emit("router-context-changed", &env);
    Ok(env)
}

#[tauri::command]
pub fn cancel_router_scan(state: State<'_, AppState>, app: tauri::AppHandle, generation: u64) {
    state.router.cancel(generation);
    let _ = app.emit("router-context-changed", state.router.environment());
}

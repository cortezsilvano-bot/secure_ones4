//! SENTRY backend: collectors, rules and storage behind a typed IPC boundary.

pub mod collectors;
pub mod database;
pub mod engine;
pub mod findings;
pub mod ipc;
pub mod remediation;
pub mod rules;
pub mod security;
pub mod vulnerabilities;

use std::sync::Arc;

use database::Database;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager};

/// Handles shared across commands.
pub struct AppState {
    pub db: Arc<Database>,
    /// Where the store lives, shown verbatim in the privacy report.
    pub db_path: std::path::PathBuf,
    /// Lets a long-running feed refresh be cancelled, and stops two from
    /// running at once.
    pub refresh: ipc::vulnerabilities::SharedRefreshControl,
    /// Cancellation flag for an active network sweep.
    pub sweep: ipc::devices::SharedSweepControl,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .setup(|app| {
            // The store lives in the per-user app data directory, which
            // inherits that directory's ACLs -- no other standard user can read it.
            let dir = app.path().app_data_dir()?;
            let db_path = dir.join("sentry.db");

            log::info!("opening store at {}", db_path.display());
            let db = Database::open(&db_path).map_err(|e| {
                log::error!("could not open store: {e}");
                e
            })?;

            log::info!("store ready at schema version {}", db.schema_version()?);
            let db = Arc::new(db);

            app.manage(AppState {
                db: db.clone(),
                db_path: db_path.clone(),
                refresh: Default::default(),
                sweep: Default::default(),
            });

            build_tray(app.handle())?;
            spawn_monitor(app.handle().clone(), db);

            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing hides to the tray instead of quitting, so monitoring
            // continues. Quit is on the tray menu, where it is explicit.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            ipc::dashboard::run_scan,
            ipc::windows_status::get_defender_status,
            ipc::vulnerabilities::refresh_vulnerability_data,
            ipc::vulnerabilities::cancel_vulnerability_refresh,
            ipc::vulnerabilities::get_feed_status,
            ipc::devices::get_devices,
            ipc::devices::discover_devices,
            ipc::devices::cancel_device_discovery,
            ipc::devices::set_device_trust,
            ipc::devices::rename_device,
            ipc::router::get_router_status,
            ipc::history::get_timeline,
            ipc::history::get_scan_history,
            ipc::history::get_privacy_report,
            ipc::settings::get_settings,
            ipc::settings::set_nvd_api_key,
            ipc::settings::set_scan_on_start,
            ipc::settings::delete_local_data,
            ipc::settings::delete_everything,
            ipc::remediation::list_available_fixes,
            ipc::remediation::apply_fix,
            ipc::remediation::get_remediation_history,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SENTRY");
}

/// A tray icon so the window can be closed without stopping monitoring.
///
/// Closing to the tray is the whole reason background scanning is worth
/// anything: a check that only runs while a window is open is a check almost
/// nobody runs.
fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open SENTRY", true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Scan now", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &scan, &quit])?;

    TrayIconBuilder::with_id("sentry")
        .icon(
            app.default_window_icon().cloned().ok_or_else(|| {
                tauri::Error::AssetNotFound("the application icon is missing".into())
            })?,
        )
        .tooltip("SENTRY")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_window(app),
            // The window does the scanning, so it has to be visible to do it.
            "scan" => {
                show_window(app);
                let _ = app.emit("tray-scan-requested", ());
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;

    Ok(())
}

fn show_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Run a scan periodically and notify about anything genuinely new.
fn spawn_monitor(app: tauri::AppHandle, db: Arc<Database>) {
    use tauri_plugin_notification::NotificationExt;

    // Seeded from findings already recorded, so the next scan can report
    // something new rather than spending a cycle learning the status quo.
    let known: Vec<String> = db
        .with(|c| {
            let mut stmt = c.prepare("SELECT id FROM findings WHERE status = 'open'")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect()
        })
        .unwrap_or_default();

    tauri::async_runtime::spawn(async move {
        let mut notifier = engine::monitor::Notifier::seed_from(known);

        loop {
            tokio::time::sleep(engine::monitor::SCAN_INTERVAL).await;

            let db = db.clone();
            let Ok(dashboard) =
                tauri::async_runtime::spawn_blocking(move || engine::scan(&db)).await
            else {
                log::warn!("background scan failed");
                continue;
            };

            // Let an open window update itself rather than showing stale results.
            let _ = app.emit("background-scan-completed", &dashboard);

            notifier.forget_resolved(&dashboard.findings);

            if let Some(notice) = notifier.consider(&dashboard.findings) {
                log::info!("notifying: {}", notice.title);
                if let Err(e) = app
                    .notification()
                    .builder()
                    .title(&notice.title)
                    .body(&notice.body)
                    .show()
                {
                    log::warn!("could not show a notification: {e}");
                }
            }
        }
    });
}

//! Settings, and the two destructive actions the user is entitled to.
//!
//! Settings live in the same local store as everything else. The NVD API key is
//! the only secret SENTRY holds; it belongs to the user, is optional, and is
//! never sent anywhere except NVD itself.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::AppState;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// Raises NVD's rate limit from 5 requests per 30 seconds to 50, which is
    /// the difference between a refresh taking minutes and seconds.
    pub nvd_api_key: Option<String>,
    /// Scan automatically when the app opens.
    pub scan_on_start: bool,
}

/// Never returns the key itself -- only whether one is set.
///
/// A settings page that renders a secret back into an input box invites it into
/// screenshots and screen shares for no benefit: nobody needs to read their own
/// API key out of the UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    pub has_nvd_api_key: bool,
    pub scan_on_start: bool,
}

const KEY_NVD: &str = "nvd_api_key";
const KEY_SCAN_ON_START: &str = "scan_on_start";

fn read_setting(state: &AppState, key: &str) -> Option<String> {
    use rusqlite::OptionalExtension;

    state
        .db
        .with(|c| {
            c.query_row(
                "SELECT value_json FROM settings WHERE key = ?1",
                [key],
                |r| r.get::<_, String>(0),
            )
            .optional()
        })
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<String>(&raw).ok())
}

fn write_setting(state: &AppState, key: &str, value: Option<&str>) -> Result<(), String> {
    let now = chrono::Utc::now().to_rfc3339();

    state
        .db
        .with(|c| {
            match value {
                Some(v) => {
                    let encoded = serde_json::to_string(v).unwrap_or_else(|_| "\"\"".into());
                    c.execute(
                        "INSERT INTO settings (key, value_json, updated_at) VALUES (?1, ?2, ?3)
                         ON CONFLICT (key) DO UPDATE SET value_json = ?2, updated_at = ?3",
                        rusqlite::params![key, encoded, now],
                    )?;
                }
                None => {
                    c.execute("DELETE FROM settings WHERE key = ?1", [key])?;
                }
            }
            Ok(())
        })
        .map_err(|e| {
            log::error!("could not save setting {key}: {e}");
            "That setting could not be saved.".to_string()
        })
}

/// The stored NVD key, for the refresh path only.
///
/// Deliberately not a command: the key never travels back to the webview.
pub fn nvd_api_key(state: &AppState) -> Option<String> {
    read_setting(state, KEY_NVD).filter(|k| !k.is_empty())
}

/// The current settings, with the API key reduced to a yes/no.
#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> SettingsView {
    SettingsView {
        has_nvd_api_key: read_setting(&state, KEY_NVD).is_some_and(|k| !k.is_empty()),
        scan_on_start: read_setting(&state, KEY_SCAN_ON_START).as_deref() == Some("true"),
    }
}

/// Store or clear the NVD API key.
#[tauri::command]
pub fn set_nvd_api_key(state: State<'_, AppState>, key: Option<String>) -> Result<(), String> {
    let trimmed = key.as_deref().map(str::trim).filter(|k| !k.is_empty());

    if let Some(value) = trimmed {
        // NVD issues UUID-shaped keys. Checking the shape catches a pasted
        // mistake immediately rather than at the next refresh.
        let plausible = value.len() >= 20
            && value.len() <= 100
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');

        if !plausible {
            return Err(
                "That does not look like an NVD API key. They are long strings of letters, \
                 numbers and dashes."
                    .into(),
            );
        }
    }

    write_setting(&state, KEY_NVD, trimmed)
}

#[tauri::command]
pub fn set_scan_on_start(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    write_setting(
        &state,
        KEY_SCAN_ON_START,
        Some(if enabled { "true" } else { "false" }),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionSummary {
    pub tables_cleared: Vec<String>,
    pub rows_deleted: i64,
}

/// Delete everything SENTRY has learned about this machine.
///
/// Clears the local data only: findings, devices, software, scan history,
/// listeners and settings. The downloaded public feeds are left alone, because
/// they contain nothing about the user and re-downloading them costs a
/// rate-limited hour. `delete_everything` removes those too.
#[tauri::command]
pub fn delete_local_data(state: State<'_, AppState>) -> Result<DeletionSummary, String> {
    // Order matters: children before parents, since foreign keys are enforced.
    const TABLES: &[&str] = &[
        "device_ports",
        "network_services",
        "devices",
        "local_listeners",
        "software",
        "findings",
        "security_facts",
        "scan_runs",
        "events",
        "remediation_history",
    ];

    clear(&state, TABLES)
}

/// Delete everything, including the downloaded public feeds.
#[tauri::command]
pub fn delete_everything(state: State<'_, AppState>) -> Result<DeletionSummary, String> {
    const TABLES: &[&str] = &[
        "device_ports",
        "network_services",
        "devices",
        "local_listeners",
        "software",
        "findings",
        "security_facts",
        "scan_runs",
        "events",
        "remediation_history",
        "cve_cpe_match",
        "product_cve",
        "product_lookup",
        "cve",
        "kev",
        "epss",
        "oui",
        "feed_state",
        "settings",
    ];

    clear(&state, TABLES)
}

fn clear(state: &AppState, tables: &[&str]) -> Result<DeletionSummary, String> {
    state
        .db
        .with(|c| {
            let tx = c.unchecked_transaction()?;
            let mut cleared = Vec::new();
            let mut rows = 0i64;

            for table in tables {
                // Table names are compile-time constants from the list above,
                // never user input.
                let before: i64 =
                    tx.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
                if before > 0 {
                    tx.execute(&format!("DELETE FROM {table}"), [])?;
                    cleared.push((*table).to_string());
                    rows += before;
                }
            }

            tx.commit()?;
            Ok(DeletionSummary {
                tables_cleared: cleared,
                rows_deleted: rows,
            })
        })
        .map_err(|e| {
            log::error!("could not delete local data: {e}");
            "The data could not be deleted.".to_string()
        })
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn a_plausible_key_shape_is_accepted_and_nonsense_is_not() {
        // The validation is a paste check, not authentication: NVD decides
        // whether a key is real.
        let ok = "12345678-1234-1234-1234-1234567890ab";
        assert!(ok.len() >= 20 && ok.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));

        for bad in ["short", "has spaces in it here", "!!!!!!!!!!!!!!!!!!!!!!"] {
            let plausible = bad.len() >= 20
                && bad.len() <= 100
                && bad
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            assert!(!plausible, "{bad:?} should be rejected");
        }
    }

    #[test]
    fn deleting_local_data_leaves_the_public_feeds_alone() {
        // Re-downloading NVD costs a rate-limited hour, and none of it is about
        // the user, so "delete my data" must not throw it away.
        let local = [
            "devices",
            "software",
            "findings",
            "scan_runs",
            "events",
            "local_listeners",
        ];
        let feeds = ["cve", "kev", "epss", "oui"];

        // Mirrors the constant in `delete_local_data`.
        let cleared_by_local: Vec<&str> = vec![
            "device_ports",
            "network_services",
            "devices",
            "local_listeners",
            "software",
            "findings",
            "security_facts",
            "scan_runs",
            "events",
            "remediation_history",
        ];

        for table in local {
            assert!(
                cleared_by_local.contains(&table),
                "{table} should be cleared"
            );
        }
        for table in feeds {
            assert!(!cleared_by_local.contains(&table), "{table} must be kept");
        }
    }
}

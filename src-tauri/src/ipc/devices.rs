//! Commands for the device list.
//!
//! Trust is the user's, not the scanner's. Every mutating command here changes
//! exactly one device's user-owned fields, and a scan never overwrites them.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::collectors::network::{devices, discover, interfaces, neighbors};
use crate::security::Known;
use crate::AppState;

/// One device as the UI shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRow {
    pub id: String,
    pub label: String,
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub display_name: Option<String>,
    pub device_type: String,
    pub trust: String,
    pub mac_is_random: bool,
    pub is_gateway: bool,
    pub is_self: bool,
    pub first_seen: Option<String>,
    pub last_seen: String,
    /// False for a device known from an earlier scan that did not answer
    /// this time -- idle, asleep or gone.
    pub currently_visible: bool,
}

impl From<&devices::Device> for DeviceRow {
    fn from(d: &devices::Device) -> Self {
        DeviceRow {
            id: d.id.clone(),
            label: d.label(),
            mac: d.mac.clone(),
            ip: d.ip.clone(),
            vendor: d.vendor.clone(),
            hostname: d.hostname.clone(),
            display_name: d.display_name.clone(),
            device_type: format!("{:?}", d.device_type).to_lowercase(),
            trust: d.trust.as_str().to_string(),
            mac_is_random: d.mac_is_random,
            is_gateway: d.is_gateway,
            is_self: d.is_self,
            first_seen: d.first_seen.clone(),
            last_seen: d.last_seen.clone(),
            currently_visible: d.currently_visible,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceList {
    pub devices: Vec<DeviceRow>,
    /// How many of them answered during this scan.
    pub visible_now: usize,
    /// False when the MAC manufacturer registry has not been downloaded, so
    /// the UI can explain why names are missing rather than looking broken.
    pub vendor_registry_available: bool,
    pub evidence: Vec<String>,
}

/// The current device list, read passively.
#[tauri::command]
pub async fn get_devices(state: State<'_, AppState>) -> Result<Known<DeviceList>, String> {
    let db = state.db.clone();

    let result = tauri::async_runtime::spawn_blocking(move || {
        let ifaces = interfaces::collect()?;
        let neigh = neighbors::collect()?;
        let facts = devices::build(&db, &ifaces, &neigh)?;
        let _ = devices::save(&db, &facts);
        Ok::<_, crate::security::CollectorError>(facts)
    })
    .await;

    match result {
        Ok(Ok(facts)) => Ok(Known::Known(DeviceList {
            devices: facts.devices.iter().map(DeviceRow::from).collect(),
            visible_now: facts.visible_now,
            vendor_registry_available: facts.vendor_registry_available,
            evidence: facts.evidence,
        })),
        Ok(Err(e)) => Ok(e.into_known()),
        Err(e) => {
            log::error!("device listing failed: {e}");
            Err("The device list could not be read. See the application log.".into())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SweepSummary {
    pub addresses_probed: usize,
    pub devices_found: usize,
    pub subnet: Option<String>,
    pub duration_ms: u64,
    /// False when the sweep was cancelled or skipped, so a short list is not
    /// presented as the whole network.
    pub conclusive: bool,
    pub skipped_reason: Option<String>,
    pub evidence: Vec<String>,
}

/// Actively sweep the local network for devices.
///
/// Sends an ARP request to every address in the subnet. Explicit and
/// cancellable, because unlike everything else in a scan it puts traffic on
/// the user's network.
#[tauri::command]
pub async fn discover_devices(state: State<'_, AppState>) -> Result<SweepSummary, String> {
    let db = state.db.clone();
    let cancelled = state.sweep.clone();
    cancelled.store(false, std::sync::atomic::Ordering::SeqCst);

    let result = tauri::async_runtime::spawn_blocking(move || {
        let ifaces = interfaces::collect()?;
        let sweep = discover::sweep(&ifaces, cancelled)?;

        // The sweep fills Windows' ARP cache; the passive read then sees
        // everything that answered.
        let neigh = neighbors::collect()?;
        let facts = devices::build(&db, &ifaces, &neigh)?;
        let _ = devices::save(&db, &facts);

        Ok::<_, crate::security::CollectorError>((sweep, facts.devices.len()))
    })
    .await;

    match result {
        Ok(Ok((sweep, device_count))) => Ok(SweepSummary {
            addresses_probed: sweep.addresses_probed,
            devices_found: device_count,
            subnet: sweep.subnet.clone(),
            duration_ms: sweep.duration_ms,
            conclusive: sweep.is_conclusive(),
            skipped_reason: sweep.skipped_reason.clone(),
            evidence: sweep.evidence,
        }),
        Ok(Err(e)) => Err(e.to_string()),
        Err(e) => {
            log::error!("device sweep failed: {e}");
            Err("The network sweep stopped unexpectedly. See the application log.".into())
        }
    }
}

/// Stop a running sweep. Devices found so far are kept.
#[tauri::command]
pub fn cancel_device_discovery(state: State<'_, AppState>) {
    state.sweep.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Record the user's judgement about a device.
///
/// The only way `trust` is ever written. A scan never touches it.
#[tauri::command]
pub fn set_device_trust(
    state: State<'_, AppState>,
    device_id: String,
    trust: String,
) -> Result<(), String> {
    // Validated against a fixed set rather than passed through: this value
    // reaches SQL, and the set of valid trust states is closed.
    let trust = match trust.as_str() {
        "none" | "trusted" | "flagged" => trust,
        other => return Err(format!("\"{other}\" is not a valid trust setting.")),
    };

    state
        .db
        .with(|c| {
            c.execute(
                "UPDATE devices SET trust = ?1 WHERE id = ?2",
                rusqlite::params![trust, device_id],
            )?;
            Ok(())
        })
        .map_err(|e| {
            log::error!("could not set device trust: {e}");
            "That change could not be saved.".to_string()
        })
}

/// Give a device a name the user will recognise.
#[tauri::command]
pub fn rename_device(
    state: State<'_, AppState>,
    device_id: String,
    name: String,
) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.len() > 64 {
        return Err("That name is too long (64 characters maximum).".into());
    }

    // An empty name clears the override rather than storing a blank.
    let value: Option<&str> = (!trimmed.is_empty()).then_some(trimmed);

    state
        .db
        .with(|c| {
            c.execute(
                "UPDATE devices SET display_name = ?1 WHERE id = ?2",
                rusqlite::params![value, device_id],
            )?;
            Ok(())
        })
        .map_err(|e| {
            log::error!("could not rename device: {e}");
            "That change could not be saved.".to_string()
        })
}

pub type SharedSweepControl = Arc<AtomicBool>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_row_shows_the_best_available_label() {
        let device = devices::Device {
            id: "aa".into(),
            mac: Some("40:d1:33:00:00:01".into()),
            ip: Some("192.168.1.5".into()),
            hostname: None,
            vendor: Some("Seiko Epson Corporation".into()),
            display_name: None,
            device_type: devices::DeviceType::Unknown,
            mac_is_random: false,
            is_gateway: false,
            is_self: false,
            trust: devices::Trust::None,
            first_seen: None,
            last_seen: "now".into(),
            discovered_via: "arp".into(),
            currently_visible: true,
        };

        let row = DeviceRow::from(&device);
        assert_eq!(row.label, "Seiko Epson Corporation");
        assert_eq!(row.trust, "none");
        assert_eq!(row.device_type, "unknown");
    }
}

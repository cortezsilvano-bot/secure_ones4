//! Operating-system hardening settings, read from the registry.
//!
//! These are the handful of switches that decide whether a Windows machine is
//! ordinarily configured or quietly wide open. All are plain registry reads,
//! so this collector is fast and makes no system changes.
//!
//! Every field is `Option`, and "the key does not exist" is not the same as
//! "the feature is on". Several of these settings default to secure *by the
//! key's absence* on modern Windows, and several default to insecure the same
//! way -- each is handled explicitly below rather than guessed at.

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardeningFacts {
    /// SMBv1 *server*: this PC serving files over the 1980s protocol.
    pub smb1_server_enabled: Option<bool>,
    /// SMBv1 *client*: this PC willing to speak it to someone else.
    pub smb1_client_enabled: Option<bool>,
    /// User Account Control. Off means every program runs elevated silently.
    pub uac_enabled: Option<bool>,
    /// UAC set to elevate without prompting, which defeats most of the point.
    pub uac_prompts_admin: Option<bool>,
    /// Remote Desktop accepting incoming connections.
    pub rdp_enabled: Option<bool>,
    /// RDP requiring Network Level Authentication before a session is created.
    pub rdp_nla_required: Option<bool>,
    /// AutoRun suppressed for all drive types.
    pub autorun_disabled: Option<bool>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

#[cfg(windows)]
pub fn collect() -> Result<HardeningFacts, CollectorError> {
    use windows_registry::LOCAL_MACHINE;

    let mut facts = HardeningFacts {
        collected_at: chrono::Utc::now().to_rfc3339(),
        evidence: vec!["Source: HKLM registry policy and service keys".to_string()],
        ..Default::default()
    };

    let mut note = |line: String| facts.evidence.push(line);

    // --- SMBv1 server ------------------------------------------------------
    // The value is absent on a default modern install, which means enabled is
    // *not* implied by absence: Windows 10/11 ship with the SMB1 feature
    // uninstalled. Absent therefore means "not explicitly disabled", and the
    // service key below is what settles it.
    {
        const PATH: &str = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        match LOCAL_MACHINE.open(PATH).and_then(|k| k.get_u32("SMB1")) {
            Ok(v) => {
                facts.smb1_server_enabled = Some(v != 0);
                note(format!(r"HKLM\{PATH}\SMB1 = {v}"));
            }
            Err(_) => {
                // No explicit value. Fall back to whether the SMB1 server
                // driver is present and set to start.
                let srv = service_start(r"SYSTEM\CurrentControlSet\Services\srv2");
                let smb1_driver = service_start(r"SYSTEM\CurrentControlSet\Services\mrxsmb10");
                let _ = srv;
                facts.smb1_server_enabled = smb1_driver.map(|start| start != 4);
                note(format!(
                    r"HKLM\{PATH}\SMB1 not set; mrxsmb10 Start = {}",
                    smb1_driver
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "service not installed".into())
                ));
            }
        }
    }

    // --- SMBv1 client ------------------------------------------------------
    // Start = 4 means disabled. A missing service key means the feature is not
    // installed at all, which is the desired state on a current machine.
    {
        const PATH: &str = r"SYSTEM\CurrentControlSet\Services\mrxsmb10";
        match service_start(PATH) {
            Some(start) => {
                facts.smb1_client_enabled = Some(start != 4);
                note(format!(r"HKLM\{PATH}\Start = {start} (4 = disabled)"));
            }
            None => {
                facts.smb1_client_enabled = Some(false);
                note(format!(r"HKLM\{PATH} absent (SMBv1 client not installed)"));
            }
        }
    }

    // --- UAC ---------------------------------------------------------------
    {
        const PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        if let Ok(key) = LOCAL_MACHINE.open(PATH) {
            if let Ok(v) = key.get_u32("EnableLUA") {
                facts.uac_enabled = Some(v != 0);
                note(format!(r"HKLM\{PATH}\EnableLUA = {v}"));
            }
            if let Ok(v) = key.get_u32("ConsentPromptBehaviorAdmin") {
                // 0 means elevate silently -- no prompt at all.
                facts.uac_prompts_admin = Some(v != 0);
                note(format!(
                    r"HKLM\{PATH}\ConsentPromptBehaviorAdmin = {v} (0 = elevate without prompting)"
                ));
            }
        } else {
            note(format!(r"HKLM\{PATH}: not readable"));
        }
    }

    // --- Remote Desktop ----------------------------------------------------
    {
        const PATH: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
        if let Ok(key) = LOCAL_MACHINE.open(PATH) {
            if let Ok(v) = key.get_u32("fDenyTSConnections") {
                // The value is a *denial*, so enabled is the inverse.
                facts.rdp_enabled = Some(v == 0);
                note(format!(
                    r"HKLM\{PATH}\fDenyTSConnections = {v} (1 = RDP refused)"
                ));
            }
        }

        const NLA: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
        if let Ok(v) = LOCAL_MACHINE
            .open(NLA)
            .and_then(|k| k.get_u32("UserAuthentication"))
        {
            facts.rdp_nla_required = Some(v != 0);
            note(format!(
                r"HKLM\{NLA}\UserAuthentication = {v} (1 = NLA required)"
            ));
        }
    }

    // --- AutoRun -----------------------------------------------------------
    // 0xFF disables AutoRun for every drive type. Anything less leaves at
    // least one class of removable media able to launch code on insertion.
    {
        const PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
        match LOCAL_MACHINE
            .open(PATH)
            .and_then(|k| k.get_u32("NoDriveTypeAutoRun"))
        {
            Ok(v) => {
                facts.autorun_disabled = Some(v == 0xFF);
                note(format!(
                    r"HKLM\{PATH}\NoDriveTypeAutoRun = 0x{v:02X} (0xFF = all drive types disabled)"
                ));
            }
            Err(_) => note(format!(r"HKLM\{PATH}\NoDriveTypeAutoRun not set")),
        }
    }

    Ok(facts)
}

/// A service's `Start` value: 2 automatic, 3 manual, 4 disabled.
/// `None` means the service is not installed.
#[cfg(windows)]
fn service_start(path: &str) -> Option<u32> {
    windows_registry::LOCAL_MACHINE
        .open(path)
        .ok()?
        .get_u32("Start")
        .ok()
}

#[cfg(not(windows))]
pub fn collect() -> Result<HardeningFacts, CollectorError> {
    Err(CollectorError::Unsupported(
        "Windows hardening settings are only available on Windows.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_default_to_entirely_unknown() {
        // The default must not assert anything about a machine, in either
        // direction, until a read has actually happened.
        let f = HardeningFacts::default();
        assert!(f.smb1_server_enabled.is_none());
        assert!(f.smb1_client_enabled.is_none());
        assert!(f.uac_enabled.is_none());
        assert!(f.rdp_enabled.is_none());
        assert!(f.autorun_disabled.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn collecting_on_this_machine_yields_evidence() {
        // Registry reads have no preconditions, so this must always succeed on
        // Windows and must always explain where its values came from.
        let facts = collect().expect("hardening collection should not fail");
        assert!(!facts.evidence.is_empty());
        assert!(facts.evidence.iter().any(|e| e.contains("registry")));
        assert!(!facts.collected_at.is_empty());
    }
}

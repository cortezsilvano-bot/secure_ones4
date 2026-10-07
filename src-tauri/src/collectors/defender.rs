//! Microsoft Defender status, read from WMI.
//!
//! Source: `root\Microsoft\Windows\Defender` class `MSFT_MpComputerStatus` --
//! the same provider `Get-MpComputerStatus` reads. Queried over COM directly
//! rather than by shelling out to PowerShell: spawning a shell from a security
//! tool is both slow and an injection surface we have no reason to open.

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

#[cfg(windows)]
const NAMESPACE: &str = r"root\Microsoft\Windows\Defender";

/// What Defender reports about itself. Every field is optional because the
/// property set differs across Windows builds, and a field we could not read
/// must surface as unknown rather than as `false`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefenderFacts {
    /// The antimalware service itself is running.
    pub am_service_enabled: Option<bool>,
    pub antivirus_enabled: Option<bool>,
    pub antispyware_enabled: Option<bool>,
    pub real_time_protection_enabled: Option<bool>,
    pub behavior_monitor_enabled: Option<bool>,
    pub on_access_protection_enabled: Option<bool>,
    /// Scanning of downloads and attachments (IOfficeAntivirus).
    pub ioav_protection_enabled: Option<bool>,
    /// Tamper Protection: blocks other software from disabling Defender.
    pub is_tamper_protected: Option<bool>,
    /// `Normal`, `Passive`, `EDR Block Mode`, `SxS Passive Mode` -- passive
    /// means another product owns real-time protection.
    pub am_running_mode: Option<String>,
    pub antivirus_signature_version: Option<String>,
    pub antivirus_signature_last_updated: Option<String>,
    pub antivirus_signature_age_days: Option<u32>,
    pub quick_scan_age_days: Option<u32>,
    pub full_scan_age_days: Option<u32>,
    /// Verbatim provenance for every value above, shown in the UI's evidence pane.
    pub evidence: Vec<String>,
    pub collected_at: String,
}

/// Read Defender's current state.
#[cfg(windows)]
pub fn collect() -> Result<DefenderFacts, CollectorError> {
    use super::wmi_util as w;

    let rows = w::query(NAMESPACE, "SELECT * FROM MSFT_MpComputerStatus")?;

    let row = rows.first().ok_or_else(|| {
        CollectorError::Unavailable(
        "Defender's WMI provider returned no status record. The Defender service may be stopped \
         or replaced by another antivirus product."
            .into(),
    )
    })?;

    let mut facts = DefenderFacts {
        am_service_enabled: w::get_bool(row, "AMServiceEnabled"),
        antivirus_enabled: w::get_bool(row, "AntivirusEnabled"),
        antispyware_enabled: w::get_bool(row, "AntispywareEnabled"),
        real_time_protection_enabled: w::get_bool(row, "RealTimeProtectionEnabled"),
        behavior_monitor_enabled: w::get_bool(row, "BehaviorMonitorEnabled"),
        on_access_protection_enabled: w::get_bool(row, "OnAccessProtectionEnabled"),
        ioav_protection_enabled: w::get_bool(row, "IoavProtectionEnabled"),
        is_tamper_protected: w::get_bool(row, "IsTamperProtected"),
        am_running_mode: w::get_string(row, "AMRunningMode"),
        antivirus_signature_version: w::get_string(row, "AntivirusSignatureVersion"),
        antivirus_signature_last_updated: w::get_datetime_rfc3339(
            row,
            "AntivirusSignatureLastUpdated",
        ),
        antivirus_signature_age_days: w::get_u32(row, "AntivirusSignatureAge"),
        quick_scan_age_days: w::get_u32(row, "QuickScanAge"),
        full_scan_age_days: w::get_u32(row, "FullScanAge"),
        evidence: Vec::new(),
        collected_at: chrono::Utc::now().to_rfc3339(),
    };

    facts.evidence = build_evidence(&facts);
    Ok(facts)
}

#[cfg(not(windows))]
pub fn collect() -> Result<DefenderFacts, CollectorError> {
    Err(CollectorError::Unsupported(
        "Microsoft Defender status is only available on Windows.".into(),
    ))
}

/// Provenance lines. These describe what was actually read -- never a claim
/// about a check that did not run.
fn build_evidence(f: &DefenderFacts) -> Vec<String> {
    let mut ev = vec![
        r"WMI namespace: root\Microsoft\Windows\Defender".to_string(),
        "WMI class: MSFT_MpComputerStatus".to_string(),
    ];

    let mut push = |label: &str, value: Option<String>| {
        if let Some(v) = value {
            ev.push(format!("{label}: {v}"));
        }
    };

    push(
        "AMServiceEnabled",
        f.am_service_enabled.map(|b| b.to_string()),
    );
    push(
        "RealTimeProtectionEnabled",
        f.real_time_protection_enabled.map(|b| b.to_string()),
    );
    push(
        "IsTamperProtected",
        f.is_tamper_protected.map(|b| b.to_string()),
    );
    push("AMRunningMode", f.am_running_mode.clone());
    push(
        "AntivirusSignatureVersion",
        f.antivirus_signature_version.clone(),
    );
    push(
        "AntivirusSignatureLastUpdated",
        f.antivirus_signature_last_updated.clone(),
    );
    push(
        "AntivirusSignatureAge",
        f.antivirus_signature_age_days
            .map(|d| format!("{d} day(s)")),
    );

    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_omits_fields_that_were_not_read() {
        // A field we could not read must leave no trace in the evidence pane;
        // an absent line is honest, a line reading "false" would not be.
        let facts = DefenderFacts {
            real_time_protection_enabled: Some(true),
            is_tamper_protected: None,
            ..Default::default()
        };

        let ev = build_evidence(&facts);
        assert!(ev.iter().any(|l| l == "RealTimeProtectionEnabled: true"));
        assert!(!ev.iter().any(|l| l.starts_with("IsTamperProtected")));
    }

    #[test]
    fn evidence_always_names_its_source() {
        let ev = build_evidence(&DefenderFacts::default());
        assert!(ev.iter().any(|l| l.contains("MSFT_MpComputerStatus")));
    }
}

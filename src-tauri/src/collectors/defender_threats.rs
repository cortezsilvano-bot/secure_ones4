//! Defender's own detection history, from `MSFT_MpThreatDetection` and
//! `MSFT_MpThreat`.
//!
//! This is what SENTRY shows instead of running its own malware scanner.
//! Defender already scans every file on the machine continuously; duplicating
//! that with a second engine would be slower, less accurate, and would fight
//! for the same files. What Defender does *not* do well is tell a
//! non-technical user what it has found and whether it actually dealt with it.
//!
//! The distinction that matters is between a threat that was **handled** and
//! one that is **still active**. Defender's UI tends to show both as history
//! entries. A quarantine that failed, or a threat marked "allowed", is a live
//! problem sitting in a list that looks like a record of past events.

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

#[cfg(windows)]
const NAMESPACE: &str = r"root\Microsoft\Windows\Defender";

/// What Defender did about a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatStatus {
    /// Found, nothing done yet.
    Detected,
    Cleaned,
    Quarantined,
    Removed,
    /// The user or a policy told Defender to permit it.
    Allowed,
    Blocked,
    /// Defender tried to deal with it and could not.
    ActionFailed,
    /// A status Microsoft has not documented.
    Other(u32),
}

impl ThreatStatus {
    fn from_raw(value: u32) -> ThreatStatus {
        match value {
            1 => ThreatStatus::Detected,
            2 => ThreatStatus::Cleaned,
            3 => ThreatStatus::Quarantined,
            4 => ThreatStatus::Removed,
            5 => ThreatStatus::Allowed,
            6 => ThreatStatus::Blocked,
            // The 1xx range is Defender's failure codes: quarantine failed,
            // remove failed, clean failed and so on.
            100..=199 => ThreatStatus::ActionFailed,
            other => ThreatStatus::Other(other),
        }
    }

    /// Whether the threat has actually been dealt with.
    ///
    /// `Detected` is deliberately *not* resolved: it means Defender found
    /// something and has not yet acted on it.
    pub fn is_resolved(&self) -> bool {
        matches!(
            self,
            ThreatStatus::Cleaned
                | ThreatStatus::Quarantined
                | ThreatStatus::Removed
                | ThreatStatus::Blocked
        )
    }

    pub fn describe(&self) -> String {
        match self {
            ThreatStatus::Detected => "found, not yet dealt with".to_string(),
            ThreatStatus::Cleaned => "cleaned".to_string(),
            ThreatStatus::Quarantined => "quarantined".to_string(),
            ThreatStatus::Removed => "removed".to_string(),
            ThreatStatus::Allowed => "allowed to run".to_string(),
            ThreatStatus::Blocked => "blocked".to_string(),
            ThreatStatus::ActionFailed => "Defender tried to remove it and failed".to_string(),
            ThreatStatus::Other(v) => format!("unrecognised status ({v})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSeverity {
    Low,
    Moderate,
    High,
    Severe,
    Unknown,
}

impl ThreatSeverity {
    fn from_raw(value: u32) -> ThreatSeverity {
        match value {
            1 => ThreatSeverity::Low,
            2 => ThreatSeverity::Moderate,
            3 => ThreatSeverity::High,
            4 | 5 => ThreatSeverity::Severe,
            _ => ThreatSeverity::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    pub detection_id: Option<String>,
    /// Defender's own name, e.g. "Trojan:Win32/Wacatac.B!ml".
    pub threat_name: Option<String>,
    pub severity: ThreatSeverity,
    pub status: ThreatStatus,
    /// Files or registry keys involved.
    pub resources: Vec<String>,
    pub process_name: Option<String>,
    pub detected_at: Option<String>,
    pub remediated_at: Option<String>,
    /// Defender's own flag for whether the malicious code ran before it was
    /// caught. The difference between a near miss and an incident.
    pub did_execute: Option<bool>,
    /// True when Defender reported the remediation action succeeded.
    pub action_succeeded: Option<bool>,
}

impl Detection {
    /// The detection still needs a human to do something about it.
    pub fn needs_attention(&self) -> bool {
        !self.status.is_resolved() || self.action_succeeded == Some(false)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatFacts {
    pub detections: Vec<Detection>,
    /// Threats Defender still considers active on this machine.
    pub active_threats: Vec<String>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl ThreatFacts {
    pub fn unresolved(&self) -> impl Iterator<Item = &Detection> {
        self.detections.iter().filter(|d| d.needs_attention())
    }

    pub fn worst_severity(&self) -> Option<ThreatSeverity> {
        self.unresolved().map(|d| d.severity).max()
    }
}

#[cfg(windows)]
pub fn collect() -> Result<ThreatFacts, CollectorError> {
    use super::wmi_util as w;
    use std::collections::HashMap;

    let mut facts = ThreatFacts {
        collected_at: chrono::Utc::now().to_rfc3339(),
        evidence: vec![
            r"WMI namespace: root\Microsoft\Windows\Defender".to_string(),
            "WMI classes: MSFT_MpThreatDetection, MSFT_MpThreat".to_string(),
        ],
        ..Default::default()
    };

    // The threat catalogue carries the human-readable names; detections carry
    // what happened. They are joined on ThreatID.
    let mut names: HashMap<u64, String> = HashMap::new();
    let mut severities: HashMap<u64, u32> = HashMap::new();

    if let Ok(threats) = w::query(NAMESPACE, "SELECT * FROM MSFT_MpThreat") {
        for row in &threats {
            let Some(id) = w::get_u64(row, "ThreatID") else {
                continue;
            };

            if let Some(name) = w::get_string(row, "ThreatName") {
                names.insert(id, name.clone());

                // A threat flagged active is still present on the machine.
                if w::get_bool(row, "IsActive") == Some(true) {
                    facts.active_threats.push(name);
                }
            }
            if let Some(severity) = w::get_u32(row, "SeverityID") {
                severities.insert(id, severity);
            }
        }
    }

    let detections = w::query(NAMESPACE, "SELECT * FROM MSFT_MpThreatDetection")?;

    for row in &detections {
        let threat_id = w::get_u64(row, "ThreatID");

        facts.detections.push(Detection {
            detection_id: w::get_u64(row, "DetectionID")
                .map(|v| v.to_string())
                .or_else(|| w::get_string(row, "DetectionID")),
            threat_name: threat_id.and_then(|id| names.get(&id).cloned()),
            severity: threat_id
                .and_then(|id| severities.get(&id).copied())
                .map(ThreatSeverity::from_raw)
                .unwrap_or(ThreatSeverity::Unknown),
            status: w::get_u32(row, "ThreatStatusID")
                .map(ThreatStatus::from_raw)
                .unwrap_or(ThreatStatus::Other(0)),
            resources: w::get_string_list(row, "Resources"),
            process_name: w::get_string(row, "ProcessName"),
            detected_at: w::get_datetime_rfc3339(row, "InitialDetectionTime"),
            remediated_at: w::get_datetime_rfc3339(row, "RemediationTime"),
            did_execute: w::get_bool(row, "CurrentThreatExecutionStatusID")
                .or_else(|| w::get_u32(row, "CurrentThreatExecutionStatusID").map(|v| v != 0)),
            action_succeeded: w::get_bool(row, "ActionSuccess"),
        });
    }

    // Newest first: recent detections are what a user needs to see.
    facts
        .detections
        .sort_by(|a, b| b.detected_at.cmp(&a.detected_at));

    facts.evidence.push(format!(
        "{} detection(s) in Defender's history, {} needing attention, {} threat(s) still active",
        facts.detections.len(),
        facts.unresolved().count(),
        facts.active_threats.len()
    ));

    Ok(facts)
}

#[cfg(not(windows))]
pub fn collect() -> Result<ThreatFacts, CollectorError> {
    Err(CollectorError::Unsupported(
        "Defender detection history is only available on Windows.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection(status: ThreatStatus, action_succeeded: Option<bool>) -> Detection {
        Detection {
            detection_id: Some("1".into()),
            threat_name: Some("Trojan:Win32/Wacatac.B!ml".into()),
            severity: ThreatSeverity::High,
            status,
            resources: vec![r"file:_C:\Users\x\Downloads\thing.exe".into()],
            process_name: None,
            detected_at: Some("2026-09-17T10:00:00+00:00".into()),
            remediated_at: None,
            did_execute: Some(false),
            action_succeeded,
        }
    }

    #[test]
    fn handled_threats_are_resolved() {
        for status in [
            ThreatStatus::Cleaned,
            ThreatStatus::Quarantined,
            ThreatStatus::Removed,
            ThreatStatus::Blocked,
        ] {
            assert!(
                status.is_resolved(),
                "{status:?} should count as dealt with"
            );
            assert!(!detection(status, Some(true)).needs_attention());
        }
    }

    #[test]
    fn a_merely_detected_threat_still_needs_attention() {
        // The important one: "Detected" means found and not yet acted on.
        assert!(!ThreatStatus::Detected.is_resolved());
        assert!(detection(ThreatStatus::Detected, None).needs_attention());
    }

    #[test]
    fn an_allowed_threat_needs_attention() {
        // Someone told Defender to permit this. It is still malware.
        assert!(!ThreatStatus::Allowed.is_resolved());
        assert!(detection(ThreatStatus::Allowed, Some(true)).needs_attention());
    }

    #[test]
    fn a_failed_removal_needs_attention_despite_a_resolved_status() {
        // Quarantined-but-failed is the nastiest case: the history row looks
        // like a success and the file is still there.
        let d = detection(ThreatStatus::Quarantined, Some(false));
        assert!(
            d.needs_attention(),
            "a failed action must not be read as handled"
        );
    }

    #[test]
    fn failure_status_codes_map_to_action_failed() {
        assert_eq!(ThreatStatus::from_raw(102), ThreatStatus::ActionFailed);
        assert_eq!(ThreatStatus::from_raw(107), ThreatStatus::ActionFailed);
        assert!(!ThreatStatus::ActionFailed.is_resolved());
    }

    #[test]
    fn undocumented_statuses_report_their_number() {
        assert_eq!(ThreatStatus::from_raw(9999), ThreatStatus::Other(9999));
        assert!(ThreatStatus::from_raw(9999).describe().contains("9999"));
        assert!(
            !ThreatStatus::Other(9999).is_resolved(),
            "unknown is not resolved"
        );
    }

    #[test]
    fn severities_order_from_low_to_severe() {
        assert!(ThreatSeverity::Severe > ThreatSeverity::High);
        assert!(ThreatSeverity::High > ThreatSeverity::Moderate);
        assert_eq!(ThreatSeverity::from_raw(4), ThreatSeverity::Severe);
        assert_eq!(ThreatSeverity::from_raw(5), ThreatSeverity::Severe);
        assert_eq!(ThreatSeverity::from_raw(77), ThreatSeverity::Unknown);
    }

    #[test]
    fn worst_severity_considers_only_unresolved_detections() {
        let facts = ThreatFacts {
            detections: vec![
                Detection {
                    severity: ThreatSeverity::Severe,
                    ..detection(ThreatStatus::Quarantined, Some(true))
                },
                Detection {
                    severity: ThreatSeverity::Low,
                    ..detection(ThreatStatus::Detected, None)
                },
            ],
            ..Default::default()
        };

        assert_eq!(facts.unresolved().count(), 1);
        assert_eq!(
            facts.worst_severity(),
            Some(ThreatSeverity::Low),
            "a handled severe threat must not drive the current severity"
        );
    }

    #[test]
    fn a_clean_history_has_nothing_unresolved() {
        let facts = ThreatFacts {
            detections: vec![detection(ThreatStatus::Quarantined, Some(true))],
            ..Default::default()
        };
        assert_eq!(facts.unresolved().count(), 0);
        assert_eq!(facts.worst_severity(), None);
    }

    #[cfg(windows)]
    #[test]
    fn reading_the_history_on_this_machine_works() {
        let facts = collect().expect("Defender history should be readable");
        assert!(facts
            .evidence
            .iter()
            .any(|e| e.contains("MSFT_MpThreatDetection")));
        // A clean machine legitimately has an empty history; only the call
        // succeeding and reporting its provenance is asserted.
    }
}

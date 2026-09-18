//! Rules over Microsoft Defender state.
//!
//! Each rule reads one or more `Option` fields and returns early when the field
//! is `None`. That is deliberate: a property Windows did not report is not
//! evidence of a problem, and inventing a finding from missing data would be
//! the same failure as inventing a clean bill of health from it.

use crate::collectors::defender::DefenderFacts;
use crate::findings::{Confidence, Finding, FindingBuilder, FixRisk, Severity};

const SOURCE: &str = "windows.defender";
const CATEGORY: &str = "Malware Protection";
const WMI_CLASS: &str = "WMI class: MSFT_MpComputerStatus";

/// Signatures older than this are treated as stale. Defender normally updates
/// daily; a week without one means updates are broken, not merely late.
const STALE_SIGNATURE_DAYS: u32 = 7;

/// Beyond this, stale definitions stop being a warning and become a real gap.
const ABANDONED_SIGNATURE_DAYS: u32 = 30;

pub fn evaluate(f: &DefenderFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    // Defender reports "Passive" or "SxS Passive Mode" when a third-party
    // product owns real-time protection. Several rules below would be actively
    // misleading in that state, so it is computed once here.
    let passive = f
        .am_running_mode
        .as_deref()
        .is_some_and(|m| m.to_ascii_lowercase().contains("passive"));

    // DEF-001 -- the antimalware service itself is not running.
    if f.am_service_enabled == Some(false) {
        out.push(
            FindingBuilder::new("DEF-001", CATEGORY, Severity::Critical, "Defender is turned off")
                .what("The Microsoft Defender antimalware service is not running.")
                .why(
                    "With the service stopped, nothing is scanning this PC for malware. Files you \
                     download or open are not checked at all.",
                )
                .evidence(vec![WMI_CLASS.to_string(), "AMServiceEnabled: false".to_string()])
                .remediation(
                    "Start Microsoft Defender Antivirus, or confirm another antivirus product is protecting this PC.",
                    false,
                    FixRisk::Manual,
                )
                .source(SOURCE)
                .build(),
        );
    }

    // DEF-002 -- real-time protection off while Defender is the active product.
    // Suppressed in passive mode, where another product legitimately owns it
    // and DEF-003 describes the situation instead.
    if f.real_time_protection_enabled == Some(false) && !passive {
        out.push(
            FindingBuilder::new("DEF-002", CATEGORY, Severity::Critical, "Real-time protection is off")
                .what("Defender is running, but real-time protection is disabled.")
                .why(
                    "Real-time protection is what catches malware as it arrives. Without it a threat \
                     is only found during a manual scan, which is usually long after the damage is done.",
                )
                .evidence(vec![
                    WMI_CLASS.to_string(),
                    "RealTimeProtectionEnabled: false".to_string(),
                    format!(
                        "AMRunningMode: {}",
                        f.am_running_mode.as_deref().unwrap_or("unreported")
                    ),
                ])
                .remediation(
                    "Turn on real-time protection in Windows Security, under Virus & threat protection.",
                    true,
                    FixRisk::Safe,
                )
                .source(SOURCE)
                .build(),
        );
    }

    // DEF-003 -- Defender has stood down for a third-party product. Worth
    // stating plainly rather than alarming about: it is a normal arrangement,
    // but it means SENTRY can no longer see what is being scanned.
    if passive {
        out.push(
            FindingBuilder::new(
                "DEF-003",
                CATEGORY,
                Severity::Attention,
                "Another antivirus is in charge",
            )
            .what(
                "Defender has handed real-time protection to a different antivirus product and is \
                     running in passive mode.",
            )
            .why(
                "This is normal when you have installed another antivirus. SENTRY cannot confirm \
                     what that product is scanning, so check that it is enabled and up to date.",
            )
            .confidence(Confidence::Confirmed)
            .evidence(vec![
                WMI_CLASS.to_string(),
                format!(
                    "AMRunningMode: {}",
                    f.am_running_mode.as_deref().unwrap_or("passive")
                ),
            ])
            .remediation(
                "Open your other antivirus product and confirm it is enabled and current.",
                false,
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
    }

    // DEF-004 -- stale definitions.
    if let Some(age) = f.antivirus_signature_age_days {
        if age >= STALE_SIGNATURE_DAYS {
            let severity = if age >= ABANDONED_SIGNATURE_DAYS {
                Severity::Critical
            } else {
                Severity::Warning
            };

            let mut evidence = vec![
                WMI_CLASS.to_string(),
                format!("AntivirusSignatureAge: {age} day(s)"),
            ];
            if let Some(v) = &f.antivirus_signature_version {
                evidence.push(format!("AntivirusSignatureVersion: {v}"));
            }
            if let Some(t) = &f.antivirus_signature_last_updated {
                evidence.push(format!("AntivirusSignatureLastUpdated: {t}"));
            }

            out.push(
                FindingBuilder::new("DEF-004", CATEGORY, severity, "Malware definitions are out of date")
                    .what(&format!(
                        "Defender's malware definitions were last updated {age} days ago."
                    ))
                    .why(
                        "Definitions are how Defender recognises known threats. Ones this old will not \
                         recognise anything discovered since, which in practice is most of what is circulating.",
                    )
                    .evidence(evidence)
                    .remediation(
                        "Check for updates in Windows Security, under Virus & threat protection, Protection updates.",
                        true,
                        FixRisk::Safe,
                    )
                    .source(SOURCE)
                    .build(),
            );
        }
    }

    // DEF-005 -- tamper protection off.
    if f.is_tamper_protected == Some(false) {
        out.push(
            FindingBuilder::new("DEF-005", CATEGORY, Severity::Warning, "Tamper Protection is off")
                .what("Tamper Protection is disabled, so other software can change Defender's settings.")
                .why(
                    "Modern malware often disables antivirus before doing anything else. Tamper \
                     Protection is the safeguard that stops it, and it is not currently in place.",
                )
                .evidence(vec![WMI_CLASS.to_string(), "IsTamperProtected: false".to_string()])
                .remediation(
                    "Turn on Tamper Protection in Windows Security, under Virus & threat protection, Manage settings.",
                    false,
                    FixRisk::Manual,
                )
                .source(SOURCE)
                .build(),
        );
    }

    // DEF-006 -- behaviour monitoring off. Also suppressed in passive mode.
    if f.behavior_monitor_enabled == Some(false) && !passive {
        out.push(
            FindingBuilder::new("DEF-006", CATEGORY, Severity::Warning, "Behaviour monitoring is off")
                .what("Defender's behaviour monitoring is disabled.")
                .why(
                    "Behaviour monitoring catches malware that no definition recognises yet, by noticing \
                     what a program does rather than what it looks like.",
                )
                .evidence(vec![WMI_CLASS.to_string(), "BehaviorMonitorEnabled: false".to_string()])
                .remediation(
                    "Re-enable real-time protection, which includes behaviour monitoring.",
                    true,
                    FixRisk::Safe,
                )
                .source(SOURCE)
                .build(),
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> DefenderFacts {
        DefenderFacts {
            am_service_enabled: Some(true),
            antivirus_enabled: Some(true),
            antispyware_enabled: Some(true),
            real_time_protection_enabled: Some(true),
            behavior_monitor_enabled: Some(true),
            on_access_protection_enabled: Some(true),
            ioav_protection_enabled: Some(true),
            is_tamper_protected: Some(true),
            am_running_mode: Some("Normal".into()),
            antivirus_signature_version: Some("1.459.260.0".into()),
            antivirus_signature_last_updated: Some("2026-09-17T16:02:20+00:00".into()),
            antivirus_signature_age_days: Some(0),
            quick_scan_age_days: Some(0),
            full_scan_age_days: None,
            evidence: vec![],
            collected_at: "2026-09-17T16:00:00+00:00".into(),
        }
    }

    fn rule_ids(f: &DefenderFacts) -> Vec<String> {
        evaluate(f).into_iter().map(|x| x.rule_id).collect()
    }

    #[test]
    fn a_healthy_machine_produces_no_findings() {
        assert!(evaluate(&healthy()).is_empty());
    }

    #[test]
    fn unknown_fields_produce_no_findings() {
        // Every field unreported. Nothing is known, so nothing may be claimed
        // in either direction. Coverage, not a rule, tells the user this.
        assert!(
            evaluate(&DefenderFacts::default()).is_empty(),
            "missing data must not be read as a problem"
        );
    }

    #[test]
    fn service_disabled_is_critical() {
        let mut f = healthy();
        f.am_service_enabled = Some(false);

        let def001 = evaluate(&f)
            .into_iter()
            .find(|x| x.rule_id == "DEF-001")
            .expect("DEF-001 should fire");
        assert_eq!(def001.severity, Severity::Critical);
        assert!(!def001.evidence.is_empty());
    }

    #[test]
    fn realtime_off_is_critical() {
        let mut f = healthy();
        f.real_time_protection_enabled = Some(false);
        assert!(rule_ids(&f).contains(&"DEF-002".to_string()));
    }

    #[test]
    fn passive_mode_reports_handover_not_alarm() {
        let mut f = healthy();
        f.am_running_mode = Some("SxS Passive Mode".into());
        f.real_time_protection_enabled = Some(false);
        f.behavior_monitor_enabled = Some(false);

        let ids = rule_ids(&f);
        // The handover is reported...
        assert!(ids.contains(&"DEF-003".to_string()));
        // ...and the alarms that would be wrong in passive mode stay quiet.
        assert!(
            !ids.contains(&"DEF-002".to_string()),
            "DEF-002 must not fire in passive mode"
        );
        assert!(
            !ids.contains(&"DEF-006".to_string()),
            "DEF-006 must not fire in passive mode"
        );
    }

    #[test]
    fn signature_age_escalates_with_time() {
        let mut f = healthy();

        f.antivirus_signature_age_days = Some(STALE_SIGNATURE_DAYS - 1);
        assert!(
            !rule_ids(&f).contains(&"DEF-004".to_string()),
            "six days is not yet stale"
        );

        f.antivirus_signature_age_days = Some(STALE_SIGNATURE_DAYS + 1);
        let warn = evaluate(&f)
            .into_iter()
            .find(|x| x.rule_id == "DEF-004")
            .unwrap();
        assert_eq!(warn.severity, Severity::Warning);

        f.antivirus_signature_age_days = Some(ABANDONED_SIGNATURE_DAYS + 15);
        let crit = evaluate(&f)
            .into_iter()
            .find(|x| x.rule_id == "DEF-004")
            .unwrap();
        assert_eq!(crit.severity, Severity::Critical);
    }

    #[test]
    fn tamper_protection_off_is_reported() {
        let mut f = healthy();
        f.is_tamper_protected = Some(false);
        assert!(rule_ids(&f).contains(&"DEF-005".to_string()));
    }

    #[test]
    fn every_finding_carries_evidence_and_a_rationale() {
        let mut f = healthy();
        f.am_service_enabled = Some(false);
        f.real_time_protection_enabled = Some(false);
        f.is_tamper_protected = Some(false);
        f.antivirus_signature_age_days = Some(99);

        let found = evaluate(&f);
        assert!(
            found.len() >= 4,
            "expected several findings, got {}",
            found.len()
        );

        for finding in found {
            assert!(
                !finding.evidence.is_empty(),
                "{} has no evidence",
                finding.rule_id
            );
            assert!(!finding.id.is_empty(), "{} has no id", finding.rule_id);
            assert!(
                !finding.why_it_matters.is_empty(),
                "{} has no rationale",
                finding.rule_id
            );
            assert_eq!(finding.source, SOURCE);
        }
    }
}

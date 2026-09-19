//! Rules over Windows Update state.
//!
//! Two different problems live here and they are kept apart deliberately:
//! updates that are *pending*, and update checking that has *stopped working*.
//! The second is worse and less visible -- a machine that has not checked in
//! two months reports zero pending updates, which looks identical to a machine
//! that is fully patched.

use crate::collectors::updates::UpdateFacts;
use crate::findings::{Confidence, Finding, FindingBuilder, FixRisk, Severity};

const SOURCE: &str = "windows.update";
const CATEGORY: &str = "Updates";

/// Windows checks daily by default. Two weeks of silence means the mechanism
/// is broken, not that the machine has been quiet.
const STALE_CHECK_DAYS: i64 = 14;
const ABANDONED_CHECK_DAYS: i64 = 45;

pub fn evaluate(f: &UpdateFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    let security: Vec<_> = f.security_updates().collect();

    // UPD-001 -- pending security updates.
    if !security.is_empty() {
        // Microsoft's own rating drives severity; "Critical" from MSRC means
        // remotely exploitable without user action.
        let worst_is_critical = security.iter().any(|u| {
            u.msrc_severity
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("critical"))
        });

        let mut evidence = vec![
            "COM interface: IUpdateSearcher (wuapi.dll)".to_string(),
            "Search criteria: IsInstalled=0 AND IsHidden=0".to_string(),
            format!("Pending security updates: {}", security.len()),
        ];
        for u in security.iter().take(10) {
            let kbs = if u.kb_article_ids.is_empty() {
                String::new()
            } else {
                format!(" [KB{}]", u.kb_article_ids.join(", KB"))
            };
            evidence.push(format!(
                "  {} (MSRC: {}){kbs}",
                u.title,
                u.msrc_severity.as_deref().unwrap_or("unrated")
            ));
        }

        out.push(
            FindingBuilder::new(
                "UPD-001",
                CATEGORY,
                if worst_is_critical { Severity::Critical } else { Severity::Warning },
                &format!(
                    "{} security update{} waiting to install",
                    security.len(),
                    if security.len() == 1 { "" } else { "s" }
                ),
            )
            .what(&format!(
                "Windows has {} security update{} downloaded or available that {} not been installed.",
                security.len(),
                if security.len() == 1 { "" } else { "s" },
                if security.len() == 1 { "has" } else { "have" }
            ))
            .why(
                "Security updates fix holes that are already public. Until they are installed, this \
                 PC is exposed to problems Microsoft has already told attackers about by publishing \
                 the fix.",
            )
            .evidence(evidence)
            .remediation(
                "Install the pending updates from Settings, under Windows Update.",
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
    }

    // UPD-002 -- a fix is installed but not in effect until the machine restarts.
    if f.reboot_required == Some(true) {
        out.push(
            FindingBuilder::new(
                "UPD-002",
                CATEGORY,
                Severity::Warning,
                "A restart is needed to finish updating",
            )
            .what("Updates have been installed but will not take effect until this PC restarts.")
            .why(
                "Until the restart happens the old, vulnerable code is still the code that is \
                     running. The update is on disk, not in force.",
            )
            .evidence(vec![
                "COM interface: ISystemInformation (wuapi.dll)".to_string(),
                "RebootRequired: true".to_string(),
            ])
            .remediation("Restart this PC when convenient.", FixRisk::Manual)
            .source(SOURCE)
            .build(),
        );
    }

    // UPD-003 -- update checking itself has stopped.
    if let Some(age) = f.search_age_days {
        if age >= STALE_CHECK_DAYS {
            let severity = if age >= ABANDONED_CHECK_DAYS {
                Severity::Critical
            } else {
                Severity::Warning
            };

            out.push(
                FindingBuilder::new("UPD-003", CATEGORY, severity, "Windows has stopped checking for updates")
                    .what(&format!(
                        "Windows last successfully checked for updates {age} days ago."
                    ))
                    .why(
                        "This matters more than it looks. A PC that cannot check for updates will \
                         report that it has none pending, which is indistinguishable from being \
                         fully up to date. It is not up to date; it is unaware.",
                    )
                    .evidence(vec![
                        r"Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update".to_string(),
                        format!(
                            "Last successful check: {} (UTC)",
                            f.last_search_success.as_deref().unwrap_or("unknown")
                        ),
                        format!("Age: {age} day(s)"),
                    ])
                    .remediation(
                        "Open Settings, then Windows Update, and select Check for updates. If it fails, the Windows Update service may be stopped or blocked by policy.",
                        FixRisk::Manual,
                    )
                    .source(SOURCE)
                    .build(),
            );
        }
    } else if !f.pending.is_empty() {
        // We have update data but no idea how old it is. Say so rather than
        // presenting the count as current.
        out.push(
            FindingBuilder::new("UPD-004", CATEGORY, Severity::Attention, "Update information may be out of date")
                .what("Windows did not record when it last checked for updates.")
                .why(
                    "The pending updates listed here come from cached information. Without a check \
                     date there is no way to tell how current that cache is.",
                )
                .confidence(Confidence::Likely)
                .evidence(vec![
                    r"Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update".to_string(),
                    "Last successful check: not recorded".to_string(),
                ])
                .remediation(
                    "Open Settings, then Windows Update, and select Check for updates.",
                    FixRisk::Manual,
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
    use crate::collectors::updates::PendingUpdate;

    fn update(title: &str, severity: Option<&str>) -> PendingUpdate {
        PendingUpdate {
            title: title.to_string(),
            msrc_severity: severity.map(str::to_string),
            is_security_update: severity.is_some(),
            kb_article_ids: vec!["5034123".into()],
            is_downloaded: true,
            is_mandatory: false,
        }
    }

    fn healthy() -> UpdateFacts {
        UpdateFacts {
            pending: vec![],
            reboot_required: Some(false),
            last_search_success: Some("2026-09-17 20:19:19".into()),
            last_install_success: None,
            search_age_days: Some(0),
            evidence: vec![],
            collected_at: "2026-09-17T20:30:00+00:00".into(),
        }
    }

    fn rule_ids(f: &UpdateFacts) -> Vec<String> {
        evaluate(f).into_iter().map(|x| x.rule_id).collect()
    }

    #[test]
    fn an_up_to_date_machine_produces_no_findings() {
        assert!(evaluate(&healthy()).is_empty());
    }

    #[test]
    fn a_pending_driver_update_is_not_a_security_finding() {
        let mut f = healthy();
        f.pending = vec![update("Driver update for a printer", None)];
        assert!(
            !rule_ids(&f).contains(&"UPD-001".to_string()),
            "non-security updates must not raise a security finding"
        );
    }

    #[test]
    fn pending_security_updates_are_reported() {
        let mut f = healthy();
        f.pending = vec![update("Security Update", Some("Important"))];

        let found = evaluate(&f);
        let u = found
            .iter()
            .find(|x| x.rule_id == "UPD-001")
            .expect("UPD-001");
        assert_eq!(u.severity, Severity::Warning);
        assert!(u.evidence.iter().any(|e| e.contains("KB5034123")));
    }

    #[test]
    fn an_msrc_critical_update_escalates() {
        let mut f = healthy();
        f.pending = vec![
            update("Ordinary", Some("Moderate")),
            update("Bad one", Some("Critical")),
        ];
        let found = evaluate(&f);
        let u = found.iter().find(|x| x.rule_id == "UPD-001").unwrap();
        assert_eq!(u.severity, Severity::Critical);
    }

    #[test]
    fn a_pending_reboot_is_reported() {
        let mut f = healthy();
        f.reboot_required = Some(true);
        assert!(rule_ids(&f).contains(&"UPD-002".to_string()));
    }

    #[test]
    fn an_unreported_reboot_state_raises_nothing() {
        let mut f = healthy();
        f.reboot_required = None;
        assert!(!rule_ids(&f).contains(&"UPD-002".to_string()));
    }

    #[test]
    fn stale_update_checking_escalates_with_time() {
        let mut f = healthy();

        f.search_age_days = Some(STALE_CHECK_DAYS - 1);
        assert!(!rule_ids(&f).contains(&"UPD-003".to_string()));

        f.search_age_days = Some(STALE_CHECK_DAYS + 1);
        let warn = evaluate(&f)
            .into_iter()
            .find(|x| x.rule_id == "UPD-003")
            .unwrap();
        assert_eq!(warn.severity, Severity::Warning);

        f.search_age_days = Some(ABANDONED_CHECK_DAYS + 1);
        let crit = evaluate(&f)
            .into_iter()
            .find(|x| x.rule_id == "UPD-003")
            .unwrap();
        assert_eq!(crit.severity, Severity::Critical);
    }

    #[test]
    fn an_unknown_check_date_is_flagged_only_when_there_is_data_to_doubt() {
        let mut f = healthy();
        f.search_age_days = None;
        f.last_search_success = None;

        // Nothing pending: no cached figures to cast doubt on.
        assert!(!rule_ids(&f).contains(&"UPD-004".to_string()));

        // Pending updates of unknown vintage: say the vintage is unknown.
        f.pending = vec![update("Something", None)];
        assert!(rule_ids(&f).contains(&"UPD-004".to_string()));
    }

    #[test]
    fn every_finding_carries_evidence() {
        let mut f = healthy();
        f.pending = vec![update("Security Update", Some("Critical"))];
        f.reboot_required = Some(true);
        f.search_age_days = Some(90);

        let found = evaluate(&f);
        assert!(found.len() >= 3);
        for finding in found {
            assert!(
                !finding.evidence.is_empty(),
                "{} has no evidence",
                finding.rule_id
            );
            assert!(!finding.why_it_matters.is_empty());
            assert_eq!(finding.source, SOURCE);
        }
    }
}

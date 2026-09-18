//! Rules over Windows Defender Firewall state.
//!
//! Severity here turns on whether a profile is *active*. A disabled Public
//! profile on a laptop sitting at home is a real problem waiting to happen, but
//! it is not the same problem as the profile you are on right now being off,
//! and flattening the two would either cry wolf or miss the fire.

use crate::collectors::firewall::{FirewallFacts, FirewallProfile};
use crate::findings::{Finding, FindingBuilder, FixRisk, Severity};

const SOURCE: &str = "windows.firewall";
const CATEGORY: &str = "Firewall";
const COM_SOURCE: &str = "COM interface: INetFwPolicy2 (FirewallAPI.dll)";

pub fn evaluate(f: &FirewallFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    for profile in &f.profiles {
        out.extend(evaluate_profile(profile));
    }

    out
}

fn evaluate_profile(p: &FirewallProfile) -> Vec<Finding> {
    let mut out = Vec::new();
    let name = &p.name;

    // FW-001 / FW-002 -- the profile's firewall is switched off.
    if p.enabled == Some(false) {
        let (severity, why) = if p.is_active {
            (
                Severity::Critical,
                "This is the profile your current network is using, so nothing is filtering \
                 incoming connections right now. Any service listening on this PC is reachable \
                 by anything else on the network.",
            )
        } else {
            (
                Severity::Warning,
                "This profile is not in use at the moment, but Windows will switch to it the next \
                 time you join a network of that type -- and the firewall will be off when it does.",
            )
        };

        out.push(
            FindingBuilder::new(
                if p.is_active { "FW-001" } else { "FW-002" },
                CATEGORY,
                severity,
                &format!("Firewall is off for the {name} profile"),
            )
            .what(&format!(
                "The Windows Defender Firewall is disabled for the {name} network profile{}.",
                if p.is_active { ", which is currently active" } else { "" }
            ))
            .why(why)
            .asset(name)
            .evidence(vec![
                COM_SOURCE.to_string(),
                format!("Profile: {name}"),
                format!("IsActive: {}", p.is_active),
                "FirewallEnabled: false".to_string(),
            ])
            .remediation(
                &format!("Turn the firewall back on for the {name} profile in Windows Security, under Firewall & network protection."),
                true,
                FixRisk::Safe,
            )
            .source(SOURCE)
            .build(),
        );
    }

    // FW-003 -- unsolicited inbound traffic is allowed by default. Worse than
    // the firewall being off in one respect: it looks on.
    if p.inbound_blocked_by_default == Some(false) {
        out.push(
            FindingBuilder::new(
                "FW-003",
                CATEGORY,
                if p.is_active { Severity::Critical } else { Severity::Warning },
                &format!("Incoming connections are allowed by default ({name})"),
            )
            .what(&format!(
                "The {name} profile is set to allow inbound connections that no rule explicitly blocks."
            ))
            .why(
                "This inverts what a firewall is for. The firewall reports itself as on, but the \
                 default answer to an unexpected incoming connection is yes rather than no.",
            )
            .asset(name)
            .evidence(vec![
                COM_SOURCE.to_string(),
                format!("Profile: {name}"),
                format!("IsActive: {}", p.is_active),
                "DefaultInboundAction: Allow".to_string(),
            ])
            .remediation(
                &format!("Set the {name} profile's inbound default back to Block in Windows Defender Firewall advanced settings."),
                true,
                FixRisk::Safe,
            )
            .source(SOURCE)
            .build(),
        );
    }

    // FW-004 -- blocked-connection notifications are suppressed. Minor on its
    // own, but it is how a firewall stops being something the user notices.
    if p.notifications_disabled == Some(true) && p.is_active {
        out.push(
            FindingBuilder::new(
                "FW-004",
                CATEGORY,
                Severity::Attention,
                &format!("Firewall notifications are off ({name})"),
            )
            .what(&format!(
                "Windows will not tell you when the firewall blocks a program on the {name} profile."
            ))
            .why(
                "The firewall still works. You just will not find out when something on this PC \
                 tried to accept a connection and was stopped.",
            )
            .asset(name)
            .evidence(vec![
                COM_SOURCE.to_string(),
                format!("Profile: {name}"),
                "NotificationsDisabled: true".to_string(),
            ])
            .remediation(
                "Re-enable firewall notifications in Windows Security, under Firewall & network protection.",
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

    fn profile(name: &str, active: bool) -> FirewallProfile {
        FirewallProfile {
            name: name.to_string(),
            is_active: active,
            enabled: Some(true),
            block_all_inbound: Some(false),
            inbound_blocked_by_default: Some(true),
            outbound_allowed_by_default: Some(true),
            notifications_disabled: Some(false),
        }
    }

    fn facts(profiles: Vec<FirewallProfile>) -> FirewallFacts {
        FirewallFacts {
            profiles,
            evidence: vec![],
            collected_at: "2026-09-17T16:00:00+00:00".into(),
        }
    }

    #[test]
    fn a_healthy_firewall_produces_no_findings() {
        let f = facts(vec![
            profile("Domain", false),
            profile("Private", true),
            profile("Public", true),
        ]);
        assert!(evaluate(&f).is_empty());
    }

    #[test]
    fn unreported_fields_produce_no_findings() {
        let mut p = profile("Public", true);
        p.enabled = None;
        p.inbound_blocked_by_default = None;
        p.notifications_disabled = None;
        assert!(evaluate(&facts(vec![p])).is_empty());
    }

    #[test]
    fn a_disabled_active_profile_is_critical() {
        let mut p = profile("Public", true);
        p.enabled = Some(false);

        let found = evaluate(&facts(vec![p]));
        let f = found
            .iter()
            .find(|x| x.rule_id == "FW-001")
            .expect("FW-001");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.affected_asset.as_deref(), Some("Public"));
    }

    #[test]
    fn a_disabled_inactive_profile_is_only_a_warning() {
        let mut p = profile("Domain", false);
        p.enabled = Some(false);

        let found = evaluate(&facts(vec![p]));
        let f = found
            .iter()
            .find(|x| x.rule_id == "FW-002")
            .expect("FW-002");
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn each_profile_gets_its_own_finding() {
        let mut private = profile("Private", true);
        private.enabled = Some(false);
        let mut public = profile("Public", true);
        public.enabled = Some(false);

        let found = evaluate(&facts(vec![private, public]));
        assert_eq!(found.len(), 2);
        // Same rule, different assets, so the ids must differ.
        assert_ne!(found[0].id, found[1].id);
    }

    #[test]
    fn default_allow_inbound_is_reported() {
        let mut p = profile("Private", true);
        p.inbound_blocked_by_default = Some(false);

        let found = evaluate(&facts(vec![p]));
        let f = found
            .iter()
            .find(|x| x.rule_id == "FW-003")
            .expect("FW-003");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn notifications_off_only_matters_on_an_active_profile() {
        let mut inactive = profile("Domain", false);
        inactive.notifications_disabled = Some(true);
        assert!(evaluate(&facts(vec![inactive])).is_empty());

        let mut active = profile("Public", true);
        active.notifications_disabled = Some(true);
        let found = evaluate(&facts(vec![active]));
        assert_eq!(found[0].rule_id, "FW-004");
        assert_eq!(found[0].severity, Severity::Attention);
    }

    #[test]
    fn every_finding_carries_evidence() {
        let mut p = profile("Public", true);
        p.enabled = Some(false);
        p.inbound_blocked_by_default = Some(false);
        p.notifications_disabled = Some(true);

        for finding in evaluate(&facts(vec![p])) {
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

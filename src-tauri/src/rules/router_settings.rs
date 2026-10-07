//! Rules over normalized provider evidence; never initiates collection.
use crate::{
    collectors::network::router::{settings::WifiAuthentication, RouterFacts},
    findings::{Confidence, Finding, FindingBuilder, Severity},
    security::Known,
};

fn finding(rule: &str, title: &str, evidence: Vec<String>, detail: &str) -> Finding {
    FindingBuilder::new(rule, "Router", Severity::Warning, title)
        .what(detail)
        .why("This is a reported configuration observation, not a test of Internet reachability or successful exploitation.")
        .confidence(Confidence::Confirmed).evidence(evidence)
        .remediation("Review the reported setting in the router's administration interface. SENTRY does not change router settings.")
        .source("network.router").build()
}

pub fn evaluate(f: &RouterFacts) -> Vec<Finding> {
    let mut out = Vec::new();
    if matches!(f.settings.wan_management_enabled, Known::Known(true)) {
        out.push(finding("RTR-007", "Router reports WAN management enabled", vec!["WAN management configuration: enabled".into()], "The router reports that WAN management is configured as enabled. External access was not tested."));
    }
    let disabled: Vec<_> = [
        (&f.settings.ipv4_firewall_enabled, "IPv4"),
        (&f.settings.ipv6_firewall_enabled, "IPv6"),
    ]
    .into_iter()
    .filter(|(state, _)| matches!(state, Known::Known(false)))
    .map(|(_, family)| format!("{family} firewall configuration: disabled"))
    .collect();
    if !disabled.is_empty() {
        out.push(finding("RTR-008", "Router reports a firewall disabled", disabled, "A router firewall setting is reported disabled. Other filtering layers and effective packet handling were not tested."));
    }
    if let Known::Known(profiles) = &f.settings.wifi_profiles {
        let mut weak = Vec::new();
        let mut wps = Vec::new();
        for (index, profile) in profiles.iter().enumerate() {
            if !matches!(profile.enabled, Known::Known(true)) {
                continue;
            }
            if matches!(
                profile.authentication,
                Known::Known(
                    WifiAuthentication::Open
                        | WifiAuthentication::Wep
                        | WifiAuthentication::WpaPersonal
                )
            ) {
                weak.push(format!(
                    "Enabled Wi-Fi profile {} reports authentication {:?}",
                    index + 1,
                    profile.authentication.value().unwrap()
                ));
            }
            if matches!(profile.wps_enabled, Known::Known(true)) {
                wps.push(format!(
                    "Enabled Wi-Fi profile {} reports WPS enabled",
                    index + 1
                ));
            }
        }
        if !weak.is_empty() {
            out.push(finding("RTR-009", "Review reported Wi-Fi authentication", weak, "An enabled Wi-Fi profile reports open or legacy authentication. Password strength and negotiated client encryption were not tested."));
        }
        if !wps.is_empty() {
            out.push(finding("RTR-010", "Router reports WPS enabled", wps, "An enabled Wi-Fi profile reports WPS enabled. SENTRY did not test enrollment, PIN acceptance, or exploitability."));
        }
    }
    if let Known::Known(matches) = &f.firmware_assessment.advisory_matches {
        if !matches.is_empty() {
            out.push(finding("RTR-011", "Installed firmware matches advisory records",
                matches.iter().map(|m| format!("{} — {}", m.id, m.source)).collect(),
                "Exact firmware identity matched the supplied advisory catalog. This is advisory applicability, not proof of successful exploitation. Review each source for its conditions and remediation."));
        }
    }
    if let Known::Known(reviews) = &f.firmware_assessment.advisory_reviews {
        let pending: Vec<_> = reviews
            .iter()
            .filter(|r| {
                r.disposition
                    == crate::collectors::network::router::intelligence::Disposition::ReviewRequired
            })
            .collect();
        if !pending.is_empty() {
            out.push(FindingBuilder::new("RTR-012", "Router", Severity::Attention, "Review firmware advisory applicability")
                .what("Reviewed upstream advisories require a component or feature check for this exact firmware build. They are not confirmed exploitable vulnerabilities on this router.")
                .why("A later published fix is useful review evidence, but it does not prove that the affected feature is present or reachable.")
                .confidence(Confidence::Potential)
                .evidence(pending.iter().map(|r| format!("{}: {} Sources: {}", r.id, r.detail, r.sources.join(" "))).collect::<Vec<_>>())
                .remediation("Review the cited advisory and GNUton release notes. SENTRY neither tests exploitation nor installs firmware.")
                .source("network.router").build());
        }
    }
    if matches!(f.firmware_assessment.end_of_support, Known::Known(true)) {
        out.push(finding("RTR-013", "ASUS lists this model as end-of-life in the selected region",
            f.firmware_assessment.lifecycle_evidence.clone(),
            "The ASUS vendor lifecycle entry matches this model and the user-supplied support region. GNUton project support is separate; this is not a claim that the router stopped working."));
    }
    if matches!(f.firmware_assessment.update_available, Known::Known(true)) {
        out.push(FindingBuilder::new("RTR-014", "Router", Severity::Attention, "A newer GNUton firmware release is published")
            .what("Reviewed release evidence identifies a newer build for this model. Upgrade suitability and installed-binary integrity were not tested.")
            .why("Release notes can include security fixes and model-specific upgrade conditions.")
            .confidence(Confidence::Confirmed).evidence(f.firmware_assessment.release_evidence.clone())
            .remediation("Review the model-specific GNUton release instructions. Firmware installation is a separate manual action.")
            .source("network.router").build());
    }
    out
}

/// Positive contrary evidence for the exact settings checked by these rules.
/// This does not establish that the whole router or its Wi-Fi is safe.
pub fn resolved_rules(f: &RouterFacts) -> Vec<&'static str> {
    let mut rules = Vec::new();
    if matches!(f.settings.wan_management_enabled, Known::Known(false)) {
        rules.push("RTR-007");
    }
    if matches!(f.settings.ipv4_firewall_enabled, Known::Known(true))
        && matches!(f.settings.ipv6_firewall_enabled, Known::Known(true))
    {
        rules.push("RTR-008");
    }
    if matches!(f.settings.wifi_inventory_complete, Known::Known(true)) {
        if let Known::Known(profiles) = &f.settings.wifi_profiles {
            // Empty inventories may mean unsupported firmware or missing radios.
            if !profiles.is_empty()
                && profiles.iter().all(|p| {
                    matches!(p.enabled, Known::Known(false))
                        || (matches!(p.enabled, Known::Known(true))
                            && matches!(
                                p.authentication,
                                Known::Known(
                                    WifiAuthentication::Wpa2Personal
                                        | WifiAuthentication::Wpa3Personal
                                        | WifiAuthentication::Wpa2Wpa3Personal
                                )
                            ))
                })
            {
                rules.push("RTR-009");
            }
            if !profiles.is_empty()
                && profiles.iter().all(|p| {
                    matches!(p.enabled, Known::Known(false))
                        || (matches!(p.enabled, Known::Known(true))
                            && matches!(p.wps_enabled, Known::Known(false)))
                })
            {
                rules.push("RTR-010");
            }
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reviewed_data_creates_scoped_review_and_lifecycle_findings_without_false_cves() {
        use crate::collectors::network::router::{
            asus,
            intelligence::{self, SupportRegion},
        };
        let now = "2026-10-02T12:00:00Z".parse().unwrap();
        let mut f = RouterFacts {
            firmware_assessment: intelligence::assess(
                "RT-AX82U",
                asus::REVIEWED_BUILD,
                SupportRegion::Unknown,
                now,
            ),
            ..Default::default()
        };
        let findings = evaluate(&f);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "RTR-012" && matches!(f.confidence, Confidence::Potential)));
        assert!(findings.iter().any(|f| f.rule_id == "RTR-014"));
        assert!(!findings
            .iter()
            .any(|f| matches!(f.rule_id.as_str(), "RTR-011" | "RTR-013")));
        f.firmware_assessment =
            intelligence::assess("RT-AX82U", asus::REVIEWED_BUILD, SupportRegion::Eu, now);
        assert!(evaluate(&f).iter().any(|f| f.rule_id == "RTR-013"));
        f.firmware_assessment = intelligence::assess(
            "RT-AX82U",
            asus::REVIEWED_BUILD,
            SupportRegion::Eu,
            now + chrono::Duration::days(30),
        );
        assert!(evaluate(&f).is_empty());
    }

    #[test]
    fn resolution_requires_positive_complete_evidence() {
        let mut f = RouterFacts::default();
        assert!(resolved_rules(&f).is_empty());
        f.settings.wan_management_enabled = Known::Known(false);
        f.settings.ipv4_firewall_enabled = Known::Known(true);
        assert_eq!(resolved_rules(&f), vec!["RTR-007"]);
        f.settings.ipv6_firewall_enabled = Known::Known(true);
        assert_eq!(resolved_rules(&f), vec!["RTR-007", "RTR-008"]);
        f.settings.wifi_profiles = Known::Known(vec![WifiProfile {
            enabled: Known::Known(true),
            authentication: Known::Known(WifiAuthentication::Wpa3Personal),
            wps_enabled: Known::Known(false),
            ..Default::default()
        }]);
        assert!(!resolved_rules(&f).contains(&"RTR-009"));
        f.settings.wifi_inventory_complete = Known::Known(true);
        assert!(resolved_rules(&f).contains(&"RTR-009"));
        assert!(resolved_rules(&f).contains(&"RTR-010"));
    }
    use crate::collectors::network::router::settings::WifiProfile;
    #[test]
    fn unknown_settings_do_not_create_findings() {
        assert!(evaluate(&RouterFacts::default()).is_empty());
    }
    #[test]
    fn disabled_or_unknown_profiles_do_not_raise_active_wifi_findings() {
        for enabled in [Known::Known(false), Known::NotScanned] {
            let mut f = RouterFacts::default();
            f.settings.wifi_profiles = Known::Known(vec![WifiProfile {
                enabled,
                authentication: Known::Known(WifiAuthentication::Open),
                wps_enabled: Known::Known(true),
                ..Default::default()
            }]);
            assert!(evaluate(&f).is_empty());
        }
    }
    #[test]
    fn partial_profile_evidence_can_raise_findings_without_claiming_complete_coverage() {
        let mut f = RouterFacts::default();
        f.settings.wifi_profiles = Known::Known(vec![WifiProfile {
            enabled: Known::Known(true),
            authentication: Known::Known(WifiAuthentication::Wep),
            wps_enabled: Known::Known(true),
            ..Default::default()
        }]);
        let found = evaluate(&f);
        assert_eq!(found.len(), 2);
        assert!(!f.settings.wifi_inventory_complete.is_known());
    }
    #[test]
    fn each_ip_family_is_independent() {
        let mut f = RouterFacts::default();
        f.settings.ipv6_firewall_enabled = Known::Known(false);
        let found = evaluate(&f);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].evidence,
            vec!["IPv6 firewall configuration: disabled"]
        );
    }
}

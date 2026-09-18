//! Rules over Windows hardening settings.

use crate::collectors::hardening::HardeningFacts;
use crate::findings::{Confidence, Finding, FindingBuilder, FixRisk, Severity};

const SOURCE: &str = "windows.hardening";
const CATEGORY: &str = "System Configuration";

pub fn evaluate(f: &HardeningFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    // SYS-001 -- SMBv1 server. The protocol WannaCry and NotPetya spread over.
    if f.smb1_server_enabled == Some(true) {
        out.push(
            FindingBuilder::new("SYS-001", CATEGORY, Severity::Critical, "SMBv1 file sharing is enabled")
                .what("This PC can share files using SMBv1, a protocol Microsoft deprecated in 2014.")
                .why(
                    "SMBv1 is how WannaCry and NotPetya spread across networks in 2017, encrypting \
                     every machine they reached without anyone clicking anything. Nothing made since \
                     needs it, and leaving it on gives ransomware a way to move from one PC to the next.",
                )
                .evidence(f.evidence.clone())
                .remediation(
                    "Turn off SMB 1.0/CIFS File Sharing Support in Windows Features, then restart.",
                    true,
                    FixRisk::Caution,
                )
                .reference("https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3")
                .source(SOURCE)
                .build(),
        );
    }

    // SYS-002 -- SMBv1 client. Less dangerous than serving it, but it is still
    // a downgrade path an attacker on the network can steer this PC into.
    if f.smb1_client_enabled == Some(true) {
        out.push(
            FindingBuilder::new("SYS-002", CATEGORY, Severity::Warning, "This PC can still use SMBv1")
                .what("The SMBv1 client is installed and not disabled.")
                .why(
                    "Even if this PC shares nothing, it will happily connect to another machine over \
                     SMBv1 -- including a hostile one that asks it to, which is how credentials get \
                     captured on a shared network.",
                )
                .evidence(f.evidence.clone())
                .remediation(
                    "Turn off SMB 1.0/CIFS Client in Windows Features, then restart.",
                    true,
                    FixRisk::Caution,
                )
                .source(SOURCE)
                .build(),
        );
    }

    // SYS-003 -- UAC off entirely.
    if f.uac_enabled == Some(false) {
        out.push(
            FindingBuilder::new("SYS-003", CATEGORY, Severity::Critical, "User Account Control is turned off")
                .what("UAC is disabled, so programs can make system-wide changes without asking.")
                .why(
                    "UAC is the prompt that appears when something wants administrator rights. With \
                     it off, any program you run -- including one you did not mean to run -- gets \
                     those rights silently, with no prompt to notice and refuse.",
                )
                .evidence(f.evidence.clone())
                .remediation(
                    "Turn User Account Control back on in Control Panel, under User Accounts. A restart is required.",
                    false,
                    FixRisk::Manual,
                )
                .source(SOURCE)
                .build(),
        );
    }

    // SYS-004 -- UAC on, but elevating without ever prompting.
    if f.uac_enabled != Some(false) && f.uac_prompts_admin == Some(false) {
        out.push(
            FindingBuilder::new(
                "SYS-004",
                CATEGORY,
                Severity::Warning,
                "Administrator prompts are suppressed",
            )
            .what("UAC is on, but administrators are elevated without being asked to confirm.")
            .why(
                "The protection is nominally enabled while the part you would actually notice \
                     -- the prompt -- never appears. Programs gain full control of the PC without \
                     anything being shown to you.",
            )
            .evidence(f.evidence.clone())
            .remediation(
                "Set User Account Control back to its default notification level in Control Panel.",
                false,
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
    }

    // SYS-005 -- Remote Desktop reachable. Severity hinges on NLA, which is
    // what stands between "needs credentials to open a session" and "needs
    // credentials eventually".
    if f.rdp_enabled == Some(true) {
        let nla_off = f.rdp_nla_required == Some(false);

        out.push(
            FindingBuilder::new(
                "SYS-005",
                CATEGORY,
                if nla_off { Severity::Critical } else { Severity::Attention },
                if nla_off {
                    "Remote Desktop is on without Network Level Authentication"
                } else {
                    "Remote Desktop is enabled"
                },
            )
            .what(if nla_off {
                "This PC accepts Remote Desktop connections, and does not require Network Level \
                 Authentication first."
            } else {
                "This PC accepts incoming Remote Desktop connections."
            })
            .why(if nla_off {
                "Without Network Level Authentication, anyone who can reach this PC gets a login \
                 session created for them before proving who they are. That is both an easy target \
                 for password guessing and a way to reach bugs in the login screen itself."
            } else {
                "This may well be deliberate. It is listed because Remote Desktop is a direct route \
                 into this PC, so it is worth knowing it is open -- especially if this machine is \
                 ever on a network you do not control."
            })
            .confidence(Confidence::Confirmed)
            .evidence(f.evidence.clone())
            .remediation(
                if nla_off {
                    "Require Network Level Authentication in System Properties, under Remote, or turn Remote Desktop off if you do not use it."
                } else {
                    "If you do not use Remote Desktop, turn it off in Settings, under System, Remote Desktop."
                },
                false,
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
    }

    // SYS-006 -- AutoRun still active for some drive types.
    if f.autorun_disabled == Some(false) {
        out.push(
            FindingBuilder::new("SYS-006", CATEGORY, Severity::Attention, "AutoRun is not fully disabled")
                .what("Some drive types can still run a program automatically when connected.")
                .why(
                    "AutoRun lets a USB stick start a program the moment it is plugged in, without \
                     anyone choosing to open anything. It is a long-standing way malware gets from \
                     removable media onto a PC.",
                )
                .evidence(f.evidence.clone())
                .remediation(
                    "Disable AutoRun for all drive types in Group Policy, or set NoDriveTypeAutoRun to 0xFF.",
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

    fn hardened() -> HardeningFacts {
        HardeningFacts {
            smb1_server_enabled: Some(false),
            smb1_client_enabled: Some(false),
            uac_enabled: Some(true),
            uac_prompts_admin: Some(true),
            rdp_enabled: Some(false),
            rdp_nla_required: Some(true),
            autorun_disabled: Some(true),
            evidence: vec!["Source: HKLM registry policy and service keys".into()],
            collected_at: "2026-09-17T20:00:00+00:00".into(),
        }
    }

    fn rule_ids(f: &HardeningFacts) -> Vec<String> {
        evaluate(f).into_iter().map(|x| x.rule_id).collect()
    }

    #[test]
    fn a_hardened_machine_produces_no_findings() {
        assert!(evaluate(&hardened()).is_empty());
    }

    #[test]
    fn an_entirely_unknown_machine_produces_no_findings() {
        assert!(evaluate(&HardeningFacts::default()).is_empty());
    }

    #[test]
    fn smb1_server_is_critical() {
        let mut f = hardened();
        f.smb1_server_enabled = Some(true);
        let found = evaluate(&f);
        let s = found
            .iter()
            .find(|x| x.rule_id == "SYS-001")
            .expect("SYS-001");
        assert_eq!(s.severity, Severity::Critical);
        assert!(
            !s.references.is_empty(),
            "SMBv1 finding should cite Microsoft"
        );
    }

    #[test]
    fn smb1_client_is_a_lesser_warning_than_the_server() {
        let mut f = hardened();
        f.smb1_client_enabled = Some(true);
        let found = evaluate(&f);
        let s = found.iter().find(|x| x.rule_id == "SYS-002").unwrap();
        assert_eq!(s.severity, Severity::Warning);
    }

    #[test]
    fn uac_off_is_critical() {
        let mut f = hardened();
        f.uac_enabled = Some(false);
        assert!(rule_ids(&f).contains(&"SYS-003".to_string()));
    }

    #[test]
    fn silent_elevation_is_not_double_reported_when_uac_is_off() {
        // With UAC off entirely, SYS-003 is the finding. Also raising SYS-004
        // would charge the score twice for one misconfiguration.
        let mut f = hardened();
        f.uac_enabled = Some(false);
        f.uac_prompts_admin = Some(false);

        let ids = rule_ids(&f);
        assert!(ids.contains(&"SYS-003".to_string()));
        assert!(!ids.contains(&"SYS-004".to_string()));
    }

    #[test]
    fn silent_elevation_is_reported_when_uac_is_on() {
        let mut f = hardened();
        f.uac_prompts_admin = Some(false);
        assert!(rule_ids(&f).contains(&"SYS-004".to_string()));
    }

    #[test]
    fn rdp_severity_depends_on_nla() {
        let mut f = hardened();
        f.rdp_enabled = Some(true);

        // With NLA, it is a fact worth surfacing, not an alarm.
        let with_nla = evaluate(&f)
            .into_iter()
            .find(|x| x.rule_id == "SYS-005")
            .unwrap();
        assert_eq!(with_nla.severity, Severity::Attention);

        f.rdp_nla_required = Some(false);
        let without = evaluate(&f)
            .into_iter()
            .find(|x| x.rule_id == "SYS-005")
            .unwrap();
        assert_eq!(without.severity, Severity::Critical);
    }

    #[test]
    fn rdp_off_raises_nothing() {
        let mut f = hardened();
        f.rdp_enabled = Some(false);
        f.rdp_nla_required = Some(false);
        assert!(!rule_ids(&f).contains(&"SYS-005".to_string()));
    }

    #[test]
    fn autorun_left_on_is_reported() {
        let mut f = hardened();
        f.autorun_disabled = Some(false);
        assert!(rule_ids(&f).contains(&"SYS-006".to_string()));
    }

    #[test]
    fn every_finding_carries_evidence() {
        let mut f = hardened();
        f.smb1_server_enabled = Some(true);
        f.uac_enabled = Some(false);
        f.rdp_enabled = Some(true);
        f.rdp_nla_required = Some(false);
        f.autorun_disabled = Some(false);

        let found = evaluate(&f);
        assert!(found.len() >= 4);
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

//! Microsoft Defender's configuration, read from `MSFT_MpPreference`.
//!
//! `MSFT_MpComputerStatus` (see `defender.rs`) answers "is protection on?".
//! This answers the more interesting question: "has protection been *weakened*?"
//!
//! Those are different. Defender can report itself fully enabled while archive
//! scanning is off, removable drives are skipped, and a folder has been added
//! to the exclusion list. Adding an exclusion is a standard move for malware
//! that has gained administrative rights -- it is quieter than switching
//! Defender off, and nothing in the Windows Security UI draws attention to it.
//!
//! Exclusions themselves need administrator rights to read. Defender says so
//! explicitly rather than returning an empty list, and that distinction is
//! carried through as `PermissionRequired` rather than flattened to "none".

use serde::{Deserialize, Serialize};

use crate::security::{CollectorError, Known};

#[cfg(windows)]
const NAMESPACE: &str = r"root\Microsoft\Windows\Defender";

/// Defender's handling of potentially unwanted applications: adware bundlers,
/// browser hijackers, "PC cleaners".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PuaProtection {
    Disabled,
    /// Detected and blocked.
    Block,
    /// Detected and logged, but allowed to run.
    AuditMode,
    /// A value Microsoft has not documented; reported as the raw number rather
    /// than guessed at.
    Other(u32),
}

impl PuaProtection {
    fn from_raw(value: u32) -> PuaProtection {
        match value {
            0 => PuaProtection::Disabled,
            1 => PuaProtection::Block,
            2 => PuaProtection::AuditMode,
            other => PuaProtection::Other(other),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            PuaProtection::Disabled => "off".to_string(),
            PuaProtection::Block => "blocking".to_string(),
            PuaProtection::AuditMode => "audit only (detected but allowed to run)".to_string(),
            PuaProtection::Other(v) => format!("unrecognised setting ({v})"),
        }
    }
}

/// How much Defender shares with Microsoft's cloud protection service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapsReporting {
    Disabled,
    Basic,
    Advanced,
    Other(u32),
}

impl MapsReporting {
    fn from_raw(value: u32) -> MapsReporting {
        match value {
            0 => MapsReporting::Disabled,
            1 => MapsReporting::Basic,
            2 => MapsReporting::Advanced,
            other => MapsReporting::Other(other),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            MapsReporting::Disabled => "off".to_string(),
            MapsReporting::Basic => "basic".to_string(),
            MapsReporting::Advanced => "advanced".to_string(),
            MapsReporting::Other(v) => format!("unrecognised setting ({v})"),
        }
    }
}

/// Whether Defender uploads suspicious files to Microsoft.
///
/// Relevant to SENTRY's privacy stance: this is a Windows setting, not one
/// SENTRY controls, but a user who cares about files leaving their machine
/// should know when Windows is configured to send all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleSubmission {
    AlwaysPrompt,
    /// Files unlikely to contain personal information.
    SendSafeSamples,
    NeverSend,
    /// Every suspicious file, including documents.
    SendAllSamples,
    Other(u32),
}

impl SampleSubmission {
    fn from_raw(value: u32) -> SampleSubmission {
        match value {
            0 => SampleSubmission::AlwaysPrompt,
            1 => SampleSubmission::SendSafeSamples,
            2 => SampleSubmission::NeverSend,
            3 => SampleSubmission::SendAllSamples,
            other => SampleSubmission::Other(other),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            SampleSubmission::AlwaysPrompt => "ask first".to_string(),
            SampleSubmission::SendSafeSamples => {
                "send samples unlikely to contain personal data".to_string()
            }
            SampleSubmission::NeverSend => "never send".to_string(),
            SampleSubmission::SendAllSamples => {
                "send all suspicious files, including documents".to_string()
            }
            SampleSubmission::Other(v) => format!("unrecognised setting ({v})"),
        }
    }
}

/// Paths, processes and file types Defender has been told to skip.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Exclusions {
    pub paths: Vec<String>,
    pub processes: Vec<String>,
    pub extensions: Vec<String>,
}

impl Exclusions {
    pub fn total(&self) -> usize {
        self.paths.len() + self.processes.len() + self.extensions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefenderPolicyFacts {
    pub realtime_monitoring_disabled: Option<bool>,
    pub behavior_monitoring_disabled: Option<bool>,
    pub script_scanning_disabled: Option<bool>,
    pub archive_scanning_disabled: Option<bool>,
    /// USB sticks and external drives skipped during scans.
    pub removable_drive_scanning_disabled: Option<bool>,
    pub ioav_protection_disabled: Option<bool>,
    pub email_scanning_disabled: Option<bool>,
    pub pua_protection: Option<PuaProtection>,
    pub maps_reporting: Option<MapsReporting>,
    pub sample_submission: Option<SampleSubmission>,
    /// Reading these needs administrator rights, which SENTRY does not require.
    pub exclusions: Known<Exclusions>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl Default for DefenderPolicyFacts {
    fn default() -> Self {
        DefenderPolicyFacts {
            realtime_monitoring_disabled: None,
            behavior_monitoring_disabled: None,
            script_scanning_disabled: None,
            archive_scanning_disabled: None,
            removable_drive_scanning_disabled: None,
            ioav_protection_disabled: None,
            email_scanning_disabled: None,
            pua_protection: None,
            maps_reporting: None,
            sample_submission: None,
            exclusions: Known::NotScanned,
            evidence: Vec::new(),
            collected_at: String::new(),
        }
    }
}

#[cfg(windows)]
pub fn collect() -> Result<DefenderPolicyFacts, CollectorError> {
    use super::wmi_util as w;

    let rows = w::query(NAMESPACE, "SELECT * FROM MSFT_MpPreference")?;

    let row = rows.first().ok_or_else(|| {
        CollectorError::Unavailable(
            "Defender returned no configuration record. The Defender service may be stopped."
                .into(),
        )
    })?;

    let mut facts = DefenderPolicyFacts {
        realtime_monitoring_disabled: w::get_bool(row, "DisableRealtimeMonitoring"),
        behavior_monitoring_disabled: w::get_bool(row, "DisableBehaviorMonitoring"),
        script_scanning_disabled: w::get_bool(row, "DisableScriptScanning"),
        archive_scanning_disabled: w::get_bool(row, "DisableArchiveScanning"),
        removable_drive_scanning_disabled: w::get_bool(row, "DisableRemovableDriveScanning"),
        ioav_protection_disabled: w::get_bool(row, "DisableIOAVProtection"),
        email_scanning_disabled: w::get_bool(row, "DisableEmailScanning"),
        pua_protection: w::get_u32(row, "PUAProtection").map(PuaProtection::from_raw),
        maps_reporting: w::get_u32(row, "MAPSReporting").map(MapsReporting::from_raw),
        sample_submission: w::get_u32(row, "SubmitSamplesConsent").map(SampleSubmission::from_raw),
        exclusions: read_exclusions(row),
        evidence: vec![
            r"WMI namespace: root\Microsoft\Windows\Defender".to_string(),
            "WMI class: MSFT_MpPreference".to_string(),
        ],
        collected_at: chrono::Utc::now().to_rfc3339(),
    };

    facts.evidence.extend(build_evidence(&facts));
    Ok(facts)
}

/// Read the three exclusion lists.
///
/// Without administrator rights Defender does not return an empty list -- it
/// returns the literal text "N/A: Must be an administrator to view exclusions"
/// in place of the values. Treating that as an exclusion path would be absurd,
/// and treating it as "no exclusions" would be a lie, so it is detected and
/// reported as needing elevation.
#[cfg(windows)]
fn read_exclusions(row: &super::wmi_util::Row) -> Known<Exclusions> {
    use super::wmi_util as w;

    let paths = w::get_string_list(row, "ExclusionPath");
    let processes = w::get_string_list(row, "ExclusionProcess");
    let extensions = w::get_string_list(row, "ExclusionExtension");

    let needs_admin = [&paths, &processes, &extensions]
        .iter()
        .flat_map(|list| list.iter())
        .any(|value| value.contains("Must be an administrator"));

    if needs_admin {
        return Known::PermissionRequired(
            "Windows only reveals Defender's exclusion list to an administrator. Run SENTRY as an \
             administrator to check whether any folders have been excluded from scanning."
                .into(),
        );
    }

    Known::Known(Exclusions {
        paths,
        processes,
        extensions,
    })
}

fn build_evidence(f: &DefenderPolicyFacts) -> Vec<String> {
    let mut evidence = Vec::new();

    let mut flag = |label: &str, value: Option<bool>| {
        if let Some(v) = value {
            evidence.push(format!("{label}: {v}"));
        }
    };

    flag("DisableRealtimeMonitoring", f.realtime_monitoring_disabled);
    flag("DisableBehaviorMonitoring", f.behavior_monitoring_disabled);
    flag("DisableScriptScanning", f.script_scanning_disabled);
    flag("DisableArchiveScanning", f.archive_scanning_disabled);
    flag(
        "DisableRemovableDriveScanning",
        f.removable_drive_scanning_disabled,
    );
    flag("DisableIOAVProtection", f.ioav_protection_disabled);
    flag("DisableEmailScanning", f.email_scanning_disabled);

    if let Some(pua) = f.pua_protection {
        evidence.push(format!("PUAProtection: {}", pua.describe()));
    }
    if let Some(maps) = f.maps_reporting {
        evidence.push(format!("MAPSReporting: {}", maps.describe()));
    }
    if let Some(samples) = f.sample_submission {
        evidence.push(format!("SubmitSamplesConsent: {}", samples.describe()));
    }

    match &f.exclusions {
        Known::Known(e) if e.is_empty() => evidence.push("Exclusions: none configured".to_string()),
        Known::Known(e) => {
            evidence.push(format!(
                "Exclusions: {} path(s), {} process(es), {} extension(s)",
                e.paths.len(),
                e.processes.len(),
                e.extensions.len()
            ));
            for path in e.paths.iter().take(10) {
                evidence.push(format!("  excluded path: {path}"));
            }
            for process in e.processes.iter().take(10) {
                evidence.push(format!("  excluded process: {process}"));
            }
        }
        Known::PermissionRequired(_) => {
            evidence.push("Exclusions: not readable without administrator rights".to_string())
        }
        _ => {}
    }

    evidence
}

#[cfg(not(windows))]
pub fn collect() -> Result<DefenderPolicyFacts, CollectorError> {
    Err(CollectorError::Unsupported(
        "Defender configuration is only available on Windows.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_enum_values_are_named() {
        assert_eq!(PuaProtection::from_raw(0), PuaProtection::Disabled);
        assert_eq!(PuaProtection::from_raw(1), PuaProtection::Block);
        assert_eq!(PuaProtection::from_raw(2), PuaProtection::AuditMode);

        assert_eq!(MapsReporting::from_raw(0), MapsReporting::Disabled);
        assert_eq!(MapsReporting::from_raw(2), MapsReporting::Advanced);

        assert_eq!(
            SampleSubmission::from_raw(1),
            SampleSubmission::SendSafeSamples
        );
        assert_eq!(
            SampleSubmission::from_raw(3),
            SampleSubmission::SendAllSamples
        );
    }

    #[test]
    fn undocumented_values_report_the_number_rather_than_guessing() {
        // Microsoft adds settings. Mapping an unknown value onto the nearest
        // known one would invent a fact.
        assert_eq!(PuaProtection::from_raw(99), PuaProtection::Other(99));
        assert!(PuaProtection::from_raw(99).describe().contains("99"));
        assert!(MapsReporting::from_raw(7)
            .describe()
            .contains("unrecognised"));
        assert!(SampleSubmission::from_raw(42).describe().contains("42"));
    }

    #[test]
    fn audit_mode_is_described_as_not_blocking() {
        // The distinction that matters: audit mode detects but permits.
        let described = PuaProtection::AuditMode.describe();
        assert!(described.contains("allowed to run"), "got: {described}");
    }

    #[test]
    fn sending_all_samples_is_described_as_including_documents() {
        let described = SampleSubmission::SendAllSamples.describe();
        assert!(described.contains("documents"), "got: {described}");
    }

    #[test]
    fn exclusions_count_across_all_three_lists() {
        let e = Exclusions {
            paths: vec![r"C:\Temp".into()],
            processes: vec!["a.exe".into(), "b.exe".into()],
            extensions: vec![".dat".into()],
        };
        assert_eq!(e.total(), 4);
        assert!(!e.is_empty());
        assert!(Exclusions::default().is_empty());
    }

    #[test]
    fn facts_default_to_entirely_unknown() {
        let f = DefenderPolicyFacts::default();
        assert!(f.realtime_monitoring_disabled.is_none());
        assert!(f.pua_protection.is_none());
        assert!(matches!(f.exclusions, Known::NotScanned));
    }

    #[test]
    fn evidence_omits_settings_that_were_not_read() {
        let facts = DefenderPolicyFacts {
            removable_drive_scanning_disabled: Some(true),
            ..Default::default()
        };
        let evidence = build_evidence(&facts);

        assert!(evidence
            .iter()
            .any(|e| e == "DisableRemovableDriveScanning: true"));
        assert!(!evidence
            .iter()
            .any(|e| e.starts_with("DisableScriptScanning")));
    }

    #[test]
    fn evidence_distinguishes_no_exclusions_from_unreadable_ones() {
        let none = DefenderPolicyFacts {
            exclusions: Known::Known(Exclusions::default()),
            ..Default::default()
        };
        assert!(build_evidence(&none)
            .iter()
            .any(|e| e == "Exclusions: none configured"));

        let blocked = DefenderPolicyFacts {
            exclusions: Known::PermissionRequired("needs admin".into()),
            ..Default::default()
        };
        assert!(build_evidence(&blocked)
            .iter()
            .any(|e| e.contains("not readable without administrator")));
    }

    #[test]
    fn excluded_paths_appear_individually_in_the_evidence() {
        let facts = DefenderPolicyFacts {
            exclusions: Known::Known(Exclusions {
                paths: vec![r"C:\Users\Public\Downloads".into()],
                processes: vec!["updater.exe".into()],
                extensions: vec![],
            }),
            ..Default::default()
        };

        let evidence = build_evidence(&facts);
        assert!(evidence
            .iter()
            .any(|e| e.contains(r"C:\Users\Public\Downloads")));
        assert!(evidence.iter().any(|e| e.contains("updater.exe")));
    }

    #[cfg(windows)]
    #[test]
    fn collecting_on_this_machine_reads_the_policy() {
        let facts = collect().expect("Defender policy should be readable");
        assert!(facts
            .evidence
            .iter()
            .any(|e| e.contains("MSFT_MpPreference")));
        // Whatever the values, at least one boolean setting must have been read
        // on a machine where Defender is present.
        assert!(
            facts.realtime_monitoring_disabled.is_some()
                || facts.archive_scanning_disabled.is_some(),
            "no Defender settings were read at all"
        );
    }
}

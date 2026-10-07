//! The Finding model: what the rules layer produces and the UI renders.

use serde::{Deserialize, Serialize};

/// How much the user should care. Ordered, so a set of findings can be reduced
/// to the worst one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Safe,
    Attention,
    Warning,
    Critical,
}

impl Severity {
    pub fn worst(items: impl IntoIterator<Item = Severity>) -> Option<Severity> {
        items.into_iter().max()
    }
}

/// How sure we are the finding is real, distinct from how bad it would be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Directly observed from an authoritative source.
    Confirmed,
    /// Strong indirect evidence.
    Likely,
    /// Consistent with the evidence but not established.
    Potential,
}

impl Confidence {
    /// Numeric form for the UI and the score engine.
    pub fn as_f32(self) -> f32 {
        match self {
            Confidence::Confirmed => 1.0,
            Confidence::Likely => 0.8,
            Confidence::Potential => 0.5,
        }
    }
}

/// How dangerous applying the fix automatically would be.
///
/// This describes an `Action` SENTRY will actually carry out, so it is derived
/// from the action and never stated by a rule. A finding with no action has no
/// risk to report: there is nothing to apply. Saying "reversible, no side
/// effects" beside a recommendation SENTRY cannot act on describes a fix that
/// does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixRisk {
    /// Reversible, no side effects beyond the setting itself.
    Safe,
    /// Could disrupt something the user relies on; needs a backup first.
    Caution,
}

/// A Windows page the user can be sent to when SENTRY will not make a change
/// itself.
///
/// Opening one of these changes nothing. It is the Settings or Windows Security
/// page the finding's recommendation already describes in prose, so the user
/// does not have to hunt for it through four menus. Each variant maps to one
/// fixed literal target; nothing from a finding, a feed or the webview is ever
/// interpolated into it, so this is a closed list of pages rather than a way to
/// launch things.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelpTarget {
    /// Virus & threat protection settings: real-time protection, archive, USB
    /// and script scanning, PUA, exclusions, sample submission.
    VirusProtectionSettings,
    /// Current threats, which lists what Defender is acting on and links to
    /// the full protection history.
    CurrentThreats,
    /// Protection updates, for definition age.
    ProtectionUpdates,
    /// Firewall & network protection.
    FirewallAndNetwork,
    /// Windows Update.
    WindowsUpdate,
    /// Settings, System, Remote Desktop.
    RemoteDesktop,
    /// The Windows Features dialog, where SMBv1 is turned off.
    WindowsFeatures,
    /// The User Account Control notification slider.
    UserAccountControl,
    /// Network status, for adapter and DNS settings.
    NetworkStatus,
}

impl HelpTarget {
    /// What the button says. Names the destination, so the user knows where
    /// they are being taken before they click.
    pub fn label(&self) -> &'static str {
        match self {
            HelpTarget::VirusProtectionSettings => "Open virus protection settings",
            HelpTarget::CurrentThreats => "Open current threats",
            HelpTarget::ProtectionUpdates => "Open protection updates",
            HelpTarget::FirewallAndNetwork => "Open firewall settings",
            HelpTarget::WindowsUpdate => "Open Windows Update",
            HelpTarget::RemoteDesktop => "Open Remote Desktop settings",
            HelpTarget::WindowsFeatures => "Open Windows Features",
            HelpTarget::UserAccountControl => "Open User Account Control",
            HelpTarget::NetworkStatus => "Open network settings",
        }
    }

    /// The fixed shell target. A constant in every arm, by construction.
    pub fn target(&self) -> &'static str {
        match self {
            HelpTarget::VirusProtectionSettings => "windowsdefender://threatsettings",
            HelpTarget::CurrentThreats => "windowsdefender://threat",
            HelpTarget::ProtectionUpdates => "windowsdefender://protectionupdates",
            HelpTarget::FirewallAndNetwork => "windowsdefender://network",
            HelpTarget::WindowsUpdate => "ms-settings:windowsupdate",
            HelpTarget::RemoteDesktop => "ms-settings:remotedesktop",
            HelpTarget::NetworkStatus => "ms-settings:network-status",
            // Two settings Windows still only exposes through a control panel
            // applet. Both are in-box, signed Windows executables named by a
            // literal here, and both open a dialog rather than changing
            // anything.
            HelpTarget::WindowsFeatures => "optionalfeatures.exe",
            HelpTarget::UserAccountControl => "useraccountcontrolsettings.exe",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Resolved,
    Dismissed,
    Allowlisted,
}

/// The complete set of changes SENTRY can make.
///
/// Adding a variant is the only way to add a capability, which makes the
/// privileged surface reviewable in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Defender: scan USB sticks and external drives.
    EnableRemovableDriveScanning,
    /// Defender: look inside .zip and similar archives.
    EnableArchiveScanning,
    /// Defender: scan PowerShell and other scripts.
    EnableScriptScanning,
    /// Defender: block potentially unwanted applications rather than only
    /// logging them.
    EnablePuaBlocking,
    /// Defender: start a quick scan now.
    RunQuickScan,
    /// Defender: fetch the latest malware definitions.
    UpdateDefinitions,
}

impl Action {
    /// What the user is told will happen.
    pub fn describe(&self) -> &'static str {
        match self {
            Action::EnableRemovableDriveScanning => {
                "Turn on scanning of USB sticks and external drives"
            }
            Action::EnableArchiveScanning => "Turn on scanning inside zip files and archives",
            Action::EnableScriptScanning => "Turn on scanning of scripts",
            Action::EnablePuaBlocking => {
                "Block potentially unwanted applications instead of only recording them"
            }
            Action::RunQuickScan => "Run a quick malware scan now",
            Action::UpdateDefinitions => "Download the latest malware definitions",
        }
    }

    /// How risky the change is.
    ///
    /// Everything here is `Safe`: each one turns a protection *on* or asks
    /// Defender to do something it already does on a schedule, and each is
    /// reversible through Windows' own settings. Anything that weakens a
    /// protection, edits the registry directly, or cannot be reversed does not
    /// belong in this enum at all -- it belongs in the instructions SENTRY
    /// gives the user.
    pub fn risk(&self) -> FixRisk {
        match self {
            Action::EnableRemovableDriveScanning
            | Action::EnableArchiveScanning
            | Action::EnableScriptScanning
            | Action::EnablePuaBlocking
            | Action::RunQuickScan
            | Action::UpdateDefinitions => FixRisk::Safe,
        }
    }

    /// Whether Windows will refuse this without administrator rights.
    pub fn needs_admin(&self) -> bool {
        match self {
            // Changing Defender policy is an administrative operation.
            Action::EnableRemovableDriveScanning
            | Action::EnableArchiveScanning
            | Action::EnableScriptScanning
            | Action::EnablePuaBlocking => true,
            // Starting a scan and updating definitions are not.
            Action::RunQuickScan | Action::UpdateDefinitions => false,
        }
    }

    /// How to reverse it, for the history record.
    pub fn undo_hint(&self) -> Option<&'static str> {
        match self {
            Action::EnableRemovableDriveScanning => {
                Some("Set-MpPreference -DisableRemovableDriveScanning $true")
            }
            Action::EnableArchiveScanning => Some("Set-MpPreference -DisableArchiveScanning $true"),
            Action::EnableScriptScanning => Some("Set-MpPreference -DisableScriptScanning $true"),
            Action::EnablePuaBlocking => Some("Set-MpPreference -PUAProtection AuditMode"),
            // Neither changes a setting, so neither has anything to undo.
            Action::RunQuickScan | Action::UpdateDefinitions => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Action::EnableRemovableDriveScanning => "enable_removable_drive_scanning",
            Action::EnableArchiveScanning => "enable_archive_scanning",
            Action::EnableScriptScanning => "enable_script_scanning",
            Action::EnablePuaBlocking => "enable_pua_blocking",
            Action::RunQuickScan => "run_quick_scan",
            Action::UpdateDefinitions => "update_definitions",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable across scans: the same problem keeps the same id, so history and
    /// dismissals survive a re-scan.
    pub id: String,
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub what_happened: String,
    pub why_it_matters: String,
    pub affected_asset: Option<String>,
    pub remediation: Option<String>,
    /// The fix that resolves this, when SENTRY can actually apply one.
    ///
    /// `None` means the user has to do it themselves. It is deliberately an
    /// `Action` rather than a boolean: a finding cannot advertise a fix that
    /// does not exist, because there is no way to name one.
    pub fix_action: Option<Action>,
    pub auto_fix: bool,
    /// Set only alongside `fix_action`, because it describes that action.
    pub auto_fix_risk: Option<FixRisk>,
    /// Where in Windows the user carries out `remediation` themselves, when
    /// SENTRY will not do it for them. Advice that ends "in Windows Security,
    /// under Virus & threat protection settings" is a scavenger hunt otherwise.
    pub help_target: Option<HelpTarget>,
    /// Verbatim observations. Never prose, never a claim about a check that
    /// did not run.
    pub evidence: Vec<String>,
    pub references: Vec<String>,
    pub status: FindingStatus,
    pub source: String,
}

impl Finding {
    pub fn id_for(rule_id: &str, asset: Option<&str>) -> String {
        // FNV-1a: small, deterministic, and stable across Rust releases --
        // unlike DefaultHasher, whose output is explicitly not guaranteed.
        let key = format!("{rule_id}|{}", asset.unwrap_or("-"));
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in key.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{}-{:012x}", rule_id, hash & 0xffff_ffff_ffff)
    }
}

/// Builder keeping rule definitions readable.
pub struct FindingBuilder {
    finding: Finding,
}

impl FindingBuilder {
    pub fn new(rule_id: &str, category: &str, severity: Severity, title: &str) -> Self {
        Self {
            finding: Finding {
                id: Finding::id_for(rule_id, None),
                rule_id: rule_id.to_string(),
                category: category.to_string(),
                severity,
                confidence: Confidence::Confirmed,
                title: title.to_string(),
                what_happened: String::new(),
                why_it_matters: String::new(),
                affected_asset: None,
                remediation: None,
                fix_action: None,
                auto_fix: false,
                auto_fix_risk: None,
                help_target: None,
                evidence: Vec::new(),
                references: Vec::new(),
                status: FindingStatus::Open,
                source: String::new(),
            },
        }
    }

    pub fn what(mut self, text: &str) -> Self {
        self.finding.what_happened = text.to_string();
        self
    }

    pub fn why(mut self, text: &str) -> Self {
        self.finding.why_it_matters = text.to_string();
        self
    }

    pub fn confidence(mut self, c: Confidence) -> Self {
        self.finding.confidence = c;
        self
    }

    pub fn asset(mut self, asset: &str) -> Self {
        self.finding.affected_asset = Some(asset.to_string());
        self.finding.id = Finding::id_for(&self.finding.rule_id, Some(asset));
        self
    }

    /// What the user should do. Describing a fix does not imply SENTRY can
    /// apply it -- see `fixable_with`.
    /// What the user should do. Advice only: it does not imply SENTRY can do
    /// it, and does not set `auto_fix_risk` -- only `fixable_with` can, because
    /// only an action has a risk.
    pub fn remediation(mut self, text: &str) -> Self {
        self.finding.remediation = Some(text.to_string());
        self
    }

    /// The Windows page where the recommendation above is carried out.
    pub fn help(mut self, target: HelpTarget) -> Self {
        self.finding.help_target = Some(target);
        self
    }

    /// Declare that SENTRY can fix this itself, with the action that does it.
    ///
    /// The only way `auto_fix` is ever set, so an offered fix always has an
    /// implementation behind it.
    pub fn fixable_with(mut self, action: Action) -> Self {
        self.finding.fix_action = Some(action);
        self.finding.auto_fix = true;
        self.finding.auto_fix_risk = Some(action.risk());
        self
    }

    pub fn evidence(mut self, lines: impl IntoIterator<Item = String>) -> Self {
        self.finding.evidence.extend(lines);
        self
    }

    pub fn reference(mut self, url: &str) -> Self {
        self.finding.references.push(url.to_string());
        self
    }

    pub fn source(mut self, source: &str) -> Self {
        self.finding.source = source.to_string();
        self
    }

    pub fn build(self) -> Finding {
        debug_assert!(
            !self.finding.what_happened.is_empty(),
            "finding needs a what"
        );
        debug_assert!(!self.finding.evidence.is_empty(), "finding needs evidence");
        self.finding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_worst_last() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Attention);
        assert!(Severity::Attention > Severity::Safe);
        assert_eq!(
            Severity::worst([Severity::Safe, Severity::Critical, Severity::Attention]),
            Some(Severity::Critical)
        );
        assert_eq!(Severity::worst([]), None);
    }

    #[test]
    fn ids_are_stable_and_distinct() {
        let a = Finding::id_for("DEF-001", None);
        assert_eq!(
            a,
            Finding::id_for("DEF-001", None),
            "id must be reproducible"
        );
        assert_ne!(a, Finding::id_for("DEF-002", None));
        assert_ne!(
            Finding::id_for("SW-001", Some("7-Zip")),
            Finding::id_for("SW-001", Some("Firefox")),
            "same rule on different assets must not collide"
        );
        assert!(a.starts_with("DEF-001-"));
    }

    #[test]
    fn a_finding_cannot_offer_a_fix_without_one_behind_it() {
        // The bug this prevents: 16 findings once advertised an automatic fix
        // while only a handful had an implementation, so most of those buttons
        // would have done nothing. `auto_fix` is now settable only by naming
        // the Action that performs it.
        let described_only = FindingBuilder::new("X", "T", Severity::Warning, "t")
            .what("w")
            .evidence(["e".to_string()])
            .remediation("Do it yourself in Windows Settings.")
            .help(HelpTarget::VirusProtectionSettings)
            .build();

        assert!(
            !described_only.auto_fix,
            "describing a fix must not advertise one"
        );
        assert!(described_only.fix_action.is_none());
        assert!(
            described_only.remediation.is_some(),
            "the advice is still shown"
        );
        // The second half of the same bug: those 16 findings also printed a
        // note about the automatic fix -- "reversible, with no side effects" --
        // under advice SENTRY cannot act on. A risk belongs to an action, so
        // with no action there is nothing to state.
        assert!(
            described_only.auto_fix_risk.is_none(),
            "advice with no action has no risk to report"
        );
        assert!(
            described_only.help_target.is_some(),
            "advice naming a Windows page should link to it"
        );

        let applicable = FindingBuilder::new("Y", "T", Severity::Warning, "t")
            .what("w")
            .evidence(["e".to_string()])
            .remediation("Turn archive scanning back on.")
            .fixable_with(Action::EnableArchiveScanning)
            .build();

        assert!(applicable.auto_fix);
        assert_eq!(applicable.fix_action, Some(Action::EnableArchiveScanning));
        // The risk shown always comes from the action itself, never a claim
        // made alongside it.
        assert_eq!(
            applicable.auto_fix_risk,
            Some(Action::EnableArchiveScanning.risk())
        );
    }

    #[test]
    fn setting_an_asset_rebinds_the_id() {
        let f = FindingBuilder::new("SW-001", "Software", Severity::Warning, "t")
            .what("w")
            .evidence(["e".into()])
            .asset("7-Zip")
            .build();
        assert_eq!(f.id, Finding::id_for("SW-001", Some("7-Zip")));
    }
}

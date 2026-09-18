//! Making changes to the machine.
//!
//! This is the most dangerous code in SENTRY, so it is the most constrained.
//!
//! Every fix is a **named verb** in a fixed list. There is no
//! `run_command(string)`, nothing is assembled from a finding's text, and
//! nothing a model or a feed produces ever becomes something that executes. A
//! compromised webview can ask for `EnableRemovableDriveScanning`; it cannot
//! ask for anything that is not in the enum below.
//!
//! Every fix also:
//!   * declares its risk, and a `Caution` fix refuses to run without explicit
//!     confirmation for that specific action;
//!   * records what the setting was before, so the change can be described and
//!     undone;
//!   * writes a history row before it acts, so a crash mid-change still leaves
//!     evidence;
//!   * requires administrator rights where Windows requires them, and says so
//!     rather than failing obscurely.

use serde::{Deserialize, Serialize};

use crate::database::Database;
use crate::findings::FixRisk;

pub mod actions;
pub mod elevation;

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

/// The result of attempting a fix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub action: Action,
    pub succeeded: bool,
    /// What happened, in the user's terms.
    pub detail: String,
    /// Present when the change can be reversed.
    pub undo_hint: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RemediationError {
    #[error("{0}")]
    NeedsAdministrator(String),

    #[error("{0}")]
    NeedsConfirmation(String),

    #[error("{0}")]
    Failed(String),

    #[error("{0}")]
    Unsupported(String),
}

/// Open a history row before the change is attempted.
///
/// Written first on purpose: if the process dies mid-change, the row is still
/// there, marked `running`, which is the only evidence that something was
/// started.
pub fn begin(
    db: &Database,
    action: Action,
    finding_id: Option<&str>,
    confirmed: bool,
    previous_value: Option<&str>,
) -> rusqlite::Result<i64> {
    let now = chrono::Utc::now().to_rfc3339();

    db.with(|c| {
        c.execute(
            "INSERT INTO remediation_history
                (finding_id, action, risk, started_at, status, previous_value, undo_hint, confirmed)
             VALUES (?1, ?2, ?3, ?4, 'running', ?5, ?6, ?7)",
            rusqlite::params![
                finding_id,
                action.as_str(),
                format!("{:?}", action.risk()).to_lowercase(),
                now,
                previous_value,
                action.undo_hint(),
                confirmed as i32,
            ],
        )?;
        Ok(c.last_insert_rowid())
    })
}

/// Close a history row.
pub fn finish(db: &Database, id: i64, status: &str, detail: &str) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();

    db.with(|c| {
        c.execute(
            "UPDATE remediation_history SET finished_at = ?1, status = ?2, detail = ?3 WHERE id = ?4",
            rusqlite::params![now, status, detail, id],
        )?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[Action] = &[
        Action::EnableRemovableDriveScanning,
        Action::EnableArchiveScanning,
        Action::EnableScriptScanning,
        Action::EnablePuaBlocking,
        Action::RunQuickScan,
        Action::UpdateDefinitions,
    ];

    #[test]
    fn every_action_is_describable_in_plain_language() {
        for action in ALL {
            let described = action.describe();
            assert!(!described.is_empty());
            // No PowerShell, no registry paths in what the user is shown.
            assert!(!described.contains("Set-MpPreference"), "{action:?}");
            assert!(!described.contains("HKLM"), "{action:?}");
        }
    }

    #[test]
    fn every_action_has_a_stable_identifier() {
        let mut names: Vec<&str> = ALL.iter().map(|a| a.as_str()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "action identifiers must be unique");
    }

    #[test]
    fn every_action_in_the_list_is_safe() {
        // The enum is the privileged surface. If a Caution or Manual action is
        // ever added, this test should fail and force the confirmation path to
        // be reviewed rather than silently inherited.
        for action in ALL {
            assert_eq!(
                action.risk(),
                FixRisk::Safe,
                "{action:?} is not Safe -- the confirmation flow needs revisiting"
            );
        }
    }

    #[test]
    fn setting_changes_can_be_undone_and_one_off_actions_cannot() {
        assert!(Action::EnableArchiveScanning.undo_hint().is_some());
        assert!(Action::EnablePuaBlocking.undo_hint().is_some());
        // Starting a scan changes no setting, so there is nothing to reverse.
        assert!(Action::RunQuickScan.undo_hint().is_none());
        assert!(Action::UpdateDefinitions.undo_hint().is_none());
    }

    #[test]
    fn policy_changes_need_administrator_rights_and_scans_do_not() {
        assert!(Action::EnableRemovableDriveScanning.needs_admin());
        assert!(Action::EnablePuaBlocking.needs_admin());
        assert!(!Action::RunQuickScan.needs_admin());
        assert!(!Action::UpdateDefinitions.needs_admin());
    }

    #[test]
    fn history_records_the_attempt_before_the_outcome() {
        let db = Database::open_in_memory().unwrap();

        let id = begin(
            &db,
            Action::EnableArchiveScanning,
            Some("MAL-012-abc"),
            true,
            Some("true"),
        )
        .unwrap();

        let (status, finished): (String, Option<String>) = db
            .with(|c| {
                c.query_row(
                    "SELECT status, finished_at FROM remediation_history WHERE id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .unwrap();

        assert_eq!(
            status, "running",
            "the row must exist before the change is made"
        );
        assert!(finished.is_none());

        finish(&db, id, "succeeded", "Archive scanning is on").unwrap();

        let (status, finished, undo): (String, Option<String>, Option<String>) = db
            .with(|c| {
                c.query_row(
                    "SELECT status, finished_at, undo_hint FROM remediation_history WHERE id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
            })
            .unwrap();

        assert_eq!(status, "succeeded");
        assert!(finished.is_some());
        assert!(undo.unwrap().contains("DisableArchiveScanning"));
    }

    #[test]
    fn history_records_what_the_setting_was_before() {
        let db = Database::open_in_memory().unwrap();
        let id = begin(
            &db,
            Action::EnablePuaBlocking,
            None,
            true,
            Some("audit_mode"),
        )
        .unwrap();

        let previous: Option<String> = db
            .with(|c| {
                c.query_row(
                    "SELECT previous_value FROM remediation_history WHERE id = ?1",
                    [id],
                    |r| r.get(0),
                )
            })
            .unwrap();

        assert_eq!(previous.as_deref(), Some("audit_mode"));
    }
}

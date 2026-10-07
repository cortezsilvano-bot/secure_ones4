//! The command that changes the machine.
//!
//! One entry point, taking a value from a fixed enum. The webview cannot name
//! an action that does not exist, and serde rejects anything that is not one of
//! the known variants before a single line of privileged code runs.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::remediation::{self, Action, RemediationError};
use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixDescription {
    pub action: Action,
    pub id: String,
    pub describes: String,
    pub risk: String,
    pub needs_admin: bool,
    pub reversible: bool,
}

/// Every fix SENTRY can apply, for the UI to offer.
#[tauri::command]
pub fn list_available_fixes() -> Vec<FixDescription> {
    const ALL: &[Action] = &[
        Action::EnableRemovableDriveScanning,
        Action::EnableArchiveScanning,
        Action::EnableScriptScanning,
        Action::EnablePuaBlocking,
        Action::RunQuickScan,
        Action::UpdateDefinitions,
    ];

    ALL.iter()
        .map(|a| FixDescription {
            action: *a,
            id: a.as_str().to_string(),
            describes: a.describe().to_string(),
            risk: format!("{:?}", a.risk()).to_lowercase(),
            needs_admin: a.needs_admin(),
            reversible: a.undo_hint().is_some(),
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixResult {
    pub succeeded: bool,
    pub detail: String,
    pub undo_hint: Option<String>,
    /// True when the change would work with administrator rights, so the UI can
    /// say that rather than showing a bare failure.
    pub needs_admin: bool,
}

/// Apply one fix.
#[tauri::command]
pub async fn apply_fix(
    state: State<'_, AppState>,
    action: Action,
    finding_id: Option<String>,
    confirmed: Option<bool>,
) -> Result<FixResult, String> {
    let db = state.db.clone();
    let confirmed = confirmed.unwrap_or(false);

    let result = tauri::async_runtime::spawn_blocking(move || {
        // The history row is opened first, so a change that crashes halfway
        // still leaves a record that it was attempted.
        let history = remediation::begin(&db, action, finding_id.as_deref(), confirmed, None).ok();

        let outcome = remediation::actions::perform(action, confirmed);

        if let Some(id) = history {
            let (status, detail) = match &outcome {
                Ok(o) => ("succeeded", o.detail.clone()),
                Err(RemediationError::NeedsConfirmation(m)) => ("refused", m.clone()),
                Err(e) => ("failed", e.to_string()),
            };
            let _ = remediation::finish(&db, id, status, &detail);
        }

        outcome
    })
    .await;

    match result {
        Ok(Ok(outcome)) => Ok(FixResult {
            succeeded: outcome.succeeded,
            detail: outcome.detail,
            undo_hint: outcome.undo_hint,
            needs_admin: false,
        }),
        Ok(Err(e)) => Ok(FixResult {
            succeeded: false,
            needs_admin: matches!(e, RemediationError::NeedsAdministrator(_)),
            detail: e.to_string(),
            undo_hint: None,
        }),
        Err(e) => {
            log::error!("fix task failed: {e}");
            Err("The change stopped unexpectedly. See the application log.".into())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationRecord {
    pub action: String,
    pub started_at: String,
    pub status: String,
    pub detail: Option<String>,
    pub undo_hint: Option<String>,
}

/// Every change SENTRY has made, newest first.
#[tauri::command]
pub fn get_remediation_history(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<RemediationRecord>, String> {
    let limit = limit.unwrap_or(50).clamp(1, 200);

    state
        .db
        .with(|c| {
            let mut stmt = c.prepare(
                "SELECT action, started_at, status, detail, undo_hint
                 FROM remediation_history ORDER BY started_at DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map([limit], |r| {
                Ok(RemediationRecord {
                    action: r.get(0)?,
                    started_at: r.get(1)?,
                    status: r.get(2)?,
                    detail: r.get(3)?,
                    undo_hint: r.get(4)?,
                })
            })?;
            rows.collect()
        })
        .map_err(|e| {
            log::error!("could not read the remediation history: {e}");
            "The list of changes could not be read.".to_string()
        })
}

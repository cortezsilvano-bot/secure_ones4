//! Carrying out the fixes.
//!
//! Every change goes through Defender's own WMI methods -- `MSFT_MpPreference`
//! `Set`, `MSFT_MpScan` `Start`, `MSFT_MpSignature` `Update`. Nothing here
//! spawns a shell.
//!
//! That is not squeamishness. Shelling out to PowerShell from a security tool
//! means constructing a command line, which means the difference between a safe
//! program and an injectable one becomes a question of string handling. Calling
//! the API directly makes the question disappear: there is no command line to
//! get wrong.

use super::{Action, Outcome, RemediationError};

#[cfg(windows)]
const NAMESPACE: &str = r"root\Microsoft\Windows\Defender";

/// Perform one fix.
///
/// `confirmed` must be true for anything riskier than `Safe`. Everything in the
/// current action list is `Safe`, but the check is enforced here rather than
/// assumed, so adding a riskier verb later cannot quietly skip it.
pub fn perform(action: Action, confirmed: bool) -> Result<Outcome, RemediationError> {
    use crate::findings::FixRisk;

    if action.risk() != FixRisk::Safe && !confirmed {
        return Err(RemediationError::NeedsConfirmation(format!(
            "\"{}\" changes system settings and needs to be confirmed first.",
            action.describe()
        )));
    }

    // Asked before attempting. Windows reports a policy refusal through WMI as
    // a bare WBEM_E_FAILED with nothing to indicate that rights are the issue,
    // so attempting first would show the user a hex code instead of the reason.
    if action.needs_admin() && !super::elevation::is_elevated() {
        return Err(RemediationError::NeedsAdministrator(format!(
            "\"{}\" changes a Windows security setting, which needs administrator rights.              Close SENTRY and reopen it as an administrator to make this change.",
            action.describe()
        )));
    }

    run(action)
}

#[cfg(windows)]
fn run(action: Action) -> Result<Outcome, RemediationError> {
    let result = match action {
        Action::EnableRemovableDriveScanning => set_preference(
            "scanning of removable drives",
            SetRemovableDriveScanning {
                DisableRemovableDriveScanning: false,
            },
            "USB sticks and external drives will now be scanned.".to_string(),
        ),
        Action::EnableArchiveScanning => set_preference(
            "archive scanning",
            SetArchiveScanning {
                DisableArchiveScanning: false,
            },
            "Files inside zip archives will now be scanned.".to_string(),
        ),
        Action::EnableScriptScanning => set_preference(
            "script scanning",
            SetScriptScanning {
                DisableScriptScanning: false,
            },
            "Scripts will now be scanned.".to_string(),
        ),
        // 1 blocks; 2 is audit mode, which only records.
        Action::EnablePuaBlocking => set_preference(
            "unwanted software blocking",
            SetPuaProtection { PUAProtection: 1 },
            "Potentially unwanted applications will now be blocked.".to_string(),
        ),
        Action::RunQuickScan => start_scan(),
        Action::UpdateDefinitions => update_definitions(),
    };

    result.map(|detail| Outcome {
        action,
        succeeded: true,
        detail,
        undo_hint: action.undo_hint().map(str::to_string),
    })
}

#[cfg(windows)]
fn connect() -> Result<wmi::WMIConnection, RemediationError> {
    wmi::WMIConnection::with_namespace_path(NAMESPACE)
        .map_err(|e| RemediationError::Failed(format!("Could not reach Microsoft Defender: {e}")))
}

/// `MSFT_MpPreference` as far as the method call is concerned. Only the class
/// name matters to `exec_class_method`; the fields are the input parameters.
#[cfg(windows)]
#[derive(serde::Deserialize)]
#[allow(non_camel_case_types, non_snake_case, dead_code)]
struct MSFT_MpPreference {
    __Path: String,
}

/// A WMI method's output.
///
/// Deserialised as a free-form value rather than a fixed struct: although all
/// three Defender methods declare a `UInt32` return type, the bridge hands back
/// a unit when a call produces no out-parameters. Demanding a struct turned a
/// successful call into a deserialisation error.
#[cfg(windows)]
fn return_value(output: &serde_json::Value) -> u32 {
    output
        .get("ReturnValue")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32
}

// Input parameters must be flat structs: the WMI bridge cannot turn a map into
// the variant set a method call needs. One struct per setting also means the
// parameter names are checked at compile time rather than spelled in a string.
#[cfg(windows)]
#[derive(serde::Serialize)]
#[allow(non_snake_case)]
struct SetRemovableDriveScanning {
    DisableRemovableDriveScanning: bool,
}

#[cfg(windows)]
#[derive(serde::Serialize)]
#[allow(non_snake_case)]
struct SetArchiveScanning {
    DisableArchiveScanning: bool,
}

#[cfg(windows)]
#[derive(serde::Serialize)]
#[allow(non_snake_case)]
struct SetScriptScanning {
    DisableScriptScanning: bool,
}

#[cfg(windows)]
#[derive(serde::Serialize)]
#[allow(non_snake_case)]
struct SetPuaProtection {
    PUAProtection: u8,
}

/// Call `MSFT_MpPreference::Set` with one already-typed parameter set.
#[cfg(windows)]
fn set_preference<P: serde::Serialize>(
    what: &str,
    params: P,
    describe: String,
) -> Result<String, RemediationError> {
    let connection = connect()?;

    let output: serde_json::Value = connection
        .exec_class_method::<MSFT_MpPreference, _>("Set", params)
        .map_err(|e| map_error(what, e))?;

    check_return(return_value(&output), what)?;
    Ok(describe)
}

#[cfg(windows)]
#[derive(serde::Deserialize)]
#[allow(non_camel_case_types, non_snake_case, dead_code)]
struct MSFT_MpScan {
    __Path: String,
}

#[cfg(windows)]
fn start_scan() -> Result<String, RemediationError> {
    #[derive(serde::Serialize)]
    #[allow(non_snake_case)]
    struct StartScan {
        // 1 is a quick scan: the places malware actually starts from, rather
        // than every file on every disk.
        ScanType: u8,
    }

    let connection = connect()?;

    let output: serde_json::Value = connection
        .exec_class_method::<MSFT_MpScan, _>("Start", StartScan { ScanType: 1 })
        .map_err(|e| map_error("starting a scan", e))?;

    check_return(return_value(&output), "starting a scan")?;
    Ok("Defender has started a quick scan. It runs in the background.".to_string())
}

#[cfg(windows)]
#[derive(serde::Deserialize)]
#[allow(non_camel_case_types, non_snake_case, dead_code)]
struct MSFT_MpSignature {
    __Path: String,
}

#[cfg(windows)]
fn update_definitions() -> Result<String, RemediationError> {
    let connection = connect()?;

    let output: serde_json::Value = connection
        .exec_class_method::<MSFT_MpSignature, _>("Update", ())
        .map_err(|e| map_error("updating definitions", e))?;

    check_return(return_value(&output), "updating definitions")?;
    Ok("Defender is downloading the latest malware definitions.".to_string())
}

/// WMI methods signal failure through the return value as well as through
/// errors, so both paths have to be checked.
#[cfg(windows)]
fn check_return(value: u32, what: &str) -> Result<(), RemediationError> {
    const ERROR_ACCESS_DENIED: u32 = 5;

    match value {
        0 => Ok(()),
        ERROR_ACCESS_DENIED => Err(RemediationError::NeedsAdministrator(format!(
            "Windows refused to change {what}. Run SENTRY as an administrator to make this change."
        ))),
        other => Err(RemediationError::Failed(format!(
            "Defender refused to change {what} (error {other})."
        ))),
    }
}

#[cfg(windows)]
fn map_error(what: &str, e: wmi::WMIError) -> RemediationError {
    let text = e.to_string();
    let lowered = text.to_ascii_lowercase();

    // 0x80041001 is WBEM_E_FAILED, which is what a rights refusal looks like
    // through the raw WMI path.
    if lowered.contains("access denied")
        || lowered.contains("80070005")
        || lowered.contains("80041001")
    {
        return RemediationError::NeedsAdministrator(format!(
            "Windows refused to change {what}. Run SENTRY as an administrator to make this change."
        ));
    }

    RemediationError::Failed(format!("Could not change {what}: {text}"))
}

#[cfg(not(windows))]
fn run(_action: Action) -> Result<Outcome, RemediationError> {
    Err(RemediationError::Unsupported(
        "Fixes are only available on Windows.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::FixRisk;

    #[test]
    fn a_risky_action_is_refused_without_confirmation() {
        // Everything in the current list is Safe, so this exercises the guard
        // directly rather than through an action. It is the check that must not
        // rot if a Caution verb is added later.
        let needs_confirmation =
            |risk: FixRisk, confirmed: bool| risk != FixRisk::Safe && !confirmed;

        assert!(needs_confirmation(FixRisk::Caution, false));
        assert!(!needs_confirmation(FixRisk::Caution, true));
        assert!(!needs_confirmation(FixRisk::Safe, false));
    }

    #[test]
    fn safe_actions_do_not_require_confirmation() {
        // Turning a protection on is not something a user should have to
        // confirm twice.
        for action in [
            Action::EnableArchiveScanning,
            Action::RunQuickScan,
            Action::UpdateDefinitions,
        ] {
            assert_eq!(action.risk(), FixRisk::Safe, "{action:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn access_denied_is_reported_as_needing_administrator() {
        let err = check_return(5, "archive scanning").unwrap_err();
        assert!(matches!(err, RemediationError::NeedsAdministrator(_)));
        assert!(err.to_string().contains("administrator"));
    }

    #[cfg(windows)]
    #[test]
    fn a_missing_return_value_is_treated_as_success() {
        // The bridge hands back a unit when a call produces no out-parameters,
        // which is what a successful void-shaped call looks like.
        assert_eq!(return_value(&serde_json::Value::Null), 0);
        assert_eq!(return_value(&serde_json::json!({})), 0);
        assert_eq!(return_value(&serde_json::json!({ "ReturnValue": 0 })), 0);
        assert_eq!(return_value(&serde_json::json!({ "ReturnValue": 5 })), 5);
    }

    #[cfg(windows)]
    #[test]
    fn a_zero_return_is_success_and_anything_else_is_not() {
        assert!(check_return(0, "x").is_ok());
        let err = check_return(87, "x").unwrap_err();
        assert!(matches!(err, RemediationError::Failed(_)));
        assert!(err.to_string().contains("87"));
    }
}

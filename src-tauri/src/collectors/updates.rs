//! Windows Update status, read through the Windows Update Agent COM API
//! (`wuapi.dll`) plus the agent's own registry results key.
//!
//! The search is run with `Online = false`. That is a deliberate trade:
//!
//!   * An online search contacts Microsoft's update servers on every scan. For
//!     a privacy-first tool that is an outbound call the user did not ask for,
//!     and it can block for tens of seconds.
//!   * An offline search reads the metadata the Windows Update Agent has
//!     already cached from its own scheduled scans. It is immediate and makes
//!     no network call of our own.
//!
//! The cost is that results are only as fresh as Windows' last scan, so the
//! age of that scan is collected alongside them and reported. A pending-update
//! count means little without knowing when it was last established.

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingUpdate {
    pub title: String,
    /// Microsoft's rating: "Critical", "Important", "Moderate", "Low".
    /// Absent for non-security updates, which is how they are told apart.
    pub msrc_severity: Option<String>,
    pub is_security_update: bool,
    /// KB numbers, e.g. "5034123".
    pub kb_article_ids: Vec<String>,
    /// Already downloaded and waiting to install.
    pub is_downloaded: bool,
    pub is_mandatory: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFacts {
    pub pending: Vec<PendingUpdate>,
    /// An install has completed but the machine has not restarted, so the fix
    /// is not actually in effect yet.
    pub reboot_required: Option<bool>,
    /// When Windows itself last successfully checked for updates.
    pub last_search_success: Option<String>,
    pub last_install_success: Option<String>,
    /// Days since that check, if it could be determined.
    pub search_age_days: Option<i64>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl UpdateFacts {
    pub fn security_updates(&self) -> impl Iterator<Item = &PendingUpdate> {
        self.pending.iter().filter(|u| u.is_security_update)
    }
}

#[cfg(windows)]
pub fn collect() -> Result<UpdateFacts, CollectorError> {
    use windows::core::BSTR;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::System::UpdateAgent::{
        ISystemInformation, IUpdateSession, SystemInformation, UpdateSession,
    };

    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }

    let mut facts = UpdateFacts {
        collected_at: chrono::Utc::now().to_rfc3339(),
        evidence: vec!["COM interface: IUpdateSearcher (wuapi.dll)".to_string()],
        ..Default::default()
    };

    // Read from the registry first: it needs no COM and still gives us
    // something useful if the update agent itself will not answer.
    read_agent_results(&mut facts);

    unsafe {
        let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if hr.is_err() {
            return Err(CollectorError::Unavailable(format!(
                "Could not initialise COM to read Windows Update: {hr:?}"
            )));
        }
        let _com = ComGuard;

        // Reboot-pending is a separate, cheap call; a failure here should not
        // cost us the update list.
        if let Ok(info) = CoCreateInstance::<_, ISystemInformation>(
            &SystemInformation,
            None,
            CLSCTX_INPROC_SERVER,
        ) {
            facts.reboot_required = info.RebootRequired().ok().map(|b| b.as_bool());
            facts.evidence.push(format!(
                "ISystemInformation.RebootRequired: {}",
                facts
                    .reboot_required
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "unreported".into())
            ));
        }

        let session: IUpdateSession = CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| map_com_error("creating the Windows Update session", &e))?;

        // Identifies us in Windows Update's own logs rather than posing as
        // another product.
        let _ = session.SetClientApplicationID(&BSTR::from("SENTRY"));

        let searcher = session
            .CreateUpdateSearcher()
            .map_err(|e| map_com_error("creating the update searcher", &e))?;

        // See the module comment: cached metadata only, no network call.
        let _ = searcher.SetOnline(false.into());
        facts
            .evidence
            .push("Search mode: offline (cached Windows Update metadata)".to_string());

        const CRITERIA: &str = "IsInstalled=0 AND IsHidden=0";
        let result = searcher
            .Search(&BSTR::from(CRITERIA))
            .map_err(|e| map_com_error("searching for pending updates", &e))?;
        facts.evidence.push(format!("Search criteria: {CRITERIA}"));

        let updates = result
            .Updates()
            .map_err(|e| map_com_error("reading the update collection", &e))?;

        let count = updates.Count().unwrap_or(0);
        for i in 0..count {
            let Ok(update) = updates.get_Item(i) else {
                continue;
            };

            let title = update
                .Title()
                .map(|b| b.to_string())
                .unwrap_or_else(|_| "Unnamed update".to_string());

            let msrc_severity = update
                .MsrcSeverity()
                .ok()
                .map(|b| b.to_string())
                .filter(|s| !s.is_empty());

            let mut kb_article_ids = Vec::new();
            if let Ok(kbs) = update.KBArticleIDs() {
                let n = kbs.Count().unwrap_or(0);
                for k in 0..n {
                    if let Ok(id) = kbs.get_Item(k) {
                        kb_article_ids.push(id.to_string());
                    }
                }
            }

            // An update is a security update if Microsoft rated it, or if it
            // carries a security bulletin. Checking both avoids missing ones
            // that are rated but unbulletined and vice versa.
            let has_bulletin = update
                .SecurityBulletinIDs()
                .ok()
                .and_then(|c| c.Count().ok())
                .is_some_and(|n| n > 0);

            facts.pending.push(PendingUpdate {
                title,
                is_security_update: msrc_severity.is_some() || has_bulletin,
                msrc_severity,
                kb_article_ids,
                is_downloaded: update.IsDownloaded().map(|b| b.as_bool()).unwrap_or(false),
                is_mandatory: update.IsMandatory().map(|b| b.as_bool()).unwrap_or(false),
            });
        }

        facts.evidence.push(format!(
            "Pending updates: {} ({} security)",
            facts.pending.len(),
            facts.security_updates().count()
        ));
    }

    Ok(facts)
}

/// Read the update agent's last-success timestamps from the registry. Cheaper
/// and far simpler than coaxing dates out of WUA's VARIANTs.
///
/// Two layouts exist and both are tried, because which one is populated
/// depends on the Windows build:
///
///   * `...\Auto Update\Results\{Detect,Install}\LastSuccessTime` -- the
///     classic location, still present on older builds.
///   * `...\Auto Update\LastOnlineScanTimeForAppCategory\<category>\<serviceId>`
///     -- what Windows 11 writes, one timestamp per update service. The most
///     recent across all of them is the machine's last online scan.
///
/// Checking only the first reports "never checked" on a current, fully patched
/// Windows 11 machine, which would be a false alarm rather than a missing value.
#[cfg(windows)]
fn read_agent_results(facts: &mut UpdateFacts) {
    use windows_registry::LOCAL_MACHINE;

    const AUTO_UPDATE: &str =
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update";

    let Ok(auto_update) = LOCAL_MACHINE.open(AUTO_UPDATE) else {
        facts
            .evidence
            .push("Windows Update registry key: not readable".to_string());
        return;
    };

    // Layout 1: the classic Results key.
    if let Ok(results) = auto_update.open("Results") {
        let read = |sub: &str| -> Option<String> {
            results
                .open(sub)
                .ok()?
                .get_string("LastSuccessTime")
                .ok()
                .filter(|s| !s.is_empty())
        };
        facts.last_search_success = read("Detect");
        facts.last_install_success = read("Install");
    }

    // Layout 2: Windows 11's per-service scan times. Only consulted when the
    // classic key gave nothing, so an explicit Detect time always wins.
    if facts.last_search_success.is_none() {
        facts.last_search_success = latest_online_scan(&auto_update);
    }

    match &facts.last_search_success {
        Some(raw) => {
            facts
                .evidence
                .push(format!("Last successful update check: {raw} (UTC)"));
            facts.search_age_days = age_in_days(raw);
        }
        None => facts
            .evidence
            .push("Last successful update check: not recorded by Windows".to_string()),
    }
}

/// The most recent timestamp under `LastOnlineScanTimeForAppCategory`.
///
/// The tree is `<category GUID>\<service GUID> = "YYYY-MM-DD HH:MM:SS"`, with
/// one entry per update service. Lexicographic comparison is safe here because
/// that format sorts chronologically.
#[cfg(windows)]
fn latest_online_scan(auto_update: &windows_registry::Key) -> Option<String> {
    let categories = auto_update.open("LastOnlineScanTimeForAppCategory").ok()?;

    let mut newest: Option<String> = None;

    for category in categories.keys().ok()?.collect::<Vec<_>>() {
        let Ok(key) = categories.open(&category) else {
            continue;
        };
        let Ok(values) = key.values() else { continue };

        for (name, _value) in values {
            // Re-read by name: `Value` is a raw typed blob, and `get_string`
            // is the accessor that yields the REG_SZ text we want.
            let Ok(stamp) = key.get_string(&name) else {
                continue;
            };
            let stamp = stamp.trim();
            // Ignore anything that is not the expected shape rather than
            // letting a stray value become the reported scan time.
            if age_in_days(stamp).is_none() {
                continue;
            }
            if newest.as_deref().is_none_or(|current| stamp > current) {
                newest = Some(stamp.to_string());
            }
        }
    }

    newest
}

/// Days between a `YYYY-MM-DD HH:MM:SS` UTC stamp and now.
fn age_in_days(raw: &str) -> Option<i64> {
    use chrono::{NaiveDateTime, Utc};

    let parsed = NaiveDateTime::parse_from_str(raw.trim(), "%Y-%m-%d %H:%M:%S").ok()?;
    let days = Utc::now()
        .naive_utc()
        .signed_duration_since(parsed)
        .num_days();

    // A negative age means a clock skew, not a fresh scan; report nothing
    // rather than something impossible.
    (days >= 0).then_some(days)
}

#[cfg(windows)]
fn map_com_error(during: &str, e: &windows::core::Error) -> CollectorError {
    use windows::Win32::Foundation::{E_ACCESSDENIED, REGDB_E_CLASSNOTREG};

    match e.code() {
        E_ACCESSDENIED => CollectorError::PermissionDenied(format!(
            "Windows refused access while {during}. Run SENTRY as an administrator to read this."
        )),
        REGDB_E_CLASSNOTREG => CollectorError::Unsupported(format!(
            "The Windows Update Agent is not available on this system (while {during})."
        )),
        _ => CollectorError::Unavailable(format!(
            "The Windows Update Agent failed while {during}: {e}. This often means the Windows \
             Update service is stopped or managed by a policy."
        )),
    }
}

#[cfg(not(windows))]
pub fn collect() -> Result<UpdateFacts, CollectorError> {
    Err(CollectorError::Unsupported(
        "Windows Update status is only available on Windows.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(title: &str, severity: Option<&str>, bulletin: bool) -> PendingUpdate {
        PendingUpdate {
            title: title.to_string(),
            msrc_severity: severity.map(str::to_string),
            is_security_update: severity.is_some() || bulletin,
            kb_article_ids: vec![],
            is_downloaded: false,
            is_mandatory: false,
        }
    }

    #[test]
    fn security_updates_are_filtered_by_rating_or_bulletin() {
        let facts = UpdateFacts {
            pending: vec![
                update("Security Update for Windows", Some("Critical"), false),
                update("Definition Update", None, true),
                update("Driver update for a printer", None, false),
            ],
            ..Default::default()
        };
        assert_eq!(facts.security_updates().count(), 2);
    }

    #[test]
    fn parses_the_agent_timestamp_format() {
        // Windows writes this exact shape; a 2020 stamp is unambiguously old.
        let age = age_in_days("2020-01-01 00:00:00").expect("should parse");
        assert!(age > 1000, "expected a large age, got {age}");
    }

    #[test]
    fn rejects_unparseable_timestamps() {
        assert_eq!(age_in_days(""), None);
        assert_eq!(age_in_days("not a date"), None);
        assert_eq!(age_in_days("2026/09/17 10:00:00"), None);
    }

    #[test]
    fn a_future_timestamp_reports_no_age() {
        // Clock skew must not present as a suspiciously fresh scan.
        let future = (chrono::Utc::now() + chrono::Duration::days(30))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        assert_eq!(age_in_days(&future), None);
    }

    #[test]
    fn a_recent_timestamp_is_zero_days_old() {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        assert_eq!(age_in_days(&now), Some(0));
    }
}

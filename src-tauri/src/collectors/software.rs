//! Installed software inventory, read from the registry uninstall keys.
//!
//! Deliberately *not* WMI's `Win32_Product`. Microsoft documents (KB 974524)
//! that the class "isn't query optimized" and that enumerating it makes the MSI
//! provider "start a consistency check of packages installed, verifying and
//! repairing the install" -- every installed product, on every scan. It can
//! take minutes, it writes MsiInstaller events, and it has been known to
//! trigger unwanted repairs. A security tool must not reconfigure the machine
//! it is inspecting, so the inventory is read from the registry instead.
//!
//! Three hives are read, and all three matter:
//!   * HKLM 64-bit  -- machine-wide 64-bit software
//!   * HKLM WOW6432Node -- machine-wide 32-bit software
//!   * HKCU         -- per-user installs, which never appear under HKLM
//!
//! Missing any one of them under-reports what is installed, and an inventory
//! that silently omits software produces vulnerability scans that silently
//! omit its vulnerabilities.

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledSoftware {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    /// "HKLM64", "HKLM32" or "HKCU" -- part of the evidence trail.
    pub scope: String,
    /// The uninstall key's own name, often a GUID. Identifies the entry exactly.
    pub registry_key: String,
    pub install_location: Option<String>,
    /// Raw `InstallDate`, usually YYYYMMDD.
    pub install_date: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftwareFacts {
    pub programs: Vec<InstalledSoftware>,
    /// Hives that could not be read at all, so a short list is not mistaken
    /// for a clean one.
    pub unreadable_scopes: Vec<String>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

#[cfg(windows)]
const UNINSTALL_PATHS: [(&str, &str, bool); 3] = [
    // (scope, subkey path, is_hklm)
    (
        "HKLM64",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        true,
    ),
    (
        "HKLM32",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        true,
    ),
    (
        "HKCU",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        false,
    ),
];

#[cfg(windows)]
pub fn collect() -> Result<SoftwareFacts, CollectorError> {
    use windows_registry::{Key, CURRENT_USER, LOCAL_MACHINE};

    let mut facts = SoftwareFacts {
        programs: Vec::new(),
        unreadable_scopes: Vec::new(),
        evidence: vec!["Source: registry uninstall keys (not Win32_Product)".to_string()],
        collected_at: chrono::Utc::now().to_rfc3339(),
    };

    for (scope, path, is_hklm) in UNINSTALL_PATHS {
        let root: &Key = if is_hklm { LOCAL_MACHINE } else { CURRENT_USER };

        let hive = match root.open(path) {
            Ok(k) => k,
            Err(e) => {
                // A hive that will not open is recorded, not swallowed.
                log::warn!("could not open {scope} uninstall key: {e}");
                facts.unreadable_scopes.push(scope.to_string());
                facts
                    .evidence
                    .push(format!("{scope}: could not open ({e})"));
                continue;
            }
        };

        let names: Vec<String> = match hive.keys() {
            Ok(iter) => iter.collect(),
            Err(e) => {
                log::warn!("could not enumerate {scope} uninstall key: {e}");
                facts.unreadable_scopes.push(scope.to_string());
                facts
                    .evidence
                    .push(format!("{scope}: could not enumerate ({e})"));
                continue;
            }
        };

        let before = facts.programs.len();

        for key_name in names {
            let Ok(entry) = hive.open(&key_name) else {
                continue;
            };

            // No DisplayName means nothing to show the user and nothing to
            // match against a vulnerability feed.
            let Ok(name) = entry.get_string("DisplayName") else {
                continue;
            };
            let name = name.trim().to_string();
            if name.is_empty() {
                continue;
            }

            if should_skip(
                entry.get_u32("SystemComponent").ok(),
                entry.get_string("ReleaseType").ok().as_deref(),
                entry.get_string("ParentKeyName").ok().as_deref(),
            ) {
                continue;
            }

            facts.programs.push(InstalledSoftware {
                name,
                version: entry
                    .get_string("DisplayVersion")
                    .ok()
                    .filter(|s| !s.is_empty()),
                publisher: entry.get_string("Publisher").ok().filter(|s| !s.is_empty()),
                scope: scope.to_string(),
                registry_key: key_name.clone(),
                install_location: entry
                    .get_string("InstallLocation")
                    .ok()
                    .filter(|s| !s.is_empty()),
                install_date: entry
                    .get_string("InstallDate")
                    .ok()
                    .filter(|s| !s.is_empty()),
            });
        }

        facts.evidence.push(format!(
            "{scope}: {} program(s) from {}{}",
            facts.programs.len() - before,
            if is_hklm { "HKLM\\" } else { "HKCU\\" },
            path
        ));
    }

    // The same product can appear in more than one hive; collapse exact repeats.
    dedupe(&mut facts.programs);
    facts.evidence.push(format!(
        "Total after de-duplication: {}",
        facts.programs.len()
    ));

    if facts.programs.is_empty() && !facts.unreadable_scopes.is_empty() {
        return Err(CollectorError::PermissionDenied(
            "None of the registry uninstall keys could be read, so the software inventory is empty \
             rather than genuinely clear."
                .into(),
        ));
    }

    Ok(facts)
}

/// Entries that are not user-facing programs.
///
/// Windows stores patches, hotfixes and component sub-entries in the same keys
/// as real applications. Listing them would bury the actual software inventory
/// under hundreds of rows that no vulnerability feed knows about.
fn should_skip(
    system_component: Option<u32>,
    release_type: Option<&str>,
    parent_key_name: Option<&str>,
) -> bool {
    if system_component == Some(1) {
        return true;
    }

    // A ParentKeyName means this entry is a child of another product, which is
    // how Windows models updates to an installed application.
    if parent_key_name.is_some_and(|p| !p.is_empty()) {
        return true;
    }

    matches!(
        release_type.map(str::trim),
        Some("Security Update") | Some("Update Rollup") | Some("Hotfix") | Some("ServicePack")
    )
}

/// Collapse entries that describe the same install of the same product.
fn dedupe(programs: &mut Vec<InstalledSoftware>) {
    use std::collections::HashSet;

    let mut seen: HashSet<(String, Option<String>)> = HashSet::new();
    programs.retain(|p| seen.insert((p.name.to_ascii_lowercase(), p.version.clone())));

    programs.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
    });
}

#[cfg(not(windows))]
pub fn collect() -> Result<SoftwareFacts, CollectorError> {
    Err(CollectorError::Unsupported(
        "The installed software inventory is only available on Windows.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(name: &str, version: Option<&str>) -> InstalledSoftware {
        InstalledSoftware {
            name: name.to_string(),
            version: version.map(str::to_string),
            publisher: None,
            scope: "HKLM64".into(),
            registry_key: name.to_string(),
            install_location: None,
            install_date: None,
        }
    }

    #[test]
    fn keeps_ordinary_applications() {
        assert!(!should_skip(None, None, None));
        assert!(!should_skip(Some(0), None, None));
        assert!(!should_skip(None, Some(""), Some("")));
    }

    #[test]
    fn skips_system_components() {
        assert!(should_skip(Some(1), None, None));
    }

    #[test]
    fn skips_patches_and_child_entries() {
        assert!(should_skip(None, Some("Security Update"), None));
        assert!(should_skip(None, Some("Update Rollup"), None));
        assert!(should_skip(None, Some("Hotfix"), None));
        assert!(should_skip(None, None, Some("Office16")));
    }

    #[test]
    fn dedupe_collapses_identical_entries_across_hives() {
        let mut programs = vec![
            program("7-Zip", Some("23.01")),
            program("7-Zip", Some("23.01")),
            program("Firefox", Some("140.0")),
        ];
        dedupe(&mut programs);
        assert_eq!(programs.len(), 2);
    }

    #[test]
    fn dedupe_keeps_different_versions_of_one_product() {
        // Two real installs side by side must both survive: collapsing them
        // would hide whichever is the vulnerable one.
        let mut programs = vec![
            program("Python", Some("3.11.0")),
            program("Python", Some("3.13.2")),
        ];
        dedupe(&mut programs);
        assert_eq!(programs.len(), 2);
    }

    #[test]
    fn dedupe_is_case_insensitive_on_names() {
        let mut programs = vec![
            program("7-Zip", Some("23.01")),
            program("7-ZIP", Some("23.01")),
        ];
        dedupe(&mut programs);
        assert_eq!(programs.len(), 1);
    }

    #[test]
    fn dedupe_sorts_alphabetically() {
        let mut programs = vec![
            program("Zoom", Some("1")),
            program("Adobe Reader", Some("1")),
            program("Firefox", Some("1")),
        ];
        dedupe(&mut programs);
        let names: Vec<&str> = programs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["Adobe Reader", "Firefox", "Zoom"]);
    }
}

//! Windows Defender Firewall status, read through the `INetFwPolicy2` COM
//! interface exposed by FirewallAPI.dll.
//!
//! Windows keeps three independent profiles -- Domain, Private and Public --
//! and only one is active at a time. "Is the firewall on?" is therefore not a
//! single question, and a collector that answers it as one will eventually
//! tell someone they are protected while the profile they are actually on is
//! switched off. Every profile is reported separately, with the active one
//! marked.

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallProfile {
    /// "Domain", "Private" or "Public".
    pub name: String,
    /// True when this is the profile the machine's network is currently using.
    pub is_active: bool,
    pub enabled: Option<bool>,
    /// "Block all incoming connections" -- a hardened state, not a fault.
    pub block_all_inbound: Option<bool>,
    /// True when unsolicited inbound traffic is blocked by default.
    pub inbound_blocked_by_default: Option<bool>,
    /// True when outbound traffic is allowed by default (the Windows default).
    pub outbound_allowed_by_default: Option<bool>,
    pub notifications_disabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallFacts {
    pub profiles: Vec<FirewallProfile>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl FirewallFacts {
    pub fn active_profiles(&self) -> impl Iterator<Item = &FirewallProfile> {
        self.profiles.iter().filter(|p| p.is_active)
    }
}

#[cfg(windows)]
pub fn collect() -> Result<FirewallFacts, CollectorError> {
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwPolicy2, NetFwPolicy2, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN,
        NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE_TYPE2,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED,
    };

    // RAII guard so COM is uninitialised even on the error paths below.
    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }

    const PROFILES: [(&str, NET_FW_PROFILE_TYPE2); 3] = [
        ("Domain", NET_FW_PROFILE2_DOMAIN),
        ("Private", NET_FW_PROFILE2_PRIVATE),
        ("Public", NET_FW_PROFILE2_PUBLIC),
    ];

    unsafe {
        // S_FALSE means COM was already initialised on this thread, which is
        // fine; only a genuine failure is an error.
        let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if hr.is_err() {
            return Err(CollectorError::Unavailable(format!(
                "Could not initialise COM to read the firewall: {hr:?}"
            )));
        }
        let _com = ComGuard;

        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| map_com_error("creating the firewall policy object", &e))?;

        // Bitmask of the profiles currently in force.
        let current = policy.CurrentProfileTypes().unwrap_or(0);

        let mut facts = FirewallFacts {
            profiles: Vec::with_capacity(PROFILES.len()),
            evidence: vec![
                "COM interface: INetFwPolicy2 (FirewallAPI.dll)".to_string(),
                format!("CurrentProfileTypes: 0x{current:04x}"),
            ],
            collected_at: chrono::Utc::now().to_rfc3339(),
        };

        for (name, kind) in PROFILES {
            let is_active = (current & kind.0) != 0;

            let enabled = policy.get_FirewallEnabled(kind).ok().map(|b| b.as_bool());
            let block_all = policy
                .get_BlockAllInboundTraffic(kind)
                .ok()
                .map(|b| b.as_bool());
            let notifications_disabled = policy
                .get_NotificationsDisabled(kind)
                .ok()
                .map(|b| b.as_bool());

            let inbound_blocked = policy
                .get_DefaultInboundAction(kind)
                .ok()
                .map(|a| a == NET_FW_ACTION_BLOCK);
            let outbound_allowed = policy
                .get_DefaultOutboundAction(kind)
                .ok()
                .map(|a| a != NET_FW_ACTION_BLOCK);

            facts.evidence.push(format!(
                "{name} profile{}: FirewallEnabled={}, DefaultInboundAction={}, BlockAllInbound={}",
                if is_active { " (active)" } else { "" },
                describe(enabled),
                match inbound_blocked {
                    Some(true) => "Block",
                    Some(false) => "Allow",
                    None => "unreported",
                },
                describe(block_all),
            ));

            facts.profiles.push(FirewallProfile {
                name: name.to_string(),
                is_active,
                enabled,
                block_all_inbound: block_all,
                inbound_blocked_by_default: inbound_blocked,
                outbound_allowed_by_default: outbound_allowed,
                notifications_disabled,
            });
        }

        Ok(facts)
    }
}

#[cfg(windows)]
fn map_com_error(during: &str, e: &windows::core::Error) -> CollectorError {
    use windows::Win32::Foundation::{E_ACCESSDENIED, REGDB_E_CLASSNOTREG};

    match e.code() {
        E_ACCESSDENIED => CollectorError::PermissionDenied(format!(
            "Windows refused access while {during}. Run SENTRY as an administrator to read this."
        )),
        REGDB_E_CLASSNOTREG => CollectorError::Unsupported(format!(
            "The Windows Firewall service is not registered on this system (while {during})."
        )),
        _ => CollectorError::Unavailable(format!("Firewall API failed while {during}: {e}")),
    }
}

fn describe(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "true",
        Some(false) => "false",
        None => "unreported",
    }
}

#[cfg(not(windows))]
pub fn collect() -> Result<FirewallFacts, CollectorError> {
    Err(CollectorError::Unsupported(
        "Windows Defender Firewall status is only available on Windows.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_unreported_values_distinctly() {
        assert_eq!(describe(Some(true)), "true");
        assert_eq!(describe(Some(false)), "false");
        // The important case: absent must not collapse into "false".
        assert_eq!(describe(None), "unreported");
    }

    #[test]
    fn active_profiles_are_filtered() {
        let facts = FirewallFacts {
            profiles: vec![
                FirewallProfile {
                    name: "Domain".into(),
                    is_active: false,
                    enabled: Some(true),
                    block_all_inbound: Some(false),
                    inbound_blocked_by_default: Some(true),
                    outbound_allowed_by_default: Some(true),
                    notifications_disabled: Some(false),
                },
                FirewallProfile {
                    name: "Public".into(),
                    is_active: true,
                    enabled: Some(false),
                    block_all_inbound: Some(false),
                    inbound_blocked_by_default: Some(true),
                    outbound_allowed_by_default: Some(true),
                    notifications_disabled: Some(false),
                },
            ],
            evidence: vec![],
            collected_at: String::new(),
        };

        let active: Vec<&str> = facts.active_profiles().map(|p| p.name.as_str()).collect();
        assert_eq!(active, vec!["Public"]);
    }
}

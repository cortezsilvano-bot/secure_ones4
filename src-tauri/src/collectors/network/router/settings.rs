//! Normalized read-only settings contract for future validated providers.
//! No vendor endpoint names, passwords, SSIDs, keys, or raw configuration dumps.
//! Missing fields remain unscanned, including in older stored snapshots.
use crate::security::Known;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiAuthentication {
    Open,
    Wep,
    WpaPersonal,
    Wpa2Personal,
    Wpa3Personal,
    Wpa2Wpa3Personal,
    Enterprise,
    #[serde(other)]
    Unrecognized,
}

/// Each radio or guest-network profile is independent. Authentication mode
/// alone does not establish its cipher, password strength, or overall safety.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WifiProfile {
    /// Provider-local non-secret identifier, not an SSID or password.
    pub profile_id: String,
    pub enabled: Known<bool>,
    pub authentication: Known<WifiAuthentication>,
    pub wps_enabled: Known<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RouterSettings {
    /// A partial list must never be treated as a complete inventory.
    pub wifi_profiles: Known<Vec<WifiProfile>>,
    pub wifi_inventory_complete: Known<bool>,
    /// Configured state only, not proven WAN reachability.
    pub wan_management_enabled: Known<bool>,
    /// Separate IP-family states; neither establishes effective packet filtering.
    pub ipv4_firewall_enabled: Known<bool>,
    pub ipv6_firewall_enabled: Known<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_fields_never_become_disabled_or_safe() {
        let settings: RouterSettings = serde_json::from_str("{}").unwrap();
        let value = serde_json::to_value(settings).unwrap();
        for field in [
            "wifiProfiles",
            "wifiInventoryComplete",
            "wanManagementEnabled",
            "ipv4FirewallEnabled",
            "ipv6FirewallEnabled",
        ] {
            assert_eq!(value[field]["state"], "not_scanned");
        }
    }

    #[test]
    fn partial_wifi_results_preserve_unknowns_and_inventory_gap() {
        let settings: RouterSettings = serde_json::from_str(r#"{
            "wifiProfiles":{"state":"known","data":[
                {"profileId":"radio0","authentication":{"state":"known","data":"wpa3_personal"}},
                {"profileId":"guest0","authentication":{"state":"unavailable","data":"Not returned"}}
            ]},
            "wifiInventoryComplete":{"state":"known","data":false}
        }"#).unwrap();
        let profiles = settings.wifi_profiles.value().unwrap();
        assert_eq!(profiles.len(), 2);
        assert!(!profiles[0].wps_enabled.is_known());
        assert!(!profiles[1].authentication.is_known());
        assert!(matches!(
            settings.wifi_inventory_complete,
            Known::Known(false)
        ));
        assert!(!settings.wan_management_enabled.is_known());
    }

    #[test]
    fn future_authentication_names_are_unrecognized_not_secure() {
        let profile: WifiProfile = serde_json::from_str(
            r#"{
            "authentication":{"state":"known","data":"future_vendor_mode"}
        }"#,
        )
        .unwrap();
        assert!(matches!(
            profile.authentication,
            Known::Known(WifiAuthentication::Unrecognized)
        ));
    }

    #[test]
    fn unsupported_and_permission_states_survive_round_trip() {
        let settings = RouterSettings {
            ipv6_firewall_enabled: Known::Unsupported("No IPv6 settings reader".into()),
            wan_management_enabled: Known::PermissionRequired("Read-only login required".into()),
            ipv4_firewall_enabled: Known::Known(false),
            ..Default::default()
        };
        let restored: RouterSettings =
            serde_json::from_value(serde_json::to_value(settings).unwrap()).unwrap();
        assert!(matches!(
            restored.ipv6_firewall_enabled,
            Known::Unsupported(_)
        ));
        assert!(matches!(
            restored.wan_management_enabled,
            Known::PermissionRequired(_)
        ));
        assert!(matches!(
            restored.ipv4_firewall_enabled,
            Known::Known(false)
        ));
    }

    #[test]
    fn older_router_snapshot_gets_unscanned_settings() {
        let mut snapshot = serde_json::to_value(super::super::RouterFacts::default()).unwrap();
        snapshot.as_object_mut().unwrap().remove("settings");
        let restored: super::super::RouterFacts = serde_json::from_value(snapshot).unwrap();
        assert!(!restored.settings.wifi_profiles.is_known());
        assert!(!restored.settings.ipv4_firewall_enabled.is_known());
    }
}

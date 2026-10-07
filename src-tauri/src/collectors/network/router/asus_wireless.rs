//! Enumerate the selected router's declared wireless interfaces before reading flags.
//! Only validated interface IDs plus fixed non-secret suffixes become request keys.
use super::{
    asus,
    settings::{RouterSettings, WifiProfile},
};
use crate::security::{CollectorError, Known};
use serde::de::{self, MapAccess, Visitor};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub(super) const INVENTORY_PATH: &str =
    "/appGet.cgi?hook=nvram_get(wl_ifnames)%3Bnvram_get(wl0_vifnames)%3Bnvram_get(wl1_vifnames)";
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Inventory {
    physical: Vec<String>,
    profiles: Vec<(usize, String)>,
}
#[derive(Clone)]
pub(super) struct Batch {
    pub path: String,
    keys: Vec<String>,
}
pub(super) struct Readings {
    fields: BTreeMap<String, String>,
    complete: bool,
}

fn unavailable(message: &str) -> CollectorError {
    CollectorError::Unavailable(message.into())
}

// Ignore unrequested values, reject duplicate requested keys and non-string values.
// Raw bodies never enter normalized facts or history.
fn fields(body: &str, expected: &[String]) -> Result<BTreeMap<String, String>, CollectorError> {
    if body.len() > 16384 {
        return Err(unavailable("Wireless response exceeds the limit."));
    }
    struct Fields<'a>(&'a [String]);
    impl<'de> Visitor<'de> for Fields<'_> {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("string-valued wireless fields")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if self.0.contains(&key) {
                    let value = map.next_value::<String>()?;
                    if value.len() > 256
                        || value.chars().any(char::is_control)
                        || result.insert(key, value).is_some()
                    {
                        return Err(de::Error::custom(
                            "duplicate, invalid or oversized wireless field",
                        ));
                    }
                } else {
                    map.next_value::<de::IgnoredAny>()?;
                }
            }
            Ok(result)
        }
    }
    let mut deserializer = serde_json::Deserializer::from_str(body);
    let result = serde::Deserializer::deserialize_map(&mut deserializer, Fields(expected))
        .map_err(|_| unavailable("Malformed wireless response; no values retained."))?;
    deserializer
        .end()
        .map_err(|_| unavailable("Trailing data in wireless response."))?;
    Ok(result)
}

impl Inventory {
    pub fn parse(build: &str, body: &str) -> Result<Self, CollectorError> {
        if build != asus::REVIEWED_BUILD {
            return Err(CollectorError::Unsupported(
                "Wireless inventory is not reviewed for this build.".into(),
            ));
        }
        let keys = ["wl_ifnames", "wl0_vifnames", "wl1_vifnames"].map(String::from);
        let values = fields(body, &keys)?;
        let physical = values
            .get("wl_ifnames")
            .ok_or_else(|| unavailable("Missing physical radio inventory."))?;
        let physical: Vec<_> = physical.split_ascii_whitespace().collect();
        if physical.len() != 2
            || physical[0] == physical[1]
            || physical.iter().any(|v| {
                v.is_empty()
                    || v.len() > 16
                    || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        {
            return Err(unavailable(
                "The physical radio inventory does not match the reviewed two-radio model.",
            ));
        }
        let mut profiles = Vec::new();
        for radio in 0..=1 {
            profiles.push((radio, format!("wl{radio}")));
            let raw = values.get(&format!("wl{radio}_vifnames")).ok_or_else(|| {
                unavailable(
                    "Missing guest-interface inventory; completeness cannot be established.",
                )
            })?;
            let mut seen = BTreeSet::new();
            for name in raw.split_ascii_whitespace() {
                // Do not interpolate an untrusted hook argument. Only one of 15
                // explicitly generated interface IDs can pass this boundary.
                if !(1..=15).any(|sub| name == format!("wl{radio}.{sub}"))
                    || !seen.insert(name.to_owned())
                {
                    return Err(unavailable("Unsupported or duplicate guest interface; no partial inventory is called complete."));
                }
            }
            profiles.extend(seen.into_iter().map(|name| (radio, name)));
        }
        Ok(Self {
            physical: physical.into_iter().map(String::from).collect(),
            profiles,
        })
    }

    pub fn batches(&self) -> Vec<Batch> {
        self.profiles
            .chunks(6)
            .map(|profiles| {
                let mut keys = vec!["wps_enable".into(), "wl0_radio".into(), "wl1_radio".into()];
                for (_, name) in profiles {
                    for suffix in ["bss_enabled", "auth_mode_x", "wep_x", "wps_mode"] {
                        keys.push(format!("{name}_{suffix}"));
                    }
                }
                let path = format!(
                    "/appGet.cgi?hook={}",
                    keys.iter()
                        .map(|k| format!("nvram_get({k})"))
                        .collect::<Vec<_>>()
                        .join("%3B")
                );
                Batch { keys, path }
            })
            .collect()
    }
}

impl Readings {
    pub fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
            complete: true,
        }
    }
    pub fn add(&mut self, batch: &Batch, body: &str) -> Result<(), CollectorError> {
        let values = fields(body, &batch.keys)?;
        for (key, value) in values {
            if self.fields.get(&key).is_some_and(|old| old != &value) {
                self.complete = false;
                return Err(unavailable("Wireless configuration changed between reads."));
            }
            self.fields.insert(key, value);
        }
        Ok(())
    }
    pub fn incomplete(&mut self) {
        self.complete = false;
    }
    pub fn finish(self, inventory: &Inventory, unchanged: bool) -> RouterSettings {
        let get = |key: &str| self.fields.get(key).map(String::as_str);
        let mut profiles = Vec::new();
        for (radio, prefix) in &inventory.profiles {
            let enabled = both(
                flag(get(&format!("wl{radio}_radio"))),
                flag(get(&format!("{prefix}_bss_enabled"))),
            );
            let wps_mode = match get(&format!("{prefix}_wps_mode")) {
                Some("enabled") => Known::Known(true),
                Some("disabled") => Known::Known(false),
                _ => Known::Unavailable(
                    "Interface-specific WPS configuration was not returned.".into(),
                ),
            };
            profiles.push(WifiProfile {
                profile_id: prefix.clone(),
                enabled,
                authentication: asus::decode_wifi_authentication(
                    get(&format!("{prefix}_auth_mode_x")),
                    get(&format!("{prefix}_wep_x")),
                ),
                wps_enabled: both(flag(get("wps_enable")), wps_mode),
            });
        }
        RouterSettings {
            wifi_profiles: Known::Known(profiles),
            // Completeness is local configured interface coverage, not mesh topology
            // or proof that every setting/negotiated encryption was established.
            wifi_inventory_complete: Known::Known(self.complete && unchanged),
            ..Default::default()
        }
    }
}

fn flag(value: Option<&str>) -> Known<bool> {
    match value {
        Some("1") => Known::Known(true),
        Some("0") => Known::Known(false),
        _ => Known::Unavailable("Explicit wireless flag was not returned.".into()),
    }
}
fn both(a: Known<bool>, b: Known<bool>) -> Known<bool> {
    match (a, b) {
        (Known::Known(false), _) | (_, Known::Known(false)) => Known::Known(false),
        (Known::Known(true), Known::Known(true)) => Known::Known(true),
        _ => Known::Unavailable("Wireless enablement is incomplete.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const INVENTORY: &str =
        r#"{"wl_ifnames":"eth5 eth6","wl0_vifnames":"wl0.1 wl0.4","wl1_vifnames":""}"#;
    #[test]
    fn enumerates_all_declared_profiles_without_three_guest_truncation() {
        let inventory = Inventory::parse(asus::REVIEWED_BUILD, INVENTORY).unwrap();
        assert_eq!(inventory.profiles.len(), 4);
        assert!(inventory.profiles.iter().any(|(_, p)| p == "wl0.4"));
        let batches = inventory.batches();
        let mut readings = Readings::new();
        readings.add(&batches[0], r#"{"wps_enable":"0","wl0_radio":"1","wl1_radio":"0","wl0_bss_enabled":"1","wl0_auth_mode_x":"psk2","wl0.1_bss_enabled":"0","wl0.4_bss_enabled":"1","wl0.4_auth_mode_x":"open","wl0.4_wep_x":"0","wl0_wpa_psk":"secret"}"#).unwrap();
        let settings = readings.finish(&inventory, true);
        assert!(matches!(
            settings.wifi_inventory_complete,
            Known::Known(true)
        ));
        let facts = super::super::RouterFacts {
            settings,
            ..Default::default()
        };
        assert!(crate::rules::router::evaluate(&facts)
            .iter()
            .any(|f| f.rule_id == "RTR-009"));
        assert!(!serde_json::to_string(&facts).unwrap().contains("secret"));
        assert!(facts
            .settings
            .wifi_profiles
            .value()
            .unwrap()
            .iter()
            .all(|p| matches!(p.wps_enabled, Known::Known(false))));
    }
    #[test]
    fn untrusted_interfaces_cannot_become_hooks_or_complete_inventory() {
        for names in [
            "wl0.1 wl0.1",
            "wl1.1",
            "wl0.16",
            "wl0.01",
            "wl0.1);reboot(",
            "wl0.1/../../",
            "eth5",
        ] {
            let body = serde_json::json!({"wl_ifnames":"eth5 eth6","wl0_vifnames":names,"wl1_vifnames":""}).to_string();
            assert!(
                Inventory::parse(asus::REVIEWED_BUILD, &body).is_err(),
                "{names}"
            );
        }
        for body in [
            "{}",
            r#"{"wl_ifnames":"eth5 eth5","wl0_vifnames":"","wl1_vifnames":""}"#,
            r#"{"wl_ifnames":"eth5 eth6","wl0_vifnames":""}"#,
        ] {
            assert!(Inventory::parse(asus::REVIEWED_BUILD, body).is_err());
        }
    }
    #[test]
    fn partial_failed_changed_or_missing_settings_do_not_resolve_findings() {
        let inventory = Inventory::parse(asus::REVIEWED_BUILD, INVENTORY).unwrap();
        let batch = &inventory.batches()[0];
        for body in [
            r#"{"wl0_radio":"1","wl0_radio":"0"}"#,
            r#"{"wl0_radio":true}"#,
            "<html>login</html>",
        ] {
            assert!(Readings::new().add(batch, body).is_err());
        }
        let mut readings = Readings::new();
        readings.add(batch, r#"{"wps_enable":"1"}"#).unwrap();
        assert!(readings.add(batch, r#"{"wps_enable":"0"}"#).is_err());
        assert!(matches!(
            readings.finish(&inventory, true).wifi_inventory_complete,
            Known::Known(false)
        ));
        let facts = super::super::RouterFacts {
            settings: Readings::new().finish(&inventory, true),
            ..Default::default()
        };
        assert!(crate::rules::router_settings::resolved_rules(&facts).is_empty());
        assert!(matches!(
            Readings::new()
                .finish(&inventory, false)
                .wifi_inventory_complete,
            Known::Known(false)
        ));
    }
    #[test]
    fn maximum_inventory_is_batched_without_secret_fields() {
        let names = |radio| {
            (1..=15)
                .map(|sub| format!("wl{radio}.{sub}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let body = serde_json::json!({"wl_ifnames":"eth5 eth6","wl0_vifnames":names(0),"wl1_vifnames":names(1)}).to_string();
        let inventory = Inventory::parse(asus::REVIEWED_BUILD, &body).unwrap();
        assert_eq!(inventory.profiles.len(), 32);
        assert_eq!(inventory.batches().len(), 6);
        for batch in inventory.batches() {
            assert!(batch.path.len() < 1800);
            for forbidden in ["_ssid", "_psk", "_key", "apply", "restart", "wps_start"] {
                assert!(!batch.path.contains(forbidden));
            }
        }
    }
}

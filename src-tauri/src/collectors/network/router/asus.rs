//! Source-reviewed strict decoders used by the opt-in authenticated provider.
//! Source: GNUton e8493201a1a0f983c7d079a5a45f02e2c191fede,
//! release/src/router/www/Advanced_BasicFirewall_Content.asp.
//! Only reviewed non-secret settings are interpreted. No requests or secrets.
use super::settings::RouterSettings;
use crate::security::{CollectorError, Known};
use serde::Deserialize;

pub const REVIEWED_BUILD: &str = "3004.388.9_2-gnuton1";

pub fn decode_firewall_response(build: &str, body: &str) -> Result<RouterSettings, CollectorError> {
    if build != REVIEWED_BUILD {
        return Err(CollectorError::Unsupported("This firewall decoder has only been source-reviewed for the exact GNUton build 3004.388.9_2-gnuton1; hardware compatibility is unvalidated.".into()));
    }
    if body.len() > 16 * 1024 {
        return Err(CollectorError::Unavailable(
            "Router settings response exceeds the decoder limit.".into(),
        ));
    }
    #[derive(Deserialize)]
    struct Response {
        fw_enable_x: Option<String>,
        ipv6_fw_enable: Option<String>,
        misc_http_x: Option<String>,
    }
    let response: Response = serde_json::from_str(body).map_err(|_| CollectorError::Malformed {
        origin: "ASUS firewall response".into(),
        detail:
            "Expected a JSON object containing string flags; response contents are not retained."
                .into(),
    })?;
    fn flag(value: Option<String>) -> Known<bool> {
        match value.as_deref() {
            Some("1") => Known::Known(true),
            Some("0") => Known::Known(false),
            _ => Known::Unavailable(
                "The router did not return a recognized explicit setting value.".into(),
            ),
        }
    }
    Ok(RouterSettings {
        ipv4_firewall_enabled: flag(response.fw_enable_x),
        ipv6_firewall_enabled: flag(response.ipv6_fw_enable),
        wan_management_enabled: flag(response.misc_http_x),
        ..Default::default()
    })
}

/// Authentication labels from the release-pinned wireless settings page.
/// An "open" authentication label can still use WEP; the WEP flag is mandatory.
pub fn decode_wifi_authentication(
    mode: Option<&str>,
    wep: Option<&str>,
) -> Known<super::settings::WifiAuthentication> {
    use super::settings::WifiAuthentication as Auth;
    let auth = match (mode, wep) {
        (Some("open"), Some("0")) => Auth::Open,
        (Some("open" | "shared"), Some("1" | "2")) => Auth::Wep,
        (Some("psk"), _) => Auth::WpaPersonal,
        (Some("psk2"), _) => Auth::Wpa2Personal,
        (Some("sae"), _) => Auth::Wpa3Personal,
        (Some("psk2sae"), _) => Auth::Wpa2Wpa3Personal,
        // Mixed legacy and enterprise modes are not collapsed into a stronger label.
        _ => return Known::Unavailable("Wireless authentication mode is absent, ambiguous or not yet supported by this decoder.".into()),
    };
    Known::Known(auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_authentication_requires_wep_context_and_mixed_modes_stay_unknown() {
        use super::super::settings::WifiAuthentication as Auth;
        assert!(!decode_wifi_authentication(Some("open"), None).is_known());
        assert!(matches!(
            decode_wifi_authentication(Some("open"), Some("1")),
            Known::Known(Auth::Wep)
        ));
        assert!(matches!(
            decode_wifi_authentication(Some("open"), Some("0")),
            Known::Known(Auth::Open)
        ));
        assert!(!decode_wifi_authentication(Some("pskpsk2"), None).is_known());
    }

    #[test]
    fn flags_flow_to_existing_rules_without_retaining_extra_fields() {
        let settings = decode_firewall_response(
            REVIEWED_BUILD,
            r#"{"fw_enable_x":"1","ipv6_fw_enable":"0","http_passwd":"synthetic-secret"}"#,
        )
        .unwrap();
        let facts = super::super::RouterFacts {
            settings,
            ..Default::default()
        };
        let findings = crate::rules::router::evaluate(&facts);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "RTR-008");
        assert!(!serde_json::to_string(&facts)
            .unwrap()
            .contains("synthetic-secret"));
        assert!(!facts.settings.wan_management_enabled.is_known());
    }

    #[test]
    fn missing_unrecognized_and_malformed_flags_never_become_disabled() {
        for body in ["{}", r#"{"fw_enable_x":"","ipv6_fw_enable":"false"}"#] {
            let settings = decode_firewall_response(REVIEWED_BUILD, body).unwrap();
            assert!(!settings.ipv4_firewall_enabled.is_known());
            assert!(!settings.ipv6_firewall_enabled.is_known());
        }
        for body in [
            "<html>Login</html>",
            r#"{"fw_enable_x":false}"#,
            r#"{"fw_enable_x":"1","fw_enable_x":"0"}"#,
        ] {
            assert!(decode_firewall_response(REVIEWED_BUILD, body).is_err());
        }
    }

    #[test]
    fn shortened_versions_and_oversized_bodies_are_rejected() {
        assert!(decode_firewall_response("3004.388.9", "{}").is_err());
        assert!(decode_firewall_response(REVIEWED_BUILD, &" ".repeat(16385)).is_err());
    }
}

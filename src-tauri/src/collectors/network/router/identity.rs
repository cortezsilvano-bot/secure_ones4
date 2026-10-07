//! Pure interpretation of device-reported metadata. No requests or authentication.
use serde::{Deserialize, Serialize};

use crate::security::Known;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterIdentity {
    pub vendor: Known<String>,
    pub reported_model: Known<String>,
    pub firmware_version: Known<String>,
    pub authenticated_settings: Known<bool>,
    pub evidence: Vec<String>,
}

// Bound untrusted metadata before it reaches identity labels. Preserve model
// suffixes: they may distinguish hardware revisions and advisory applicability.
fn label(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_owned())
}

pub fn from_description(manufacturer: Option<&str>, model: Option<&str>) -> RouterIdentity {
    let manufacturer = label(manufacturer);
    // Explicit labels only; model prefixes, banners and substrings cannot
    // establish a vendor. These are self-reported claims, not verified identity.
    let asus = manufacturer.as_deref().is_some_and(|value| {
        ["asus", "asustek computer inc.", "asustek computer inc"]
            .iter()
            .any(|alias| value.eq_ignore_ascii_case(alias))
    });
    RouterIdentity {
        vendor: if asus {
            Known::Known("ASUS".into())
        } else {
            Known::Unavailable(
                "No recognized ASUS manufacturer label in the device description.".into(),
            )
        },
        reported_model: label(model).map(Known::Known).unwrap_or_else(|| {
            Known::Unavailable("No usable model label in the device description.".into())
        }),
        firmware_version: Known::NotScanned,
        authenticated_settings: Known::Unsupported(
            "This generic scan does not authenticate. Use the separate ASUS settings scan for a reviewed model/build.".into(),
        ),
        evidence: if asus {
            vec!["The UPnP description reports an ASUS manufacturer label. This is not authenticated identity or confirmation of ASUSWRT, Merlin, or model support.".into()]
        } else {
            vec!["Device-description metadata does not establish ASUS support.".into()]
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_asus_preserves_model_revision_without_enabling_login() {
        let identity = from_description(Some(" ASUSTeK COMPUTER INC. "), Some("RT-AX88U Pro"));
        assert!(matches!(identity.vendor, Known::Known(ref value) if value == "ASUS"));
        assert!(
            matches!(identity.reported_model, Known::Known(ref value) if value == "RT-AX88U Pro")
        );
        assert!(matches!(identity.firmware_version, Known::NotScanned));
        assert!(matches!(
            identity.authenticated_settings,
            Known::Unsupported(_)
        ));
    }

    #[test]
    fn model_names_and_substrings_do_not_establish_vendor() {
        for manufacturer in [
            None,
            Some("Not ASUS"),
            Some("asus.example"),
            Some("Other vendor"),
        ] {
            let identity = from_description(manufacturer, Some("ASUS RT-AX88U Merlin"));
            assert!(!identity.vendor.is_known());
            assert!(!identity.firmware_version.is_known());
        }
    }

    #[test]
    fn rejects_empty_oversized_and_control_character_labels() {
        for value in [
            "".to_string(),
            " ".into(),
            "ASUS\n".repeat(2),
            "x".repeat(129),
        ] {
            let identity = from_description(Some(&value), Some(&value));
            assert!(!identity.vendor.is_known());
            assert!(!identity.reported_model.is_known());
        }
    }
}

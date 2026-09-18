//! IEEE MAC address registry: turning a MAC prefix into a manufacturer name.
//!
//! A bare MAC address tells a home user nothing. "Espressif Inc." tells them it
//! is probably a smart plug or an ESP32-based gadget; "Sonos" tells them it is
//! the speaker in the kitchen. That is the difference between a device list
//! they can act on and a list of hex strings.
//!
//! Fetched from the official IEEE registry rather than a third-party
//! aggregator, so the data's provenance and licensing are unambiguous, and
//! cached locally. The MAC addresses on the user's network are never sent
//! anywhere -- the whole registry comes down and lookups happen on disk.

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

/// The MA-L registry: 24-bit prefixes, which covers the overwhelming majority
/// of consumer hardware.
pub const OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OuiEntry {
    /// Six uppercase hex characters, no separators: "001A2B".
    pub prefix: String,
    pub organization: String,
}

/// Download and parse the registry.
pub fn fetch() -> Result<Vec<OuiEntry>, CollectorError> {
    let body = super::http::get_text(OUI_URL)?;
    parse(&body)
}

/// Parse the IEEE CSV.
///
/// Columns are `Registry,Assignment,Organization Name,Organization Address`.
/// Only the assignment and organisation are kept; the address is a postal
/// address for the company and is of no use here.
pub fn parse(body: &str) -> Result<Vec<OuiEntry>, CollectorError> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(body.as_bytes());

    let mut entries = Vec::new();

    for record in reader.records() {
        let Ok(record) = record else { continue };

        let (Some(assignment), Some(organization)) = (record.get(1), record.get(2)) else {
            continue;
        };

        let prefix = normalize_prefix(assignment);
        let organization = organization.trim();

        // A prefix that is not six hex characters is not an MA-L assignment.
        if prefix.len() != 6 || organization.is_empty() {
            continue;
        }

        entries.push(OuiEntry {
            prefix,
            organization: organization.to_string(),
        });
    }

    // An empty registry cannot be right, and silently accepting one would
    // leave every device unidentified with no explanation.
    if entries.is_empty() {
        return Err(CollectorError::Malformed {
            origin: "IEEE OUI registry".to_string(),
            detail: "no usable entries were found in the downloaded registry".to_string(),
        });
    }

    Ok(entries)
}

/// Strip separators and upper-case a MAC or prefix fragment.
fn normalize_prefix(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// The 24-bit prefix of a full MAC address, as stored in the registry.
///
/// Returns `None` for anything that is not a MAC.
pub fn prefix_of(mac: &str) -> Option<String> {
    let cleaned = normalize_prefix(mac);
    // A full MAC is 12 hex characters; anything shorter cannot be split.
    if cleaned.len() < 6 {
        return None;
    }
    Some(cleaned[..6].to_string())
}

/// True when the MAC is locally administered (the second-least-significant bit
/// of the first octet is set).
///
/// Phones and laptops randomise their MAC per network by default now, and a
/// randomised address has no manufacturer to look up. Reporting "unknown
/// vendor" for one is correct; reporting it as a mystery device is not.
pub fn is_locally_administered(mac: &str) -> Option<bool> {
    let cleaned = normalize_prefix(mac);
    if cleaned.len() < 2 {
        return None;
    }
    let first_octet = u8::from_str_radix(&cleaned[..2], 16).ok()?;
    Some(first_octet & 0b0000_0010 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
Registry,Assignment,Organization Name,Organization Address
MA-L,001A2B,Ayecom Technology Co.  Ltd.,\"5F No.6 Lane 45 Bao Shing Road Taipei\"
MA-L,F0D1A9,Apple  Inc.,\"1 Infinite Loop Cupertino CA US 95014\"
MA-L,2462AB,Espressif Inc.,\"Room 204 Building 2 Shanghai CN\"
";

    #[test]
    fn parses_the_registry() {
        let entries = parse(FIXTURE).expect("should parse");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].prefix, "001A2B");
        assert_eq!(entries[1].organization, "Apple  Inc.");
    }

    #[test]
    fn rows_without_a_usable_prefix_are_skipped() {
        let body = "Registry,Assignment,Organization Name,Organization Address\n\
                    MA-L,NOTHEX,Somebody,addr\n\
                    MA-L,2462AB,Espressif Inc.,addr\n";
        let entries = parse(body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].prefix, "2462AB");
    }

    #[test]
    fn rows_without_an_organisation_are_skipped() {
        let body = "Registry,Assignment,Organization Name,Organization Address\n\
                    MA-L,001A2B,,addr\n\
                    MA-L,2462AB,Espressif Inc.,addr\n";
        assert_eq!(parse(body).unwrap().len(), 1);
    }

    #[test]
    fn an_empty_registry_is_an_error() {
        // Accepting one would leave every device unidentified with no reason given.
        let body = "Registry,Assignment,Organization Name,Organization Address\n";
        assert!(matches!(parse(body), Err(CollectorError::Malformed { .. })));
    }

    #[test]
    fn extracts_the_prefix_from_a_mac_in_any_format() {
        assert_eq!(prefix_of("00:1a:2b:3c:4d:5e").as_deref(), Some("001A2B"));
        assert_eq!(prefix_of("00-1A-2B-3C-4D-5E").as_deref(), Some("001A2B"));
        assert_eq!(prefix_of("001a2b3c4d5e").as_deref(), Some("001A2B"));
        assert_eq!(prefix_of("001a.2b3c.4d5e").as_deref(), Some("001A2B"));
    }

    #[test]
    fn rejects_things_that_are_not_macs() {
        assert_eq!(prefix_of(""), None);
        assert_eq!(prefix_of("zz:zz"), None);
        assert_eq!(prefix_of("00:1a"), None, "too short to carry a prefix");
    }

    #[test]
    fn detects_randomised_addresses() {
        // Bit 1 of the first octet set means locally administered. Phones
        // randomise per network, so these have no manufacturer to find.
        assert_eq!(is_locally_administered("02:1a:2b:3c:4d:5e"), Some(true));
        assert_eq!(is_locally_administered("06:1a:2b:3c:4d:5e"), Some(true));
        assert_eq!(is_locally_administered("0a:1a:2b:3c:4d:5e"), Some(true));

        assert_eq!(is_locally_administered("00:1a:2b:3c:4d:5e"), Some(false));
        assert_eq!(is_locally_administered("f0:d1:a9:3c:4d:5e"), Some(false));

        assert_eq!(is_locally_administered(""), None);
    }
}

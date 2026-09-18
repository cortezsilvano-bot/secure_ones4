//! CISA Known Exploited Vulnerabilities catalogue.
//!
//! KEV is the single most decision-relevant feed SENTRY uses. A CVE being in
//! it does not mean "someone could exploit this" -- it means the US government
//! has evidence that someone *has*. That is a categorically different claim
//! from a CVSS score, and the risk engine weights it accordingly.
//!
//! The whole catalogue is around 1,400 entries and a couple of megabytes, so
//! it is downloaded and cached in full. No per-CVE lookups, no telling anyone
//! which CVEs we are interested in.

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub due_date: String,
    /// CISA's own assessment: "Known", "Unknown". "Known" is as bad as it gets.
    pub known_ransomware_use: String,
}

impl KevEntry {
    pub fn used_in_ransomware(&self) -> bool {
        self.known_ransomware_use.eq_ignore_ascii_case("known")
    }
}

/// The catalogue as published.
#[derive(Debug, Clone, Deserialize)]
struct KevCatalog {
    #[serde(rename = "catalogVersion")]
    catalog_version: Option<String>,
    #[serde(rename = "dateReleased")]
    date_released: Option<String>,
    vulnerabilities: Vec<RawEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject", default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(rename = "vulnerabilityName", default)]
    vulnerability_name: String,
    #[serde(rename = "dateAdded", default)]
    date_added: String,
    #[serde(rename = "shortDescription", default)]
    short_description: String,
    #[serde(rename = "requiredAction", default)]
    required_action: String,
    #[serde(rename = "dueDate", default)]
    due_date: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    known_ransomware_campaign_use: String,
}

#[derive(Debug, Clone)]
pub struct KevSnapshot {
    pub catalog_version: Option<String>,
    pub date_released: Option<String>,
    pub entries: Vec<KevEntry>,
}

/// Download and parse the catalogue.
pub fn fetch() -> Result<KevSnapshot, CollectorError> {
    // CISA's CDN answers 403 to SENTRY's own user agent. See
    // `http::BROWSER_USER_AGENT` for why this one feed is fetched differently.
    let body = super::http::get_text_as(KEV_URL, super::http::BROWSER_USER_AGENT)?;
    parse(&body)
}

/// Parse a catalogue document. Separate from `fetch` so it can be tested
/// against fixtures without a network call.
pub fn parse(body: &str) -> Result<KevSnapshot, CollectorError> {
    let catalog: KevCatalog =
        serde_json::from_str(body).map_err(|e| CollectorError::Malformed {
            origin: "CISA KEV".to_string(),
            detail: format!("could not parse the catalogue: {e}"),
        })?;

    // An empty catalogue is not a valid answer; treating it as "nothing is
    // exploited" would silently disable the feed's entire contribution.
    if catalog.vulnerabilities.is_empty() {
        return Err(CollectorError::Malformed {
            origin: "CISA KEV".to_string(),
            detail: "the catalogue contained no vulnerabilities, which cannot be right".to_string(),
        });
    }

    let entries = catalog
        .vulnerabilities
        .into_iter()
        .filter(|r| !r.cve_id.trim().is_empty())
        .map(|r| KevEntry {
            cve_id: r.cve_id.trim().to_ascii_uppercase(),
            vendor_project: r.vendor_project,
            product: r.product,
            vulnerability_name: r.vulnerability_name,
            date_added: r.date_added,
            short_description: r.short_description,
            required_action: r.required_action,
            due_date: r.due_date,
            known_ransomware_use: r.known_ransomware_campaign_use,
        })
        .collect();

    Ok(KevSnapshot {
        catalog_version: catalog.catalog_version,
        date_released: catalog.date_released,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "title": "CISA Catalog of Known Exploited Vulnerabilities",
      "catalogVersion": "2026.09.17",
      "dateReleased": "2026-09-17T14:00:00.0000Z",
      "count": 2,
      "vulnerabilities": [
        {
          "cveID": "cve-2021-44228",
          "vendorProject": "Apache",
          "product": "Log4j2",
          "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
          "dateAdded": "2021-12-10",
          "shortDescription": "Apache Log4j2 contains a vulnerability.",
          "requiredAction": "Apply updates.",
          "dueDate": "2021-12-24",
          "knownRansomwareCampaignUse": "Known"
        },
        {
          "cveID": "CVE-2017-0144",
          "vendorProject": "Microsoft",
          "product": "SMBv1",
          "vulnerabilityName": "Microsoft SMBv1 Remote Code Execution",
          "dateAdded": "2022-03-03",
          "shortDescription": "SMBv1 allows remote code execution.",
          "requiredAction": "Apply updates.",
          "dueDate": "2022-03-24",
          "knownRansomwareCampaignUse": "Unknown"
        }
      ]
    }"#;

    #[test]
    fn parses_the_catalogue() {
        let snapshot = parse(FIXTURE).expect("should parse");
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.catalog_version.as_deref(), Some("2026.09.17"));
    }

    #[test]
    fn cve_ids_are_normalised_to_upper_case() {
        // The feed is consistent today, but ids are joined against other feeds
        // and a lower-case one would silently fail to match.
        let snapshot = parse(FIXTURE).unwrap();
        assert_eq!(snapshot.entries[0].cve_id, "CVE-2021-44228");
    }

    #[test]
    fn ransomware_use_is_read_from_the_right_field() {
        let snapshot = parse(FIXTURE).unwrap();
        assert!(snapshot.entries[0].used_in_ransomware());
        assert!(!snapshot.entries[1].used_in_ransomware());
    }

    #[test]
    fn an_empty_catalogue_is_an_error_not_a_clean_bill() {
        let empty = r#"{"catalogVersion":"1","vulnerabilities":[]}"#;
        assert!(
            parse(empty).is_err(),
            "an empty KEV must fail loudly rather than disable the feed silently"
        );
    }

    #[test]
    fn malformed_json_is_reported_as_malformed() {
        let e = parse("{not json").unwrap_err();
        assert!(matches!(e, CollectorError::Malformed { .. }));
    }

    #[test]
    fn entries_without_a_cve_id_are_dropped() {
        let body = r#"{"vulnerabilities":[
          {"cveID":"  ","product":"x"},
          {"cveID":"CVE-2024-0001","product":"y"}
        ]}"#;
        let snapshot = parse(body).unwrap();
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].cve_id, "CVE-2024-0001");
    }

    #[test]
    fn missing_optional_fields_default_rather_than_fail() {
        let body = r#"{"vulnerabilities":[{"cveID":"CVE-2024-0001"}]}"#;
        let snapshot = parse(body).expect("sparse entries must still parse");
        assert_eq!(snapshot.entries[0].product, "");
        assert!(!snapshot.entries[0].used_in_ransomware());
    }
}

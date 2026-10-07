//! NIST National Vulnerability Database, CVE API 2.0.
//!
//! NVD is the authority for which versions of which products a CVE affects,
//! expressed as CPE match rules with version bounds. That structure is what
//! lets SENTRY say "your 7-Zip 21.07 is affected, 23.01 is not" rather than
//! "7-Zip has had vulnerabilities".
//!
//! # Rate limiting
//!
//! NVD allows 5 requests per rolling 30-second window without an API key, and
//! 50 with one. Their own guidance is to sleep roughly 6 seconds between
//! unkeyed requests. That is slow enough that per-product lookups cannot live
//! inside an interactive scan, so results are cached aggressively and refreshed
//! in the background -- see the `store` module.
//!
//! No API key is required and none is shipped. A user who has one can supply
//! it to raise their own limit; requests still contain nothing but a product
//! keyword.

use serde::Deserialize;

use crate::security::CollectorError;
use crate::vulnerabilities::version::VersionRange;

const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// NVD's documented pacing for unauthenticated clients: 5 requests per rolling
/// 30 seconds.
pub const UNKEYED_REQUEST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6);

/// Pacing with an API key: 50 requests per rolling 30 seconds.
pub const KEYED_REQUEST_INTERVAL: std::time::Duration = std::time::Duration::from_millis(700);

/// The interval to use for the key the caller has, if any.
pub fn request_interval(api_key: Option<&str>) -> std::time::Duration {
    match api_key {
        Some(key) if !key.is_empty() => KEYED_REQUEST_INTERVAL,
        _ => UNKEYED_REQUEST_INTERVAL,
    }
}

/// One CPE match rule from a CVE's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeMatch {
    pub criteria: String,
    pub vulnerable: bool,
    pub range: VersionRange,
}

/// A CVE as SENTRY stores it.
#[derive(Debug, Clone, PartialEq)]
pub struct CveRecord {
    pub id: String,
    pub description: String,
    pub published: Option<String>,
    pub last_modified: Option<String>,
    /// Best available CVSS base score, newest metric version wins.
    pub cvss_score: Option<f64>,
    pub cvss_severity: Option<String>,
    pub cvss_vector: Option<String>,
    pub matches: Vec<CpeMatch>,
}

impl CveRecord {
    /// Every CPE match rule marked vulnerable.
    pub fn vulnerable_matches(&self) -> impl Iterator<Item = &CpeMatch> {
        self.matches.iter().filter(|m| m.vulnerable)
    }
}

/// Search NVD for CVEs mentioning `keyword`.
pub fn search_by_keyword(
    keyword: &str,
    api_key: Option<&str>,
) -> Result<Vec<CveRecord>, CollectorError> {
    // NVD treats a multi-word keyword as an OR unless asked otherwise; exact
    // matching keeps "adobe reader" from returning every Adobe CVE.
    let encoded = urlencode(keyword);
    let url = format!("{NVD_API}?keywordSearch={encoded}&keywordExactMatch&resultsPerPage=200");

    // NVD reads the key from a header. It goes to NVD and nowhere else, and it
    // is the user's own key.
    let body = match api_key.filter(|k| !k.is_empty()) {
        Some(key) => super::http::get_text_with_header(&url, "apiKey", key)?,
        None => super::http::get_text(&url)?,
    };

    parse(&body)
}

/// Parse an NVD CVE API response. Separate from the fetch for offline testing.
pub fn parse(body: &str) -> Result<Vec<CveRecord>, CollectorError> {
    let response: NvdResponse =
        serde_json::from_str(body).map_err(|e| CollectorError::Malformed {
            origin: "NVD".to_string(),
            detail: format!("could not parse the CVE response: {e}"),
        })?;

    Ok(response
        .vulnerabilities
        .into_iter()
        .filter_map(|v| convert(v.cve))
        .collect())
}

fn convert(cve: RawCve) -> Option<CveRecord> {
    let id = cve.id.trim().to_ascii_uppercase();
    if id.is_empty() {
        return None;
    }

    // Prefer the English description; fall back to whatever came first rather
    // than showing nothing.
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .or_else(|| cve.descriptions.first())
        .map(|d| d.value.clone())
        .unwrap_or_default();

    // CVSS v4 supersedes v3.1, which supersedes v3.0, which supersedes v2.
    // Taking the newest available avoids reporting a stale severity for a CVE
    // that has since been re-scored.
    let metrics = &cve.metrics;
    let (cvss_score, cvss_severity, cvss_vector) = metrics
        .cvss_metric_v40
        .first()
        .map(|m| (&m.cvss_data, ()))
        .or_else(|| metrics.cvss_metric_v31.first().map(|m| (&m.cvss_data, ())))
        .or_else(|| metrics.cvss_metric_v30.first().map(|m| (&m.cvss_data, ())))
        .or_else(|| metrics.cvss_metric_v2.first().map(|m| (&m.cvss_data, ())))
        .map(|(d, _)| {
            (
                Some(d.base_score),
                d.base_severity.clone(),
                d.vector_string.clone(),
            )
        })
        .unwrap_or((None, None, None));

    let mut matches = Vec::new();
    for config in &cve.configurations {
        for node in &config.nodes {
            for m in &node.cpe_match {
                matches.push(CpeMatch {
                    criteria: m.criteria.clone(),
                    vulnerable: m.vulnerable,
                    range: VersionRange {
                        start_including: m.version_start_including.clone(),
                        start_excluding: m.version_start_excluding.clone(),
                        end_including: m.version_end_including.clone(),
                        end_excluding: m.version_end_excluding.clone(),
                    },
                });
            }
        }
    }

    Some(CveRecord {
        id,
        description,
        published: cve.published,
        last_modified: cve.last_modified,
        cvss_score,
        cvss_severity: cvss_severity.map(|s| s.to_ascii_uppercase()),
        cvss_vector,
        matches,
    })
}

/// Minimal percent-encoding for a query-string value.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// --- Wire format ------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<Wrapper>,
}

#[derive(Debug, Deserialize)]
struct Wrapper {
    cve: RawCve,
}

#[derive(Debug, Deserialize)]
struct RawCve {
    id: String,
    #[serde(default)]
    published: Option<String>,
    #[serde(rename = "lastModified", default)]
    last_modified: Option<String>,
    #[serde(default)]
    descriptions: Vec<Description>,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    configurations: Vec<Configuration>,
}

#[derive(Debug, Deserialize)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Debug, Default, Deserialize)]
struct Metrics {
    #[serde(rename = "cvssMetricV40", default)]
    cvss_metric_v40: Vec<MetricEntry>,
    #[serde(rename = "cvssMetricV31", default)]
    cvss_metric_v31: Vec<MetricEntry>,
    #[serde(rename = "cvssMetricV30", default)]
    cvss_metric_v30: Vec<MetricEntry>,
    #[serde(rename = "cvssMetricV2", default)]
    cvss_metric_v2: Vec<MetricEntry>,
}

#[derive(Debug, Deserialize)]
struct MetricEntry {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct CvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "baseSeverity", default)]
    base_severity: Option<String>,
    #[serde(rename = "vectorString", default)]
    vector_string: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Configuration {
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Debug, Deserialize)]
struct Node {
    #[serde(rename = "cpeMatch", default)]
    cpe_match: Vec<RawCpeMatch>,
}

#[derive(Debug, Deserialize)]
struct RawCpeMatch {
    criteria: String,
    #[serde(default)]
    vulnerable: bool,
    #[serde(rename = "versionStartIncluding", default)]
    version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding", default)]
    version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding", default)]
    version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding", default)]
    version_end_excluding: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "resultsPerPage": 1,
      "totalResults": 1,
      "vulnerabilities": [
        {
          "cve": {
            "id": "CVE-2023-31102",
            "published": "2023-05-05T21:15:10.907",
            "lastModified": "2024-11-21T08:01:20.100",
            "descriptions": [
              { "lang": "es", "value": "Desbordamiento de enteros en 7-Zip." },
              { "lang": "en", "value": "An integer underflow in 7-Zip before 22.00 allows code execution." }
            ],
            "metrics": {
              "cvssMetricV31": [
                {
                  "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    "baseScore": 7.8,
                    "baseSeverity": "high"
                  }
                }
              ],
              "cvssMetricV2": [
                { "cvssData": { "version": "2.0", "baseScore": 4.3, "baseSeverity": "MEDIUM" } }
              ]
            },
            "configurations": [
              {
                "nodes": [
                  {
                    "operator": "OR",
                    "cpeMatch": [
                      {
                        "vulnerable": true,
                        "criteria": "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*",
                        "versionEndExcluding": "22.00"
                      },
                      {
                        "vulnerable": false,
                        "criteria": "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      ]
    }"#;

    #[test]
    fn parses_a_cve() {
        let cves = parse(FIXTURE).expect("should parse");
        assert_eq!(cves.len(), 1);
        assert_eq!(cves[0].id, "CVE-2023-31102");
    }

    #[test]
    fn prefers_the_english_description() {
        let cves = parse(FIXTURE).unwrap();
        assert!(cves[0].description.starts_with("An integer underflow"));
    }

    #[test]
    fn prefers_the_newest_cvss_metric() {
        // Both v3.1 (7.8) and v2 (4.3) are present; reporting the v2 score
        // would understate the severity by more than three points.
        let cves = parse(FIXTURE).unwrap();
        assert_eq!(cves[0].cvss_score, Some(7.8));
        assert_eq!(cves[0].cvss_severity.as_deref(), Some("HIGH"));
        assert!(cves[0]
            .cvss_vector
            .as_deref()
            .unwrap()
            .starts_with("CVSS:3.1/"));
    }

    #[test]
    fn extracts_cpe_match_rules_with_bounds() {
        let cves = parse(FIXTURE).unwrap();
        let vulnerable: Vec<_> = cves[0].vulnerable_matches().collect();
        assert_eq!(
            vulnerable.len(),
            1,
            "the non-vulnerable OS row must be excluded"
        );
        assert_eq!(
            vulnerable[0].criteria,
            "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*"
        );
        assert_eq!(vulnerable[0].range.end_excluding.as_deref(), Some("22.00"));
    }

    #[test]
    fn the_extracted_range_decides_versions_correctly() {
        use crate::vulnerabilities::version::Version;

        let cves = parse(FIXTURE).unwrap();
        let range = &cves[0].vulnerable_matches().next().unwrap().range;

        assert_eq!(
            range.contains(&Version::parse("21.07").unwrap()),
            Some(true)
        );
        assert_eq!(
            range.contains(&Version::parse("22.00").unwrap()),
            Some(false)
        );
        assert_eq!(
            range.contains(&Version::parse("23.01").unwrap()),
            Some(false)
        );
    }

    #[test]
    fn an_empty_result_set_is_valid() {
        let cves = parse(r#"{"totalResults":0,"vulnerabilities":[]}"#).expect("empty is fine");
        assert!(cves.is_empty());
    }

    #[test]
    fn a_cve_with_no_metrics_still_parses() {
        let body = r#"{"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","descriptions":[]}}]}"#;
        let cves = parse(body).expect("should parse");
        assert_eq!(cves[0].cvss_score, None);
        assert!(cves[0].matches.is_empty());
    }

    #[test]
    fn malformed_json_is_reported_as_malformed() {
        assert!(matches!(
            parse("<html>error</html>").unwrap_err(),
            CollectorError::Malformed { .. }
        ));
    }

    #[test]
    fn a_key_buys_a_much_shorter_interval() {
        assert_eq!(request_interval(None), UNKEYED_REQUEST_INTERVAL);
        assert_eq!(request_interval(Some("")), UNKEYED_REQUEST_INTERVAL);
        assert_eq!(request_interval(Some("a-key")), KEYED_REQUEST_INTERVAL);
        assert!(KEYED_REQUEST_INTERVAL < UNKEYED_REQUEST_INTERVAL);
    }

    #[test]
    fn urlencodes_query_values() {
        assert_eq!(urlencode("7-zip"), "7-zip");
        assert_eq!(urlencode("adobe reader"), "adobe%20reader");
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
    }
}

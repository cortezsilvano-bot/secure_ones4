//! FIRST's Exploit Prediction Scoring System.
//!
//! EPSS gives each CVE a probability that it will be exploited in the wild in
//! the next 30 days. It answers a question CVSS does not: CVSS says how bad
//! exploitation *would* be, EPSS says how likely it is to happen. A 9.8 that
//! nobody is exploiting is usually less urgent than a 6.5 that everybody is.
//!
//! Scores are republished daily, shortly after 13:30 UTC, and are free with no
//! registration. SENTRY fetches only the CVEs it already has reason to care
//! about, in batches, so the request reveals nothing about the machine beyond
//! a list of public CVE identifiers.

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

const EPSS_API: &str = "https://api.first.org/data/v1/epss";

/// The API accepts a comma-separated list; keep requests well inside any
/// practical URL length limit.
const BATCH_SIZE: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpssScore {
    /// Probability of exploitation in the next 30 days, 0.0 to 1.0.
    pub epss: f64,
    /// Where that sits against every other scored CVE, 0.0 to 1.0.
    pub percentile: f64,
}

impl EpssScore {
    /// EPSS as a percentage, for display.
    pub fn as_percent(&self) -> f64 {
        self.epss * 100.0
    }

    /// FIRST's own guidance treats the top few percent as the actionable tail.
    /// Used as a prioritisation hint, never as a verdict on its own.
    pub fn is_high(&self) -> bool {
        self.epss >= 0.1 || self.percentile >= 0.95
    }
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    #[serde(default)]
    data: Vec<EpssRow>,
}

#[derive(Debug, Deserialize)]
struct EpssRow {
    cve: String,
    /// The API returns these as JSON strings, not numbers.
    epss: String,
    percentile: String,
}

/// Fetch scores for the given CVE ids.
///
/// Unknown ids are simply absent from the result rather than an error: a CVE
/// too new or too old to be scored is a normal occurrence.
pub fn fetch(cve_ids: &[String]) -> Result<Vec<(String, EpssScore)>, CollectorError> {
    let mut out = Vec::new();

    for chunk in cve_ids.chunks(BATCH_SIZE) {
        let url = format!("{EPSS_API}?cve={}", chunk.join(","));
        let body = super::http::get_text(&url)?;
        out.extend(parse(&body)?);
    }

    Ok(out)
}

/// Parse an API response. Separate from `fetch` for offline testing.
pub fn parse(body: &str) -> Result<Vec<(String, EpssScore)>, CollectorError> {
    let response: EpssResponse =
        serde_json::from_str(body).map_err(|e| CollectorError::Malformed {
            origin: "FIRST EPSS".to_string(),
            detail: format!("could not parse the response: {e}"),
        })?;

    let mut out = Vec::with_capacity(response.data.len());

    for row in response.data {
        // A row whose numbers will not parse is skipped rather than defaulted:
        // an EPSS of 0.0 is a meaningful claim ("almost certainly not being
        // exploited") and must never be invented.
        let (Ok(epss), Ok(percentile)) = (row.epss.parse::<f64>(), row.percentile.parse::<f64>())
        else {
            log::warn!("skipping unparseable EPSS row for {}", row.cve);
            continue;
        };

        if !(0.0..=1.0).contains(&epss) || !(0.0..=1.0).contains(&percentile) {
            log::warn!("skipping out-of-range EPSS row for {}", row.cve);
            continue;
        }

        out.push((
            row.cve.trim().to_ascii_uppercase(),
            EpssScore { epss, percentile },
        ));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "status": "OK",
      "status-code": 200,
      "version": "1.0",
      "total": 2,
      "data": [
        { "cve": "CVE-2021-44228", "epss": "0.944290000", "percentile": "0.999880000", "date": "2026-09-17" },
        { "cve": "cve-2017-0144",  "epss": "0.010340000", "percentile": "0.782100000", "date": "2026-09-17" }
      ]
    }"#;

    #[test]
    fn parses_scores() {
        let scores = parse(FIXTURE).expect("should parse");
        assert_eq!(scores.len(), 2);
        assert!((scores[0].1.epss - 0.94429).abs() < 1e-9);
        assert!((scores[0].1.percentile - 0.99988).abs() < 1e-9);
    }

    #[test]
    fn cve_ids_are_normalised_to_upper_case() {
        let scores = parse(FIXTURE).unwrap();
        assert_eq!(scores[1].0, "CVE-2017-0144");
    }

    #[test]
    fn converts_to_a_percentage_for_display() {
        let scores = parse(FIXTURE).unwrap();
        assert!((scores[0].1.as_percent() - 94.429).abs() < 1e-6);
    }

    #[test]
    fn identifies_the_actionable_tail() {
        let scores = parse(FIXTURE).unwrap();
        assert!(scores[0].1.is_high(), "a 0.94 EPSS is unambiguously high");
        assert!(
            !scores[1].1.is_high(),
            "a 0.01 EPSS at the 78th percentile is not"
        );
    }

    #[test]
    fn an_empty_result_is_valid() {
        // Unlike KEV, no matching CVEs is a normal answer here.
        let scores = parse(r#"{"status":"OK","data":[]}"#).expect("empty is fine");
        assert!(scores.is_empty());
    }

    #[test]
    fn unparseable_rows_are_skipped_not_defaulted() {
        // Defaulting to 0.0 would assert "not being exploited", which is a
        // claim, not an absence.
        let body = r#"{"data":[
          {"cve":"CVE-2024-0001","epss":"not-a-number","percentile":"0.5"},
          {"cve":"CVE-2024-0002","epss":"0.5","percentile":"0.5"}
        ]}"#;
        let scores = parse(body).unwrap();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].0, "CVE-2024-0002");
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        let body = r#"{"data":[{"cve":"CVE-2024-0001","epss":"5.0","percentile":"0.5"}]}"#;
        assert!(parse(body).unwrap().is_empty());
    }

    #[test]
    fn malformed_json_is_reported_as_malformed() {
        assert!(matches!(
            parse("nonsense").unwrap_err(),
            CollectorError::Malformed { .. }
        ));
    }
}

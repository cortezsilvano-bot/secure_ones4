//! Reviewed bundled data, evaluated locally. No network access or version guessing.
//! Source citations and review expiry are part of the versioned input contract.
use super::firmware::{AdvisoryMatch, FirmwareAssessment};
use crate::security::Known;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const BUNDLED: &str = include_str!("asus-catalog.json");
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportRegion {
    #[default]
    Unknown,
    Eu,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    FixDocumented,
    ReviewRequired,
    AffectedBuild,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvisoryReview {
    pub id: String,
    pub disposition: Disposition,
    pub detail: String,
    pub sources: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Lifecycle {
    authority: String,
    region: String,
    models: Vec<String>,
    source: String,
    detail: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Catalog {
    schema_version: u32,
    reviewed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    models: Vec<String>,
    family: String,
    installed_version: String,
    newer_release: String,
    release_source: String,
    advisories: Vec<AdvisoryReview>,
    vendor_eol: Lifecycle,
}
fn source(url: &str) -> bool {
    if url.len() > 512 || url.contains(['\\', '#', '?']) || url.chars().any(char::is_control) {
        return false;
    }
    let Ok(uri) = url.parse::<ureq::http::Uri>() else {
        return false;
    };
    if uri.scheme_str() != Some("https")
        || uri
            .authority()
            .is_none_or(|a| a.as_str().contains('@') || a.port().is_some())
    {
        return false;
    }
    match uri.host() {
        Some("github.com") => {
            uri.path().starts_with("/gnuton/asuswrt-merlin.ng/blob/")
                || uri
                    .path()
                    .starts_with("/gnuton/asuswrt-merlin.ng/releases/tag/")
        }
        Some("www.asus.com") => uri.path() == "/event/network/EOL-product/",
        Some("openssl-library.org") => uri.path().starts_with("/news/secadv/"),
        _ => false,
    }
}
fn label(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.trim() == s && !s.chars().any(char::is_control)
}
fn cve(id: &str) -> bool {
    let parts: Vec<_> = id.split('-').collect();
    parts.len() == 3
        && parts[0] == "CVE"
        && parts[1].len() == 4
        && (4..=9).contains(&parts[2].len())
        && parts[1..]
            .iter()
            .all(|s| s.bytes().all(|b| b.is_ascii_digit()))
}
fn parse(body: &str) -> Result<Catalog, &'static str> {
    if body.len() > 65536 {
        return Err("Router catalog exceeds its size limit.");
    }
    let c: Catalog = serde_json::from_str(body).map_err(|_| "Router catalog is malformed.")?;
    let supported = |models: &[String]| {
        !models.is_empty()
            && models.len() <= 2
            && models
                .iter()
                .all(|m| matches!(m.as_str(), "RT-AX82U" | "RT-AX82U_V2"))
            && models
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == models.len()
    };
    let unique = c
        .advisories
        .iter()
        .map(|r| &r.id)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == c.advisories.len();
    if c.schema_version != 1
        || c.family != "gnuton"
        || !supported(&c.models)
        || c.installed_version != super::asus::REVIEWED_BUILD
        || !label(&c.newer_release, 128)
        || !source(&c.release_source)
        || c.valid_until <= c.reviewed_at
        || c.valid_until - c.reviewed_at > chrono::Duration::days(31)
        || c.advisories.is_empty()
        || c.advisories.len() > 128
        || !unique
        || c.advisories.iter().any(|r| {
            !cve(&r.id)
                || !label(&r.detail, 1000)
                || r.sources.is_empty()
                || r.sources.len() > 4
                || r.sources.iter().any(|s| !source(s))
        })
        || c.vendor_eol.authority != "ASUS"
        || c.vendor_eol.region != "EU"
        || !supported(&c.vendor_eol.models)
        || !source(&c.vendor_eol.source)
        || !label(&c.vendor_eol.detail, 1000)
    {
        return Err("Router catalog has invalid scope, provenance, dates or records.");
    }
    Ok(c)
}

pub fn assess(
    model: &str,
    version: &str,
    region: SupportRegion,
    now: DateTime<Utc>,
) -> FirmwareAssessment {
    assess_body(BUNDLED, model, version, region, now)
}
fn assess_body(
    body: &str,
    model: &str,
    version: &str,
    region: SupportRegion,
    now: DateTime<Utc>,
) -> FirmwareAssessment {
    let mut result = FirmwareAssessment {
        support_region: Some(region),
        ..Default::default()
    };
    let unknown = |result: &mut FirmwareAssessment, reason: &str| {
        result.advisory_matches = Known::Unavailable(reason.into());
        result.advisory_reviews = Known::Unavailable(reason.into());
        result.update_available = Known::Unavailable(reason.into());
        result.end_of_support = Known::Unavailable(reason.into());
    };
    let c = match parse(body) {
        Ok(c) => c,
        Err(reason) => {
            unknown(&mut result, reason);
            return result;
        }
    };
    result.catalog_reviewed_at = Some(c.reviewed_at.to_rfc3339());
    result.catalog_valid_until = Some(c.valid_until.to_rfc3339());
    if now < c.reviewed_at || now >= c.valid_until {
        unknown(&mut result, "Bundled router intelligence is outside its review window; refresh the reviewed catalog before using it.");
        return result;
    }
    if !c.models.iter().any(|m| m == model) || version != c.installed_version {
        unknown(
            &mut result,
            "No reviewed catalog scope covers this exact model, firmware family and build.",
        );
        return result;
    }
    result.catalog_scope = Some("Selected GNUton release advisories; not an exhaustive CVE audit. Published fixes are not installed-binary verification.".into());
    result.update_available = Known::Known(true);
    result.release_evidence = vec![format!("The reviewed {} release succeeds this exact installed build. Check model-specific release guidance before any upgrade.", c.newer_release), c.release_source];
    result.advisory_matches = if c
        .advisories
        .iter()
        .any(|r| r.disposition == Disposition::ReviewRequired)
    {
        Known::Unavailable("At least one advisory requires component/feature review. No clean-vulnerability conclusion is supported.".into())
    } else {
        Known::Known(
            c.advisories
                .iter()
                .filter(|r| r.disposition == Disposition::AffectedBuild)
                .map(|r| AdvisoryMatch {
                    id: r.id.clone(),
                    source: r.sources.join(" "),
                })
                .collect(),
        )
    };
    // Keep confirmed records visible even when other records are uncertain.
    let confirmed: Vec<_> = c
        .advisories
        .iter()
        .filter(|r| r.disposition == Disposition::AffectedBuild)
        .map(|r| AdvisoryMatch {
            id: r.id.clone(),
            source: r.sources.join(" "),
        })
        .collect();
    if !confirmed.is_empty() {
        result.advisory_matches = Known::Known(confirmed);
    }
    result.advisory_reviews = Known::Known(c.advisories);
    result.lifecycle_evidence = vec![c.vendor_eol.detail, c.vendor_eol.source, format!("Support region supplied for this scan: {region:?}. No region is inferred from Wi-Fi regulatory settings or the PC.")];
    result.end_of_support = if region == SupportRegion::Eu
        && c.vendor_eol.models.iter().any(|m| m == model)
    {
        Known::Known(true)
    } else {
        Known::Unavailable("ASUS evidence is EU-only. A non-EU or unknown region does not establish support; GNUton support is a separate question.".into())
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn now() -> DateTime<Utc> {
        "2026-10-02T12:00:00Z".parse().unwrap()
    }
    #[test]
    fn bundled_evidence_distinguishes_documented_fixes_review_and_regional_eol() {
        for model in ["RT-AX82U", "RT-AX82U_V2"] {
            let f = assess(
                model,
                super::super::asus::REVIEWED_BUILD,
                SupportRegion::Eu,
                now(),
            );
            assert!(matches!(f.end_of_support, Known::Known(true)));
            assert!(matches!(f.update_available, Known::Known(true)));
            assert!(!f.advisory_matches.is_known());
            let reviews = f.advisory_reviews.value().unwrap();
            assert!(reviews
                .iter()
                .any(|r| r.id == "CVE-2025-2492" && r.disposition == Disposition::FixDocumented));
            assert!(reviews
                .iter()
                .any(|r| r.id == "CVE-2025-9230" && r.disposition == Disposition::ReviewRequired));
        }
        for region in [SupportRegion::Unknown, SupportRegion::Other] {
            assert!(!assess(
                "RT-AX82U",
                super::super::asus::REVIEWED_BUILD,
                region,
                now()
            )
            .end_of_support
            .is_known());
        }
    }
    #[test]
    fn untrusted_malformed_wrong_scope_and_stale_data_fail_closed() {
        for body in [
            "{}",
            "<html>error</html>",
            &BUNDLED.replace("https://github.com/", "https://evil.example/"),
            &BUNDLED.replace("https://www.asus.com/", "http://www.asus.com/"),
            &BUNDLED.replace("CVE-2024-9143", "CVE-2025-2492"),
        ] {
            let f = assess_body(
                body,
                "RT-AX82U",
                super::super::asus::REVIEWED_BUILD,
                SupportRegion::Eu,
                now(),
            );
            assert!(!f.advisory_reviews.is_known());
            assert!(!f.end_of_support.is_known());
        }
        for date in [
            now() - chrono::Duration::days(1),
            now() + chrono::Duration::days(30),
        ] {
            assert!(!assess(
                "RT-AX82U",
                super::super::asus::REVIEWED_BUILD,
                SupportRegion::Eu,
                date
            )
            .advisory_reviews
            .is_known());
        }
        for (model, version) in [
            ("RT-AX82U", "3004.388.9"),
            ("RT-AX88U", super::super::asus::REVIEWED_BUILD),
        ] {
            assert!(!assess(model, version, SupportRegion::Eu, now())
                .advisory_reviews
                .is_known());
        }
    }
}

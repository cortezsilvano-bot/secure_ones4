//! Offline exact-match advisory foundation. No feed downloads, version ordering,
//! firmware updates, or claims that absence of a match establishes safety.
use crate::security::Known;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareIdentity {
    pub model: String,
    pub hardware_revision: String,
    pub family: String,
    pub version: String,
}

/// An explicitly enumerated affected build, not a guessed version range.
pub struct AdvisoryRecord {
    pub id: String,
    pub affected: FirmwareIdentity,
    pub source: String,
}

/// A future ingestion layer must authenticate/validate source provenance before
/// calling this matcher. Dates and a source label alone do not establish trust.
pub struct AdvisoryCatalog {
    pub reviewed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub records: Vec<AdvisoryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryMatch {
    pub id: String,
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FirmwareAssessment {
    pub advisory_reviews: Known<Vec<super::intelligence::AdvisoryReview>>,
    pub lifecycle_evidence: Vec<String>,
    pub support_region: Option<super::intelligence::SupportRegion>,
    pub catalog_valid_until: Option<String>,
    pub catalog_scope: Option<String>,
    pub release_evidence: Vec<String>,
    pub advisory_matches: Known<Vec<AdvisoryMatch>>,
    pub catalog_reviewed_at: Option<String>,
    // These require their own release/support evidence. Never derive them from
    // a matching CVE list, a software banner, or an arbitrary version comparison.
    pub update_available: Known<bool>,
    pub end_of_support: Known<bool>,
}

/// Compatibility entry point; data and provenance live in the reviewed catalog.
pub fn reviewed_gnuton_release(
    model: &str,
    installed: &str,
    now: DateTime<Utc>,
) -> FirmwareAssessment {
    super::intelligence::assess(
        model,
        installed,
        super::intelligence::SupportRegion::Unknown,
        now,
    )
}
fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_identity(identity: &FirmwareIdentity) -> bool {
    [
        &identity.model,
        &identity.hardware_revision,
        &identity.family,
        &identity.version,
    ]
    .into_iter()
    .all(|value| valid_label(value))
}

pub fn assess(
    identity: &Known<FirmwareIdentity>,
    catalog: Option<&AdvisoryCatalog>,
    now: DateTime<Utc>,
) -> FirmwareAssessment {
    let mut result = FirmwareAssessment::default();
    let Some(identity) = identity.value().filter(|identity| valid_identity(identity)) else {
        result.advisory_matches = Known::Unavailable(
            "Exact model, hardware revision, firmware family and installed version are required."
                .into(),
        );
        return result;
    };
    let Some(catalog) = catalog else {
        result.advisory_matches =
            Known::Unavailable("No reviewed advisory catalog is loaded.".into());
        return result;
    };
    result.catalog_reviewed_at = Some(catalog.reviewed_at.to_rfc3339());
    if catalog.reviewed_at > now
        || catalog.valid_until <= now
        || catalog.valid_until <= catalog.reviewed_at
    {
        result.advisory_matches =
            Known::Unavailable("Advisory catalog is stale or has invalid dates.".into());
        return result;
    }
    if catalog.records.is_empty()
        || catalog.records.len() > 10_000
        || catalog.records.iter().any(|record| {
            !valid_identity(&record.affected)
                || !valid_label(&record.id)
                || !valid_label(&record.source)
        })
    {
        result.advisory_matches =
            Known::Unavailable("Advisory catalog is empty, oversized or incomplete.".into());
        return result;
    }
    let mut matches = Vec::<AdvisoryMatch>::new();
    for record in &catalog.records {
        if &record.affected == identity
            && !matches
                .iter()
                .any(|found| found.id == record.id && found.source == record.source)
        {
            matches.push(AdvisoryMatch {
                id: record.id.clone(),
                source: record.source.clone(),
            });
        }
    }
    result.advisory_matches = Known::Known(matches);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundled_release_is_exact_scoped_and_expires() {
        let date = DateTime::parse_from_rfc3339("2026-10-02T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        for model in ["RT-AX82U", "RT-AX82U_V2"] {
            let result = reviewed_gnuton_release(model, super::super::asus::REVIEWED_BUILD, date);
            assert!(matches!(result.update_available, Known::Known(true)));
            assert!(!result.advisory_matches.is_known());
            assert!(!result.end_of_support.is_known());
            assert_eq!(result.release_evidence.len(), 2);
        }
        for (model, version) in [
            ("RT-AX82U", "3004.388.9"),
            ("RT-AX88U", super::super::asus::REVIEWED_BUILD),
        ] {
            assert!(!reviewed_gnuton_release(model, version, date)
                .update_available
                .is_known());
        }
        for date in [
            date - chrono::Duration::days(1),
            date + chrono::Duration::days(30),
        ] {
            assert!(
                !reviewed_gnuton_release("RT-AX82U", super::super::asus::REVIEWED_BUILD, date)
                    .update_available
                    .is_known()
            );
        }
    }
    use chrono::Duration;

    // Synthetic fixtures, not real advisory data or a supported hardware claim.
    fn now() -> DateTime<Utc> {
        "2026-01-02T00:00:00Z".parse().unwrap()
    }
    fn identity() -> FirmwareIdentity {
        FirmwareIdentity {
            model: "TEST-ROUTER Pro".into(),
            hardware_revision: "A1".into(),
            family: "test-stock".into(),
            version: "1.2.3_4".into(),
        }
    }
    fn catalog() -> AdvisoryCatalog {
        AdvisoryCatalog {
            reviewed_at: now() - Duration::days(1),
            valid_until: now() + Duration::days(1),
            records: vec![AdvisoryRecord {
                id: "TEST-ADVISORY-1".into(),
                affected: identity(),
                source: "Synthetic test fixture".into(),
            }],
        }
    }

    #[test]
    fn exact_match_preserves_source_without_inferring_update_or_support() {
        let result = assess(&Known::Known(identity()), Some(&catalog()), now());
        let matches = result.advisory_matches.value().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].source, "Synthetic test fixture");
        assert!(!result.update_available.is_known());
        assert!(!result.end_of_support.is_known());
    }

    #[test]
    fn related_models_revisions_families_and_versions_do_not_match() {
        for mutate in [
            (|i: &mut FirmwareIdentity| i.model = "TEST-ROUTER".into())
                as fn(&mut FirmwareIdentity),
            |i| i.hardware_revision = "B1".into(),
            |i| i.family = "test-custom".into(),
            |i| i.version = "1.2.3_40".into(),
        ] {
            let mut observed = identity();
            mutate(&mut observed);
            let result = assess(&Known::Known(observed), Some(&catalog()), now());
            assert!(result.advisory_matches.value().unwrap().is_empty());
            assert!(!result.update_available.is_known());
        }
    }

    #[test]
    fn missing_identity_or_catalog_remains_unknown() {
        assert!(!assess(&Known::NotScanned, Some(&catalog()), now())
            .advisory_matches
            .is_known());
        assert!(!assess(&Known::Known(identity()), None, now())
            .advisory_matches
            .is_known());
        let mut incomplete = identity();
        incomplete.hardware_revision.clear();
        assert!(!assess(&Known::Known(incomplete), Some(&catalog()), now())
            .advisory_matches
            .is_known());
    }

    #[test]
    fn expired_and_future_catalogs_cannot_establish_current_results() {
        let mut expired = catalog();
        expired.valid_until = now();
        assert!(!assess(&Known::Known(identity()), Some(&expired), now())
            .advisory_matches
            .is_known());
        let mut future = catalog();
        future.reviewed_at = now() + Duration::hours(1);
        assert!(!assess(&Known::Known(identity()), Some(&future), now())
            .advisory_matches
            .is_known());
    }

    #[test]
    fn empty_or_malformed_catalog_is_not_a_clean_scan() {
        let mut empty = catalog();
        empty.records.clear();
        assert!(!assess(&Known::Known(identity()), Some(&empty), now())
            .advisory_matches
            .is_known());
        let mut malformed = catalog();
        malformed.records[0].source.clear();
        assert!(!assess(&Known::Known(identity()), Some(&malformed), now())
            .advisory_matches
            .is_known());
    }

    #[test]
    fn old_snapshots_default_to_unscanned_firmware_assessment() {
        let result: FirmwareAssessment = serde_json::from_str("{}").unwrap();
        assert!(matches!(result.advisory_matches, Known::NotScanned));
        assert!(matches!(result.update_available, Known::NotScanned));
        assert!(matches!(result.end_of_support, Known::NotScanned));
    }
}

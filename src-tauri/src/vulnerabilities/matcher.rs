//! Matching installed software to cached CVEs.
//!
//! This is where the honesty rules bite hardest. Matching a registry
//! DisplayName to a CPE product is fuzzy, version strings are inconsistent,
//! and feed data is incomplete. Every one of those uncertainties has a way to
//! be expressed rather than rounded away:
//!
//!   * A confident name match on a version inside a stated range is
//!     `Confirmed`.
//!   * A weaker name match, or a range that could not be parsed, degrades to
//!     `Likely` or `Potential`.
//!   * A program with *no version recorded* can never be confirmed vulnerable,
//!     because there is nothing to compare. It is reported as undetermined.
//!
//! The last point is the one that matters most: roughly one program in ten on
//! a real machine has no version in the registry. Treating those as safe would
//! hide real vulnerabilities; treating them as vulnerable would flood the user
//! with noise. They are reported as what they are -- unknown.

use serde::{Deserialize, Serialize};

use crate::collectors::software::InstalledSoftware;
use crate::findings::Confidence;
use crate::vulnerabilities::cpe::{self, Cpe, MatchQuality};
use crate::vulnerabilities::feeds::epss::EpssScore;
use crate::vulnerabilities::feeds::kev::KevEntry;
use crate::vulnerabilities::feeds::nvd::CveRecord;
use crate::vulnerabilities::version::Version;

/// What the matcher concluded about one program and one CVE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The installed version falls inside a stated affected range.
    Vulnerable,
    /// The installed version is outside every affected range.
    NotVulnerable,
    /// The product matches but the version question cannot be settled.
    Undetermined,
}

/// One program matched against one CVE.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VulnerabilityMatch {
    pub program_name: String,
    pub installed_version: Option<String>,
    pub cve_id: String,
    pub verdict: Verdict,
    pub confidence: Confidence,
    pub cvss_score: Option<f64>,
    pub cvss_severity: Option<String>,
    pub description: String,
    /// Present when CISA lists this CVE as actively exploited.
    pub kev: Option<KevSummary>,
    pub epss: Option<EpssScore>,
    /// The CPE rule that produced the match, for the evidence pane.
    pub matched_criteria: String,
    pub affected_range: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevSummary {
    pub date_added: String,
    pub known_ransomware_use: bool,
    pub required_action: String,
}

impl From<&KevEntry> for KevSummary {
    fn from(e: &KevEntry) -> Self {
        KevSummary {
            date_added: e.date_added.clone(),
            known_ransomware_use: e.used_in_ransomware(),
            required_action: e.required_action.clone(),
        }
    }
}

/// Everything the matcher needs about one CVE beyond the NVD record.
pub struct Enrichment<'a> {
    pub kev: Option<&'a KevEntry>,
    pub epss: Option<EpssScore>,
}

/// Match one program against one CVE.
///
/// Returns `None` when the CVE has no rule that plausibly refers to this
/// program at all.
pub fn match_one(
    program: &InstalledSoftware,
    cve: &CveRecord,
    enrichment: Enrichment<'_>,
) -> Option<VulnerabilityMatch> {
    let installed_version = program.version.as_deref().and_then(Version::parse);

    // Find the best CPE rule that refers to this program.
    //
    // Ranked by name-match quality first, then by whether the rule actually
    // states a version range. A CVE often carries both a precise bounded rule
    // and a vague catch-all one; the bounded rule is the one that can settle
    // the version question, so it wins.
    let mut best: Option<(
        MatchQuality,
        bool,
        &crate::vulnerabilities::feeds::nvd::CpeMatch,
        Cpe,
    )> = None;

    for rule in cve.vulnerable_matches() {
        let Some(parsed) = Cpe::parse(&rule.criteria) else {
            continue;
        };
        let Some(quality) =
            cpe::match_quality(&program.name, program.publisher.as_deref(), &parsed)
        else {
            continue;
        };

        let states_a_version = !(parsed.version_is_wildcard() && rule.range.is_unbounded());

        // MatchQuality orders Strong < Moderate < Weak, so the best is the
        // smallest; among equals, a rule that states a version wins.
        let better = match best.as_ref() {
            None => true,
            Some((q, bounded, _, _)) => {
                quality < *q || (quality == *q && states_a_version && !bounded)
            }
        };

        if better {
            best = Some((quality, states_a_version, rule, parsed));
        }
    }

    let (quality, states_a_version, rule, parsed_cpe) = best?;

    // Decide the version question.
    let (verdict, version_note) = if !states_a_version {
        // The rule names the product but no version at all -- a wildcard or
        // not-applicable CPE with no bounds. NVD uses this shape for products
        // it never recorded version data for, and it is the single largest
        // source of false positives in version-matching scanners: it would
        // mark a current Edge as vulnerable to a 2015 EdgeHTML bug, because
        // "no range" reads as "every version".
        //
        // We genuinely cannot tell, so we say so.
        (
            Verdict::Undetermined,
            "The advisory does not state which versions are affected".to_string(),
        )
    } else {
        match &installed_version {
            None => (
                Verdict::Undetermined,
                "Installed version: not recorded in the registry".to_string(),
            ),
            Some(v) => {
                // A CPE that pins an exact version carries the range itself.
                let in_range = if parsed_cpe.version_is_wildcard() {
                    rule.range.contains(v)
                } else {
                    Version::parse(&parsed_cpe.version).map(|pinned| *v == pinned)
                };

                match in_range {
                    Some(true) => (
                        Verdict::Vulnerable,
                        format!(
                            "Installed {} falls within the affected range",
                            program.version.as_deref().unwrap_or("?")
                        ),
                    ),
                    Some(false) => (
                        Verdict::NotVulnerable,
                        format!(
                            "Installed {} is outside the affected range",
                            program.version.as_deref().unwrap_or("?")
                        ),
                    ),
                    None => (
                        Verdict::Undetermined,
                        "The affected range could not be interpreted".to_string(),
                    ),
                }
            }
        }
    };

    // A weak name match cannot confirm anything, however clean the version
    // arithmetic looks. The version numbers of two different products are not
    // comparable quantities, so a confident-looking "1.138.0 <= 2012" across a
    // product boundary is arithmetic, not evidence.
    let (verdict, version_note) = if quality == MatchQuality::Weak && verdict == Verdict::Vulnerable
    {
        (
            Verdict::Undetermined,
            format!("{version_note}, but this may be a different product with a similar name"),
        )
    } else {
        (verdict, version_note)
    };

    // Confidence is the weaker of the name match and the version certainty.
    // A Strong name match on an uninterpretable version is still only a guess.
    let confidence = match (quality, verdict) {
        (_, Verdict::Undetermined) => Confidence::Potential,
        (MatchQuality::Strong, _) => Confidence::Confirmed,
        (MatchQuality::Moderate, _) => Confidence::Likely,
        (MatchQuality::Weak, _) => Confidence::Potential,
    };

    let affected_range = if parsed_cpe.version_is_wildcard() {
        rule.range.describe()
    } else {
        format!("= {}", parsed_cpe.version)
    };

    let mut evidence = vec![
        format!("Program: {}", program.name),
        format!(
            "Installed version: {}",
            program.version.as_deref().unwrap_or("not recorded")
        ),
        format!("Matched CPE: {}", rule.criteria),
        format!("Affected versions: {affected_range}"),
        format!("Name match quality: {quality:?}"),
        version_note,
    ];

    if let Some(score) = cve.cvss_score {
        evidence.push(format!(
            "CVSS: {score} ({})",
            cve.cvss_severity.as_deref().unwrap_or("unrated")
        ));
    }
    if let Some(kev) = enrichment.kev {
        evidence.push(format!(
            "CISA KEV: listed {} as actively exploited{}",
            kev.date_added,
            if kev.used_in_ransomware() {
                ", with known ransomware use"
            } else {
                ""
            }
        ));
    }
    if let Some(epss) = &enrichment.epss {
        evidence.push(format!(
            "EPSS: {:.2}% chance of exploitation in the next 30 days ({:.0}th percentile)",
            epss.as_percent(),
            epss.percentile * 100.0
        ));
    }

    Some(VulnerabilityMatch {
        program_name: program.name.clone(),
        installed_version: program.version.clone(),
        cve_id: cve.id.clone(),
        verdict,
        confidence,
        cvss_score: cve.cvss_score,
        cvss_severity: cve.cvss_severity.clone(),
        description: cve.description.clone(),
        kev: enrichment.kev.map(KevSummary::from),
        epss: enrichment.epss,
        matched_criteria: rule.criteria.clone(),
        affected_range,
        evidence,
    })
}

/// The keyword used to look a program up in NVD.
///
/// Derived from the program name with versions and noise stripped, so
/// "Mozilla Firefox 140.0 (x64 en-US)" and "Mozilla Firefox 141.0 (x64)" share
/// one lookup rather than consuming two of a very small rate-limit budget.
pub fn lookup_keyword(program: &InstalledSoftware) -> Option<String> {
    cpe::search_keyword(&program.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::feeds::nvd::CpeMatch;
    use crate::vulnerabilities::version::VersionRange;

    fn program(name: &str, version: Option<&str>, publisher: Option<&str>) -> InstalledSoftware {
        InstalledSoftware {
            name: name.to_string(),
            version: version.map(str::to_string),
            publisher: publisher.map(str::to_string),
            scope: "HKLM64".into(),
            registry_key: name.to_string(),
            install_location: None,
            install_date: None,
        }
    }

    fn cve_with_range(range: VersionRange) -> CveRecord {
        CveRecord {
            id: "CVE-2023-31102".into(),
            description: "An integer underflow in 7-Zip before 22.00.".into(),
            published: Some("2023-05-05".into()),
            last_modified: None,
            cvss_score: Some(7.8),
            cvss_severity: Some("HIGH".into()),
            cvss_vector: None,
            matches: vec![CpeMatch {
                criteria: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*".into(),
                vulnerable: true,
                range,
            }],
        }
    }

    fn before_22() -> CveRecord {
        cve_with_range(VersionRange {
            end_excluding: Some("22.00".into()),
            ..Default::default()
        })
    }

    fn plain() -> Enrichment<'static> {
        Enrichment {
            kev: None,
            epss: None,
        }
    }

    #[test]
    fn an_affected_version_is_confirmed_vulnerable() {
        let m = match_one(
            &program("7-Zip", Some("21.07"), Some("Igor Pavlov")),
            &before_22(),
            plain(),
        )
        .expect("should match");
        assert_eq!(m.verdict, Verdict::Vulnerable);
        assert_eq!(m.cve_id, "CVE-2023-31102");
    }

    #[test]
    fn a_patched_version_is_not_vulnerable() {
        let m = match_one(
            &program("7-Zip", Some("23.01"), None),
            &before_22(),
            plain(),
        )
        .expect("should still match the product");
        assert_eq!(
            m.verdict,
            Verdict::NotVulnerable,
            "a patched install must not be reported as vulnerable"
        );
    }

    #[test]
    fn the_boundary_version_is_not_vulnerable() {
        // "before 22.00" excludes 22.00 itself. Off by one here means telling
        // someone who patched that they did not.
        let m = match_one(
            &program("7-Zip", Some("22.00"), None),
            &before_22(),
            plain(),
        )
        .unwrap();
        assert_eq!(m.verdict, Verdict::NotVulnerable);
    }

    #[test]
    fn a_program_with_no_version_is_undetermined_never_vulnerable() {
        let m = match_one(&program("7-Zip", None, None), &before_22(), plain()).unwrap();
        assert_eq!(m.verdict, Verdict::Undetermined);
        assert_eq!(m.confidence, Confidence::Potential);
        assert!(m.evidence.iter().any(|e| e.contains("not recorded")));
    }

    #[test]
    fn an_unbounded_advisory_cannot_confirm_a_vulnerability() {
        // The Edge regression. NVD carries 2015-era CVEs for the old EdgeHTML
        // browser as `cpe:2.3:a:microsoft:edge:-:*` with no version bounds at
        // all. Reading "no range" as "every version" marked a current Edge 153
        // as Critically vulnerable to a decade-old bug.
        let cve = CveRecord {
            matches: vec![CpeMatch {
                criteria: "cpe:2.3:a:microsoft:edge:-:*:*:*:*:*:*:*".into(),
                vulnerable: true,
                range: VersionRange::default(),
            }],
            ..before_22()
        };

        let m = match_one(
            &program("Microsoft Edge", Some("153.0.4234.32"), Some("Microsoft")),
            &cve,
            plain(),
        )
        .expect("the product still matches by name");

        assert_eq!(
            m.verdict,
            Verdict::Undetermined,
            "an advisory with no version range cannot confirm anything"
        );
        assert_eq!(m.confidence, Confidence::Potential);
        assert!(m
            .evidence
            .iter()
            .any(|e| e.contains("does not state which versions")));
    }

    #[test]
    fn a_bounded_rule_is_preferred_over_an_unbounded_one() {
        // CVEs often carry both. The bounded rule is the only one that can
        // settle the version question, so it must win.
        let cve = CveRecord {
            matches: vec![
                CpeMatch {
                    criteria: "cpe:2.3:a:7-zip:7-zip:-:*:*:*:*:*:*:*".into(),
                    vulnerable: true,
                    range: VersionRange::default(),
                },
                CpeMatch {
                    criteria: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*".into(),
                    vulnerable: true,
                    range: VersionRange {
                        end_excluding: Some("22.00".into()),
                        ..Default::default()
                    },
                },
            ],
            ..before_22()
        };

        let affected = match_one(&program("7-Zip", Some("21.07"), None), &cve, plain()).unwrap();
        assert_eq!(affected.verdict, Verdict::Vulnerable);
        assert_eq!(affected.affected_range, "< 22.00");

        let patched = match_one(&program("7-Zip", Some("23.01"), None), &cve, plain()).unwrap();
        assert_eq!(
            patched.verdict,
            Verdict::NotVulnerable,
            "the bounded rule must clear a patched install despite the catch-all rule"
        );
    }

    #[test]
    fn an_uninterpretable_range_is_undetermined() {
        let cve = cve_with_range(VersionRange {
            end_excluding: Some("unknown".into()),
            ..Default::default()
        });
        let m = match_one(&program("7-Zip", Some("21.07"), None), &cve, plain()).unwrap();
        assert_eq!(m.verdict, Verdict::Undetermined);
    }

    #[test]
    fn a_sibling_product_cannot_be_confirmed_vulnerable() {
        // The VS Code regression. "Microsoft Visual Studio Code" matched the
        // CPE product "visual_studio", whose versions are years -- so the
        // comparison 1.138.0 <= 2012 came out true and a current VS Code was
        // reported vulnerable to a 2014 Visual Studio bug.
        let cve = CveRecord {
            matches: vec![CpeMatch {
                criteria: "cpe:2.3:a:microsoft:visual_studio:*:*:*:*:*:*:*:*".into(),
                vulnerable: true,
                range: VersionRange {
                    end_including: Some("2012".into()),
                    ..Default::default()
                },
            }],
            ..before_22()
        };

        let m = match_one(
            &program(
                "Microsoft Visual Studio Code",
                Some("1.138.0"),
                Some("Microsoft"),
            ),
            &cve,
            plain(),
        );

        if let Some(m) = m {
            assert_ne!(
                m.verdict,
                Verdict::Vulnerable,
                "a different product in the same family must not be confirmed vulnerable"
            );
            assert_eq!(m.confidence, Confidence::Potential);
        }
    }

    #[test]
    fn a_plugin_advisory_does_not_match_the_standalone_program() {
        // The Git regression. `cpe:2.3:a:jenkins:git:...:jenkins:*:*` describes
        // the Jenkins Git plugin, not Git for Windows.
        let cve = CveRecord {
            matches: vec![CpeMatch {
                criteria: "cpe:2.3:a:jenkins:git:*:*:*:*:*:jenkins:*:*".into(),
                vulnerable: true,
                range: VersionRange {
                    end_including: Some("3.9.0".into()),
                    ..Default::default()
                },
            }],
            ..before_22()
        };

        assert!(
            match_one(
                &program(
                    "Git",
                    Some("2.55.0.3"),
                    Some("The Git Development Community")
                ),
                &cve,
                plain()
            )
            .is_none(),
            "a Jenkins plugin advisory must not match standalone Git"
        );
    }

    #[test]
    fn a_plugin_advisory_still_matches_when_the_platform_is_present() {
        let cve = CveRecord {
            matches: vec![CpeMatch {
                criteria: "cpe:2.3:a:jenkins:git:*:*:*:*:*:jenkins:*:*".into(),
                vulnerable: true,
                range: VersionRange {
                    end_including: Some("3.9.0".into()),
                    ..Default::default()
                },
            }],
            ..before_22()
        };

        assert!(
            match_one(
                &program("Jenkins Git plugin", Some("3.0.0"), Some("Jenkins")),
                &cve,
                plain()
            )
            .is_some(),
            "the advisory should still apply where the platform really is installed"
        );
    }

    #[test]
    fn unrelated_software_does_not_match_at_all() {
        assert!(match_one(
            &program("Epson Event Manager", Some("3.11"), Some("Epson")),
            &before_22(),
            plain()
        )
        .is_none());
    }

    #[test]
    fn a_pinned_cpe_version_matches_exactly() {
        let cve = CveRecord {
            matches: vec![CpeMatch {
                criteria: "cpe:2.3:a:7-zip:7-zip:21.07:*:*:*:*:*:*:*".into(),
                vulnerable: true,
                range: VersionRange::default(),
            }],
            ..before_22()
        };

        assert_eq!(
            match_one(&program("7-Zip", Some("21.07"), None), &cve, plain())
                .unwrap()
                .verdict,
            Verdict::Vulnerable
        );
        assert_eq!(
            match_one(&program("7-Zip", Some("23.01"), None), &cve, plain())
                .unwrap()
                .verdict,
            Verdict::NotVulnerable
        );
    }

    #[test]
    fn confidence_tracks_name_match_quality() {
        // Vendor corroborated by the publisher.
        let strong = match_one(
            &program("7-Zip", Some("21.07"), Some("7-Zip")),
            &before_22(),
            plain(),
        )
        .unwrap();
        assert_eq!(strong.confidence, Confidence::Confirmed);

        // Product name matches, but nothing corroborates the vendor.
        let cve = CveRecord {
            matches: vec![CpeMatch {
                criteria: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*".into(),
                vulnerable: true,
                range: VersionRange {
                    end_excluding: Some("141.0".into()),
                    ..Default::default()
                },
            }],
            ..before_22()
        };
        let moderate = match_one(
            &program("Firefox", Some("140.0"), Some("Unrelated Reseller")),
            &cve,
            plain(),
        )
        .expect("product name alone should still match");
        assert_eq!(moderate.confidence, Confidence::Likely);
    }

    #[test]
    fn a_generic_name_does_not_match_a_hyphenated_product() {
        // A program merely called "Zip" must not inherit 7-Zip's CVEs.
        assert!(match_one(
            &program("Zip", Some("21.07"), Some("Unrelated Co")),
            &before_22(),
            plain()
        )
        .is_none());
    }

    #[test]
    fn kev_and_epss_appear_in_the_evidence() {
        let kev = KevEntry {
            cve_id: "CVE-2023-31102".into(),
            vendor_project: "7-Zip".into(),
            product: "7-Zip".into(),
            vulnerability_name: "n".into(),
            date_added: "2024-01-15".into(),
            short_description: "d".into(),
            required_action: "Apply updates".into(),
            due_date: "2024-02-05".into(),
            known_ransomware_use: "Known".into(),
        };
        let epss = EpssScore {
            epss: 0.42,
            percentile: 0.97,
        };

        let m = match_one(
            &program("7-Zip", Some("21.07"), Some("Igor Pavlov")),
            &before_22(),
            Enrichment {
                kev: Some(&kev),
                epss: Some(epss),
            },
        )
        .unwrap();

        assert!(m.kev.is_some());
        assert!(m.kev.as_ref().unwrap().known_ransomware_use);
        assert!(m.evidence.iter().any(|e| e.contains("actively exploited")));
        assert!(m.evidence.iter().any(|e| e.contains("ransomware")));
        assert!(m.evidence.iter().any(|e| e.contains("EPSS")));
    }

    #[test]
    fn evidence_always_names_the_cpe_and_range() {
        let m = match_one(
            &program("7-Zip", Some("21.07"), None),
            &before_22(),
            plain(),
        )
        .unwrap();
        assert!(m
            .evidence
            .iter()
            .any(|e| e.contains("cpe:2.3:a:7-zip:7-zip")));
        assert_eq!(m.affected_range, "< 22.00");
    }

    #[test]
    fn lookup_keywords_collapse_across_versions() {
        // The point of the keyword: two versions of one product must not cost
        // two lookups against a 5-per-30-seconds budget.
        let a = lookup_keyword(&program(
            "Mozilla Firefox 140.0 (x64 en-US)",
            Some("140.0"),
            None,
        ));
        let b = lookup_keyword(&program(
            "Mozilla Firefox 141.0 (x64 en-US)",
            Some("141.0"),
            None,
        ));
        assert_eq!(a, b);
        assert_eq!(a.as_deref(), Some("mozilla firefox"));
    }

    #[test]
    fn lookup_keywords_keep_hyphens_for_text_search() {
        // "7zip" and "7-zip" return very different results from NVD.
        assert_eq!(
            lookup_keyword(&program("7-Zip 21.07 (x64)", Some("21.07"), None)).as_deref(),
            Some("7-zip")
        );
    }

    #[test]
    fn lookup_keywords_are_capped_in_length() {
        let k = lookup_keyword(&program(
            "Microsoft Visual Studio Community Edition Preview Channel",
            None,
            None,
        ))
        .unwrap();
        assert_eq!(
            k.split(' ').count(),
            3,
            "keyword must stay broad enough to return results"
        );
    }

    #[test]
    fn a_nameless_program_yields_no_keyword() {
        assert_eq!(lookup_keyword(&program("", None, None)), None);
        assert_eq!(lookup_keyword(&program("2026 x64", None, None)), None);
    }
}

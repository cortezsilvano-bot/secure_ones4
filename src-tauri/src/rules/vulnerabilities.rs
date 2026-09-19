//! Rules over the vulnerability assessment.
//!
//! Findings are grouped per program rather than per CVE. A user with an old
//! Adobe install does not need eleven separate alarms about it; they need one
//! that says "update this, here is why, here is the worst of it". The full CVE
//! list stays in the evidence.

use crate::findings::{Confidence, Finding, FindingBuilder, FixRisk, Severity};
use crate::vulnerabilities::assess::VulnerabilityFacts;
use crate::vulnerabilities::matcher::VulnerabilityMatch;

const SOURCE: &str = "vulnerabilities";
const CATEGORY: &str = "Vulnerabilities";

pub fn evaluate(f: &VulnerabilityFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    // --- VULN-001: programs with known vulnerabilities ----------------------
    // Group by program, preserving the worst-first order `assess` established.
    let mut by_program: Vec<(String, Vec<&VulnerabilityMatch>)> = Vec::new();
    for m in &f.vulnerable {
        match by_program
            .iter_mut()
            .find(|(name, _)| *name == m.program_name)
        {
            Some((_, list)) => list.push(m),
            None => by_program.push((m.program_name.clone(), vec![m])),
        }
    }

    for (program, matches) in by_program {
        let worst = matches[0];
        let exploited: Vec<&&VulnerabilityMatch> =
            matches.iter().filter(|m| m.kev.is_some()).collect();
        let ransomware = exploited
            .iter()
            .any(|m| m.kev.as_ref().is_some_and(|k| k.known_ransomware_use));

        let severity = severity_for(worst);

        let version = worst
            .installed_version
            .as_deref()
            .unwrap_or("unknown version");

        // The "why" leads with exploitation status when there is one, because
        // "someone is using this right now" is a different message from
        // "this scored highly".
        let why: &str = if ransomware {
            "At least one of these flaws is being used in ransomware attacks right now. CISA \
             lists it as actively exploited, which means this is not a theoretical risk to \
             weigh up -- it is one being used against people today."
        } else if !exploited.is_empty() {
            "At least one of these flaws is confirmed to be exploited in the wild. CISA lists it \
             in the Known Exploited Vulnerabilities catalogue, so attackers already have working \
             code for it."
        } else {
            "These are publicly documented flaws in the version you have installed. Updating \
             closes them; the details of each are in the evidence below."
        };

        let mut evidence = vec![
            format!("Program: {program}"),
            format!("Installed version: {version}"),
            format!("Vulnerabilities matched: {}", matches.len()),
        ];
        if !exploited.is_empty() {
            evidence.push(format!(
                "Known to be exploited (CISA KEV): {}",
                exploited.len()
            ));
        }
        // Detail the worst handful; the rest are counted.
        for m in matches.iter().take(5) {
            let kev_note = match &m.kev {
                Some(k) if k.known_ransomware_use => " [KEV, ransomware]",
                Some(_) => " [KEV]",
                None => "",
            };
            let epss_note = m
                .epss
                .map(|e| format!(", EPSS {:.1}%", e.as_percent()))
                .unwrap_or_default();
            evidence.push(format!(
                "  {} -- CVSS {} ({}){kev_note}{epss_note}",
                m.cve_id,
                m.cvss_score
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unrated".into()),
                m.cvss_severity.as_deref().unwrap_or("unrated"),
            ));
        }
        if matches.len() > 5 {
            evidence.push(format!("  ... and {} more", matches.len() - 5));
        }
        evidence.push(format!("Matched CPE: {}", worst.matched_criteria));
        evidence.push(format!("Affected versions: {}", worst.affected_range));

        let mut builder = FindingBuilder::new(
            "VULN-001",
            CATEGORY,
            severity,
            &format!("{program} has known security flaws"),
        )
        .what(&format!(
            "{program} {version} is affected by {} publicly documented {}.",
            matches.len(),
            if matches.len() == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            }
        ))
        .why(why)
        .confidence(worst.confidence)
        .asset(&program)
        .evidence(evidence)
        .remediation(
            &format!("Update {program} to the latest version from its official source."),
            FixRisk::Manual,
        )
        .source(SOURCE);

        // Link the worst CVE so the user can read the primary source.
        builder = builder.reference(&format!(
            "https://nvd.nist.gov/vuln/detail/{}",
            worst.cve_id
        ));

        out.push(builder.build());
    }

    // --- VULN-002: the feed data itself is stale ----------------------------
    if f.feed_is_stale {
        let age = f.feed_age_days.unwrap_or_default();
        out.push(
            FindingBuilder::new(
                "VULN-002",
                CATEGORY,
                Severity::Warning,
                "Vulnerability data is out of date",
            )
            .what(&format!(
                "The vulnerability feeds were last refreshed {age} days ago."
            ))
            .why(
                "Results above were checked against data this old. Anything discovered since \
                     will not appear, so a clean result here is weaker than it looks.",
            )
            .confidence(Confidence::Confirmed)
            .evidence(vec![
                "Feeds: NVD CVE API 2.0, CISA KEV, FIRST EPSS".to_string(),
                format!("Last refreshed: {age} day(s) ago"),
            ])
            .remediation(
                "Refresh the vulnerability data from the Vulnerabilities view.",
                FixRisk::Safe,
            )
            .source(SOURCE)
            .build(),
        );
    }

    // --- VULN-004: advisories that could not be resolved either way ---------
    //
    // These are not "probably vulnerable". They are advisories that name the
    // product but give no usable version range -- NVD carries a great many of
    // these for older products -- or software with no version in the registry.
    // Left invisible, the Vulnerabilities tile would read "No issues found",
    // which overstates what was actually established.
    if !f.undetermined.is_empty() {
        // Count per program rather than per advisory: 159 unresolvable Edge
        // advisories are one situation, not 159 of them.
        let mut by_program: Vec<(String, usize)> = Vec::new();
        for m in &f.undetermined {
            match by_program
                .iter_mut()
                .find(|(name, _)| *name == m.program_name)
            {
                Some((_, count)) => *count += 1,
                None => by_program.push((m.program_name.clone(), 1)),
            }
        }
        by_program.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

        let mut evidence = vec![
            format!(
                "Advisories that could not be resolved: {}",
                f.undetermined.len()
            ),
            format!("Programs affected: {}", by_program.len()),
            "Reason: the advisory names the product but states no affected version range, \
             or the program records no version."
                .to_string(),
        ];
        for (name, count) in by_program.iter().take(8) {
            evidence.push(format!("  {name}: {count}"));
        }

        out.push(
            FindingBuilder::new(
                "VULN-004",
                CATEGORY,
                Severity::Attention,
                "Some advisories could not be checked against your software",
            )
            .what(&format!(
                "{} advisories across {} program{} could not be confirmed or ruled out.",
                f.undetermined.len(),
                by_program.len(),
                if by_program.len() == 1 { "" } else { "s" }
            ))
            .why(
                "These are not findings against you. They are advisories that name a program you \
                 have but do not say which versions are affected, so there is nothing to compare \
                 your version against. Most are old entries for products that have since been \
                 replaced. They are listed so that \"no problems found\" means what it says.",
            )
            .confidence(Confidence::Confirmed)
            .evidence(evidence)
            .remediation(
                "No action needed. Keeping the affected programs up to date covers these anyway.",
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
    }

    // --- VULN-003: coverage gap --------------------------------------------
    // Only worth raising when a meaningful share of the machine went unchecked.
    if f.programs_total > 0 {
        let unchecked = f.programs_never_checked;
        let proportion = unchecked as f64 / f.programs_total as f64;

        if proportion >= 0.25 && unchecked >= 3 {
            out.push(
                FindingBuilder::new(
                    "VULN-003",
                    CATEGORY,
                    Severity::Attention,
                    "Some programs have not been checked",
                )
                .what(&format!(
                    "{unchecked} of {} installed programs have not been checked against the vulnerability feeds.",
                    f.programs_total
                ))
                .why(
                    "Checking each program costs a request to a rate-limited public service, so a \
                     refresh works through them gradually. Until it finishes, nothing is known \
                     about these programs either way.",
                )
                .confidence(Confidence::Confirmed)
                .evidence(vec![
                    format!("Programs installed: {}", f.programs_total),
                    format!("Programs checked: {}", f.programs_checked()),
                    format!("Programs never looked up: {unchecked}"),
                    format!("Programs with no version recorded: {}", f.programs_without_version),
                ])
                .remediation("Run a vulnerability data refresh to continue working through them.", FixRisk::Safe)
                .source(SOURCE)
                .build(),
            );
        }
    }

    out
}

/// Severity for one matched vulnerability.
///
/// Known exploitation dominates. A CVSS 6.5 that attackers are actively using
/// is a more urgent problem than a 9.8 that nobody has ever weaponised, and
/// ranking purely by score gets that backwards.
fn severity_for(m: &VulnerabilityMatch) -> Severity {
    // Any KEV listing is Critical regardless of score. Ransomware use does not
    // raise it further -- there is nothing above Critical -- but it changes the
    // wording the user sees, which is handled in `evaluate`.
    if m.kev.is_some() {
        return Severity::Critical;
    }

    match m.cvss_score {
        Some(s) if s >= 9.0 => Severity::Critical,
        Some(s) if s >= 7.0 => Severity::Warning,
        Some(s) if s >= 4.0 => Severity::Attention,
        Some(_) => Severity::Attention,
        // No score at all: it is a real CVE match, so it is not nothing, but
        // there is no basis to call it severe.
        None => Severity::Attention,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::feeds::epss::EpssScore;
    use crate::vulnerabilities::matcher::{KevSummary, Verdict};

    fn m(program: &str, cve: &str, score: Option<f64>, kev: Option<bool>) -> VulnerabilityMatch {
        VulnerabilityMatch {
            program_name: program.into(),
            installed_version: Some("21.07".into()),
            cve_id: cve.into(),
            verdict: Verdict::Vulnerable,
            confidence: Confidence::Confirmed,
            cvss_score: score,
            cvss_severity: score.map(|s| {
                if s >= 9.0 {
                    "CRITICAL".into()
                } else {
                    "HIGH".into()
                }
            }),
            description: "d".into(),
            kev: kev.map(|ransomware| KevSummary {
                date_added: "2024-01-15".into(),
                known_ransomware_use: ransomware,
                required_action: "Apply updates".into(),
            }),
            epss: Some(EpssScore {
                epss: 0.5,
                percentile: 0.98,
            }),
            matched_criteria: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*".into(),
            affected_range: "< 22.00".into(),
            evidence: vec![],
        }
    }

    fn facts(vulnerable: Vec<VulnerabilityMatch>) -> VulnerabilityFacts {
        VulnerabilityFacts {
            vulnerable,
            undetermined: vec![],
            programs_total: 10,
            programs_without_version: 0,
            programs_never_checked: 0,
            kev_entries: 1713,
            feed_age_days: Some(0),
            feed_is_stale: false,
            evidence: vec![],
            collected_at: "2026-09-17T20:00:00+00:00".into(),
        }
    }

    #[test]
    fn a_clean_assessment_produces_no_findings() {
        assert!(evaluate(&facts(vec![])).is_empty());
    }

    #[test]
    fn one_finding_per_program_not_per_cve() {
        // Eleven CVEs in one old Adobe install must not become eleven alarms.
        let matches = (0..11)
            .map(|i| m("Adobe Reader", &format!("CVE-2024-{i:05}"), Some(7.5), None))
            .collect();

        let found = evaluate(&facts(matches));
        assert_eq!(found.len(), 1);
        assert!(found[0].evidence.iter().any(|e| e.contains("and 6 more")));
    }

    #[test]
    fn separate_programs_get_separate_findings() {
        let found = evaluate(&facts(vec![
            m("7-Zip", "CVE-2023-31102", Some(7.8), None),
            m("Adobe Reader", "CVE-2024-00001", Some(7.5), None),
        ]));
        assert_eq!(found.len(), 2);
        assert_ne!(found[0].id, found[1].id, "per-asset ids must differ");
    }

    #[test]
    fn exploitation_outranks_a_higher_score() {
        // The core judgement of this module.
        let exploited = severity_for(&m("p", "CVE-1", Some(6.5), Some(false)));
        let unexploited_critical = severity_for(&m("p", "CVE-2", Some(9.8), None));
        assert_eq!(exploited, Severity::Critical);
        assert_eq!(unexploited_critical, Severity::Critical);

        let exploited_low = severity_for(&m("p", "CVE-3", Some(4.0), Some(true)));
        let unexploited_high = severity_for(&m("p", "CVE-4", Some(8.0), None));
        assert_eq!(exploited_low, Severity::Critical);
        assert_eq!(unexploited_high, Severity::Warning);
    }

    #[test]
    fn severity_follows_cvss_when_nothing_is_exploited() {
        assert_eq!(
            severity_for(&m("p", "c", Some(9.5), None)),
            Severity::Critical
        );
        assert_eq!(
            severity_for(&m("p", "c", Some(7.5), None)),
            Severity::Warning
        );
        assert_eq!(
            severity_for(&m("p", "c", Some(5.0), None)),
            Severity::Attention
        );
        assert_eq!(severity_for(&m("p", "c", None, None)), Severity::Attention);
    }

    #[test]
    fn ransomware_use_is_called_out_in_plain_language() {
        let found = evaluate(&facts(vec![m(
            "7-Zip",
            "CVE-2023-31102",
            Some(7.8),
            Some(true),
        )]));
        assert!(found[0].why_it_matters.contains("ransomware"));
        assert!(found[0].evidence.iter().any(|e| e.contains("ransomware")));
    }

    #[test]
    fn evidence_cites_cve_cvss_and_the_matched_cpe() {
        let found = evaluate(&facts(vec![m("7-Zip", "CVE-2023-31102", Some(7.8), None)]));
        let ev = &found[0].evidence;
        assert!(ev.iter().any(|e| e.contains("CVE-2023-31102")));
        assert!(ev.iter().any(|e| e.contains("CVSS 7.8")));
        assert!(ev.iter().any(|e| e.contains("cpe:2.3:a:7-zip")));
        assert!(ev.iter().any(|e| e.contains("< 22.00")));
        assert!(!found[0].references.is_empty(), "should link to NVD");
    }

    #[test]
    fn unresolvable_advisories_are_surfaced_not_hidden() {
        // Without this, a machine with 166 unresolvable advisories would show
        // "No issues found", which claims more than was established.
        let mut f = facts(vec![]);
        f.undetermined = vec![
            m("Microsoft Edge", "CVE-2016-7200", Some(8.8), None),
            m("Microsoft Edge", "CVE-2016-7201", Some(8.8), None),
            m("Google Chrome", "CVE-2015-1234", Some(7.0), None),
        ];

        let found = evaluate(&f);
        let v = found
            .iter()
            .find(|x| x.rule_id == "VULN-004")
            .expect("VULN-004");

        assert_eq!(
            v.severity,
            Severity::Attention,
            "unresolvable is not the same as bad"
        );
        // Grouped by program: two programs, not three advisories.
        assert!(v
            .evidence
            .iter()
            .any(|e| e.contains("Programs affected: 2")));
        assert!(v.evidence.iter().any(|e| e.contains("Microsoft Edge: 2")));
        // The wording must not imply the user is vulnerable.
        assert!(v.why_it_matters.contains("not findings against you"));
    }

    #[test]
    fn nothing_undetermined_means_no_such_finding() {
        let ids: Vec<String> = evaluate(&facts(vec![]))
            .into_iter()
            .map(|x| x.rule_id)
            .collect();
        assert!(!ids.contains(&"VULN-004".to_string()));
    }

    #[test]
    fn stale_feeds_are_reported() {
        let mut f = facts(vec![]);
        f.feed_is_stale = true;
        f.feed_age_days = Some(30);

        let found = evaluate(&f);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "VULN-002");
    }

    #[test]
    fn a_large_coverage_gap_is_reported() {
        let mut f = facts(vec![]);
        f.programs_total = 48;
        f.programs_never_checked = 40;

        let ids: Vec<String> = evaluate(&f).into_iter().map(|x| x.rule_id).collect();
        assert!(ids.contains(&"VULN-003".to_string()));
    }

    #[test]
    fn a_small_coverage_gap_is_not_worth_an_alarm() {
        let mut f = facts(vec![]);
        f.programs_total = 48;
        f.programs_never_checked = 2;

        let ids: Vec<String> = evaluate(&f).into_iter().map(|x| x.rule_id).collect();
        assert!(!ids.contains(&"VULN-003".to_string()));
    }

    #[test]
    fn every_finding_carries_evidence() {
        let mut f = facts(vec![m("7-Zip", "CVE-2023-31102", Some(7.8), Some(true))]);
        f.feed_is_stale = true;
        f.programs_never_checked = 40;
        f.programs_total = 48;

        let found = evaluate(&f);
        assert!(found.len() >= 3);
        for finding in found {
            assert!(
                !finding.evidence.is_empty(),
                "{} has no evidence",
                finding.rule_id
            );
            assert!(!finding.why_it_matters.is_empty());
            assert_eq!(finding.source, SOURCE);
        }
    }
}

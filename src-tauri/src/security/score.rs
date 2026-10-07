//! The security score.
//!
//! Deterministic and fully itemised: the number is only ever the sum of visible
//! deductions, each naming the finding that caused it. No model produces it, no
//! weighting is hidden, and re-running on unchanged facts always gives the same
//! answer.
//!
//! The harder design constraint is coverage. A score computed from two working
//! checks out of nine is not a 100 -- it is a 100 over a tenth of the machine,
//! and presenting it as the former is the exact dishonesty this codebase
//! exists to avoid. So the score travels with its coverage and the names of
//! what did not report, and refuses to exist at all when nothing did.

use serde::{Deserialize, Serialize};

use crate::findings::{Finding, Severity};

/// How much of the intended checking actually completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// Every module reported.
    Complete,
    /// Some modules reported; the score describes only those.
    Partial,
    /// Too little reported for the score to mean anything.
    Incomplete,
}

/// One itemised deduction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreLine {
    /// Negative. Shown to the user verbatim, e.g. "-12".
    pub delta: i32,
    pub reason: String,
    pub finding_id: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityScore {
    /// `None` when coverage is too thin to justify a number. The UI must render
    /// this as "Not enough data", never as zero and never as a hundred.
    pub score: Option<u32>,
    pub coverage: Coverage,
    /// Human-readable names of modules that did not report.
    pub gaps: Vec<String>,
    /// Every deduction, worst first.
    pub lines: Vec<ScoreLine>,
    pub modules_reporting: usize,
    pub modules_total: usize,
}

/// Base deduction per severity, before confidence weighting.
///
/// Chosen so that one Critical is worse than any pile of Attentions: a single
/// exploited hole should dominate a long tail of housekeeping.
fn base_deduction(severity: Severity) -> i32 {
    match severity {
        Severity::Critical => 12,
        Severity::Warning => 7,
        Severity::Attention => 3,
        Severity::Safe => 0,
    }
}

/// Compute the score from findings and coverage.
///
/// `modules_reporting` / `modules_total` describe how much of the machine was
/// actually inspected; `gaps` names the rest.
pub fn compute(
    findings: &[Finding],
    modules_reporting: usize,
    modules_total: usize,
    gaps: Vec<String>,
) -> SecurityScore {
    let coverage = if modules_reporting == 0 {
        Coverage::Incomplete
    } else if modules_reporting >= modules_total {
        Coverage::Complete
    } else {
        Coverage::Partial
    };

    let mut lines: Vec<ScoreLine> = findings
        .iter()
        .filter(|f| base_deduction(f.severity) > 0)
        .map(|f| {
            // Weight by confidence so a "potential" finding cannot sink the
            // score as hard as a confirmed one.
            let weighted =
                (base_deduction(f.severity) as f32 * f.confidence.as_f32()).round() as i32;
            ScoreLine {
                delta: -weighted.max(1),
                reason: f.title.clone(),
                finding_id: f.id.clone(),
                severity: f.severity,
            }
        })
        .collect();

    // Worst first, so the UI can show the top few and mean it.
    lines.sort_by_key(|a| a.delta);

    let score = if coverage == Coverage::Incomplete {
        None
    } else {
        let total: i32 = lines.iter().map(|l| l.delta).sum();
        Some((100 + total).clamp(0, 100) as u32)
    };

    SecurityScore {
        score,
        coverage,
        gaps,
        lines,
        modules_reporting,
        modules_total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Confidence, FindingBuilder};

    fn finding(rule: &str, severity: Severity) -> Finding {
        FindingBuilder::new(rule, "Test", severity, rule)
            .what("w")
            .why("y")
            .evidence(["e".to_string()])
            .build()
    }

    #[test]
    fn a_clean_complete_scan_is_one_hundred() {
        let s = compute(&[], 9, 9, vec![]);
        assert_eq!(s.score, Some(100));
        assert_eq!(s.coverage, Coverage::Complete);
        assert!(s.lines.is_empty());
    }

    #[test]
    fn nothing_reporting_yields_no_score_at_all() {
        // The critical case: zero coverage must never render as a perfect score.
        let s = compute(&[], 0, 9, vec!["Firewall".into()]);
        assert_eq!(s.score, None);
        assert_eq!(s.coverage, Coverage::Incomplete);
    }

    #[test]
    fn partial_coverage_still_scores_but_says_so() {
        let s = compute(&[], 2, 9, vec!["Router".into(), "Devices".into()]);
        assert_eq!(s.coverage, Coverage::Partial);
        assert_eq!(s.score, Some(100));
        assert_eq!(s.gaps.len(), 2);
    }

    #[test]
    fn deductions_are_itemised_and_sum_to_the_score() {
        let s = compute(
            &[
                finding("A", Severity::Critical),
                finding("B", Severity::Warning),
            ],
            9,
            9,
            vec![],
        );
        let total: i32 = s.lines.iter().map(|l| l.delta).sum();
        assert_eq!(s.score, Some((100 + total) as u32));
        assert_eq!(s.score, Some(100 - 12 - 7));
    }

    #[test]
    fn worst_deduction_is_listed_first() {
        let s = compute(
            &[
                finding("A", Severity::Attention),
                finding("B", Severity::Critical),
                finding("C", Severity::Warning),
            ],
            9,
            9,
            vec![],
        );
        assert_eq!(s.lines[0].severity, Severity::Critical);
        assert_eq!(s.lines[2].severity, Severity::Attention);
    }

    #[test]
    fn confidence_softens_a_deduction() {
        let confirmed = FindingBuilder::new("A", "T", Severity::Critical, "A")
            .what("w")
            .evidence(["e".to_string()])
            .confidence(Confidence::Confirmed)
            .build();
        let potential = FindingBuilder::new("B", "T", Severity::Critical, "B")
            .what("w")
            .evidence(["e".to_string()])
            .confidence(Confidence::Potential)
            .build();

        let strong = compute(std::slice::from_ref(&confirmed), 9, 9, vec![])
            .score
            .unwrap();
        let weak = compute(std::slice::from_ref(&potential), 9, 9, vec![])
            .score
            .unwrap();
        assert!(weak > strong, "a merely potential finding must cost less");
    }

    #[test]
    fn score_never_goes_below_zero() {
        let many: Vec<Finding> = (0..50)
            .map(|i| finding(&format!("R-{i}"), Severity::Critical))
            .collect();
        assert_eq!(compute(&many, 9, 9, vec![]).score, Some(0));
    }

    #[test]
    fn safe_findings_do_not_deduct() {
        let s = compute(&[finding("A", Severity::Safe)], 9, 9, vec![]);
        assert_eq!(s.score, Some(100));
        assert!(s.lines.is_empty(), "a Safe finding is not a deduction");
    }

    #[test]
    fn one_critical_outweighs_three_attentions() {
        let crit = compute(&[finding("A", Severity::Critical)], 9, 9, vec![])
            .score
            .unwrap();
        let attn = compute(
            &[
                finding("A", Severity::Attention),
                finding("B", Severity::Attention),
                finding("C", Severity::Attention),
            ],
            9,
            9,
            vec![],
        )
        .score
        .unwrap();
        assert!(crit < attn);
    }
}

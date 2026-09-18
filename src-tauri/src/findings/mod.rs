//! The Finding model: what the rules layer produces and the UI renders.

use serde::{Deserialize, Serialize};

/// How much the user should care. Ordered, so a set of findings can be reduced
/// to the worst one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Safe,
    Attention,
    Warning,
    Critical,
}

impl Severity {
    pub fn worst(items: impl IntoIterator<Item = Severity>) -> Option<Severity> {
        items.into_iter().max()
    }
}

/// How sure we are the finding is real, distinct from how bad it would be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Directly observed from an authoritative source.
    Confirmed,
    /// Strong indirect evidence.
    Likely,
    /// Consistent with the evidence but not established.
    Potential,
}

impl Confidence {
    /// Numeric form for the UI and the score engine.
    pub fn as_f32(self) -> f32 {
        match self {
            Confidence::Confirmed => 1.0,
            Confidence::Likely => 0.8,
            Confidence::Potential => 0.5,
        }
    }
}

/// How dangerous applying the fix automatically would be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixRisk {
    /// Reversible, no side effects beyond the setting itself.
    Safe,
    /// Could disrupt something the user relies on; needs a backup first.
    Caution,
    /// We will not do this for you; we explain how.
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Resolved,
    Dismissed,
    Allowlisted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable across scans: the same problem keeps the same id, so history and
    /// dismissals survive a re-scan.
    pub id: String,
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub what_happened: String,
    pub why_it_matters: String,
    pub affected_asset: Option<String>,
    pub remediation: Option<String>,
    pub auto_fix: bool,
    pub auto_fix_risk: Option<FixRisk>,
    /// Verbatim observations. Never prose, never a claim about a check that
    /// did not run.
    pub evidence: Vec<String>,
    pub references: Vec<String>,
    pub status: FindingStatus,
    pub source: String,
}

impl Finding {
    pub fn id_for(rule_id: &str, asset: Option<&str>) -> String {
        // FNV-1a: small, deterministic, and stable across Rust releases --
        // unlike DefaultHasher, whose output is explicitly not guaranteed.
        let key = format!("{rule_id}|{}", asset.unwrap_or("-"));
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in key.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{}-{:012x}", rule_id, hash & 0xffff_ffff_ffff)
    }
}

/// Builder keeping rule definitions readable.
pub struct FindingBuilder {
    finding: Finding,
}

impl FindingBuilder {
    pub fn new(rule_id: &str, category: &str, severity: Severity, title: &str) -> Self {
        Self {
            finding: Finding {
                id: Finding::id_for(rule_id, None),
                rule_id: rule_id.to_string(),
                category: category.to_string(),
                severity,
                confidence: Confidence::Confirmed,
                title: title.to_string(),
                what_happened: String::new(),
                why_it_matters: String::new(),
                affected_asset: None,
                remediation: None,
                auto_fix: false,
                auto_fix_risk: None,
                evidence: Vec::new(),
                references: Vec::new(),
                status: FindingStatus::Open,
                source: String::new(),
            },
        }
    }

    pub fn what(mut self, text: &str) -> Self {
        self.finding.what_happened = text.to_string();
        self
    }

    pub fn why(mut self, text: &str) -> Self {
        self.finding.why_it_matters = text.to_string();
        self
    }

    pub fn confidence(mut self, c: Confidence) -> Self {
        self.finding.confidence = c;
        self
    }

    pub fn asset(mut self, asset: &str) -> Self {
        self.finding.affected_asset = Some(asset.to_string());
        self.finding.id = Finding::id_for(&self.finding.rule_id, Some(asset));
        self
    }

    pub fn remediation(mut self, text: &str, auto_fix: bool, risk: FixRisk) -> Self {
        self.finding.remediation = Some(text.to_string());
        self.finding.auto_fix = auto_fix;
        self.finding.auto_fix_risk = Some(risk);
        self
    }

    pub fn evidence(mut self, lines: impl IntoIterator<Item = String>) -> Self {
        self.finding.evidence.extend(lines);
        self
    }

    pub fn reference(mut self, url: &str) -> Self {
        self.finding.references.push(url.to_string());
        self
    }

    pub fn source(mut self, source: &str) -> Self {
        self.finding.source = source.to_string();
        self
    }

    pub fn build(self) -> Finding {
        debug_assert!(
            !self.finding.what_happened.is_empty(),
            "finding needs a what"
        );
        debug_assert!(!self.finding.evidence.is_empty(), "finding needs evidence");
        self.finding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_worst_last() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Attention);
        assert!(Severity::Attention > Severity::Safe);
        assert_eq!(
            Severity::worst([Severity::Safe, Severity::Critical, Severity::Attention]),
            Some(Severity::Critical)
        );
        assert_eq!(Severity::worst([]), None);
    }

    #[test]
    fn ids_are_stable_and_distinct() {
        let a = Finding::id_for("DEF-001", None);
        assert_eq!(
            a,
            Finding::id_for("DEF-001", None),
            "id must be reproducible"
        );
        assert_ne!(a, Finding::id_for("DEF-002", None));
        assert_ne!(
            Finding::id_for("SW-001", Some("7-Zip")),
            Finding::id_for("SW-001", Some("Firefox")),
            "same rule on different assets must not collide"
        );
        assert!(a.starts_with("DEF-001-"));
    }

    #[test]
    fn setting_an_asset_rebinds_the_id() {
        let f = FindingBuilder::new("SW-001", "Software", Severity::Warning, "t")
            .what("w")
            .evidence(["e".into()])
            .asset("7-Zip")
            .build();
        assert_eq!(f.id, Finding::id_for("SW-001", Some("7-Zip")));
    }
}

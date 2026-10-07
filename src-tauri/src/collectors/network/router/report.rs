//! Atomic, passive projection of one router snapshot and its findings.
use super::RouterFacts;
use crate::{findings::Finding, security::Known};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterReport {
    #[serde(default)]
    pub history_error: Option<String>,
    pub facts: RouterFacts,
    pub findings: Vec<Finding>,
}

pub fn from_snapshot(snapshot: Known<RouterFacts>, generation: u64) -> Known<RouterReport> {
    match snapshot {
        Known::Known(facts) => {
            if facts
                .target
                .as_ref()
                .map(|target| target.network_generation)
                != Some(generation)
            {
                return Known::Unavailable(
                    "Router results do not belong to the current network context.".into(),
                );
            }
            let findings = crate::rules::router::evaluate(&facts);
            Known::Known(RouterReport {
                facts,
                findings,
                history_error: None,
            })
        }
        other => other.map(|_| unreachable!("known snapshots handled above")),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{target, AdminPort};
    use super::*;

    #[test]
    fn report_binds_findings_and_facts_to_the_same_snapshot() {
        let target = target::candidates(&target::fixture(), 7).remove(0);
        let facts = RouterFacts {
            target: Some(target.clone()),
            admin_ports: vec![AdminPort::tcp_open(22)],
            evidence: vec!["Synthetic gateway TCP acceptance on port 22".into()],
            ..Default::default()
        };
        let report = from_snapshot(Known::Known(facts), 7);
        let report = report.value().unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].affected_asset, Some(target.asset()));
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["facts"]["target"]["networkGeneration"], 7);
        assert_eq!(json["findings"][0]["ruleId"], "RTR-003");
    }

    #[test]
    fn stale_and_unbound_snapshots_cannot_publish_findings() {
        let mut facts = RouterFacts::default();
        assert!(!from_snapshot(Known::Known(facts.clone()), 1).is_known());
        facts.target = Some(target::candidates(&target::fixture(), 1).remove(0));
        assert!(!from_snapshot(Known::Known(facts), 2).is_known());
    }

    #[test]
    fn unknown_status_is_preserved_without_inventing_a_clean_report() {
        assert!(matches!(
            from_snapshot(Known::NotScanned, 1),
            Known::NotScanned
        ));
        assert!(matches!(
            from_snapshot(Known::PermissionRequired("Confirm scan".into()), 1),
            Known::PermissionRequired(_)
        ));
        assert!(matches!(
            from_snapshot(Known::Unavailable("Expired".into()), 1),
            Known::Unavailable(_)
        ));
    }
}

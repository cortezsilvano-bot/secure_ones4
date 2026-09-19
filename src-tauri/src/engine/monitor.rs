//! Background monitoring.
//!
//! SENTRY watches while it is open. It does not install a privileged Windows
//! service, which is a deliberate limit rather than an unfinished feature: a
//! service running as SYSTEM on a home machine is a large, permanent piece of
//! attack surface, and a home user has no way to audit it. The UI says plainly
//! that monitoring happens while the app is running.
//!
//! The rules that matter here are about *not* becoming noise:
//!
//!   * Only a finding that is genuinely new is notified. A problem the user has
//!     already seen is not re-announced on every scan.
//!   * Only Critical and Warning findings notify at all. An Attention-level
//!     item waits for the user to open the app.
//!   * Notifications are rate-limited, and several at once collapse into one.
//!
//! A security tool that notifies too often gets muted, and a muted tool is
//! worse than no tool, because the user believes they are covered.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::findings::{Finding, Severity};

/// How often a background scan runs.
///
/// Six hours is a compromise: frequent enough to catch a change on the day it
/// happens, rare enough that the machine is not doing security work while
/// someone is trying to use it.
pub const SCAN_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// No more than one notification in this window, however many scans run.
pub const NOTIFY_COOLDOWN: Duration = Duration::from_secs(60 * 60);

/// What the user should be told about after a background scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub title: String,
    pub body: String,
}

/// Decides what, if anything, to notify about.
///
/// Holds the ids already announced so the same problem is never reported twice.
pub struct Notifier {
    announced: HashSet<String>,
    last_sent: Option<Instant>,
    /// First run seeds the known set without notifying: everything is "new" the
    /// first time, and a burst of notifications the moment the app opens is
    /// exactly the behaviour that gets it muted.
    seeded: bool,
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Notifier {
    pub fn new() -> Notifier {
        Notifier {
            announced: HashSet::new(),
            last_sent: None,
            seeded: false,
        }
    }

    /// Seed from findings already in the store at startup.
    ///
    /// Without this the notifier would spend its first background scan learning
    /// what already existed, so nothing could be announced until the second one
    /// -- half a day after the app opened. Seeding from what the user has
    /// already seen makes the very next scan able to report something new.
    pub fn seed_from(ids: impl IntoIterator<Item = String>) -> Notifier {
        Notifier {
            announced: ids.into_iter().collect(),
            last_sent: None,
            seeded: true,
        }
    }

    /// Consider a completed scan's findings.
    ///
    /// Returns `None` when there is nothing worth interrupting the user for.
    pub fn consider(&mut self, findings: &[Finding]) -> Option<Notification> {
        self.consider_at(findings, Instant::now())
    }

    /// Testable form: the caller supplies "now".
    pub fn consider_at(&mut self, findings: &[Finding], now: Instant) -> Option<Notification> {
        let worth_telling: Vec<&Finding> = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::Warning))
            .collect();

        // First pass records what already existed without announcing it.
        if !self.seeded {
            self.seeded = true;
            for finding in &worth_telling {
                self.announced.insert(finding.id.clone());
            }
            return None;
        }

        let fresh: Vec<&&Finding> = worth_telling
            .iter()
            .filter(|f| !self.announced.contains(&f.id))
            .collect();

        if fresh.is_empty() {
            return None;
        }

        // Record them regardless of whether the cooldown allows a notification,
        // so a suppressed item is not announced later as though it were new.
        for finding in &fresh {
            self.announced.insert(finding.id.clone());
        }

        if let Some(last) = self.last_sent {
            if now.duration_since(last) < NOTIFY_COOLDOWN {
                return None;
            }
        }

        self.last_sent = Some(now);

        let worst = fresh
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Warning);

        // Several at once collapse into one notification.
        let (title, body) = if fresh.len() == 1 {
            let finding = fresh[0];
            (
                match worst {
                    Severity::Critical => "SENTRY found something serious",
                    _ => "SENTRY found something new",
                }
                .to_string(),
                finding.title.clone(),
            )
        } else {
            (
                format!(
                    "SENTRY found {} new {}",
                    fresh.len(),
                    if worst == Severity::Critical {
                        "problems"
                    } else {
                        "things to check"
                    }
                ),
                fresh
                    .iter()
                    .take(3)
                    .map(|f| f.title.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        };

        Some(Notification { title, body })
    }

    /// A finding that has gone away is forgotten, so if it returns later it
    /// counts as new again.
    pub fn forget_resolved(&mut self, current: &[Finding]) {
        let present: HashSet<&str> = current.iter().map(|f| f.id.as_str()).collect();
        self.announced.retain(|id| present.contains(id.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::FindingBuilder;

    fn finding(rule: &str, severity: Severity, title: &str) -> Finding {
        FindingBuilder::new(rule, "Test", severity, title)
            .what("w")
            .evidence(["e".to_string()])
            .build()
    }

    #[test]
    fn the_first_scan_never_notifies() {
        // Otherwise opening the app fires a notification for every pre-existing
        // problem at once.
        let mut notifier = Notifier::new();
        let found = [finding("A", Severity::Critical, "Something bad")];
        assert_eq!(notifier.consider(&found), None);
    }

    #[test]
    fn seeding_from_the_store_lets_the_first_scan_notify() {
        // A finding already in the store is known; a different one is new.
        let mut notifier = Notifier::seed_from([Finding::id_for("A", None)]);

        let known = [finding("A", Severity::Critical, "Already seen")];
        assert_eq!(notifier.consider(&known), None);

        let plus_new = [
            finding("A", Severity::Critical, "Already seen"),
            finding("B", Severity::Critical, "Brand new"),
        ];
        let notification = notifier
            .consider(&plus_new)
            .expect("the new one should notify");
        assert_eq!(notification.body, "Brand new");
    }

    #[test]
    fn a_genuinely_new_finding_notifies() {
        let mut notifier = Notifier::new();
        notifier.consider(&[]);

        let found = [finding(
            "A",
            Severity::Critical,
            "Real-time protection is off",
        )];
        let notification = notifier.consider(&found).expect("should notify");

        assert!(notification.title.contains("serious"));
        assert_eq!(notification.body, "Real-time protection is off");
    }

    #[test]
    fn the_same_finding_is_never_announced_twice() {
        let mut notifier = Notifier::new();
        notifier.consider(&[]);

        let found = [finding("A", Severity::Critical, "Something bad")];
        assert!(notifier.consider(&found).is_some());
        assert_eq!(
            notifier.consider(&found),
            None,
            "a problem the user has already been told about must stay quiet"
        );
    }

    #[test]
    fn attention_level_findings_do_not_interrupt() {
        let mut notifier = Notifier::new();
        notifier.consider(&[]);

        let found = [finding("A", Severity::Attention, "One device not reviewed")];
        assert_eq!(notifier.consider(&found), None);
    }

    #[test]
    fn the_cooldown_suppresses_a_second_notification() {
        let start = Instant::now();
        let mut notifier = Notifier::new();
        notifier.consider_at(&[], start);

        let first = [finding("A", Severity::Critical, "First")];
        assert!(notifier.consider_at(&first, start).is_some());

        // A different new finding, ten minutes later.
        let second = [
            finding("A", Severity::Critical, "First"),
            finding("B", Severity::Critical, "Second"),
        ];
        assert_eq!(
            notifier.consider_at(&second, start + Duration::from_secs(600)),
            None,
            "a second notification inside the cooldown must be suppressed"
        );
    }

    #[test]
    fn a_suppressed_finding_is_not_announced_later_as_new() {
        // The subtle one: if the cooldown swallows a finding, it must not
        // resurface as though it had just appeared.
        let start = Instant::now();
        let mut notifier = Notifier::new();
        notifier.consider_at(&[], start);

        assert!(notifier
            .consider_at(&[finding("A", Severity::Critical, "First")], start)
            .is_some());

        let both = [
            finding("A", Severity::Critical, "First"),
            finding("B", Severity::Critical, "Second"),
        ];
        // Suppressed by the cooldown...
        assert!(notifier
            .consider_at(&both, start + Duration::from_secs(600))
            .is_none());
        // ...and still not announced once the cooldown has passed, because the
        // user can see it in the app and it is no longer news.
        assert!(notifier
            .consider_at(&both, start + NOTIFY_COOLDOWN + Duration::from_secs(60))
            .is_none());
    }

    #[test]
    fn several_new_findings_collapse_into_one_notification() {
        let start = Instant::now();
        let mut notifier = Notifier::new();
        notifier.consider_at(&[], start);

        let found = [
            finding("A", Severity::Critical, "First"),
            finding("B", Severity::Warning, "Second"),
            finding("C", Severity::Warning, "Third"),
        ];

        let notification = notifier.consider_at(&found, start).expect("should notify");
        assert!(notification.title.contains('3'));
        assert!(notification.body.contains("First"));
    }

    #[test]
    fn a_resolved_finding_counts_as_new_if_it_comes_back() {
        let start = Instant::now();
        let mut notifier = Notifier::new();
        notifier.consider_at(&[], start);

        let found = [finding("A", Severity::Critical, "Firewall is off")];
        assert!(notifier.consider_at(&found, start).is_some());

        // The user fixes it.
        notifier.forget_resolved(&[]);

        // It comes back later; that is worth telling them about again.
        assert!(notifier
            .consider_at(&found, start + NOTIFY_COOLDOWN + Duration::from_secs(60))
            .is_some());
    }

    #[test]
    fn the_scan_interval_is_not_punishing() {
        assert!(SCAN_INTERVAL >= Duration::from_secs(60 * 60));
        assert!(NOTIFY_COOLDOWN >= Duration::from_secs(30 * 60));
    }
}

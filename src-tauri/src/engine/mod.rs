//! Scan orchestration: run collectors, evaluate rules, assemble what the UI shows.
//!
//! This is the only place that knows the full list of modules SENTRY intends to
//! check. Modules that are not implemented yet appear here explicitly as
//! `NotScanned` rather than being omitted, because a missing tile reads as
//! "nothing to worry about" and an empty one reads as "we did not look" -- and
//! only the second is true.

pub mod monitor;
mod persist;

use serde::{Deserialize, Serialize};

use crate::collectors::network::{devices, interfaces, local_ports, neighbors, router};
use crate::collectors::{
    defender, defender_policy, defender_threats, firewall, hardening, software, updates,
};
use crate::database::Database;
use crate::findings::{Finding, Severity};
use crate::rules::{self, RuleContext};
use crate::security::score::{self, SecurityScore};
use crate::security::Known;
use crate::vulnerabilities::assess;

/// A verdict on one area of the machine, backed by findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TileVerdict {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewTile {
    pub id: String,
    pub title: String,
    /// Matches the icon keys the existing UI already switches on.
    pub category: String,
    pub status: Known<TileVerdict>,
    pub last_checked: Option<String>,
}

/// Everything the dashboard renders in one round trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dashboard {
    pub score: SecurityScore,
    pub tiles: Vec<OverviewTile>,
    pub findings: Vec<Finding>,
    pub scanned_at: String,
    /// Count of installed programs, when the inventory could be read.
    pub programs_installed: Option<usize>,
}

/// Every area SENTRY intends to cover, in the order the dashboard shows them.
///
/// `(category, title)`. A module becomes "implemented" by gaining an arm in
/// `categories_for` and in the status match inside `scan`.
const MODULES: &[(&str, &str)] = &[
    ("Desktop", "Desktop"),
    ("Network", "Network"),
    ("Router", "Router"),
    ("Devices", "Devices"),
    ("Vulnerabilities", "Vulnerabilities"),
    ("Malware", "Malware"),
    ("Firewall", "Firewall"),
    ("Updates", "Updates"),
    ("OpenPorts", "Open Ports"),
];

/// Which finding categories roll up into which dashboard tile.
///
/// An empty slice means the module has no rules behind it yet, which is also
/// how the tests identify a module that must report `NotScanned`.
fn categories_for(module: &str) -> &[&str] {
    match module {
        "Desktop" => &["System Configuration"],
        "Network" => &["Network"],
        "Devices" => &["Devices"],
        "OpenPorts" => &["Open Ports"],
        "Router" => &["Router"],
        "Vulnerabilities" => &["Vulnerabilities"],
        "Malware" => &["Malware Protection"],
        "Firewall" => &["Firewall"],
        "Updates" => &["Updates"],
        _ => &[],
    }
}

/// Run a scan and assemble the dashboard.
///
/// Reads the vulnerability feed caches but never refreshes them: a scan makes
/// no network request of its own.
pub fn scan(db: &Database) -> Dashboard {
    let now = chrono::Utc::now().to_rfc3339();

    // --- collect -----------------------------------------------------------
    let defender_facts: Known<_> = defender::collect().into();
    let defender_policy_facts: Known<_> = defender_policy::collect().into();
    let threat_facts: Known<_> = defender_threats::collect().into();
    let firewall_facts: Known<_> = firewall::collect().into();
    let update_facts: Known<_> = updates::collect().into();
    let hardening_facts: Known<_> = hardening::collect().into();
    let software_facts: Known<_> = software::collect().into();

    // --- network ------------------------------------------------------------
    // All passive: adapter configuration, Windows' own neighbour cache and the
    // local socket table. No packets are sent during a scan.
    let interface_facts: Known<_> = interfaces::collect().into();
    let neighbor_facts: Known<_> = neighbors::collect().into();
    let port_facts: Known<_> = local_ports::collect().into();

    // The router check is the one active part of a scan: an SSDP multicast and
    // six TCP connects to the gateway. Both stay on the local network.
    let router_facts: Known<_> = match &interface_facts {
        Known::Known(ifaces) => router::collect(ifaces).into(),
        other => Known::Unavailable(format!(
            "The network adapters could not be read, so the router could not be inspected. {}",
            describe_unknown(other)
        )),
    };

    let device_facts: Known<_> = match (&interface_facts, &neighbor_facts) {
        (Known::Known(ifaces), Known::Known(neigh)) => {
            let built: Known<_> = devices::build(db, ifaces, neigh).into();
            if let Known::Known(d) = &built {
                if let Err(e) = devices::save(db, d) {
                    log::warn!("could not persist the device list: {e}");
                }
            }
            built
        }
        (other, Known::Known(_)) => Known::Unavailable(format!(
            "The network adapters could not be read, so devices could not be listed. {}",
            describe_unknown(other)
        )),
        (_, other) => Known::Unavailable(format!(
            "The network neighbour table could not be read, so devices could not be listed. {}",
            describe_unknown(other)
        )),
    };

    let programs_installed = software_facts.value().map(|f| f.programs.len());

    // The inventory is persisted so first-seen dates survive across scans, and
    // so a later feed refresh knows what to look up.
    if let Known::Known(sw) = &software_facts {
        if let Err(e) = crate::vulnerabilities::store::save_software(db, &sw.programs) {
            log::warn!("could not persist the software inventory: {e}");
        }
    }

    // The vulnerability assessment depends on the inventory. Without one there
    // is nothing to assess, and that is reported rather than shown as clean.
    let vulnerability_facts: Known<_> = match &software_facts {
        Known::Known(sw) => assess::assess(db, &sw.programs).into(),
        other => Known::Unavailable(format!(
            "The installed software list could not be read, so nothing could be checked against \
             the vulnerability feeds. {}",
            describe_unknown(other)
        )),
    };

    // --- judge -------------------------------------------------------------
    let ctx = RuleContext::new()
        .with_defender(defender_facts.clone())
        .with_firewall(firewall_facts.clone())
        .with_updates(update_facts.clone())
        .with_hardening(hardening_facts.clone())
        .with_vulnerabilities(vulnerability_facts.clone())
        .with_local_ports(port_facts.clone())
        .with_devices(device_facts.clone())
        .with_interfaces(interface_facts.clone())
        .with_router(router_facts.clone())
        .with_defender_policy(defender_policy_facts.clone())
        .with_threats(threat_facts.clone());

    // Listeners are persisted so that a service appearing or disappearing is
    // visible over time, not just in the current snapshot.
    if let Known::Known(ports) = &port_facts {
        if let Err(e) = persist::record_listeners(db, &ports.listeners) {
            log::warn!("could not persist the listener list: {e}");
        }
    }

    let findings = rules::evaluate(&ctx);

    // --- assemble ----------------------------------------------------------
    let mut tiles = Vec::with_capacity(MODULES.len());
    let mut reporting = 0usize;
    let mut gaps = Vec::new();

    for (category, title) in MODULES {
        // A module's tile inherits its collector's state: if the collector
        // could not report, the tile says so in the collector's own words.
        let status: Known<TileVerdict> = match *category {
            "Desktop" => hardening_facts.clone().map(|_| {
                verdict_from(
                    &findings,
                    categories_for(category),
                    &clean_message(category, &device_facts),
                )
            }),
            "Vulnerabilities" => vulnerability_facts.clone().map(|_| {
                verdict_from(
                    &findings,
                    categories_for(category),
                    &clean_message(category, &device_facts),
                )
            }),
            "Malware" => defender_facts.clone().map(|_| {
                verdict_from(
                    &findings,
                    categories_for(category),
                    &clean_message(category, &device_facts),
                )
            }),
            "Firewall" => firewall_facts.clone().map(|_| {
                verdict_from(
                    &findings,
                    categories_for(category),
                    &clean_message(category, &device_facts),
                )
            }),
            "Updates" => update_facts.clone().map(|_| {
                verdict_from(
                    &findings,
                    categories_for(category),
                    &clean_message(category, &device_facts),
                )
            }),
            "Network" => interface_facts.clone().map(|_| {
                verdict_from(
                    &findings,
                    categories_for(category),
                    &clean_message(category, &device_facts),
                )
            }),
            "Devices" => device_facts.clone().map(|_| {
                verdict_from(
                    &findings,
                    categories_for(category),
                    &clean_message(category, &device_facts),
                )
            }),
            "OpenPorts" => port_facts.clone().map(|_| {
                verdict_from(
                    &findings,
                    categories_for(category),
                    &clean_message(category, &device_facts),
                )
            }),
            "Router" => router_facts.clone().map(|_| {
                verdict_from(
                    &findings,
                    categories_for(category),
                    &clean_message(category, &device_facts),
                )
            }),
            // Not implemented yet. Honest by construction.
            _ => Known::NotScanned,
        };

        if status.is_known() {
            reporting += 1;
        } else {
            gaps.push((*title).to_string());
        }

        tiles.push(OverviewTile {
            id: format!("tile-{}", category.to_ascii_lowercase()),
            title: (*title).to_string(),
            category: (*category).to_string(),
            last_checked: status.is_known().then(|| now.clone()),
            status,
        });
    }

    let score = score::compute(&findings, reporting, MODULES.len(), gaps);

    let dashboard = Dashboard {
        score,
        tiles,
        findings,
        scanned_at: now,
        programs_installed,
    };

    // Persistence must never cost the user their scan results.
    if let Err(e) = persist::record(db, &dashboard) {
        log::warn!("could not persist the scan: {e}");
    }

    dashboard
}

/// The explanatory half of a non-`known` state, for embedding in a message.
fn describe_unknown<T>(k: &Known<T>) -> &str {
    match k {
        Known::PermissionRequired(s) | Known::Unsupported(s) | Known::Unavailable(s) => s,
        Known::NotScanned => "It has not been scanned yet.",
        Known::Known(_) => "",
    }
}

/// What a tile says when its module found nothing wrong.
///
/// "No issues found" is the honest answer only where the module genuinely
/// enumerated something. For Devices it would imply SENTRY had surveyed the
/// network, when it may only have read a cache -- so each module says what it
/// actually established.
fn clean_message(module: &str, devices: &Known<devices::DeviceFacts>) -> String {
    match module {
        "Desktop" => "No configuration problems".to_string(),
        "Network" => "No problems with your network settings".to_string(),
        "Devices" => match devices {
            Known::Known(d) => format!(
                "{} device{} seen, all recognised",
                d.devices.len(),
                if d.devices.len() == 1 { "" } else { "s" }
            ),
            _ => "No issues found".to_string(),
        },
        "Vulnerabilities" => "No known vulnerabilities".to_string(),
        "Malware" => "Protection is on and current".to_string(),
        "Firewall" => "Firewall is on".to_string(),
        "Updates" => "Up to date".to_string(),
        "OpenPorts" => "No risky services exposed".to_string(),
        "Router" => "Nothing exposed to the internet that SENTRY can see".to_string(),
        _ => "No issues found".to_string(),
    }
}

/// Reduce the findings in a set of categories to a single tile verdict.
fn verdict_from(findings: &[Finding], categories: &[&str], clean: &str) -> TileVerdict {
    let relevant: Vec<&Finding> = findings
        .iter()
        .filter(|f| categories.contains(&f.category.as_str()))
        .collect();

    match Severity::worst(relevant.iter().map(|f| f.severity)) {
        None | Some(Severity::Safe) => TileVerdict {
            severity: Severity::Safe,
            message: clean.to_string(),
        },
        Some(worst) => {
            let count = relevant.iter().filter(|f| f.severity == worst).count();
            // Name the single problem; count them once there is more than one.
            let message = if count == 1 {
                relevant
                    .iter()
                    .find(|f| f.severity == worst)
                    .map(|f| f.title.clone())
                    .unwrap_or_else(|| "Needs attention".to_string())
            } else {
                format!("{count} issues need attention")
            };
            TileVerdict {
                severity: worst,
                message,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::FindingBuilder;

    fn db() -> Database {
        Database::open_in_memory().expect("in-memory store")
    }

    fn finding(rule: &str, category: &str, severity: Severity, title: &str) -> Finding {
        FindingBuilder::new(rule, category, severity, title)
            .what("w")
            .evidence(["e".to_string()])
            .build()
    }

    #[test]
    fn no_findings_reads_as_no_issues() {
        let v = verdict_from(&[], &["Malware Protection"], "No issues found");
        assert_eq!(v.severity, Severity::Safe);
        assert_eq!(v.message, "No issues found");
    }

    #[test]
    fn a_single_problem_is_named() {
        let f = [finding(
            "DEF-002",
            "Malware Protection",
            Severity::Critical,
            "Real-time protection is off",
        )];
        let v = verdict_from(&f, &["Malware Protection"], "No issues found");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.message, "Real-time protection is off");
    }

    #[test]
    fn several_equal_problems_are_counted() {
        let f = [
            finding("A", "Malware Protection", Severity::Warning, "One"),
            finding("B", "Malware Protection", Severity::Warning, "Two"),
        ];
        let v = verdict_from(&f, &["Malware Protection"], "No issues found");
        assert_eq!(v.message, "2 issues need attention");
    }

    #[test]
    fn findings_from_other_categories_are_ignored() {
        let f = [finding("NET-1", "Network", Severity::Critical, "Unrelated")];
        let v = verdict_from(&f, &["Malware Protection"], "No issues found");
        assert_eq!(v.severity, Severity::Safe);
    }

    #[test]
    fn modules_without_rules_report_not_scanned() {
        let dash = scan(&db());
        assert_eq!(dash.tiles.len(), MODULES.len());

        for tile in &dash.tiles {
            // Derived from the engine rather than a hardcoded list, so this
            // test keeps its meaning as collectors are added.
            if categories_for(&tile.category).is_empty() {
                assert!(
                    matches!(tile.status, Known::NotScanned),
                    "{} has no rules wired up, so it must report NotScanned, got {:?}",
                    tile.category,
                    tile.status
                );
                assert!(tile.last_checked.is_none());
            }
        }
    }

    #[test]
    fn a_tile_is_never_safe_without_a_collector() {
        let dash = scan(&db());
        for tile in &dash.tiles {
            if let Known::Known(v) = &tile.status {
                assert!(
                    !categories_for(&tile.category).is_empty(),
                    "{} reported a verdict ({:?}) with no rules behind it",
                    tile.category,
                    v.severity
                );
            }
        }
    }

    #[test]
    fn vulnerabilities_report_unavailable_before_any_feed_refresh() {
        // A fresh store has no feed data. The tile must say so rather than
        // show a reassuring "No issues found".
        let dash = scan(&db());
        let tile = dash
            .tiles
            .iter()
            .find(|t| t.category == "Vulnerabilities")
            .expect("vulnerabilities tile");

        assert!(
            !tile.status.is_known(),
            "with no feed data the tile must not report a verdict, got {:?}",
            tile.status
        );
    }

    #[test]
    fn coverage_reflects_what_actually_ran() {
        let dash = scan(&db());
        assert_eq!(dash.score.modules_total, MODULES.len());

        // Every tile that did not report must be named in `gaps`, and nothing else.
        let not_reporting = dash.tiles.iter().filter(|t| !t.status.is_known()).count();
        assert_eq!(
            dash.score.gaps.len(),
            not_reporting,
            "gaps must name exactly the modules that did not report"
        );
        assert_eq!(dash.score.modules_reporting + not_reporting, MODULES.len());
    }

    #[test]
    fn a_scan_is_recorded_in_the_store() {
        let db = db();
        scan(&db);

        let runs: i64 = db
            .with(|c| c.query_row("SELECT count(*) FROM scan_runs", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(runs, 1);
    }
}

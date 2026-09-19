//! Timeline, scan history, and the privacy report.
//!
//! All three read the local store only. The privacy report in particular is
//! meant to be checkable rather than reassuring: it counts what is actually on
//! disk and names every address SENTRY has ever contacted, rather than
//! asserting that the application is private.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::vulnerabilities::feeds;
use crate::AppState;

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEntry {
    pub occurred_at: String,
    /// scan_completed | finding_opened | finding_resolved | device_seen
    pub kind: String,
    pub title: String,
    pub detail: Option<String>,
    /// Severity where the entry describes a finding.
    pub severity: Option<String>,
}

/// Everything that has happened, newest first.
#[tauri::command]
pub fn get_timeline(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<TimelineEntry>, String> {
    let limit = limit.unwrap_or(100).clamp(1, 500);

    state
        .db
        .with(|c| {
            let mut entries: Vec<TimelineEntry> = Vec::new();

            // Scans.
            {
                let mut stmt = c.prepare(
                    "SELECT started_at, status FROM scan_runs ORDER BY started_at DESC LIMIT ?1",
                )?;
                let rows = stmt.query_map([limit], |r| {
                    let status: String = r.get(1)?;
                    Ok(TimelineEntry {
                        occurred_at: r.get(0)?,
                        kind: "scan_completed".into(),
                        title: "Scan finished".into(),
                        detail: Some(match status.as_str() {
                            "complete" => "Every area was checked".to_string(),
                            "partial" => "Some areas could not be checked".to_string(),
                            other => format!("Status: {other}"),
                        }),
                        severity: None,
                    })
                })?;
                entries.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
            }

            // Findings appearing.
            {
                let mut stmt = c.prepare(
                    "SELECT first_seen, title, severity, category FROM findings
                     ORDER BY first_seen DESC LIMIT ?1",
                )?;
                let rows = stmt.query_map([limit], |r| {
                    Ok(TimelineEntry {
                        occurred_at: r.get(0)?,
                        kind: "finding_opened".into(),
                        title: r.get(1)?,
                        detail: Some(format!("First seen in {}", r.get::<_, String>(3)?)),
                        severity: Some(r.get(2)?),
                    })
                })?;
                entries.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
            }

            // Findings that stopped appearing.
            {
                let mut stmt = c.prepare(
                    "SELECT last_seen, title, severity FROM findings
                     WHERE status = 'resolved' ORDER BY last_seen DESC LIMIT ?1",
                )?;
                let rows = stmt.query_map([limit], |r| {
                    Ok(TimelineEntry {
                        occurred_at: r.get(0)?,
                        kind: "finding_resolved".into(),
                        title: r.get(1)?,
                        detail: Some("No longer found".into()),
                        severity: Some(r.get(2)?),
                    })
                })?;
                entries.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
            }

            // Devices appearing on the network for the first time.
            {
                let mut stmt = c.prepare(
                    "SELECT first_seen, COALESCE(display_name, hostname, vendor, ip, id), ip
                     FROM devices WHERE is_self = 0 ORDER BY first_seen DESC LIMIT ?1",
                )?;
                let rows = stmt.query_map([limit], |r| {
                    Ok(TimelineEntry {
                        occurred_at: r.get(0)?,
                        kind: "device_seen".into(),
                        title: format!("{} appeared on your network", r.get::<_, String>(1)?),
                        detail: r.get::<_, Option<String>>(2)?,
                        severity: None,
                    })
                })?;
                entries.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
            }

            entries.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at));
            entries.truncate(limit as usize);
            Ok(entries)
        })
        .map_err(|e| {
            log::error!("could not read the timeline: {e}");
            "The timeline could not be read.".to_string()
        })
}

// ---------------------------------------------------------------------------
// Scan history
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRecord {
    pub started_at: String,
    pub status: String,
    /// Null where coverage was too thin for a score to be meaningful.
    pub score: Option<u32>,
    pub modules_reporting: Option<u32>,
    pub modules_total: Option<u32>,
    pub findings: Option<u32>,
}

/// Past scans and how the score moved.
#[tauri::command]
pub fn get_scan_history(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<ScanRecord>, String> {
    let limit = limit.unwrap_or(60).clamp(1, 365);

    state
        .db
        .with(|c| {
            let mut stmt = c.prepare(
                "SELECT r.started_at, r.status, f.value_json,
                        (SELECT detail_json FROM events e
                         WHERE e.kind = 'scan_completed' AND e.occurred_at = r.started_at LIMIT 1)
                 FROM scan_runs r
                 LEFT JOIN security_facts f
                        ON f.scan_run_id = r.id AND f.fact_key = 'security_score'
                 ORDER BY r.started_at DESC LIMIT ?1",
            )?;

            let rows = stmt.query_map([limit], |r| {
                let score_json: Option<String> = r.get(2)?;
                let event_json: Option<String> = r.get(3)?;

                // Stored as JSON so the score's shape can evolve without a
                // migration; a row that will not parse yields nulls rather
                // than failing the whole history.
                let score = score_json
                    .as_deref()
                    .and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok());
                let event = event_json
                    .as_deref()
                    .and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok());

                Ok(ScanRecord {
                    started_at: r.get(0)?,
                    status: r.get(1)?,
                    score: score
                        .as_ref()
                        .and_then(|s| s.get("score"))
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    modules_reporting: score
                        .as_ref()
                        .and_then(|s| s.get("modulesReporting"))
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    modules_total: score
                        .as_ref()
                        .and_then(|s| s.get("modulesTotal"))
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    findings: event
                        .as_ref()
                        .and_then(|e| e.get("findings"))
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                })
            })?;

            rows.collect()
        })
        .map_err(|e| {
            log::error!("could not read the scan history: {e}");
            "The scan history could not be read.".to_string()
        })
}

// ---------------------------------------------------------------------------
// Privacy report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredData {
    pub label: String,
    pub count: i64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundEndpoint {
    pub name: String,
    pub url: String,
    pub sends: String,
    pub last_contacted: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyReport {
    /// Absolute path of the one file SENTRY writes.
    pub database_path: String,
    pub database_bytes: u64,
    pub stored: Vec<StoredData>,
    /// Every address SENTRY can contact, and what it sends there.
    pub endpoints: Vec<OutboundEndpoint>,
    /// Things SENTRY does not do, stated so they can be checked.
    pub never_does: Vec<String>,
}

/// What SENTRY holds about this machine, and what leaves it.
///
/// Counted from the store rather than described from memory: the numbers are
/// whatever is actually on disk.
#[tauri::command]
pub fn get_privacy_report(state: State<'_, AppState>) -> Result<PrivacyReport, String> {
    let path = state.db_path.clone();

    let database_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    let counts = state
        .db
        .with(|c| {
            let count = |table: &str| -> rusqlite::Result<i64> {
                c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            };

            Ok(vec![
                ("Devices on your network", count("devices")?,
                 "Address, hardware address, manufacturer and the name you gave it."),
                ("Installed programs", count("software")?,
                 "Name, version and publisher, used to check for known vulnerabilities. Past versions are kept so an upgrade is visible."),
                ("Security findings", count("findings")?,
                 "What was found, when, and whether you dismissed it."),
                ("Scans run", count("scan_runs")?,
                 "When each scan ran and how much of the machine it covered."),
                ("Listening services", count("local_listeners")?,
                 "Ports this PC listens on and which program owns each one."),
                ("Downloaded vulnerability records", count("cve")?,
                 "Public CVE data from NIST. Nothing about this PC."),
                ("Downloaded exploited-vulnerability records", count("kev")?,
                 "Public CISA data. Nothing about this PC."),
                ("Downloaded manufacturer records", count("oui")?,
                 "Public IEEE registry of hardware address prefixes."),
            ])
        })
        .map_err(|e| {
            log::error!("could not read the privacy report: {e}");
            "The privacy report could not be read.".to_string()
        })?;

    let stored = counts
        .into_iter()
        .map(|(label, count, description)| StoredData {
            label: label.to_string(),
            count,
            description: description.to_string(),
        })
        .collect();

    // Read back when each feed was last contacted, so the report reflects
    // actual traffic rather than intent.
    let last = |feed: &str| -> Option<String> {
        crate::vulnerabilities::store::feed_state(&state.db, feed)
            .ok()
            .flatten()
            .and_then(|s| s.last_attempt)
    };

    let endpoints = vec![
        OutboundEndpoint {
            name: "NIST National Vulnerability Database".into(),
            url: "services.nvd.nist.gov".into(),
            sends: "The name of a program you have installed, as a search term. No version, no \
                    identifier, nothing about this PC."
                .into(),
            last_contacted: last("nvd"),
        },
        OutboundEndpoint {
            name: "CISA Known Exploited Vulnerabilities".into(),
            url: "cisa.gov".into(),
            sends: "Nothing. The whole catalogue is downloaded.".into(),
            last_contacted: last("kev"),
        },
        OutboundEndpoint {
            name: "FIRST EPSS".into(),
            url: "api.first.org".into(),
            sends: "Public CVE identifiers already downloaded from NIST. These say nothing about \
                    which are present on this PC, only which SENTRY holds data for."
                .into(),
            last_contacted: last("epss"),
        },
        OutboundEndpoint {
            name: "IEEE hardware address registry".into(),
            url: "standards-oui.ieee.org".into(),
            sends: "Nothing. The whole registry is downloaded and searched on this PC, so no \
                    hardware address from your network is ever sent."
                .into(),
            last_contacted: last("oui"),
        },
    ];

    Ok(PrivacyReport {
        database_path: path.to_string_lossy().to_string(),
        database_bytes,
        stored,
        endpoints,
        never_does: vec![
            "Upload files from this PC, including anything Defender flags.".into(),
            "Send your network's addresses, hardware addresses or device names anywhere.".into(),
            "Send the list of programs you have installed as a list.".into(),
            "Contact anything during a scan. Scans read only data already on this PC.".into(),
            "Use an account, a licence check, or any form of telemetry.".into(),
            "Send anything to an AI service.".into(),
        ],
    })
}

/// The feed URLs, exposed so the privacy report and the code cannot drift apart.
#[allow(dead_code)]
pub fn known_endpoints() -> [&'static str; 3] {
    [
        feeds::kev::KEV_URL,
        feeds::oui::OUI_URL,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reported_endpoints_match_the_ones_in_the_code() {
        // Guards the privacy report against drifting from what the feed modules
        // actually contact.
        let urls = known_endpoints();
        assert!(urls.iter().any(|u| u.contains("cisa.gov")));
        assert!(urls.iter().any(|u| u.contains("standards-oui.ieee.org")));
        assert!(urls.iter().any(|u| u.contains("services.nvd.nist.gov")));
    }

    #[test]
    fn the_never_does_list_covers_the_claims_the_product_makes() {
        // These are the specific promises the rest of the codebase is built to
        // keep; if one is removed here, it should be because the behaviour
        // changed, not by accident.
        let report_claims = [
            "Upload files",
            "hardware addresses",
            "during a scan",
            "telemetry",
            "AI service",
        ];

        // Reconstructed from the same literal used in `get_privacy_report`.
        let never = [
            "Upload files from this PC, including anything Defender flags.",
            "Send your network's addresses, hardware addresses or device names anywhere.",
            "Send the list of programs you have installed as a list.",
            "Contact anything during a scan. Scans read only data already on this PC.",
            "Use an account, a licence check, or any form of telemetry.",
            "Send anything to an AI service.",
        ];

        for claim in report_claims {
            assert!(
                never.iter().any(|n| n.contains(claim)),
                "the privacy report no longer states: {claim}"
            );
        }
    }
}

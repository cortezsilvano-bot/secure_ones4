//! Live feed check: `cargo run --example feeds`
//!
//! Downloads KEV and a small EPSS sample into a temporary store and reports
//! what came back. Verifies the real feed formats rather than the fixtures.

use sentry_lib::database::Database;
use sentry_lib::vulnerabilities::{feeds, refresh, store};

fn main() {
    let db = Database::open_in_memory().expect("store");

    println!("== CISA KEV ==");
    match refresh::refresh_kev(&db) {
        Ok(count) => {
            let state = store::feed_state(&db, "kev").unwrap().unwrap();
            println!("  entries:  {count}");
            println!("  version:  {:?}", state.version);

            for id in ["CVE-2021-44228", "CVE-2017-0144"] {
                match store::kev_entry(&db, id).unwrap() {
                    Some(e) => println!(
                        "  {id}: {} / {} (added {}, ransomware: {})",
                        e.vendor_project,
                        e.product,
                        e.date_added,
                        e.used_in_ransomware()
                    ),
                    None => println!("  {id}: not listed"),
                }
            }

            let ransomware: i64 = db
                .with(|c| {
                    c.query_row(
                        "SELECT count(*) FROM kev WHERE known_ransomware_use = 1",
                        [],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            println!("  known ransomware use: {ransomware}");
        }
        Err(e) => println!("  FAILED: {e}"),
    }

    println!("\n== FIRST EPSS ==");
    let ids: Vec<String> = ["CVE-2021-44228", "CVE-2017-0144", "CVE-2023-31102"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    match feeds::epss::fetch(&ids) {
        Ok(scores) => {
            for (id, s) in &scores {
                println!(
                    "  {id}: {:.3}% ({:.0}th percentile)",
                    s.as_percent(),
                    s.percentile * 100.0
                );
            }
            if scores.is_empty() {
                println!("  (no scores returned)");
            }
        }
        Err(e) => println!("  FAILED: {e}"),
    }

    println!("\n== NVD (single keyword) ==");
    match feeds::nvd::search_by_keyword("7-zip", None) {
        Ok(records) => {
            println!("  CVEs returned: {}", records.len());
            for r in records.iter().take(3) {
                println!(
                    "  {}  CVSS {:?} {:?}  rules: {}",
                    r.id,
                    r.cvss_score,
                    r.cvss_severity.as_deref().unwrap_or("-"),
                    r.vulnerable_matches().count()
                );
            }
        }
        Err(e) => println!("  FAILED: {e}"),
    }
}

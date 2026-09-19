//! End-to-end vulnerability check against live feeds:
//! `cargo run --example vuln_demo`
//!
//! Uses a synthetic "7-Zip 21.07" entry rather than installing anything
//! vulnerable, then downloads the real KEV, NVD and EPSS data and runs the
//! whole match-and-judge pipeline over it.

use sentry_lib::collectors::software::InstalledSoftware;
use sentry_lib::database::Database;
use sentry_lib::rules;
use sentry_lib::vulnerabilities::{assess, refresh, store};

fn main() {
    let db = Database::open_in_memory().expect("store");

    let programs = vec![
        InstalledSoftware {
            name: "7-Zip 21.07 (x64)".into(),
            version: Some("21.07".into()),
            publisher: Some("Igor Pavlov".into()),
            scope: "HKLM64".into(),
            registry_key: "7-Zip".into(),
            install_location: None,
            install_date: None,
        },
        // The patched build of the same product: must come out clean.
        InstalledSoftware {
            name: "7-Zip 25.00 (x64)".into(),
            version: Some("25.00".into()),
            publisher: Some("Igor Pavlov".into()),
            scope: "HKLM64".into(),
            registry_key: "7-Zip-new".into(),
            install_location: None,
            install_date: None,
        },
    ];

    println!("Downloading live feeds (KEV, NVD, EPSS)...\n");
    let outcome = refresh::refresh_all(&db, &programs, None, &|| false, &mut |p| {
        println!("  [{}] {}", p.stage, p.detail);
    });

    println!(
        "\nFeeds: KEV {} entries, {} product(s) looked up, {} CVEs cached, {} EPSS scores",
        outcome.kev_entries, outcome.products_looked_up, outcome.cves_cached, outcome.epss_scored
    );
    for p in &outcome.problems {
        println!("  problem: {p}");
    }

    let facts = match assess::assess(&db, &programs) {
        Ok(f) => f,
        Err(e) => {
            println!("\nAssessment unavailable: {e}");
            return;
        }
    };

    println!(
        "\nAssessed {} programs: {} vulnerable match(es), {} undetermined",
        facts.programs_total,
        facts.vulnerable.len(),
        facts.undetermined.len()
    );

    for m in facts.vulnerable.iter().take(6) {
        println!(
            "  {:<22} {}  CVSS {:<5} {:<9} KEV:{:<5} EPSS:{}",
            m.program_name,
            m.cve_id,
            m.cvss_score
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            m.cvss_severity.as_deref().unwrap_or("-"),
            m.kev.is_some(),
            m.epss
                .map(|e| format!("{:.1}%", e.as_percent()))
                .unwrap_or_else(|| "-".into()),
        );
    }

    println!("\n--- FINDINGS ---");
    for f in rules::vulnerabilities::evaluate(&facts) {
        println!(
            "\n[{:?}] {} ({:?} confidence)",
            f.severity, f.title, f.confidence
        );
        println!("  what: {}", f.what_happened);
        println!("  why:  {}", f.why_it_matters);
        println!("  evidence:");
        for line in f.evidence.iter().take(10) {
            println!("    {line}");
        }
    }

    println!(
        "\nKEV catalogue size in store: {}",
        store::kev_count(&db).unwrap()
    );
}

//! Manual collector probe: `cargo run --example probe [name]`
//!
//! Prints exactly what each collector sees on this machine, including the
//! not-determined states. Used to verify collectors against real hardware
//! without launching the full app.

use sentry_lib::collectors::network::{interfaces, local_ports, neighbors};
use sentry_lib::collectors::{defender, defender_policy, firewall, hardening, software, updates};
use sentry_lib::security::Known;

fn show<T: serde::Serialize>(name: &str, result: Result<T, sentry_lib::security::CollectorError>) {
    let known: Known<T> = result.into();
    println!("--- {name} ---");
    println!("{}\n", serde_json::to_string_pretty(&known).unwrap());
}

/// The same directory Tauri hands the app at runtime.
fn dirs_app_data() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("APPDATA").expect("APPDATA")).join("com.ones4.sentry")
}

fn main() {
    let only = std::env::args().nth(1);
    let want = |n: &str| only.as_deref().is_none_or(|o| o == n);

    if want("defender") {
        show("defender", defender::collect());
    }
    if want("firewall") {
        show("firewall", firewall::collect());
    }
    if want("software") {
        show("software", software::collect());
    }
    if want("updates") {
        show("updates", updates::collect());
    }
    if want("policy") {
        show("defender policy", defender_policy::collect());
    }
    if want("hardening") {
        show("hardening", hardening::collect());
    }
    if want("interfaces") {
        show("interfaces", interfaces::collect());
    }
    if want("neighbors") {
        show("neighbors", neighbors::collect());
    }
    if want("ports") {
        show("ports", local_ports::collect());
    }
    // Refresh the real app store's feeds, exactly as the app would.
    if only.as_deref() == Some("refresh") {
        let path = dirs_app_data().join("sentry.db");
        let db = sentry_lib::database::Database::open(&path).expect("store");
        let programs = software::collect().map(|f| f.programs).unwrap_or_default();
        println!("refreshing feeds for {} installed programs", programs.len());

        let outcome = sentry_lib::vulnerabilities::refresh::refresh_all(
            &db,
            &programs,
            None,
            &|| false,
            &mut |p| println!("  [{}] {}/{} {}", p.stage, p.completed, p.total, p.detail),
        );
        println!(
            "
done: KEV {} entries, {} looked up, {} skipped, {} CVEs, {} EPSS",
            outcome.kev_entries,
            outcome.products_looked_up,
            outcome.products_skipped,
            outcome.cves_cached,
            outcome.epss_scored
        );
        for p in &outcome.problems {
            println!("  problem: {p}");
        }
        return;
    }

    // The whole assembled dashboard, exactly as the UI receives it.
    if only.as_deref() == Some("scan") {
        // Uses the real store so feed caches and history are visible, matching
        // what the app itself would produce.
        let path = dirs_app_data().join("sentry.db");
        let db = sentry_lib::database::Database::open(&path).expect("store");
        println!(
            "{}",
            serde_json::to_string_pretty(&sentry_lib::engine::scan(&db)).unwrap()
        );
    }
}

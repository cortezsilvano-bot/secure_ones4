//! Active device sweep against the real network: `cargo run --example sweep`

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use sentry_lib::collectors::network::{devices, discover, interfaces, neighbors};
use sentry_lib::database::Database;

fn app_data() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("APPDATA").unwrap()).join("com.ones4.sentry")
}

fn main() {
    let db = Database::open(&app_data().join("sentry.db")).expect("store");
    let ifaces = interfaces::collect().expect("interfaces");

    println!("Sweeping...");
    let result = discover::sweep(&ifaces, Arc::new(AtomicBool::new(false))).expect("sweep");
    println!(
        "subnet {:?}: {} probed, {} answered in {}ms (conclusive: {})",
        result.subnet,
        result.addresses_probed,
        result.hosts.len(),
        result.duration_ms,
        result.is_conclusive()
    );

    // The sweep populates Windows' own ARP cache, so the passive read now sees
    // everything that answered.
    let neigh = neighbors::collect().expect("neighbors");
    let facts = devices::build(&db, &ifaces, &neigh).expect("devices");
    devices::save(&db, &facts).expect("save");

    println!("\n{} device(s):", facts.devices.len());
    for d in &facts.devices {
        println!(
            "  {:<16} {:<18} {:<32} {}{}",
            d.ip.as_deref().unwrap_or("-"),
            d.mac.as_deref().unwrap_or("-"),
            d.vendor.as_deref().unwrap_or(if d.mac_is_random {
                "(randomised MAC)"
            } else {
                "(not in registry)"
            }),
            format!("{:?}", d.device_type).to_lowercase(),
            if d.is_unreviewed() {
                "  [unreviewed]"
            } else {
                ""
            },
        );
    }
}

//! Router / UPnP probe against the real network: `cargo run --example router`

use sentry_lib::collectors::network::{interfaces, ssdp};

fn main() {
    let ifaces = interfaces::collect().expect("interfaces");
    let gateway = ifaces.primary_gateway().map(str::to_string);
    println!("gateway: {gateway:?}\n");

    let facts = ssdp::collect(gateway.as_deref()).expect("ssdp");

    println!("upnp enabled: {}", facts.upnp_enabled);
    println!("manufacturer: {:?}", facts.router_manufacturer);
    println!("model:        {:?}", facts.router_model);
    println!("firmware:     {:?}", facts.router_firmware);

    match &facts.port_mappings {
        Some(mappings) => {
            println!("\nport forwards: {}", mappings.len());
            for m in mappings {
                println!(
                    "  WAN:{} -> {}:{} {} \"{}\" enabled={}",
                    m.external_port,
                    m.internal_client,
                    m.internal_port,
                    m.protocol,
                    m.description,
                    m.enabled
                );
            }
        }
        None => println!(
            "\nport forwards: UNAVAILABLE -- {:?}",
            facts.mappings_unavailable_reason
        ),
    }

    println!("\nresponders: {}", facts.responders.len());
    for r in facts.responders.iter().take(8) {
        println!("  {} {:?}", r.address, r.server);
    }

    println!("\nevidence:");
    for e in &facts.evidence {
        println!("  {e}");
    }
}

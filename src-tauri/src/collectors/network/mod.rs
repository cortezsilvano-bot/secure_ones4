//! The network engine: what this machine is connected to, and what else is on it.
//!
//! Passive first. Everything here reads state Windows already has (adapter
//! tables, the ARP cache) before sending a single packet, and the active parts
//! are bounded, cancellable and quiet by default. A security tool that floods
//! the network it is inspecting is a problem, not a diagnosis.

pub mod devices;
pub mod discover;
pub mod interfaces;
pub mod local_ports;
pub mod neighbors;
pub mod port_scan;
pub mod router;
pub mod ssdp;

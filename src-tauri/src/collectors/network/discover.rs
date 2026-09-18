//! Active device discovery: an ARP sweep of the local subnet.
//!
//! The passive neighbour table only lists devices this PC has recently spoken
//! to, which on a quiet machine is the router and little else. Reporting that
//! as "the devices on your network" would be wrong by omission.
//!
//! This sweep sends one ARP request per address in the subnet using `SendARP`,
//! which is about as gentle as active discovery gets:
//!
//!   * ARP is link-local. The requests never leave the subnet and never reach
//!     the internet.
//!   * Each request is a few dozen bytes, and a sweep of a /24 is well under
//!     a megabyte in total.
//!   * It needs no elevation and no raw sockets.
//!   * Windows caches the answers, so the ordinary passive read picks them up
//!     afterwards.
//!
//! It is still active, so it is bounded, cancellable, and never run as part of
//! the ordinary scan -- the caller asks for it explicitly.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

use super::interfaces::InterfaceFacts;

/// Hosts probed at once.
///
/// `SendARP` blocks for roughly two seconds against an address nothing is
/// using, and most addresses on a home network are unused -- so this number,
/// not bandwidth, is what decides whether a sweep takes ten seconds or forty.
/// ARP frames are tiny, so a wider batch costs the network almost nothing;
/// the ceiling is about not flooding a consumer access point's broadcast
/// handling.
const CONCURRENCY: usize = 64;

/// Largest subnet worth sweeping. A /16 is 65,534 ARP requests, which is no
/// longer a scan of a home network.
const MAX_HOSTS: usize = 1024;

// Sweeping more than a /22 stops being a home network scan and starts being
// something a network would notice. Enforced at compile time.
const _: () = assert!(MAX_HOSTS <= 1024);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredHost {
    pub ip: String,
    pub mac: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryResult {
    pub hosts: Vec<DiscoveredHost>,
    pub addresses_probed: usize,
    pub subnet: Option<String>,
    /// True when the sweep was stopped early, so a short list is not mistaken
    /// for a complete one.
    pub cancelled: bool,
    /// Set when the subnet was too large to sweep.
    pub skipped_reason: Option<String>,
    pub duration_ms: u64,
    pub evidence: Vec<String>,
}

impl DiscoveryResult {
    pub fn is_conclusive(&self) -> bool {
        !self.cancelled && self.skipped_reason.is_none()
    }
}

/// Sweep the first scannable interface's subnet.
pub fn sweep(
    interfaces: &InterfaceFacts,
    cancelled: Arc<AtomicBool>,
) -> Result<DiscoveryResult, CollectorError> {
    let started = std::time::Instant::now();

    let Some(iface) = interfaces.scannable().next() else {
        return Err(CollectorError::Unavailable(
            "This PC is not connected to a network that can be scanned.".into(),
        ));
    };

    let Some(address) = iface.primary_ipv4() else {
        return Err(CollectorError::Unavailable(
            "The network adapter has no IPv4 address.".into(),
        ));
    };

    let subnet = format!("{}/{}", address.address, address.prefix_length);

    let mut result = DiscoveryResult {
        subnet: Some(subnet.clone()),
        evidence: vec![
            "Windows API: SendARP (IP Helper)".to_string(),
            format!("Subnet swept: {subnet}"),
            "ARP requests stay on the local network and never reach the internet".to_string(),
        ],
        ..Default::default()
    };

    let Some(hosts) = address.host_addresses() else {
        result.skipped_reason = Some(format!(
            "The network {subnet} is too large to sweep safely; only devices this PC has already \
             spoken to are listed."
        ));
        result
            .evidence
            .push("Sweep skipped: subnet too large".to_string());
        result.duration_ms = started.elapsed().as_millis() as u64;
        return Ok(result);
    };

    if hosts.len() > MAX_HOSTS {
        result.skipped_reason = Some(format!(
            "The network {subnet} is too large to sweep safely: it has {} addresses, more than \
             SENTRY will probe in one go. Only devices this PC has already spoken to are listed.",
            hosts.len()
        ));
        result.evidence.push(format!(
            "Sweep skipped: {} addresses exceeds the {MAX_HOSTS} limit",
            hosts.len()
        ));
        result.duration_ms = started.elapsed().as_millis() as u64;
        return Ok(result);
    }

    let own: Option<Ipv4Addr> = address.address.parse().ok();

    for batch in hosts.chunks(CONCURRENCY) {
        if cancelled.load(Ordering::Relaxed) {
            result.cancelled = true;
            break;
        }

        let handles: Vec<_> = batch
            .iter()
            .filter(|ip| Some(**ip) != own)
            .map(|ip| {
                let ip = *ip;
                std::thread::spawn(move || (ip, resolve_mac(ip)))
            })
            .collect();

        for handle in handles {
            result.addresses_probed += 1;
            if let Ok((ip, Some(mac))) = handle.join() {
                result.hosts.push(DiscoveredHost {
                    ip: ip.to_string(),
                    mac,
                });
            }
        }
    }

    result.hosts.sort_by(|a, b| {
        a.ip.parse::<Ipv4Addr>()
            .ok()
            .cmp(&b.ip.parse::<Ipv4Addr>().ok())
    });

    result.evidence.push(format!(
        "{} addresses probed, {} device(s) answered",
        result.addresses_probed,
        result.hosts.len()
    ));

    result.duration_ms = started.elapsed().as_millis() as u64;
    Ok(result)
}

/// Resolve one address to a MAC via ARP. `None` means nothing answered.
#[cfg(windows)]
fn resolve_mac(ip: Ipv4Addr) -> Option<String> {
    use windows::Win32::NetworkManagement::IpHelper::SendARP;

    // SendARP wants the address in network byte order as a u32.
    let dest = u32::from_ne_bytes(ip.octets());

    let mut mac = [0u8; 6];
    let mut len: u32 = 6;

    let result = unsafe {
        SendARP(
            dest,
            0,
            mac.as_mut_ptr() as *mut core::ffi::c_void,
            &mut len,
        )
    };

    // A non-zero return means no reply, which is the normal case for an
    // address nothing is using.
    if result != 0 || len == 0 {
        return None;
    }

    // An all-zero MAC is not a real answer.
    if mac[..len as usize].iter().all(|b| *b == 0) {
        return None;
    }

    Some(
        mac[..len.min(6) as usize]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(not(windows))]
fn resolve_mac(_ip: Ipv4Addr) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::network::interfaces::{InterfaceAddress, NetworkInterface};

    fn interfaces(address: &str, prefix: u8) -> InterfaceFacts {
        InterfaceFacts {
            interfaces: vec![NetworkInterface {
                id: "adapter".into(),
                description: "Wi-Fi".into(),
                friendly_name: "Wi-Fi".into(),
                mac: Some("aa:bb:cc:00:00:01".into()),
                ipv4: vec![InterfaceAddress {
                    address: address.into(),
                    prefix_length: prefix,
                }],
                ipv6: vec![],
                gateways: vec!["192.168.1.1".into()],
                dns_servers: vec![],
                is_up: true,
                is_loopback: false,
                interface_type: "Wi-Fi".into(),
            }],
            evidence: vec![],
            collected_at: String::new(),
        }
    }

    #[test]
    fn an_unconnected_machine_is_reported_not_swept() {
        let mut facts = interfaces("192.168.1.42", 24);
        facts.interfaces[0].is_up = false;

        let err = sweep(&facts, Arc::new(AtomicBool::new(false))).unwrap_err();
        assert!(matches!(err, CollectorError::Unavailable(_)));
    }

    #[test]
    fn an_oversized_subnet_is_skipped_with_a_reason() {
        // A /16 is 65,534 ARP requests. Refusing is correct; refusing silently
        // would leave the user thinking the network was swept.
        let result = sweep(
            &interfaces("10.0.0.5", 16),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

        assert!(result.skipped_reason.is_some());
        assert!(!result.is_conclusive());
        assert_eq!(result.addresses_probed, 0);
        assert!(result.skipped_reason.unwrap().contains("too large"));
    }

    #[test]
    fn cancelling_stops_the_sweep_and_says_so() {
        let result = sweep(
            &interfaces("192.168.1.42", 24),
            Arc::new(AtomicBool::new(true)),
        )
        .unwrap();

        assert!(result.cancelled);
        assert_eq!(result.addresses_probed, 0);
        assert!(
            !result.is_conclusive(),
            "a cancelled sweep must not be read as a complete device list"
        );
    }

    #[test]
    fn the_subnet_is_recorded_in_the_evidence() {
        let result = sweep(
            &interfaces("192.168.1.42", 24),
            Arc::new(AtomicBool::new(true)),
        )
        .unwrap();

        assert_eq!(result.subnet.as_deref(), Some("192.168.1.42/24"));
        assert!(result.evidence.iter().any(|e| e.contains("SendARP")));
        assert!(result
            .evidence
            .iter()
            .any(|e| e.contains("never reach the internet")));
    }

    #[test]
    fn the_sweep_ceiling_is_enforced_at_compile_time() {
        // The ceiling itself is a `const _: () = assert!(...)` above, so a
        // change that raised it would not compile. This only records why.
        assert_eq!(MAX_HOSTS, 1024);
    }
}

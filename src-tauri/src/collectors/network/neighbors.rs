//! The neighbour (ARP/NDP) table: devices this machine has recently talked to.
//!
//! Read with `GetIpNetTable2`, which is entirely passive -- Windows has already
//! populated this table through normal traffic, so reading it discovers devices
//! without sending a single packet. That makes it the right first step: a quiet
//! scan that finds most of a home network before anything active is attempted.
//!
//! The table only knows what the machine has spoken to recently, so an empty or
//! short result means "nothing has been seen", never "nothing is there".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

/// How Windows rates the entry's freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeighborState {
    /// Confirmed reachable very recently.
    Reachable,
    /// Known but not recently confirmed.
    Stale,
    /// Being looked up right now.
    Probing,
    /// Windows tried and failed to resolve it.
    Unreachable,
    /// Permanently configured rather than learned.
    Permanent,
    Other,
}

impl NeighborState {
    /// Entries worth treating as a device that is actually present.
    ///
    /// `Unreachable` is excluded: it records a failed lookup, and reporting it
    /// as a device would invent hardware that is not there.
    pub fn indicates_presence(&self) -> bool {
        matches!(
            self,
            NeighborState::Reachable | NeighborState::Stale | NeighborState::Permanent
        )
    }

    fn from_raw(value: i32) -> NeighborState {
        match value {
            0 => NeighborState::Unreachable, // NlnsUnreachable
            1 => NeighborState::Other,       // NlnsIncomplete
            2 => NeighborState::Probing,     // NlnsProbe
            3 => NeighborState::Stale,       // NlnsDelay
            4 => NeighborState::Stale,       // NlnsStale
            5 => NeighborState::Reachable,   // NlnsReachable
            6 => NeighborState::Permanent,   // NlnsPermanent
            _ => NeighborState::Other,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Neighbor {
    pub ip: String,
    /// Formatted aa:bb:cc:dd:ee:ff. Absent for incomplete entries.
    pub mac: Option<String>,
    pub state: NeighborState,
    /// Adapter index the entry belongs to.
    pub interface_index: u32,
    /// True for multicast and broadcast pseudo-entries, which are not devices.
    pub is_multicast: bool,
}

impl Neighbor {
    /// The entry describes a real, distinct device on the network.
    pub fn is_device(&self) -> bool {
        self.state.indicates_presence() && !self.is_multicast && self.mac.is_some()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NeighborFacts {
    pub neighbors: Vec<Neighbor>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl NeighborFacts {
    pub fn devices(&self) -> impl Iterator<Item = &Neighbor> {
        self.neighbors.iter().filter(|n| n.is_device())
    }
}

#[cfg(windows)]
pub fn collect() -> Result<NeighborFacts, CollectorError> {
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpNetTable2, MIB_IPNET_TABLE2,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();

    let result = unsafe { GetIpNetTable2(AF_UNSPEC, &mut table) };
    if result.is_err() {
        return Err(CollectorError::Unavailable(format!(
            "Windows could not read the network neighbour table: {result:?}"
        )));
    }

    let mut facts = NeighborFacts {
        neighbors: Vec::new(),
        evidence: vec![
            "Windows API: GetIpNetTable2 (IP Helper)".to_string(),
            "Passive: reads Windows' existing ARP/NDP cache, sends no packets".to_string(),
        ],
        collected_at: chrono::Utc::now().to_rfc3339(),
    };

    unsafe {
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);

        for row in rows {
            let ip = match row.Address.si_family {
                AF_INET => {
                    let octets = row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                AF_INET6 => IpAddr::V6(Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte)),
                _ => continue,
            };

            let mac_len = row.PhysicalAddressLength as usize;
            let mac = (mac_len > 0 && mac_len <= row.PhysicalAddress.len()).then(|| {
                row.PhysicalAddress[..mac_len]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            });

            facts.neighbors.push(Neighbor {
                is_multicast: is_multicast(&ip),
                ip: ip.to_string(),
                mac,
                state: NeighborState::from_raw(row.State.0),
                interface_index: row.InterfaceIndex,
            });
        }

        FreeMibTable(table as *const _);
    }

    let device_count = facts.devices().count();
    facts.evidence.push(format!(
        "{} table entries, {} of them distinct devices",
        facts.neighbors.len(),
        device_count
    ));

    Ok(facts)
}

/// Multicast and broadcast addresses are protocol machinery, not devices.
fn is_multicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast() || v4.octets()[3] == 255,
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

#[cfg(not(windows))]
pub fn collect() -> Result<NeighborFacts, CollectorError> {
    Err(CollectorError::Unsupported(
        "The neighbour table is only readable on Windows.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn neighbor(ip: &str, mac: Option<&str>, state: NeighborState) -> Neighbor {
        let parsed: IpAddr = ip.parse().unwrap();
        Neighbor {
            is_multicast: is_multicast(&parsed),
            ip: ip.to_string(),
            mac: mac.map(str::to_string),
            state,
            interface_index: 1,
        }
    }

    #[test]
    fn reachable_and_stale_entries_are_devices() {
        for state in [
            NeighborState::Reachable,
            NeighborState::Stale,
            NeighborState::Permanent,
        ] {
            assert!(
                neighbor("192.168.1.1", Some("aa:bb:cc:dd:ee:ff"), state).is_device(),
                "{state:?} should count as a device"
            );
        }
    }

    #[test]
    fn unreachable_entries_are_not_devices() {
        // The table records failed lookups too. Reporting one as a device
        // would invent hardware that is not on the network.
        assert!(!neighbor(
            "192.168.1.99",
            Some("aa:bb:cc:dd:ee:ff"),
            NeighborState::Unreachable
        )
        .is_device());
        assert!(!neighbor(
            "192.168.1.99",
            Some("aa:bb:cc:dd:ee:ff"),
            NeighborState::Probing
        )
        .is_device());
    }

    #[test]
    fn entries_without_a_mac_are_not_devices() {
        assert!(!neighbor("192.168.1.50", None, NeighborState::Reachable).is_device());
    }

    #[test]
    fn multicast_and_broadcast_are_excluded() {
        assert!(
            is_multicast(&"224.0.0.251".parse().unwrap()),
            "mDNS multicast"
        );
        assert!(
            is_multicast(&"239.255.255.250".parse().unwrap()),
            "SSDP multicast"
        );
        assert!(
            is_multicast(&"255.255.255.255".parse().unwrap()),
            "broadcast"
        );
        assert!(
            is_multicast(&"192.168.1.255".parse().unwrap()),
            "subnet broadcast"
        );
        assert!(is_multicast(&"ff02::1".parse().unwrap()), "IPv6 all-nodes");

        assert!(!is_multicast(&"192.168.1.1".parse().unwrap()));
        assert!(!is_multicast(&"fe80::1".parse().unwrap()));

        assert!(
            !neighbor(
                "224.0.0.251",
                Some("01:00:5e:00:00:fb"),
                NeighborState::Permanent
            )
            .is_device(),
            "a multicast group is not a device"
        );
    }

    #[test]
    fn raw_states_map_to_the_documented_meanings() {
        assert_eq!(NeighborState::from_raw(5), NeighborState::Reachable);
        assert_eq!(NeighborState::from_raw(4), NeighborState::Stale);
        assert_eq!(NeighborState::from_raw(6), NeighborState::Permanent);
        assert_eq!(NeighborState::from_raw(0), NeighborState::Unreachable);
        assert_eq!(NeighborState::from_raw(99), NeighborState::Other);
    }

    #[test]
    fn devices_filters_the_table() {
        let facts = NeighborFacts {
            neighbors: vec![
                neighbor(
                    "192.168.1.1",
                    Some("aa:bb:cc:dd:ee:01"),
                    NeighborState::Reachable,
                ),
                neighbor(
                    "192.168.1.2",
                    Some("aa:bb:cc:dd:ee:02"),
                    NeighborState::Unreachable,
                ),
                neighbor(
                    "224.0.0.251",
                    Some("01:00:5e:00:00:fb"),
                    NeighborState::Permanent,
                ),
                neighbor("192.168.1.3", None, NeighborState::Reachable),
            ],
            evidence: vec![],
            collected_at: String::new(),
        };
        assert_eq!(facts.devices().count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn reading_the_table_on_this_machine_works() {
        let facts = collect().expect("the neighbour table should be readable");
        assert!(facts.evidence.iter().any(|e| e.contains("GetIpNetTable2")));
        // A machine on a network has almost always spoken to its gateway, but
        // an empty table is still a legitimate answer, so this only checks the
        // call succeeded and reported its provenance.
    }
}

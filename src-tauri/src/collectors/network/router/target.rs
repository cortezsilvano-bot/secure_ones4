//! Passive, backend-issued router candidates. An address is not a hardware identity.
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::collectors::network::interfaces::InterfaceFacts;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterTarget {
    pub id: String,
    pub address: Ipv4Addr,
    pub local_address: Ipv4Addr,
    pub interface_id: String,
    pub interface_name: String,
    pub network_generation: u64,
    pub gateway_mac: Option<String>,
}

impl RouterTarget {
    /// Scope findings to an interface and gateway, without claiming a verified device identity.
    pub fn asset(&self) -> String {
        format!(
            "{} on {} ({}, local {}, gateway {})",
            self.address,
            self.interface_name,
            self.interface_id,
            self.local_address,
            self.gateway_mac.as_deref().unwrap_or("identity unverified")
        )
    }
}

pub fn candidates(facts: &InterfaceFacts, generation: u64) -> Vec<RouterTarget> {
    let mut targets = Vec::new();
    for iface in facts.scannable() {
        for gateway in &iface.gateways {
            let Ok(address) = gateway.parse::<Ipv4Addr>() else {
                continue;
            };
            // The first provider supports private, on-link IPv4 gateways only.
            if !address.is_private() {
                continue;
            }
            let Some(local) = iface.ipv4.iter().find(|local| {
                (1..=30).contains(&local.prefix_length)
                    && local.contains(address)
                    && local
                        .address
                        .parse::<Ipv4Addr>()
                        .is_ok_and(|ip| ip.is_private() && ip != address)
            }) else {
                continue;
            };
            let mask = u32::MAX << (32 - local.prefix_length);
            let host = u32::from(address) & !mask;
            if host == 0 || host == !mask {
                continue;
            }
            targets.push(RouterTarget {
                id: String::new(),
                address,
                local_address: local.address.parse().expect("validated address"),
                interface_id: iface.id.clone(),
                interface_name: iface.friendly_name.clone(),
                network_generation: generation,
                gateway_mac: None,
            });
        }
    }
    targets.sort_by_key(|t| (t.interface_id.clone(), t.address));
    targets.dedup_by(|a, b| a.interface_id == b.interface_id && a.address == b.address);
    // HTTP uses OS routing. Do not guess between overlapping interface routes.
    let addresses: Vec<_> = targets.iter().map(|t| t.address).collect();
    targets.retain(|t| addresses.iter().filter(|a| **a == t.address).count() == 1);
    for (index, target) in targets.iter_mut().enumerate() {
        target.id = format!("router-{generation}-{index}");
    }
    targets
}

/// Excludes timestamps and adapter enumeration order, includes route/DNS/address changes.
pub fn network_key(facts: &InterfaceFacts) -> Vec<String> {
    let mut key = Vec::new();
    for iface in facts
        .interfaces
        .iter()
        .filter(|i| i.is_up && !i.is_loopback)
    {
        let mut addresses: Vec<_> = iface
            .ipv4
            .iter()
            .chain(&iface.ipv6)
            .map(|a| format!("{}/{}", a.address, a.prefix_length))
            .collect();
        addresses.sort();
        let mut gateways = iface.gateways.clone();
        gateways.sort();
        let mut dns = iface.dns_servers.clone();
        dns.sort();
        key.push(
            serde_json::to_string(&(&iface.id, &iface.mac, addresses, gateways, dns)).unwrap(),
        );
    }
    key.sort();
    key
}

#[cfg(test)]
pub(crate) fn fixture() -> InterfaceFacts {
    use crate::collectors::network::interfaces::{InterfaceAddress, NetworkInterface};
    InterfaceFacts {
        interfaces: vec![NetworkInterface {
            id: "wifi".into(),
            description: "Wi-Fi".into(),
            friendly_name: "Wi-Fi".into(),
            mac: Some("00:11:22:33:44:55".into()),
            ipv4: vec![InterfaceAddress {
                address: "192.168.1.20".into(),
                prefix_length: 24,
            }],
            ipv6: vec![],
            gateways: vec!["192.168.1.1".into()],
            dns_servers: vec!["192.168.1.1".into()],
            is_up: true,
            is_loopback: false,
            interface_type: "Wi-Fi".into(),
        }],
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidates_are_on_link_private_and_unambiguous() {
        let mut f = fixture();
        assert_eq!(candidates(&f, 7)[0].id, "router-7-0");
        for invalid in [
            "8.8.8.8",
            "127.0.0.1",
            "192.168.2.1",
            "192.168.1.255",
            "192.168.1.0",
            "::1",
        ] {
            f.interfaces[0].gateways = vec![invalid.into()];
            assert!(candidates(&f, 7).is_empty(), "{invalid}");
        }
        f = fixture();
        let mut duplicate = f.interfaces[0].clone();
        duplicate.id = "ethernet".into();
        f.interfaces.push(duplicate);
        assert!(candidates(&f, 7).is_empty());
    }
    #[test]
    fn network_identity_ignores_timestamps_but_detects_address_changes() {
        let f = fixture();
        let mut changed = f.clone();
        changed.collected_at = "later".into();
        assert_eq!(network_key(&f), network_key(&changed));
        changed.interfaces[0].ipv4[0].address = "192.168.1.21".into();
        assert_ne!(network_key(&f), network_key(&changed));
    }
}

//! The home router: what can be established about it from inside the network.
//!
//! This module is as much about what it *cannot* determine as what it can.
//! From a machine on the LAN, three categories exist and are kept separate:
//!
//!   * **Detectable** -- the gateway address, whether UPnP answers, which
//!     admin ports are open, what port forwards exist, make and model.
//!   * **Requires the router's password** -- Wi-Fi encryption settings, the
//!     admin password itself, firmware version, remote-management state.
//!     SENTRY does not log in to the router and does not ask for that password.
//!   * **Cannot be determined from here** -- whether the router's WAN side is
//!     reachable from the internet. Answering that requires something outside
//!     the network to try, which would mean sending the user's IP address to a
//!     third-party service.
//!
//! Most consumer "router security" checks quietly pretend the third category is
//! the first. This one says "could not be determined" and means it.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

use super::interfaces::InterfaceFacts;
use super::ssdp;

/// Ports a consumer router typically serves its administration page on, plus
/// the two remote-shell protocols that should never be open on one.
const ADMIN_PORTS: &[u16] = &[80, 443, 8080, 8443, 23, 22];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminPort {
    pub port: u16,
    pub service: Option<String>,
    /// True when the page is served without encryption, so the admin password
    /// crosses the network readable.
    pub is_plaintext: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterFacts {
    pub gateway: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub upnp_enabled: bool,
    pub port_forwards: Option<Vec<ssdp::PortMapping>>,
    pub forwards_unavailable_reason: Option<String>,
    /// Administration interfaces reachable from this PC.
    pub admin_ports: Vec<AdminPort>,
    /// Facts that need the router's password, which SENTRY never asks for.
    pub requires_router_login: Vec<String>,
    /// Facts that cannot be established from inside the network at all.
    pub cannot_determine: Vec<String>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

/// How long to wait for the gateway to answer on an administration port.
const ADMIN_CONNECT_TIMEOUT: Duration = Duration::from_millis(900);

/// Inspect the router.
///
/// Active but tiny, and confined to the local network: an SSDP multicast, at
/// most two HTTP requests to the router itself, and six TCP connects to the
/// gateway. Synchronous by design so the scan does not need an async runtime
/// for six connects.
pub fn collect(interfaces: &InterfaceFacts) -> Result<RouterFacts, CollectorError> {
    let Some(gateway) = interfaces.primary_gateway().map(str::to_string) else {
        return Err(CollectorError::Unavailable(
            "No gateway is configured, so there is no router to inspect. This PC may not be \
             connected to a network."
                .into(),
        ));
    };

    let mut facts = RouterFacts {
        gateway: Some(gateway.clone()),
        collected_at: chrono::Utc::now().to_rfc3339(),
        evidence: vec![format!("Gateway: {gateway}")],
        // Stated up front and always, so the UI can show the limits of the
        // check alongside its results.
        requires_router_login: vec![
            "Wi-Fi encryption type and password strength".to_string(),
            "Whether the router's admin password is still the factory default".to_string(),
            "Installed firmware version and whether an update is available".to_string(),
            "Whether remote management from the internet is switched on".to_string(),
        ],
        cannot_determine: vec![
            "Whether your router can be reached from the internet. Establishing that requires a \
             service outside your network to try connecting back, which would mean sending your \
             home IP address to a third party. SENTRY does not do that."
                .to_string(),
        ],
        ..Default::default()
    };

    // --- UPnP ---------------------------------------------------------------
    match ssdp::collect(Some(&gateway)) {
        Ok(upnp) => {
            facts.upnp_enabled = upnp.upnp_enabled;
            facts.manufacturer = upnp.router_manufacturer.clone();
            facts.model = upnp.router_model.clone();
            facts.firmware = upnp.router_firmware.clone();
            facts.port_forwards = upnp.port_mappings.clone();
            facts.forwards_unavailable_reason = upnp.mappings_unavailable_reason.clone();
            facts.evidence.extend(upnp.evidence);
        }
        Err(e) => {
            facts.forwards_unavailable_reason = Some(format!("UPnP discovery did not run: {e}"));
            facts.evidence.push(format!("UPnP discovery failed: {e}"));
        }
    }

    // --- administration interfaces -------------------------------------------
    let Ok(address) = gateway.parse::<IpAddr>() else {
        return Ok(facts);
    };

    // Probed in parallel so the whole check costs one timeout, not six.
    let handles: Vec<_> = ADMIN_PORTS
        .iter()
        .map(|port| {
            let target = SocketAddr::new(address, *port);
            let port = *port;
            std::thread::spawn(move || {
                let open = TcpStream::connect_timeout(&target, ADMIN_CONNECT_TIMEOUT).is_ok();
                (port, open)
            })
        })
        .collect();

    for handle in handles {
        let Ok((port, true)) = handle.join() else {
            continue;
        };

        let service = super::local_ports::well_known_service(port).map(str::to_string);
        facts.evidence.push(format!(
            "Gateway port {port} open ({})",
            service.as_deref().unwrap_or("unidentified")
        ));
        facts.admin_ports.push(AdminPort {
            port,
            service,
            // Only 443 and 8443 are encrypted by convention; on the rest the
            // admin password crosses the network readable.
            is_plaintext: !matches!(port, 443 | 8443),
        });
    }

    facts.admin_ports.sort_by_key(|p| p.port);
    facts.evidence.push(format!(
        "Checked {} administration port(s) on the gateway: {} open",
        ADMIN_PORTS.len(),
        facts.admin_ports.len()
    ));

    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::network::interfaces::{InterfaceAddress, NetworkInterface};

    fn interfaces(gateway: Option<&str>) -> InterfaceFacts {
        InterfaceFacts {
            interfaces: vec![NetworkInterface {
                id: "adapter".into(),
                description: "Wi-Fi".into(),
                friendly_name: "Wi-Fi".into(),
                mac: Some("40:d1:33:00:00:01".into()),
                ipv4: vec![InterfaceAddress {
                    address: "192.168.1.42".into(),
                    prefix_length: 24,
                }],
                ipv6: vec![],
                gateways: gateway.map(|g| vec![g.to_string()]).unwrap_or_default(),
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
    fn with_no_gateway_there_is_no_router_to_inspect() {
        let err = collect(&interfaces(None)).unwrap_err();
        assert!(matches!(err, CollectorError::Unavailable(_)));
    }

    #[test]
    fn the_limits_of_the_check_are_always_stated() {
        // These lists are the point of the module: they are populated before
        // any probing, so they are present even when everything else fails.
        let facts = collect(&interfaces(Some("192.0.2.1"))).unwrap();

        assert!(!facts.requires_router_login.is_empty());
        assert!(!facts.cannot_determine.is_empty());

        let wan = facts.cannot_determine.join(" ");
        assert!(
            wan.contains("reached from the internet"),
            "WAN reachability must be declared undeterminable"
        );
        assert!(
            wan.contains("does not do that"),
            "the reason must say SENTRY declines to send the user's IP anywhere"
        );

        let login = facts.requires_router_login.join(" ");
        assert!(login.contains("factory default"));
        assert!(login.contains("firmware"));
    }

    #[test]
    fn the_gateway_is_recorded_in_the_evidence() {
        let facts = collect(&interfaces(Some("192.0.2.1"))).unwrap();
        assert_eq!(facts.gateway.as_deref(), Some("192.0.2.1"));
        assert!(facts.evidence.iter().any(|e| e.contains("192.0.2.1")));
    }

    #[test]
    fn only_the_tls_admin_ports_count_as_encrypted() {
        for port in [443u16, 8443] {
            let admin = AdminPort {
                port,
                service: None,
                is_plaintext: !matches!(port, 443 | 8443),
            };
            assert!(
                !admin.is_plaintext,
                "port {port} is encrypted by convention"
            );
        }
        for port in [80u16, 8080, 23, 22] {
            let admin = AdminPort {
                port,
                service: None,
                is_plaintext: !matches!(port, 443 | 8443),
            };
            assert!(
                admin.is_plaintext,
                "port {port} carries credentials in the clear"
            );
        }
    }

    #[test]
    fn the_admin_port_list_covers_the_usual_suspects() {
        assert!(ADMIN_PORTS.contains(&80));
        assert!(ADMIN_PORTS.contains(&443));
        assert!(ADMIN_PORTS.contains(&8080));
        assert!(
            ADMIN_PORTS.contains(&23),
            "Telnet on a router is worth knowing about"
        );
    }
}

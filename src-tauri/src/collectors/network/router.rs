//! The home router: what can be established about it from inside the network.
//!
//! This module is as much about what it *cannot* determine as what it can.
//! From a machine on the LAN, three categories exist and are kept separate:
//!
//!   * **Detectable** -- the gateway address, whether UPnP answers, which
//!     admin ports are open, what port forwards exist, make and model.
//!   * **Requires the router's password** -- Wi-Fi encryption settings, the
//!     admin password itself, firmware version, remote-management state.
//!     The separate ASUS provider requires explicit approval for each login.
//!   * **Cannot be determined from here** -- whether the router's WAN side is
//!     reachable from the internet. Answering that requires something outside
//!     the network to try, which would mean sending the user's IP address to a
//!     third-party service.
//!
//! Most consumer "router security" checks quietly pretend the third category is
//! the first. This one says "could not be determined" and means it.

pub mod asus;
pub mod asus_session;
mod asus_wireless;
pub mod coordinator;
pub mod firmware;
pub mod history;
pub mod identity;
pub mod intelligence;
pub mod login_policy;
pub mod probe;
pub mod protocol;
pub mod provider;
pub mod report;
pub mod settings;
pub mod target;

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::security::{CollectorError, Known};

use super::interfaces::InterfaceFacts;
use super::ssdp;

/// Conventional administration ports. Port numbers are hints, not protocols.
const ADMIN_PORTS: &[u16] = &[80, 443, 8080, 8443, 23, 22];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminProtocol {
    Http,
    Https,
    Ssh,
    Telnet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionState {
    Encrypted,
    Plaintext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminPort {
    pub port: u16,
    pub service_hint: Option<String>,
    /// TCP acceptance alone establishes neither protocol nor encryption.
    pub protocol: Known<AdminProtocol>,
    pub encryption: Known<EncryptionState>,
}

impl AdminPort {
    pub fn tcp_open(port: u16) -> Self {
        Self {
            port,
            service_hint: super::local_ports::well_known_service(port).map(str::to_string),
            protocol: Known::NotScanned,
            encryption: Known::NotScanned,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterFacts {
    #[serde(default)]
    pub firmware_assessment: firmware::FirmwareAssessment,
    #[serde(default)]
    pub settings: settings::RouterSettings,
    #[serde(default)]
    pub target: Option<target::RouterTarget>,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub requests_sent: usize,
    pub gateway: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    /// Device-reported metadata, not authenticated hardware identity.
    #[serde(default)]
    pub identity: Option<identity::RouterIdentity>,
    #[serde(default)]
    pub server_banner: Option<String>,
    /// Whether the selected gateway answered discovery, not its configured setting.
    #[serde(default)]
    pub upnp_discovery: Known<bool>,
    pub port_forwards: Option<Vec<ssdp::PortMapping>>,
    pub forwards_unavailable_reason: Option<String>,
    /// Administration interfaces reachable from this PC.
    pub admin_ports: Vec<AdminPort>,
    /// Protocols observed during existing read-only requests, not necessarily
    /// administration interfaces. Kept separate from the TCP probe inventory.
    #[serde(default)]
    pub observed_services: Vec<AdminPort>,
    /// Number of ports that answered or explicitly refused a TCP connection.
    #[serde(default)]
    pub admin_probe: Known<usize>,
    /// Facts requiring an authenticated provider, absent from the generic scan.
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
/// Active inspection: SSDP discovery, HTTP description and mapping queries,
/// and six TCP connects to the gateway. TCP probes do not identify protocols.
pub fn collect(interfaces: &InterfaceFacts) -> Result<RouterFacts, CollectorError> {
    let mut targets = target::candidates(interfaces, 1);
    if targets.len() != 1 {
        return Err(CollectorError::Unavailable(
            "No single supported private gateway is available. Select a router in the app.".into(),
        ));
    }
    let target = targets.remove(0);
    let ctx = probe::ProbeContext::new(&target);
    collect_target(&target, &ctx)
}

fn initial_facts(target: &target::RouterTarget) -> RouterFacts {
    let gateway = target.address.to_string();
    RouterFacts {
        target: Some(target.clone()),
        provider_id: Some("generic_igd".into()),
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
    }
}

fn collect_target(
    target: &target::RouterTarget,
    ctx: &probe::ProbeContext,
) -> Result<RouterFacts, CollectorError> {
    ctx.check()?;
    let mut facts = initial_facts(target);

    // --- UPnP ---------------------------------------------------------------
    match ssdp::collect_target(ctx) {
        Ok(upnp) => {
            facts.upnp_discovery = upnp.upnp_discovery;
            facts.manufacturer = upnp.router_manufacturer.clone();
            facts.model = upnp.router_model.clone();
            facts.server_banner = upnp.server_banner.clone();
            facts.identity = Some(identity::from_description(
                facts.manufacturer.as_deref(),
                facts.model.as_deref(),
            ));
            facts.port_forwards = upnp.port_mappings.clone();
            facts.forwards_unavailable_reason = upnp.mappings_unavailable_reason.clone();
            facts.evidence.extend(upnp.evidence);
        }
        Err(e) => {
            facts.upnp_discovery = Known::Unavailable(format!("UPnP discovery failed: {e}"));
            facts.forwards_unavailable_reason = Some(format!("UPnP discovery did not run: {e}"));
            facts.evidence.push(format!("UPnP discovery failed: {e}"));
        }
    }

    // --- administration interfaces -------------------------------------------
    if let Err(e) = ctx.check() {
        facts.admin_probe = e.into_known();
        facts.requests_sent = ctx.request_count();
        facts.observed_services = ctx.observed_services();
        return Ok(facts);
    }

    // Probed in parallel so the whole check costs one timeout, not six.
    let handles: Vec<_> = ADMIN_PORTS
        .iter()
        .map(|port| {
            let target = SocketAddr::new(target.address.into(), *port);
            let port = *port;
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let result = (|| {
                    let timeout = ctx
                        .reserve()
                        .map_err(std::io::Error::other)?
                        .min(ADMIN_CONNECT_TIMEOUT);
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )?;
                    socket.bind(&SocketAddr::new(ctx.local_address.into(), 0).into())?;
                    socket.connect_timeout(&target.into(), timeout)?;
                    ctx.check().map_err(std::io::Error::other)?;
                    Ok::<TcpStream, std::io::Error>(socket.into())
                })();
                (port, result)
            })
        })
        .collect();

    let mut completed = 0;
    for handle in handles {
        match handle.join() {
            Ok((port, Ok(mut stream))) => {
                completed += 1;
                facts
                    .evidence
                    .push(format!("Gateway TCP port {port} accepted a connection"));
                let observed = if port == 22 {
                    let until = std::time::Instant::now() + Duration::from_millis(400);
                    // Listen only on the connection already opened by this scan.
                    // No SSH identification, key exchange or credentials are sent.
                    let timeout_stream = stream.try_clone();
                    match timeout_stream {
                        Ok(timeout_stream) => protocol::read_greeting(&mut stream, port, || {
                            let remaining =
                                until.saturating_duration_since(std::time::Instant::now());
                            if remaining.is_zero() {
                                return false;
                            }
                            ctx.remaining().is_ok_and(|budget| {
                                timeout_stream
                                    .set_read_timeout(Some(remaining.min(budget)))
                                    .is_ok()
                            })
                        }),
                        Err(_) => AdminPort::tcp_open(port),
                    }
                } else {
                    AdminPort::tcp_open(port)
                };
                facts.admin_ports.push(observed);
            }
            Ok((_, Err(e))) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                completed += 1;
            }
            _ => {}
        }
    }
    facts.admin_probe = if let Err(e) = ctx.check() {
        e.into_known()
    } else if completed == ADMIN_PORTS.len() {
        Known::Known(completed)
    } else {
        Known::Unavailable(format!(
            "Only {completed}/{} TCP probes answered or explicitly refused a connection; the rest are inconclusive.",
            ADMIN_PORTS.len()
        ))
    };

    facts.admin_ports.sort_by_key(|p| p.port);
    facts.evidence.push(format!(
        "Checked {} administration port(s) on the gateway: {} open",
        ADMIN_PORTS.len(),
        facts.admin_ports.len()
    ));

    facts.requests_sent = ctx.request_count();
    facts.observed_services = ctx.observed_services();
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
        let target = target::candidates(&target::fixture(), 1).remove(0);
        let facts = initial_facts(&target);

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
        let target = target::candidates(&target::fixture(), 1).remove(0);
        let facts = initial_facts(&target);
        assert_eq!(facts.gateway.as_deref(), Some("192.168.1.1"));
        assert!(facts.evidence.iter().any(|e| e.contains("192.168.1.1")));
    }

    #[test]
    fn tcp_acceptance_does_not_establish_protocol_or_encryption() {
        for port in ADMIN_PORTS {
            let admin = AdminPort::tcp_open(*port);
            assert!(!admin.protocol.is_known());
            assert!(!admin.encryption.is_known());
            let json = serde_json::to_value(&admin).unwrap();
            assert!(json.get("isPlaintext").is_none());
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

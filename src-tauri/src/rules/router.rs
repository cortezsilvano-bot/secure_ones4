//! Rules over the home router.

use crate::collectors::network::router::{AdminProtocol, EncryptionState, RouterFacts};
use crate::findings::{Confidence, Finding, FindingBuilder, Severity};
use crate::security::Known;

const SOURCE: &str = "network.router";
const CATEGORY: &str = "Router";

/// Conventional TCP destination ports that warrant review, not verified services.
fn forward_risk(
    mapping: &crate::collectors::network::ssdp::PortMapping,
) -> Option<(Severity, &'static str)> {
    // Destination port is a service hint; neither endpoint proves a protocol.
    if !mapping.protocol.eq_ignore_ascii_case("TCP") {
        return None;
    }
    Some(match mapping.internal_port {
        23 => (
            Severity::Critical,
            "Telnet, which sends passwords in plain text",
        ),
        3389 => (
            Severity::Critical,
            "Remote Desktop, which gives full control of a PC",
        ),
        5900 => (Severity::Critical, "VNC remote control"),
        22 => (Severity::Warning, "SSH remote access"),
        445 | 139 => (Severity::Critical, "Windows file sharing"),
        1433 | 3306 | 5432 | 27017 | 6379 => (Severity::Critical, "a database"),
        21 => (
            Severity::Warning,
            "FTP, which sends passwords in plain text",
        ),
        _ => return None,
    })
}

pub fn evaluate(f: &RouterFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    out.extend(port_forward_findings(f));
    out.extend(admin_interface_findings(f));
    out.extend(observed_protocol_findings(f));
    out.extend(super::router_settings::evaluate(f));

    // RTR-004 -- the gateway answered and its mapping table was readable.
    //
    // Only raised when the forward list was actually readable: warning about
    // UPnP while unable to see what it has done would be alarming without
    // being useful.
    if matches!(f.upnp_discovery, Known::Known(true)) && f.port_forwards.is_some() && out.is_empty()
    {
        out.push(
            FindingBuilder::new(
                "RTR-004",
                CATEGORY,
                Severity::Attention,
                "Your router answered UPnP queries",
            )
            .what("SENTRY read the router's UPnP mapping table. No risky destination ports were identified in that table.")
            .why(
                "UPnP can let applications request port forwards. SENTRY only read the table; it did not test permission to create mappings or public Internet reachability. Static forwards and other exposure paths may not appear here.",
            )
            .confidence(Confidence::Confirmed)
            .evidence(f.evidence.clone())
            .remediation(
                "If nothing on your network needs it, turning UPnP off in your router's settings closes this off."
            )
            .source(SOURCE)
            .build(),
        );
    }

    if let Some(target) = &f.target {
        let asset = target.asset();
        for finding in &mut out {
            finding.id = Finding::id_for(&finding.rule_id, Some(&asset));
            finding.affected_asset = Some(asset.clone());
            finding.evidence.push(format!(
                "Provider: {}; target: {}; network generation: {}; observed: {}",
                f.provider_id.as_deref().unwrap_or("unknown"),
                target.id,
                target.network_generation,
                f.collected_at
            ));
        }
    }
    out
}

fn port_forward_findings(f: &RouterFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    let Some(forwards) = &f.port_forwards else {
        return out;
    };

    let active: Vec<_> = forwards.iter().filter(|m| m.enabled).collect();
    if active.is_empty() {
        return out;
    }

    // RTR-001 -- a mapping targets a port commonly used by a sensitive service.
    let risky: Vec<_> = active
        .iter()
        .filter_map(|m| forward_risk(m).map(|(sev, what)| (m, sev, what)))
        .collect();

    if !risky.is_empty() {
        let worst = risky
            .iter()
            .map(|(_, sev, _)| *sev)
            .max()
            .unwrap_or(Severity::Warning);

        let mut evidence = vec![format!("{} port forward(s) are active", active.len())];
        for (mapping, _, what) in &risky {
            evidence.push(format!(
                "  Configured external port {} -> {}:{} ({}) uses a destination port commonly associated with {what}, described as \"{}\"",
                mapping.external_port,
                mapping.internal_client,
                mapping.internal_port,
                mapping.protocol,
                mapping.description
            ));
        }

        out.push(
            FindingBuilder::new(
                "RTR-001",
                CATEGORY,
                worst,
                &format!(
                    "{} configured port forward{} may target risky services",
                    risky.len(),
                    if risky.len() == 1 { "" } else { "s" },
                ),
            )
            .what(
                "The router has enabled UPnP mappings to destination ports commonly used by sensitive services. The service identity is inferred from the destination TCP port, not verified.",
            )
            .why(
                "If reachable, these services could allow remote access to your devices. SENTRY did not verify public Internet reachability; upstream firewalls, double NAT or CGNAT may block access.",
            )
            .confidence(Confidence::Potential)
            .evidence(evidence)
            .remediation(
                "Remove the port forwards you did not create deliberately, in your router's port forwarding settings."
            )
            .source(SOURCE)
            .build(),
        );
    }

    // RTR-002 -- mappings without a recognized sensitive TCP destination hint.
    let ordinary: Vec<_> = active
        .iter()
        .filter(|m| forward_risk(m).is_none())
        .collect();

    if !ordinary.is_empty() {
        let mut evidence = vec![format!("{} port forward(s) active", ordinary.len())];
        for mapping in ordinary.iter().take(10) {
            evidence.push(format!(
                "  Configured external port {} -> {}:{} ({}) \"{}\"",
                mapping.external_port,
                mapping.internal_client,
                mapping.internal_port,
                mapping.protocol,
                mapping.description
            ));
        }

        out.push(
            FindingBuilder::new(
                "RTR-002",
                CATEGORY,
                Severity::Attention,
                &format!(
                    "{} enabled UPnP port forward{} configured",
                    ordinary.len(),
                    if ordinary.len() == 1 { "" } else { "s" },
                ),
            )
            .what("Your router reports enabled UPnP port mappings to devices on your network. SENTRY did not verify public Internet reachability.")
            .why(
                "These are usually created automatically by games, consoles or media servers and \
                 are often perfectly fine. They are listed because a forward you do not recognise \
                 is worth removing, and most people never see this list.",
            )
            .confidence(Confidence::Confirmed)
            .evidence(evidence)
            .remediation(
                "Check these against what you actually use, and remove any you do not recognise."
            )
            .source(SOURCE)
            .build(),
        );
    }

    out
}

fn admin_interface_findings(f: &RouterFacts) -> Vec<Finding> {
    let ports: Vec<_> = f
        .admin_ports
        .iter()
        .filter(|p| {
            matches!(p.port, 22 | 23)
                && !p.protocol.is_known()
                && !f
                    .observed_services
                    .iter()
                    .any(|service| service.port == p.port && service.protocol.is_known())
        })
        .collect();
    if ports.is_empty() {
        return vec![];
    }
    vec![FindingBuilder::new(
        "RTR-003", CATEGORY, Severity::Warning,
        "Router ports commonly used for remote shells are open",
    )
    .what(&format!("The gateway at {} accepted TCP connections on {}. Protocol, encryption and authentication were not checked.",
        f.gateway.as_deref().unwrap_or("an unknown address"),
        ports.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(", ")))
    .why("Ports 22 and 23 are commonly used for SSH and Telnet. An open port alone does not establish which service is running. Review the router settings; disable remote shells you do not use.")
    .confidence(Confidence::Potential)
    .evidence(f.evidence.clone())
    .remediation("Check which services use these ports in your router settings. Disable unused remote-shell access.")
    .source(SOURCE)
    .build()]
}

fn observed_protocol_findings(f: &RouterFacts) -> Vec<Finding> {
    let mut out = Vec::new();
    let http: Vec<_> = f
        .admin_ports
        .iter()
        .chain(f.observed_services.iter())
        .filter(|p| {
            matches!(p.protocol, Known::Known(AdminProtocol::Http))
                && matches!(p.encryption, Known::Known(EncryptionState::Plaintext))
        })
        .collect();
    if !http.is_empty() {
        out.push(FindingBuilder::new("RTR-005", CATEGORY, Severity::Warning,
            "Your router answered using plaintext HTTP")
            .what("An HTTP response was observed over an unencrypted connection from this PC. This does not establish that the endpoint accepts login credentials or router configuration changes.")
            .why("The observed HTTP exchange had no transport encryption. SENTRY did not submit credentials or test public Internet reachability.")
            .confidence(Confidence::Confirmed)
            .evidence(http.iter().map(|p| format!("Gateway TCP port {}: HTTP response observed over plaintext transport", p.port)).collect::<Vec<_>>())
            .remediation("Review this endpoint in the router's settings. Check for a trusted HTTPS management interface before entering credentials.")
            .source(SOURCE).build());
    }
    let ssh: Vec<_> = f
        .admin_ports
        .iter()
        .chain(f.observed_services.iter())
        .filter(|p| matches!(p.protocol, Known::Known(AdminProtocol::Ssh)))
        .collect();
    if !ssh.is_empty() {
        out.push(FindingBuilder::new("RTR-006", CATEGORY, Severity::Attention,
            "Your router advertised SSH")
            .what("The gateway returned an SSH identification banner. A banner does not establish successful key exchange, encryption, authentication, or Internet reachability.")
            .why("SSH can provide administrative access. This observation identifies an advertised service; it does not establish that access is insecure.")
            .confidence(Confidence::Confirmed)
            .evidence(ssh.iter().map(|p| format!("Gateway TCP port {}: SSH identification observed", p.port)).collect::<Vec<_>>())
            .remediation("Review whether this service is expected in your router configuration.")
            .source(SOURCE).build());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::network::router::AdminPort;
    use crate::collectors::network::ssdp::PortMapping;

    fn mapping(external: u16, description: &str, enabled: bool) -> PortMapping {
        PortMapping {
            external_port: external,
            internal_port: external,
            internal_client: "192.168.1.50".into(),
            protocol: "TCP".into(),
            description: description.into(),
            enabled,
        }
    }

    fn facts() -> RouterFacts {
        RouterFacts {
            gateway: Some("192.168.1.1".into()),
            upnp_discovery: Known::Unavailable("No gateway response".into()),
            port_forwards: Some(vec![]),
            evidence: vec!["Gateway: 192.168.1.1".into()],
            ..Default::default()
        }
    }

    fn rule_ids(f: &RouterFacts) -> Vec<String> {
        evaluate(f).into_iter().map(|x| x.rule_id).collect()
    }

    #[test]
    fn plaintext_http_requires_both_protocol_and_transport_evidence() {
        use crate::collectors::network::router::protocol::{interpret, ObservedTransport};
        let mut f = facts();
        f.admin_ports = vec![interpret(
            443,
            b"HTTP/1.1 200 OK\r\n",
            ObservedTransport::PlainTcp,
        )];
        let found = evaluate(&f);
        let finding = found.iter().find(|x| x.rule_id == "RTR-005").unwrap();
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert!(finding.evidence.iter().any(|e| e.contains("443")));
        f.admin_ports[0].encryption = Known::NotScanned;
        assert!(!rule_ids(&f).contains(&"RTR-005".into()));
    }

    #[test]
    fn https_on_shell_port_does_not_raise_shell_or_plaintext_findings() {
        use crate::collectors::network::router::protocol::{interpret, ObservedTransport};
        let mut f = facts();
        f.admin_ports = vec![interpret(
            22,
            b"HTTP/1.1 200 OK\r\n",
            ObservedTransport::EstablishedTls,
        )];
        assert!(evaluate(&f).is_empty());
    }

    #[test]
    fn ssh_on_nonstandard_port_reports_only_banner_evidence() {
        use crate::collectors::network::router::protocol::{interpret, ObservedTransport};
        let mut f = facts();
        f.admin_ports = vec![interpret(
            2222,
            b"SSH-2.0-TestServer\r\n",
            ObservedTransport::PlainTcp,
        )];
        let found = evaluate(&f);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RTR-006");
        assert!(found[0].what_happened.contains("does not establish"));
        assert!(found[0].evidence.iter().any(|e| e.contains("2222")));
    }

    #[test]
    fn remapped_ssh_uses_the_destination_and_preserves_evidence() {
        let mut m = mapping(4567, "Remapped", true);
        m.internal_port = 22;
        let mut f = facts();
        f.port_forwards = Some(vec![m]);
        let found = evaluate(&f);
        let finding = found.iter().find(|f| f.rule_id == "RTR-001").unwrap();
        assert_eq!(finding.confidence, Confidence::Potential);
        assert!(finding
            .evidence
            .iter()
            .any(|e| e.contains("4567 -> 192.168.1.50:22 (TCP)") && e.contains("SSH")));
        assert!(finding
            .why_it_matters
            .contains("did not verify public Internet reachability"));
    }

    #[test]
    fn external_port_and_udp_do_not_confirm_ssh() {
        let mut remapped = mapping(22, "Other service", true);
        remapped.internal_port = 32400;
        let mut udp = mapping(4567, "UDP", true);
        udp.internal_port = 22;
        udp.protocol = "UDP".into();
        let mut f = facts();
        f.port_forwards = Some(vec![remapped, udp]);
        let found = evaluate(&f);
        assert!(!found.iter().any(|f| f.rule_id == "RTR-001"));
        let finding = found.iter().find(|f| f.rule_id == "RTR-002").unwrap();
        assert!(finding
            .what_happened
            .contains("did not verify public Internet reachability"));
        assert!(finding.evidence.iter().any(|e| e.contains("(UDP)")));
    }

    #[test]
    fn unknown_discovery_does_not_raise_an_enabled_upnp_finding() {
        let mut f = facts();
        f.upnp_discovery = Known::Unavailable("Timed out".into());
        assert!(!rule_ids(&f).contains(&"RTR-004".into()));
    }

    #[test]
    fn finding_identity_and_evidence_are_bound_to_the_router_target() {
        use crate::collectors::network::router::target;
        let mut f = facts();
        f.admin_ports = vec![AdminPort::tcp_open(22)];
        f.target = Some(target::candidates(&target::fixture(), 9).remove(0));
        f.provider_id = Some("generic_igd".into());
        let first = evaluate(&f).remove(0);
        assert!(first
            .evidence
            .iter()
            .any(|e| e.contains("network generation: 9") && e.contains("generic_igd")));
        f.target.as_mut().unwrap().address = "192.168.1.2".parse().unwrap();
        let second = evaluate(&f).remove(0);
        assert_ne!(first.id, second.id);
        assert_ne!(first.affected_asset, second.affected_asset);
    }

    #[test]
    fn a_router_with_nothing_forwarded_raises_nothing() {
        assert!(evaluate(&facts()).is_empty());
    }

    #[test]
    fn an_unreadable_forward_list_raises_nothing_rather_than_guessing() {
        // Not being able to read the forwards is a coverage gap, reported by
        // the tile's state, not a finding invented out of the absence.
        let mut f = facts();
        f.port_forwards = None;
        f.forwards_unavailable_reason = Some("router refused".into());
        f.upnp_discovery = Known::Known(true);

        assert!(evaluate(&f).is_empty());
    }

    #[test]
    fn a_forwarded_remote_desktop_is_critical() {
        let mut f = facts();
        f.port_forwards = Some(vec![mapping(3389, "RDP", true)]);

        let found = evaluate(&f);
        let rtr001 = found
            .iter()
            .find(|x| x.rule_id == "RTR-001")
            .expect("RTR-001");
        assert_eq!(rtr001.severity, Severity::Critical);
        assert!(rtr001.evidence.iter().any(|e| e.contains("Remote Desktop")));
    }

    #[test]
    fn a_disabled_forward_is_not_an_exposure() {
        let mut f = facts();
        f.port_forwards = Some(vec![mapping(3389, "Old rule", false)]);
        assert!(evaluate(&f).is_empty());
    }

    #[test]
    fn an_ordinary_forward_is_listed_without_alarm() {
        let mut f = facts();
        f.port_forwards = Some(vec![mapping(32400, "Plex Media Server", true)]);

        let found = evaluate(&f);
        let rtr002 = found
            .iter()
            .find(|x| x.rule_id == "RTR-002")
            .expect("RTR-002");
        assert_eq!(rtr002.severity, Severity::Attention);
        assert!(rtr002
            .evidence
            .iter()
            .any(|e| e.contains("Plex Media Server")));
        assert!(!rule_ids(&f).contains(&"RTR-001".to_string()));
    }

    #[test]
    fn risky_and_ordinary_forwards_are_reported_separately() {
        let mut f = facts();
        f.port_forwards = Some(vec![
            mapping(32400, "Plex", true),
            mapping(445, "Files", true),
        ]);

        let ids = rule_ids(&f);
        assert!(ids.contains(&"RTR-001".to_string()));
        assert!(ids.contains(&"RTR-002".to_string()));
    }

    #[test]
    fn a_telnet_port_hint_is_not_confirmed_plaintext() {
        let mut f = facts();
        f.admin_ports = vec![AdminPort::tcp_open(23)];

        let found = evaluate(&f);
        let rtr003 = found
            .iter()
            .find(|x| x.rule_id == "RTR-003")
            .expect("RTR-003");
        assert_eq!(rtr003.severity, Severity::Warning);
        assert_eq!(rtr003.confidence, Confidence::Potential);
        assert!(rtr003.what_happened.contains("not checked"));
    }

    #[test]
    fn ssh_on_the_router_is_a_warning_not_a_crisis() {
        let mut f = facts();
        f.admin_ports = vec![AdminPort::tcp_open(22)];

        let found = evaluate(&f);
        let rtr003 = found.iter().find(|x| x.rule_id == "RTR-003").unwrap();
        assert_eq!(rtr003.severity, Severity::Warning);
    }

    #[test]
    fn an_ordinary_web_admin_page_is_not_a_finding() {
        // Every home router serves one. Flagging it would be noise.
        let mut f = facts();
        f.admin_ports = vec![AdminPort::tcp_open(80), AdminPort::tcp_open(443)];
        assert!(evaluate(&f).is_empty());
    }

    #[test]
    fn upnp_alone_is_mentioned_once_nothing_worse_is_found() {
        let mut f = facts();
        f.upnp_discovery = Known::Known(true);
        f.port_forwards = Some(vec![]);

        let ids = rule_ids(&f);
        assert!(ids.contains(&"RTR-004".to_string()));

        // With a risky forward present, the forward is the story, not UPnP.
        f.port_forwards = Some(vec![mapping(3389, "RDP", true)]);
        let ids = rule_ids(&f);
        assert!(ids.contains(&"RTR-001".to_string()));
        assert!(!ids.contains(&"RTR-004".to_string()));
    }

    #[test]
    fn every_finding_carries_evidence() {
        let mut f = facts();
        f.upnp_discovery = Known::Known(true);
        f.port_forwards = Some(vec![
            mapping(3389, "RDP", true),
            mapping(32400, "Plex", true),
        ]);
        f.admin_ports = vec![AdminPort::tcp_open(23)];

        let found = evaluate(&f);
        assert!(found.len() >= 3);
        for finding in found {
            assert!(
                !finding.evidence.is_empty(),
                "{} has no evidence",
                finding.rule_id
            );
            assert!(!finding.why_it_matters.is_empty());
            assert_eq!(finding.source, SOURCE);
        }
    }
}

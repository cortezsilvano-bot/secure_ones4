//! Rules over the home router.

use crate::collectors::network::router::RouterFacts;
use crate::findings::{Confidence, Finding, FindingBuilder, FixRisk, Severity};

const SOURCE: &str = "network.router";
const CATEGORY: &str = "Router";

/// Forwarded ports that expose something a home user almost certainly did not
/// intend to publish to the internet.
fn forward_risk(port: u16) -> Option<(Severity, &'static str)> {
    Some(match port {
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

    // RTR-004 -- UPnP is on and nothing dangerous is forwarded yet.
    //
    // Only raised when the forward list was actually readable: warning about
    // UPnP while unable to see what it has done would be alarming without
    // being useful.
    if f.upnp_enabled && f.port_forwards.is_some() && out.is_empty() {
        out.push(
            FindingBuilder::new(
                "RTR-004",
                CATEGORY,
                Severity::Attention,
                "UPnP is turned on at your router",
            )
            .what("Your router lets devices on your network open ports to the internet by themselves.")
            .why(
                "UPnP is how a games console or media server opens the ports it needs without you \
                 doing anything. It also means any program on any device here can do the same, \
                 including one you did not install on purpose. Nothing is currently forwarded that \
                 looks risky.",
            )
            .confidence(Confidence::Confirmed)
            .evidence(f.evidence.clone())
            .remediation(
                "If nothing on your network needs it, turning UPnP off in your router's settings closes this off.",
                false,
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
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

    // RTR-001 -- a forward exposes something dangerous.
    let risky: Vec<_> = active
        .iter()
        .filter_map(|m| forward_risk(m.external_port).map(|(sev, what)| (m, sev, what)))
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
                "  Internet port {} -> {}:{} ({}) exposes {what}, described as \"{}\"",
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
                    "{} port forward{} expose{} risky services to the internet",
                    risky.len(),
                    if risky.len() == 1 { "" } else { "s" },
                    if risky.len() == 1 { "s" } else { "" }
                ),
            )
            .what(
                "Your router is forwarding connections from the internet straight through to a \
                 device on your network.",
            )
            .why(
                "A port forward is a hole through your router. Anything on the internet can reach \
                 the service on the other side of it, and these particular services are ones that \
                 get attacked continuously by automated scanners.",
            )
            .confidence(Confidence::Confirmed)
            .evidence(evidence)
            .remediation(
                "Remove the port forwards you did not create deliberately, in your router's port forwarding settings.",
                false,
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
    }

    // RTR-002 -- forwards exist, none of them obviously dangerous.
    let ordinary: Vec<_> = active
        .iter()
        .filter(|m| forward_risk(m.external_port).is_none())
        .collect();

    if !ordinary.is_empty() {
        let mut evidence = vec![format!("{} port forward(s) active", ordinary.len())];
        for mapping in ordinary.iter().take(10) {
            evidence.push(format!(
                "  Internet port {} -> {}:{} ({}) \"{}\"",
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
                    "{} thing{} on your network {} reachable from the internet",
                    ordinary.len(),
                    if ordinary.len() == 1 { "" } else { "s" },
                    if ordinary.len() == 1 { "is" } else { "are" }
                ),
            )
            .what("Your router is forwarding some internet traffic to devices on your network.")
            .why(
                "These are usually created automatically by games, consoles or media servers and \
                 are often perfectly fine. They are listed because a forward you do not recognise \
                 is worth removing, and most people never see this list.",
            )
            .confidence(Confidence::Confirmed)
            .evidence(evidence)
            .remediation(
                "Check these against what you actually use, and remove any you do not recognise.",
                false,
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
    }

    out
}

fn admin_interface_findings(f: &RouterFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    // RTR-003 -- remote-shell protocols on the router itself.
    let shells: Vec<_> = f
        .admin_ports
        .iter()
        .filter(|p| matches!(p.port, 22 | 23))
        .collect();

    if !shells.is_empty() {
        let has_telnet = shells.iter().any(|p| p.port == 23);

        out.push(
            FindingBuilder::new(
                "RTR-003",
                CATEGORY,
                if has_telnet { Severity::Critical } else { Severity::Warning },
                if has_telnet {
                    "Your router has Telnet open"
                } else {
                    "Your router has SSH open"
                },
            )
            .what(&format!(
                "The router at {} is accepting {} connections from your network.",
                f.gateway.as_deref().unwrap_or("your gateway"),
                if has_telnet { "Telnet" } else { "SSH" }
            ))
            .why(if has_telnet {
                "Telnet has no encryption at all, and routers that leave it open frequently ship \
                 with well-known default passwords. It is one of the main ways home routers get \
                 taken over and pulled into botnets."
            } else {
                "SSH gives command-line access to the router itself. That is fine if you set it up \
                 on purpose, and worth closing if you did not."
            })
            .confidence(Confidence::Confirmed)
            .evidence(f.evidence.clone())
            .remediation(
                "Turn off Telnet and SSH in your router's administration settings unless you use them.",
                false,
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
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
            upnp_enabled: false,
            port_forwards: Some(vec![]),
            evidence: vec!["Gateway: 192.168.1.1".into()],
            ..Default::default()
        }
    }

    fn rule_ids(f: &RouterFacts) -> Vec<String> {
        evaluate(f).into_iter().map(|x| x.rule_id).collect()
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
        f.upnp_enabled = true;

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
    fn telnet_on_the_router_is_critical() {
        let mut f = facts();
        f.admin_ports = vec![AdminPort {
            port: 23,
            service: Some("Telnet".into()),
            is_plaintext: true,
        }];

        let found = evaluate(&f);
        let rtr003 = found
            .iter()
            .find(|x| x.rule_id == "RTR-003")
            .expect("RTR-003");
        assert_eq!(rtr003.severity, Severity::Critical);
        assert!(rtr003.why_it_matters.contains("botnets"));
    }

    #[test]
    fn ssh_on_the_router_is_a_warning_not_a_crisis() {
        let mut f = facts();
        f.admin_ports = vec![AdminPort {
            port: 22,
            service: Some("SSH".into()),
            is_plaintext: true,
        }];

        let found = evaluate(&f);
        let rtr003 = found.iter().find(|x| x.rule_id == "RTR-003").unwrap();
        assert_eq!(rtr003.severity, Severity::Warning);
    }

    #[test]
    fn an_ordinary_web_admin_page_is_not_a_finding() {
        // Every home router serves one. Flagging it would be noise.
        let mut f = facts();
        f.admin_ports = vec![
            AdminPort {
                port: 80,
                service: Some("HTTP (web)".into()),
                is_plaintext: true,
            },
            AdminPort {
                port: 443,
                service: Some("HTTPS".into()),
                is_plaintext: false,
            },
        ];
        assert!(evaluate(&f).is_empty());
    }

    #[test]
    fn upnp_alone_is_mentioned_once_nothing_worse_is_found() {
        let mut f = facts();
        f.upnp_enabled = true;
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
        f.upnp_enabled = true;
        f.port_forwards = Some(vec![
            mapping(3389, "RDP", true),
            mapping(32400, "Plex", true),
        ]);
        f.admin_ports = vec![AdminPort {
            port: 23,
            service: None,
            is_plaintext: true,
        }];

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

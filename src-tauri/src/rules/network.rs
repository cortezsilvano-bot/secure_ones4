//! Rules over the local network: what this PC exposes, and what else is on it.
//!
//! The governing principle is that a listening port is only a finding if
//! something other than this PC can reach it. A database bound to `127.0.0.1`
//! is not an exposure, and reporting it as one teaches the user that SENTRY's
//! warnings are noise.

use crate::collectors::network::devices::DeviceFacts;
use crate::collectors::network::local_ports::{BindScope, Listener, LocalPortFacts};
use crate::findings::{Confidence, Finding, FindingBuilder, FixRisk, Severity};

const SOURCE: &str = "network";
const PORTS_CATEGORY: &str = "Open Ports";
const DEVICES_CATEGORY: &str = "Devices";

/// Services that should essentially never be reachable from a home network at
/// large, paired with why a home user should care.
///
/// Scored by what an attacker gets: administrative control of the machine, or
/// direct access to stored data.
fn exposure_risk(port: u16) -> Option<(Severity, &'static str)> {
    Some(match port {
        23 => (
            Severity::Critical,
            "Telnet sends everything, including your password, as plain readable text. Anyone on \
             the network can capture it.",
        ),
        445 | 139 => (
            Severity::Warning,
            "Windows file sharing is reachable from the network. This is normal on a home network \
             you trust, but it is also how ransomware spreads between PCs.",
        ),
        3389 => (
            Severity::Warning,
            "Remote Desktop lets someone take over this PC entirely if they get the password. It \
             is one of the most attacked services there is.",
        ),
        5900 => (
            Severity::Critical,
            "VNC gives remote control of the screen and often has weak or no password protection.",
        ),
        1433 | 3306 | 5432 | 27017 | 6379 | 9200 | 11211 => (
            Severity::Warning,
            "A database is reachable from the network. Databases are usually meant to be reached \
             only by programs on the same PC, and several of these accept connections with no \
             password by default.",
        ),
        21 => (
            Severity::Warning,
            "FTP sends passwords as plain readable text and is reachable from the network.",
        ),
        _ => return None,
    })
}

pub fn evaluate_ports(f: &LocalPortFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    // NET-001 -- risky services reachable from the local network.
    //
    // Grouped by port rather than by socket. Windows commonly binds the same
    // service to several addresses, and emitting one finding per socket would
    // show the user three identical "NetBIOS is reachable" rows -- and, because
    // a finding's identity is its rule plus its asset, would give them all the
    // same id.
    let mut by_port: Vec<(u16, String, Vec<&Listener>)> = Vec::new();
    for listener in f.network_reachable() {
        if exposure_risk(listener.port).is_none() {
            continue;
        }
        match by_port
            .iter_mut()
            .find(|(port, proto, _)| *port == listener.port && *proto == listener.protocol)
        {
            Some((_, _, group)) => group.push(listener),
            None => by_port.push((listener.port, listener.protocol.clone(), vec![listener])),
        }
    }

    for (port, protocol, listeners) in by_port {
        let Some((severity, why)) = exposure_risk(port) else {
            continue;
        };
        let first = listeners[0];

        let service = first
            .well_known_service
            .as_deref()
            .unwrap_or("An unnamed service");

        // Widest scope across the group decides how it is described: if any
        // socket is bound to all interfaces, the service travels with the PC.
        let any_all_interfaces = listeners
            .iter()
            .any(|l| l.scope == BindScope::AllInterfaces);

        let mut evidence = Vec::new();
        for listener in &listeners {
            evidence.extend(evidence_for(listener));
        }

        out.push(
            FindingBuilder::new(
                "NET-001",
                PORTS_CATEGORY,
                severity,
                &format!("{service} is reachable from your network"),
            )
            .what(&format!(
                "{} listening on port {port} and accepting connections from {}.",
                first
                    .process_name
                    .as_deref()
                    .map(|p| format!("{p} is"))
                    .unwrap_or_else(|| "A program on this PC is".to_string()),
                if any_all_interfaces {
                    "any network this PC joins"
                } else {
                    "the local network"
                }
            ))
            .why(why)
            .confidence(Confidence::Confirmed)
            .asset(&format!("port {port}/{protocol}"))
            .evidence(evidence)
            .remediation(
                "If you do not need this service, turn it off. If you do, make sure it requires a strong password and is not reachable from outside your home.",
                false,
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
    }

    out
}

fn evidence_for(l: &Listener) -> Vec<String> {
    let mut evidence = vec![
        "Windows API: GetExtendedTcpTable / GetExtendedUdpTable".to_string(),
        format!(
            "Listening on: {}:{} ({})",
            l.local_address, l.port, l.protocol
        ),
        format!(
            "Reachable by: {}",
            match l.scope {
                BindScope::LoopbackOnly => "this PC only",
                BindScope::SpecificInterface => "devices on this network",
                BindScope::AllInterfaces => "devices on any network this PC joins",
            }
        ),
    ];

    match (&l.process_name, &l.process_path) {
        (Some(name), Some(path)) => {
            evidence.push(format!("Program: {name}"));
            evidence.push(format!("Path: {path}"));
        }
        _ => evidence.push(format!(
            "Program: could not be identified (PID {}, likely a protected system process)",
            l.pid
        )),
    }

    if let Some(service) = &l.well_known_service {
        evidence.push(format!("Service normally on this port: {service}"));
    }

    evidence
}

pub fn evaluate_devices(f: &DeviceFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    // NET-002 -- devices the user has not yet reviewed.
    //
    // Attention, never a warning. An unrecognised device is usually a phone or
    // a smart plug, and treating every new one as a possible intruder is how a
    // security tool becomes something people mute.
    let unreviewed: Vec<_> = f.unreviewed().collect();
    if !unreviewed.is_empty() {
        let mut evidence = vec![format!(
            "{} device(s) on the network have not been reviewed",
            unreviewed.len()
        )];

        for device in unreviewed.iter().take(10) {
            let vendor = device
                .vendor
                .as_deref()
                .map(|v| format!(" -- {v}"))
                .unwrap_or_else(|| {
                    if device.mac_is_random {
                        " -- randomised address, manufacturer cannot be determined".to_string()
                    } else if !f.vendor_registry_available {
                        " -- manufacturer registry not downloaded".to_string()
                    } else {
                        " -- manufacturer not in the registry".to_string()
                    }
                });

            evidence.push(format!(
                "  {} ({}){vendor}",
                device.ip.as_deref().unwrap_or("address unknown"),
                device.mac.as_deref().unwrap_or("no MAC"),
            ));
        }

        out.push(
            FindingBuilder::new(
                "NET-002",
                DEVICES_CATEGORY,
                Severity::Attention,
                &format!(
                    "{} device{} on your network {} not been reviewed",
                    unreviewed.len(),
                    if unreviewed.len() == 1 { "" } else { "s" },
                    if unreviewed.len() == 1 { "has" } else { "have" }
                ),
            )
            .what(&format!(
                "SENTRY found {} device{} you have not marked as recognised.",
                unreviewed.len(),
                if unreviewed.len() == 1 { "" } else { "s" }
            ))
            .why(
                "Most of these will be phones, TVs and smart plugs you own. The point of reviewing \
                 them once is that anything appearing afterwards stands out.",
            )
            .confidence(Confidence::Confirmed)
            .evidence(evidence)
            .remediation(
                "Open Devices and mark the ones you recognise as trusted.",
                false,
                FixRisk::Manual,
            )
            .source(SOURCE)
            .build(),
        );
    }

    // NET-003 -- the vendor registry is missing, so devices cannot be named.
    if !f.vendor_registry_available && !f.devices.is_empty() {
        out.push(
            FindingBuilder::new(
                "NET-003",
                DEVICES_CATEGORY,
                Severity::Attention,
                "Devices cannot be identified yet",
            )
            .what("The MAC manufacturer registry has not been downloaded.")
            .why(
                "Without it, devices show only as numbers. With it, most show the company that \
                 made them, which is usually enough to recognise what they are.",
            )
            .confidence(Confidence::Confirmed)
            .evidence(vec![
                "Source: IEEE MA-L registry".to_string(),
                "Local copy: not downloaded".to_string(),
                format!("Devices affected: {}", f.devices.len()),
            ])
            .remediation(
                "Download the vulnerability and device data from the dashboard.",
                true,
                FixRisk::Safe,
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
    use crate::collectors::network::devices::{Device, DeviceType, Trust};
    use crate::collectors::network::local_ports::well_known_service;

    fn listener(addr: &str, port: u16, process: Option<&str>) -> Listener {
        let parsed: std::net::Ipv4Addr = addr.parse().unwrap();
        Listener {
            port,
            protocol: "tcp".into(),
            local_address: addr.to_string(),
            scope: if parsed.is_loopback() {
                BindScope::LoopbackOnly
            } else if parsed.is_unspecified() {
                BindScope::AllInterfaces
            } else {
                BindScope::SpecificInterface
            },
            pid: 1234,
            process_path: process.map(|p| format!("C:\\Program Files\\{p}")),
            process_name: process.map(str::to_string),
            well_known_service: well_known_service(port).map(str::to_string),
        }
    }

    fn port_facts(listeners: Vec<Listener>) -> LocalPortFacts {
        LocalPortFacts {
            listeners,
            evidence: vec![],
            collected_at: String::new(),
        }
    }

    #[test]
    fn a_loopback_database_is_not_a_finding() {
        // The single most important rule here. Postgres on 127.0.0.1 is how
        // Postgres is supposed to run.
        let f = port_facts(vec![
            listener("127.0.0.1", 5432, Some("postgres.exe")),
            listener("127.0.0.1", 6379, Some("redis.exe")),
        ]);
        assert!(evaluate_ports(&f).is_empty());
    }

    #[test]
    fn the_same_database_exposed_to_the_network_is_a_finding() {
        let f = port_facts(vec![listener("0.0.0.0", 5432, Some("postgres.exe"))]);
        let found = evaluate_ports(&f);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "NET-001");
        assert_eq!(found[0].severity, Severity::Warning);
    }

    #[test]
    fn telnet_and_vnc_are_critical() {
        for port in [23u16, 5900] {
            let f = port_facts(vec![listener("0.0.0.0", port, None)]);
            let found = evaluate_ports(&f);
            assert_eq!(found[0].severity, Severity::Critical, "port {port}");
        }
    }

    #[test]
    fn ordinary_ports_are_not_findings() {
        // A web server or an ephemeral port is not inherently a problem.
        let f = port_facts(vec![
            listener("0.0.0.0", 443, Some("nginx.exe")),
            listener("0.0.0.0", 49152, None),
        ]);
        assert!(evaluate_ports(&f).is_empty());
    }

    #[test]
    fn several_sockets_on_one_port_produce_a_single_finding() {
        // Windows binds NetBIOS to every interface. Three sockets on port 139
        // is one situation, and three findings sharing an id would be a bug.
        let f = port_facts(vec![
            listener("192.168.1.42", 139, Some("System")),
            listener("10.0.0.5", 139, Some("System")),
            listener("0.0.0.0", 139, Some("System")),
        ]);

        let found = evaluate_ports(&f);
        assert_eq!(found.len(), 1, "one port, one finding");
        // Every bound address still appears in the evidence.
        assert!(found[0].evidence.iter().any(|e| e.contains("192.168.1.42")));
        assert!(found[0].evidence.iter().any(|e| e.contains("10.0.0.5")));
        assert!(found[0].evidence.iter().any(|e| e.contains("0.0.0.0")));
    }

    #[test]
    fn findings_never_share_an_id() {
        let f = port_facts(vec![
            listener("192.168.1.42", 139, None),
            listener("0.0.0.0", 139, None),
            listener("0.0.0.0", 445, None),
            listener("0.0.0.0", 3389, None),
        ]);

        let found = evaluate_ports(&f);
        let mut ids: Vec<&str> = found.iter().map(|x| x.id.as_str()).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "finding ids must be unique");
    }

    #[test]
    fn each_exposed_port_gets_its_own_finding_with_a_distinct_id() {
        let f = port_facts(vec![
            listener("0.0.0.0", 3389, None),
            listener("0.0.0.0", 5900, None),
        ]);
        let found = evaluate_ports(&f);
        assert_eq!(found.len(), 2);
        assert_ne!(found[0].id, found[1].id);
    }

    #[test]
    fn evidence_names_the_program_or_admits_it_could_not() {
        let known = evaluate_ports(&port_facts(vec![listener(
            "0.0.0.0",
            3389,
            Some("svchost.exe"),
        )]));
        assert!(known[0].evidence.iter().any(|e| e.contains("svchost.exe")));

        let unknown = evaluate_ports(&port_facts(vec![listener("0.0.0.0", 3389, None)]));
        assert!(unknown[0]
            .evidence
            .iter()
            .any(|e| e.contains("could not be identified")));
    }

    // --- devices ------------------------------------------------------------

    fn device(ip: &str, trust: Trust, gateway: bool, is_self: bool) -> Device {
        Device {
            id: ip.to_string(),
            mac: Some("24:62:ab:11:22:33".into()),
            ip: Some(ip.to_string()),
            hostname: None,
            vendor: None,
            display_name: None,
            device_type: DeviceType::Unknown,
            mac_is_random: false,
            is_gateway: gateway,
            is_self,
            trust,
            first_seen: None,
            last_seen: String::new(),
            discovered_via: "neighbor_table".into(),
            currently_visible: true,
        }
    }

    fn device_facts(devices: Vec<Device>, registry: bool) -> DeviceFacts {
        DeviceFacts {
            visible_now: devices.len(),
            devices,
            vendor_registry_available: registry,
            evidence: vec![],
            collected_at: String::new(),
        }
    }

    #[test]
    fn a_network_of_known_devices_raises_nothing() {
        let f = device_facts(
            vec![
                device("192.168.1.1", Trust::None, true, false),
                device("192.168.1.42", Trust::Trusted, false, true),
                device("192.168.1.77", Trust::Trusted, false, false),
            ],
            true,
        );
        assert!(evaluate_devices(&f).is_empty());
    }

    #[test]
    fn unreviewed_devices_are_attention_not_alarm() {
        let f = device_facts(
            vec![
                device("192.168.1.1", Trust::None, true, false),
                device("192.168.1.77", Trust::None, false, false),
            ],
            true,
        );
        let found = evaluate_devices(&f);
        let net002 = found
            .iter()
            .find(|x| x.rule_id == "NET-002")
            .expect("NET-002");

        assert_eq!(
            net002.severity,
            Severity::Attention,
            "an unrecognised phone is not an intrusion"
        );
        // The router and this PC must not be counted as unknown devices.
        assert!(net002.title.starts_with("1 device"));
        assert!(net002
            .why_it_matters
            .contains("phones, TVs and smart plugs"));
    }

    #[test]
    fn a_missing_vendor_registry_is_reported_and_explained_in_the_device_list() {
        let f = device_facts(
            vec![device("192.168.1.77", Trust::None, false, false)],
            false,
        );
        let found = evaluate_devices(&f);

        assert!(found.iter().any(|x| x.rule_id == "NET-003"));
        let net002 = found.iter().find(|x| x.rule_id == "NET-002").unwrap();
        assert!(
            net002
                .evidence
                .iter()
                .any(|e| e.contains("registry not downloaded")),
            "the device list must say why it has no manufacturer names"
        );
    }

    #[test]
    fn a_randomised_mac_is_explained_rather_than_left_blank() {
        let mut d = device("192.168.1.90", Trust::None, false, false);
        d.mac_is_random = true;
        d.mac = Some("02:11:22:33:44:55".into());

        let found = evaluate_devices(&device_facts(vec![d], true));
        let net002 = found.iter().find(|x| x.rule_id == "NET-002").unwrap();
        assert!(net002
            .evidence
            .iter()
            .any(|e| e.contains("randomised address")));
    }

    #[test]
    fn every_finding_carries_evidence() {
        let ports = evaluate_ports(&port_facts(vec![listener("0.0.0.0", 23, None)]));
        let devices = evaluate_devices(&device_facts(
            vec![device("192.168.1.77", Trust::None, false, false)],
            false,
        ));

        for finding in ports.into_iter().chain(devices) {
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

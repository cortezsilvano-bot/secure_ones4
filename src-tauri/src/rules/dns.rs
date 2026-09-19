//! Rules over network configuration, principally DNS.
//!
//! DNS is worth checking because changing it is one of the few attacks on a
//! home network that is both common and completely invisible to the victim.
//! Malware and compromised routers redirect DNS to a server the attacker
//! controls; every site the user visits then resolves wherever the attacker
//! says, with no certificate warning and nothing visibly wrong.
//!
//! The check is deliberately conservative. Using Cloudflare or Google DNS is a
//! perfectly ordinary choice, so a resolver being external is not by itself
//! suspicious -- only one that is external *and* unrecognised is worth raising,
//! and even then as something to confirm rather than an accusation.

use std::net::Ipv4Addr;

use crate::collectors::network::interfaces::{InterfaceFacts, NetworkInterface};
use crate::findings::{Confidence, Finding, FindingBuilder, FixRisk, Severity};

const SOURCE: &str = "network.dns";
const CATEGORY: &str = "Network";

/// Public resolvers common enough that finding one configured is unremarkable.
const KNOWN_RESOLVERS: &[(&str, &str)] = &[
    ("1.1.1.1", "Cloudflare"),
    ("1.0.0.1", "Cloudflare"),
    ("1.1.1.2", "Cloudflare (malware filtering)"),
    ("1.1.1.3", "Cloudflare (family filtering)"),
    ("8.8.8.8", "Google"),
    ("8.8.4.4", "Google"),
    ("9.9.9.9", "Quad9"),
    ("149.112.112.112", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
    ("208.67.220.220", "OpenDNS"),
    ("94.140.14.14", "AdGuard"),
    ("94.140.15.15", "AdGuard"),
    ("76.76.2.0", "Control D"),
    ("76.76.10.0", "Control D"),
    ("185.228.168.9", "CleanBrowsing"),
    ("76.76.19.19", "Alternate DNS"),
];

fn known_resolver(ip: Ipv4Addr) -> Option<&'static str> {
    let text = ip.to_string();
    KNOWN_RESOLVERS
        .iter()
        .find(|(addr, _)| *addr == text)
        .map(|(_, name)| *name)
}

/// Addresses that are not routable on the public internet, so a resolver there
/// is on the user's own network.
fn is_local(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
}

pub fn evaluate(f: &InterfaceFacts) -> Vec<Finding> {
    let mut out = Vec::new();

    for iface in f.scannable() {
        out.extend(evaluate_interface(iface));
    }

    out
}

fn evaluate_interface(iface: &NetworkInterface) -> Vec<Finding> {
    let mut out = Vec::new();

    // Only IPv4 resolvers are assessed; the IPv6 equivalents are not yet
    // classified, and guessing about them would be worse than staying quiet.
    let resolvers: Vec<Ipv4Addr> = iface
        .dns_servers
        .iter()
        .filter_map(|s| s.parse::<Ipv4Addr>().ok())
        .collect();

    if resolvers.is_empty() {
        return out;
    }

    let unrecognised: Vec<Ipv4Addr> = resolvers
        .iter()
        .copied()
        .filter(|ip| !is_local(*ip) && known_resolver(*ip).is_none())
        .collect();

    if unrecognised.is_empty() {
        return out;
    }

    let mut evidence = vec![
        "Windows API: GetAdaptersAddresses (IP Helper)".to_string(),
        format!("Adapter: {}", iface.friendly_name),
        format!(
            "Gateway: {}",
            iface.gateways.first().map(String::as_str).unwrap_or("none")
        ),
    ];

    for ip in &resolvers {
        let note = if is_local(*ip) {
            "on your own network".to_string()
        } else if let Some(name) = known_resolver(*ip) {
            format!("public resolver, {name}")
        } else {
            "public address, not a resolver SENTRY recognises".to_string()
        };
        evidence.push(format!("DNS server: {ip} ({note})"));
    }

    out.push(
        FindingBuilder::new(
            "NET-010",
            CATEGORY,
            Severity::Warning,
            "An unrecognised DNS server is configured",
        )
        .what(&format!(
            "{} is set to use {} for DNS, which is neither on your network nor a well-known public resolver.",
            iface.friendly_name,
            unrecognised
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .why(
            "DNS decides which server your PC reaches when you type an address. Changing it is a \
             quiet way to send someone to a fake version of a site they trust, and it is a common \
             result of a compromised router. This may equally be a DNS service you chose on \
             purpose -- it is worth a look either way.",
        )
        // Deliberately not Confirmed: an unrecognised resolver is a prompt to
        // check, not proof of anything.
        .confidence(Confidence::Potential)
        .asset(&iface.friendly_name)
        .evidence(evidence)
        .remediation(
            "If you did not set this DNS server yourself, check your router's settings and this PC's network adapter settings.",
            FixRisk::Manual,
        )
        .source(SOURCE)
        .build(),
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::network::interfaces::InterfaceAddress;

    fn iface(dns: Vec<&str>) -> NetworkInterface {
        NetworkInterface {
            id: "adapter".into(),
            description: "Wi-Fi".into(),
            friendly_name: "Wi-Fi".into(),
            mac: Some("aa:bb:cc:00:00:01".into()),
            ipv4: vec![InterfaceAddress {
                address: "192.168.1.42".into(),
                prefix_length: 24,
            }],
            ipv6: vec![],
            gateways: vec!["192.168.1.1".into()],
            dns_servers: dns.into_iter().map(str::to_string).collect(),
            is_up: true,
            is_loopback: false,
            interface_type: "Wi-Fi".into(),
        }
    }

    fn facts(dns: Vec<&str>) -> InterfaceFacts {
        InterfaceFacts {
            interfaces: vec![iface(dns)],
            evidence: vec![],
            collected_at: String::new(),
        }
    }

    #[test]
    fn dns_on_the_router_is_normal() {
        assert!(evaluate(&facts(vec!["192.168.1.1"])).is_empty());
    }

    #[test]
    fn well_known_public_resolvers_are_normal() {
        // Choosing Cloudflare or Quad9 is an ordinary thing to do and must not
        // produce a warning.
        for resolver in [
            "1.1.1.1",
            "8.8.8.8",
            "9.9.9.9",
            "208.67.222.222",
            "94.140.14.14",
        ] {
            assert!(
                evaluate(&facts(vec![resolver])).is_empty(),
                "{resolver} should be recognised"
            );
        }
    }

    #[test]
    fn an_unrecognised_public_resolver_is_flagged() {
        let found = evaluate(&facts(vec!["203.0.113.5"]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "NET-010");
        assert_eq!(found[0].severity, Severity::Warning);
    }

    #[test]
    fn the_finding_is_a_prompt_to_check_not_an_accusation() {
        let found = evaluate(&facts(vec!["203.0.113.5"]));
        assert_eq!(
            found[0].confidence,
            Confidence::Potential,
            "an unrecognised resolver is not proof of a hijack"
        );
        assert!(found[0].why_it_matters.contains("chose on purpose"));
    }

    #[test]
    fn a_mixed_configuration_reports_every_resolver_in_the_evidence() {
        let found = evaluate(&facts(vec!["192.168.1.1", "1.1.1.1", "203.0.113.5"]));
        let evidence = &found[0].evidence;

        assert!(evidence
            .iter()
            .any(|e| e.contains("192.168.1.1") && e.contains("your own network")));
        assert!(evidence
            .iter()
            .any(|e| e.contains("1.1.1.1") && e.contains("Cloudflare")));
        assert!(evidence
            .iter()
            .any(|e| e.contains("203.0.113.5") && e.contains("not a resolver")));
    }

    #[test]
    fn private_ranges_all_count_as_local() {
        assert!(is_local("10.0.0.1".parse().unwrap()));
        assert!(is_local("172.16.0.1".parse().unwrap()));
        assert!(is_local("192.168.1.1".parse().unwrap()));
        assert!(is_local("127.0.0.1".parse().unwrap()));
        assert!(!is_local("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn an_adapter_with_no_dns_raises_nothing() {
        assert!(evaluate(&facts(vec![])).is_empty());
    }

    #[test]
    fn unusable_adapters_are_skipped() {
        let mut f = facts(vec!["203.0.113.5"]);
        f.interfaces[0].is_up = false;
        assert!(
            evaluate(&f).is_empty(),
            "a disconnected adapter's DNS setting is not in effect"
        );
    }

    #[test]
    fn every_finding_carries_evidence() {
        for finding in evaluate(&facts(vec!["203.0.113.5"])) {
            assert!(!finding.evidence.is_empty());
            assert!(!finding.why_it_matters.is_empty());
            assert_eq!(finding.source, SOURCE);
        }
    }
}

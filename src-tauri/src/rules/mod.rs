//! Detection rules: the only layer permitted to decide whether something is a
//! problem. Collectors report, rules judge, the UI renders.
//!
//! Every rule takes facts and returns zero or more findings, each carrying the
//! evidence that produced it. A rule that cannot see the fact it needs emits
//! nothing -- silence here means "no judgement", and the coverage model, not
//! the rule set, is what tells the user a check did not run.

pub mod defender;
pub mod dns;
pub mod firewall;
pub mod hardening;
pub mod malware;
pub mod network;
pub mod router;
pub mod updates;
pub mod vulnerabilities;

use crate::collectors::defender::DefenderFacts;
use crate::collectors::defender_policy::DefenderPolicyFacts;
use crate::collectors::defender_threats::ThreatFacts;
use crate::collectors::firewall::FirewallFacts;
use crate::collectors::hardening::HardeningFacts;
use crate::collectors::network::devices::DeviceFacts;
use crate::collectors::network::interfaces::InterfaceFacts;
use crate::collectors::network::local_ports::LocalPortFacts;
use crate::collectors::network::router::RouterFacts;
use crate::collectors::updates::UpdateFacts;
use crate::findings::Finding;
use crate::security::Known;
use crate::vulnerabilities::assess::VulnerabilityFacts;

/// Everything the rules can see for one evaluation pass.
///
/// Fields are `Option<Known<_>>` rather than bare values, which distinguishes
/// three genuinely different situations: the collector was never run (`None`),
/// it ran and failed (`Some(Known::Unavailable)`), or it ran and produced facts.
#[derive(Default)]
pub struct RuleContext {
    pub defender: Option<Known<DefenderFacts>>,
    pub firewall: Option<Known<FirewallFacts>>,
    pub updates: Option<Known<UpdateFacts>>,
    pub hardening: Option<Known<HardeningFacts>>,
    pub vulnerabilities: Option<Known<VulnerabilityFacts>>,
    pub local_ports: Option<Known<LocalPortFacts>>,
    pub devices: Option<Known<DeviceFacts>>,
    pub interfaces: Option<Known<InterfaceFacts>>,
    pub router: Option<Known<RouterFacts>>,
    pub defender_policy: Option<Known<DefenderPolicyFacts>>,
    pub threats: Option<Known<ThreatFacts>>,
}

impl RuleContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_defender(mut self, facts: Known<DefenderFacts>) -> Self {
        self.defender = Some(facts);
        self
    }

    pub fn with_firewall(mut self, facts: Known<FirewallFacts>) -> Self {
        self.firewall = Some(facts);
        self
    }

    pub fn with_updates(mut self, facts: Known<UpdateFacts>) -> Self {
        self.updates = Some(facts);
        self
    }

    pub fn with_hardening(mut self, facts: Known<HardeningFacts>) -> Self {
        self.hardening = Some(facts);
        self
    }

    pub fn with_vulnerabilities(mut self, facts: Known<VulnerabilityFacts>) -> Self {
        self.vulnerabilities = Some(facts);
        self
    }

    pub fn with_local_ports(mut self, facts: Known<LocalPortFacts>) -> Self {
        self.local_ports = Some(facts);
        self
    }

    pub fn with_devices(mut self, facts: Known<DeviceFacts>) -> Self {
        self.devices = Some(facts);
        self
    }

    pub fn with_interfaces(mut self, facts: Known<InterfaceFacts>) -> Self {
        self.interfaces = Some(facts);
        self
    }

    pub fn with_router(mut self, facts: Known<RouterFacts>) -> Self {
        self.router = Some(facts);
        self
    }

    pub fn with_defender_policy(mut self, facts: Known<DefenderPolicyFacts>) -> Self {
        self.defender_policy = Some(facts);
        self
    }

    pub fn with_threats(mut self, facts: Known<ThreatFacts>) -> Self {
        self.threats = Some(facts);
        self
    }
}

/// Run every rule over the context.
///
/// Only facts that were actually established are judged; a collector that
/// failed contributes no findings, and its absence is reported through
/// coverage instead.
pub fn evaluate(ctx: &RuleContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(Known::Known(facts)) = &ctx.defender {
        findings.extend(defender::evaluate(facts));
    }
    if let Some(Known::Known(facts)) = &ctx.firewall {
        findings.extend(firewall::evaluate(facts));
    }
    if let Some(Known::Known(facts)) = &ctx.updates {
        findings.extend(updates::evaluate(facts));
    }
    if let Some(Known::Known(facts)) = &ctx.hardening {
        findings.extend(hardening::evaluate(facts));
    }
    if let Some(Known::Known(facts)) = &ctx.vulnerabilities {
        findings.extend(vulnerabilities::evaluate(facts));
    }
    if let Some(Known::Known(facts)) = &ctx.local_ports {
        findings.extend(network::evaluate_ports(facts));
    }
    if let Some(Known::Known(facts)) = &ctx.devices {
        findings.extend(network::evaluate_devices(facts));
    }
    if let Some(Known::Known(facts)) = &ctx.interfaces {
        findings.extend(dns::evaluate(facts));
    }
    if let Some(Known::Known(facts)) = &ctx.router {
        findings.extend(router::evaluate(facts));
    }
    if let Some(Known::Known(facts)) = &ctx.defender_policy {
        findings.extend(malware::evaluate_policy(facts));
    }
    if let Some(Known::Known(facts)) = &ctx.threats {
        findings.extend(malware::evaluate_threats(facts));
    }

    findings
}

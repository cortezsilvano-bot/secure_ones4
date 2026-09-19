//! Collectors turn privileged OS state into typed facts.
//!
//! A collector never decides whether something is *good*. It reports what is
//! true, or reports honestly that it could not tell. Judgement belongs to the
//! rules layer, which runs over facts these produce.

pub mod defender;
pub mod defender_policy;
pub mod defender_threats;
pub mod firewall;
pub mod hardening;
pub mod network;
pub mod software;
pub mod updates;

#[cfg(windows)]
pub mod wmi_util;

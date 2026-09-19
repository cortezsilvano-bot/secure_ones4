//! The privilege boundary.
//!
//! Every capability the webview has over the operating system is a named,
//! serde-typed command in this module. There is deliberately no generic
//! `execute(command)` escape hatch: a compromised or injected frontend can
//! only ever reach the verbs listed here, with arguments of the shape declared
//! here.

pub mod dashboard;
pub mod devices;
pub mod history;
pub mod remediation;
pub mod router;
pub mod settings;
pub mod vulnerabilities;
pub mod windows_status;

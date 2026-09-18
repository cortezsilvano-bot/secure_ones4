//! Vulnerability feed clients.
//!
//! Each module downloads and parses one public feed. None of them send
//! anything about the machine: KEV and the NVD keyword search are plain
//! downloads, and the EPSS request carries only public CVE identifiers.

pub mod epss;
pub mod http;
pub mod kev;
pub mod nvd;
pub mod oui;

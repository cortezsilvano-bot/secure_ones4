//! Core vocabulary shared by every collector, rule and IPC command.

pub mod known;
pub mod score;

pub use known::{CollectorError, Known};

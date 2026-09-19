//! The vulnerability engine: match installed software against public feeds.
//!
//! The pipeline is deliberately offline at scan time. Feeds are downloaded and
//! cached by an explicit refresh; a scan reads only what is already on disk.
//! That means a scan is fast, works without a network, and never turns the
//! machine's software list into an outbound request.

pub mod assess;
pub mod cpe;
pub mod feeds;
pub mod matcher;
pub mod refresh;
pub mod store;
pub mod version;

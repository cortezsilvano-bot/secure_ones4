//! Active TCP port scanning of hosts on the local network.
//!
//! The only genuinely *active* thing SENTRY does to a network, so it is built
//! to be a good citizen:
//!
//!   * Plain TCP connects. No raw sockets, no SYN scanning, nothing that needs
//!     elevation or looks like an attack to an IDS.
//!   * Bounded concurrency and a per-connection timeout, so a scan cannot
//!     saturate a link or exhaust a cheap router's connection table.
//!   * Cancellable between every batch.
//!   * A curated port list by default rather than all 65,535. Scanning
//!     everything takes far longer and tells a home user nothing more.
//!
//! Refusing to scan outside the local subnet is enforced by the caller
//! (`scan_host` takes an already-validated address), because scanning an
//! arbitrary internet host on a user's behalf is not something this tool does.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::local_ports::well_known_service;

/// How thorough a scan to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDepth {
    /// The handful of ports that matter most on a home network.
    Quick,
    /// Common services, roughly the nmap top-100 shape.
    Standard,
    /// Everything privileged plus common high ports.
    Deep,
}

/// Ports worth checking first: remote access, file sharing, databases and
/// admin interfaces -- the things that actually get someone owned.
const QUICK_PORTS: &[u16] = &[21, 22, 23, 80, 135, 139, 443, 445, 3389, 5900, 8080];

const STANDARD_EXTRA: &[u16] = &[
    25, 53, 110, 143, 161, 389, 443, 465, 514, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 1883,
    1900, 2049, 2082, 3000, 3306, 4444, 5000, 5060, 5432, 5555, 5601, 6379, 7547, 8000, 8008, 8081,
    8443, 8888, 9000, 9090, 9100, 9200, 11211, 27017, 32400,
];

impl ScanDepth {
    pub fn ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = QUICK_PORTS.to_vec();

        match self {
            ScanDepth::Quick => {}
            ScanDepth::Standard => ports.extend_from_slice(STANDARD_EXTRA),
            ScanDepth::Deep => {
                ports.extend_from_slice(STANDARD_EXTRA);
                ports.extend(1..=1024u16);
            }
        }

        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Per-connection timeout. Deeper scans get longer, because they are
    /// expected to take a while anyway and false negatives cost more there.
    pub fn timeout(&self) -> Duration {
        match self {
            ScanDepth::Quick => Duration::from_millis(400),
            ScanDepth::Standard => Duration::from_millis(700),
            ScanDepth::Deep => Duration::from_millis(1200),
        }
    }

    /// Simultaneous connection attempts. Deliberately modest: consumer routers
    /// have small NAT and connection tables, and a scan that knocks the user's
    /// own network over is worse than no scan.
    pub fn concurrency(&self) -> usize {
        match self {
            ScanDepth::Quick => 32,
            ScanDepth::Standard => 64,
            ScanDepth::Deep => 96,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenPort {
    pub port: u16,
    pub protocol: String,
    pub well_known_service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostScanResult {
    pub address: String,
    pub open_ports: Vec<OpenPort>,
    pub ports_scanned: usize,
    pub duration_ms: u64,
    /// True when the scan was stopped early, so an empty result is not read as
    /// "nothing is open".
    pub cancelled: bool,
}

impl HostScanResult {
    /// Whether the result can be trusted as complete.
    pub fn is_conclusive(&self) -> bool {
        !self.cancelled
    }
}

/// Scan one host.
///
/// `cancelled` is checked between batches so a scan stops promptly.
pub async fn scan_host(
    address: IpAddr,
    depth: ScanDepth,
    cancelled: Arc<AtomicBool>,
) -> HostScanResult {
    scan_ports(
        address,
        &depth.ports(),
        depth.timeout(),
        depth.concurrency(),
        cancelled,
    )
    .await
}

/// The scan itself, over an explicit port list.
///
/// Separate from `scan_host` so tests can drive it with ports they control,
/// rather than depending on what the surrounding network happens to answer --
/// addresses that "should" be unroutable are not reliably so behind captive
/// portals, transparent proxies or ISP routers that answer everything.
pub async fn scan_ports(
    address: IpAddr,
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
    cancelled: Arc<AtomicBool>,
) -> HostScanResult {
    let started = std::time::Instant::now();

    let mut open = Vec::new();
    let mut scanned = 0usize;
    let mut stopped = false;

    for batch in ports.chunks(concurrency.max(1)) {
        if cancelled.load(Ordering::Relaxed) {
            stopped = true;
            break;
        }

        let mut tasks = Vec::with_capacity(batch.len());
        for &port in batch {
            let target = SocketAddr::new(address, port);
            tasks.push(tokio::spawn(async move {
                let connected =
                    tokio::time::timeout(timeout, tokio::net::TcpStream::connect(target))
                        .await
                        .map(|r| r.is_ok())
                        .unwrap_or(false);
                (port, connected)
            }));
        }

        for task in tasks {
            scanned += 1;
            if let Ok((port, true)) = task.await {
                open.push(OpenPort {
                    port,
                    protocol: "tcp".to_string(),
                    well_known_service: well_known_service(port).map(str::to_string),
                });
            }
        }
    }

    open.sort_by_key(|p| p.port);

    HostScanResult {
        address: address.to_string(),
        open_ports: open,
        ports_scanned: scanned,
        duration_ms: started.elapsed().as_millis() as u64,
        cancelled: stopped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn quick_is_a_subset_of_standard_which_is_a_subset_of_deep() {
        let quick = ScanDepth::Quick.ports();
        let standard = ScanDepth::Standard.ports();
        let deep = ScanDepth::Deep.ports();

        assert!(quick.iter().all(|p| standard.contains(p)));
        assert!(standard.iter().all(|p| deep.contains(p)));
        assert!(quick.len() < standard.len());
        assert!(standard.len() < deep.len());
    }

    #[test]
    fn port_lists_are_sorted_and_free_of_duplicates() {
        for depth in [ScanDepth::Quick, ScanDepth::Standard, ScanDepth::Deep] {
            let ports = depth.ports();
            let mut sorted = ports.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                ports, sorted,
                "{depth:?} port list must be sorted and deduplicated"
            );
        }
    }

    #[test]
    fn the_ports_that_matter_are_always_checked() {
        // Remote Desktop and SMB are the two that most often matter on a home
        // network, so they must be in even the quickest scan.
        let quick = ScanDepth::Quick.ports();
        assert!(quick.contains(&3389), "Remote Desktop");
        assert!(quick.contains(&445), "SMB file sharing");
        assert!(quick.contains(&22), "SSH");
    }

    #[test]
    fn a_quick_scan_stays_small() {
        // The point of Quick is that it finishes in seconds.
        assert!(
            ScanDepth::Quick.ports().len() <= 20,
            "a quick scan must stay quick"
        );
    }

    #[test]
    fn concurrency_stays_gentle_enough_for_consumer_hardware() {
        for depth in [ScanDepth::Quick, ScanDepth::Standard, ScanDepth::Deep] {
            assert!(
                depth.concurrency() <= 128,
                "{depth:?} would overwhelm a consumer router's connection table"
            );
        }
    }

    #[tokio::test]
    async fn an_already_cancelled_scan_does_nothing_and_says_so() {
        let result = scan_ports(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[80, 443],
            Duration::from_millis(100),
            8,
            Arc::new(AtomicBool::new(true)),
        )
        .await;

        assert_eq!(result.ports_scanned, 0);
        assert!(result.cancelled);
        assert!(
            !result.is_conclusive(),
            "a cancelled scan must not be read as finding nothing"
        );
    }

    #[tokio::test]
    async fn an_open_port_is_found_and_a_closed_one_is_not() {
        // Bind a real listener so the test controls the answer instead of
        // relying on what the surrounding network does.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();

        tokio::spawn(async move { while listener.accept().await.is_ok() {} });

        // A second bind, immediately dropped, yields a port nothing is on.
        let transient = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = transient.local_addr().unwrap().port();
        drop(transient);

        let result = scan_ports(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[open_port, closed_port],
            Duration::from_millis(800),
            8,
            Arc::new(AtomicBool::new(false)),
        )
        .await;

        assert!(result.is_conclusive());
        assert_eq!(result.ports_scanned, 2);

        let found: Vec<u16> = result.open_ports.iter().map(|p| p.port).collect();
        assert!(
            found.contains(&open_port),
            "the listening port must be detected"
        );
        assert!(
            !found.contains(&closed_port),
            "a closed port must not be reported open"
        );
    }

    #[tokio::test]
    async fn results_are_sorted_by_port() {
        let mut listeners = Vec::new();
        for _ in 0..3 {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listeners.push(l);
        }
        let mut ports: Vec<u16> = listeners
            .iter()
            .map(|l| l.local_addr().unwrap().port())
            .collect();

        for l in listeners {
            tokio::spawn(async move { while l.accept().await.is_ok() {} });
        }

        // Hand them over in the wrong order on purpose.
        ports.sort_unstable_by(|a, b| b.cmp(a));

        let result = scan_ports(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &ports,
            Duration::from_millis(800),
            8,
            Arc::new(AtomicBool::new(false)),
        )
        .await;

        let found: Vec<u16> = result.open_ports.iter().map(|p| p.port).collect();
        let mut expected = found.clone();
        expected.sort_unstable();
        assert_eq!(
            found, expected,
            "open ports must come back in ascending order"
        );
    }

    #[tokio::test]
    async fn a_well_known_port_carries_its_service_name() {
        let result = scan_ports(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[],
            Duration::from_millis(50),
            8,
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert_eq!(result.ports_scanned, 0, "an empty port list scans nothing");

        // The naming itself is table-driven and covered here.
        assert_eq!(well_known_service(3389), Some("Remote Desktop"));
    }
}

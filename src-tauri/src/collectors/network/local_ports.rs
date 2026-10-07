//! What this machine is listening on, and which program is doing the listening.
//!
//! Read with `GetExtendedTcpTable` / `GetExtendedUdpTable`. Entirely local and
//! entirely passive: no packets, no scanning, no guessing.
//!
//! The distinction this module exists to make is **bind scope**. "Port 5432 is
//! open" is not one fact, it is three different ones:
//!
//!   * bound to `127.0.0.1` -- reachable only by programs on this PC, and not
//!     a network exposure at all
//!   * bound to `0.0.0.0` -- reachable by anything on the local network
//!   * reachable from the internet -- which this module cannot determine, and
//!     does not claim to
//!
//! Collapsing those into "open ports" is how scanners produce alarming numbers
//! that mean nothing. Each listener carries its scope so the rules can judge it
//! correctly.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

/// How far a listening socket can actually be reached from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindScope {
    /// Bound to loopback. Other machines cannot reach it, full stop.
    LoopbackOnly,
    /// Bound to a specific address on one network.
    SpecificInterface,
    /// Bound to all interfaces. Anything on the local network can reach it.
    AllInterfaces,
}

impl BindScope {
    /// Whether anything other than this PC can connect.
    pub fn is_reachable_by_others(&self) -> bool {
        !matches!(self, BindScope::LoopbackOnly)
    }

    /// Stable string form, matching the serde representation, for storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            BindScope::LoopbackOnly => "loopback_only",
            BindScope::SpecificInterface => "specific_interface",
            BindScope::AllInterfaces => "all_interfaces",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Listener {
    pub port: u16,
    pub protocol: String,
    pub local_address: String,
    pub scope: BindScope,
    pub pid: u32,
    /// Full path of the owning program, when Windows will tell us.
    pub process_path: Option<String>,
    /// Just the executable name, for display.
    pub process_name: Option<String>,
    /// The service conventionally found on this port, if it is a well-known one.
    pub well_known_service: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalPortFacts {
    pub listeners: Vec<Listener>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl LocalPortFacts {
    /// Listeners other machines on the network can actually reach.
    pub fn network_reachable(&self) -> impl Iterator<Item = &Listener> {
        self.listeners
            .iter()
            .filter(|l| l.scope.is_reachable_by_others())
    }

    /// Listeners bound to loopback, which are not a network exposure.
    pub fn loopback_only(&self) -> impl Iterator<Item = &Listener> {
        self.listeners
            .iter()
            .filter(|l| l.scope == BindScope::LoopbackOnly)
    }
}

/// Ports whose conventional service is worth naming for a non-technical user.
const WELL_KNOWN: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP (web)"),
    (110, "POP3"),
    (135, "Windows RPC"),
    (137, "NetBIOS"),
    (138, "NetBIOS"),
    (139, "NetBIOS"),
    (143, "IMAP"),
    (443, "HTTPS (secure web)"),
    (445, "Windows file sharing (SMB)"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "Microsoft SQL Server"),
    (1900, "UPnP"),
    (3306, "MySQL"),
    (3389, "Remote Desktop"),
    (5040, "Windows Connected Devices"),
    (5060, "SIP"),
    (5357, "Windows network discovery"),
    (5432, "PostgreSQL"),
    (5900, "VNC remote control"),
    (6379, "Redis"),
    (8080, "HTTP alternate"),
    (9100, "Printer (raw)"),
    (27017, "MongoDB"),
];

pub fn well_known_service(port: u16) -> Option<&'static str> {
    WELL_KNOWN
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, name)| *name)
}

fn classify_bind(addr: Ipv4Addr) -> BindScope {
    if addr.is_loopback() {
        BindScope::LoopbackOnly
    } else if addr.is_unspecified() {
        // 0.0.0.0 means every interface, present and future.
        BindScope::AllInterfaces
    } else {
        BindScope::SpecificInterface
    }
}

#[cfg(windows)]
pub fn collect() -> Result<LocalPortFacts, CollectorError> {
    let mut facts = LocalPortFacts {
        listeners: Vec::new(),
        evidence: vec![
            "Windows API: GetExtendedTcpTable / GetExtendedUdpTable (IP Helper)".to_string(),
            "Passive: reads the local socket table, sends no packets".to_string(),
        ],
        collected_at: chrono::Utc::now().to_rfc3339(),
    };

    facts.listeners.extend(tcp_listeners()?);
    facts.listeners.extend(udp_listeners()?);

    // Stable order so the evidence trail does not churn between scans.
    facts
        .listeners
        .sort_by_key(|l| (l.port, l.protocol.clone()));

    let reachable = facts.network_reachable().count();
    let loopback = facts.loopback_only().count();
    facts.evidence.push(format!(
        "{} listening sockets: {reachable} reachable from the network, {loopback} loopback only",
        facts.listeners.len()
    ));

    Ok(facts)
}

#[cfg(windows)]
fn tcp_listeners() -> Result<Vec<Listener>, CollectorError> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    const MIB_TCP_STATE_LISTEN: u32 = 2;

    let mut size: u32 = 0;
    // First call establishes the required buffer size.
    unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
    }

    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size as usize];
    let result = unsafe {
        GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };

    if result != 0 {
        return Err(CollectorError::Unavailable(format!(
            "Windows could not read the TCP socket table (error {result})."
        )));
    }

    let mut out = Vec::new();

    unsafe {
        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for row in rows {
            if row.dwState != MIB_TCP_STATE_LISTEN {
                continue;
            }

            let addr = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            // Ports arrive in network byte order in the low two bytes.
            let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            let (process_path, process_name) = process_for(row.dwOwningPid);

            out.push(Listener {
                port,
                protocol: "tcp".to_string(),
                local_address: addr.to_string(),
                scope: classify_bind(addr),
                pid: row.dwOwningPid,
                process_path,
                process_name,
                well_known_service: well_known_service(port).map(str::to_string),
            });
        }
    }

    Ok(out)
}

#[cfg(windows)]
fn udp_listeners() -> Result<Vec<Listener>, CollectorError> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut size: u32 = 0;
    unsafe {
        GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }

    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size as usize];
    let result = unsafe {
        GetExtendedUdpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if result != 0 {
        return Err(CollectorError::Unavailable(format!(
            "Windows could not read the UDP socket table (error {result})."
        )));
    }

    let mut out = Vec::new();

    unsafe {
        let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for row in rows {
            let addr = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            let (process_path, process_name) = process_for(row.dwOwningPid);

            out.push(Listener {
                port,
                protocol: "udp".to_string(),
                local_address: addr.to_string(),
                scope: classify_bind(addr),
                pid: row.dwOwningPid,
                process_path,
                process_name,
                well_known_service: well_known_service(port).map(str::to_string),
            });
        }
    }

    Ok(out)
}

/// The executable behind a PID.
///
/// Returns `(None, None)` for protected and system processes, which a standard
/// user cannot open. That is reported as unknown rather than guessed at.
#[cfg(windows)]
fn process_for(pid: u32) -> (Option<String>, Option<String>) {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return (None, None);
    }

    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return (None, None);
        };

        let mut buffer = [0u16; 512];
        let mut len = buffer.len() as u32;

        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        );

        let _ = CloseHandle(handle);

        if ok.is_err() || len == 0 {
            return (None, None);
        }

        let path = String::from_utf16_lossy(&buffer[..len as usize]);
        let name = path
            .rsplit(['\\', '/'])
            .next()
            .map(str::to_string)
            .filter(|s| !s.is_empty());

        (Some(path), name)
    }
}

#[cfg(not(windows))]
pub fn collect() -> Result<LocalPortFacts, CollectorError> {
    Err(CollectorError::Unsupported(
        "The local socket table is only readable on Windows.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(addr: &str, port: u16) -> Listener {
        let parsed: Ipv4Addr = addr.parse().unwrap();
        Listener {
            port,
            protocol: "tcp".into(),
            local_address: addr.to_string(),
            scope: classify_bind(parsed),
            pid: 1234,
            process_path: None,
            process_name: None,
            well_known_service: well_known_service(port).map(str::to_string),
        }
    }

    #[test]
    fn loopback_is_not_a_network_exposure() {
        // The distinction this module exists for.
        let l = listener("127.0.0.1", 5432);
        assert_eq!(l.scope, BindScope::LoopbackOnly);
        assert!(!l.scope.is_reachable_by_others());
    }

    #[test]
    fn binding_to_all_interfaces_is_reachable() {
        let l = listener("0.0.0.0", 445);
        assert_eq!(l.scope, BindScope::AllInterfaces);
        assert!(l.scope.is_reachable_by_others());
    }

    #[test]
    fn binding_to_one_address_is_reachable_on_that_network() {
        let l = listener("192.168.1.42", 3389);
        assert_eq!(l.scope, BindScope::SpecificInterface);
        assert!(l.scope.is_reachable_by_others());
    }

    #[test]
    fn the_stored_form_matches_the_serialised_form() {
        // The database and the UI must agree on these strings.
        for scope in [
            BindScope::LoopbackOnly,
            BindScope::SpecificInterface,
            BindScope::AllInterfaces,
        ] {
            let json = serde_json::to_string(&scope).unwrap();
            assert_eq!(json.trim_matches('"'), scope.as_str());
        }
    }

    #[test]
    fn well_known_ports_are_named_in_plain_language() {
        assert_eq!(well_known_service(445), Some("Windows file sharing (SMB)"));
        assert_eq!(well_known_service(3389), Some("Remote Desktop"));
        assert_eq!(well_known_service(80), Some("HTTP (web)"));
        assert_eq!(well_known_service(54321), None);
    }

    #[test]
    fn the_two_scopes_are_counted_separately() {
        let facts = LocalPortFacts {
            listeners: vec![
                listener("127.0.0.1", 5432),
                listener("127.0.0.1", 6379),
                listener("0.0.0.0", 445),
            ],
            evidence: vec![],
            collected_at: String::new(),
        };

        assert_eq!(facts.loopback_only().count(), 2);
        assert_eq!(facts.network_reachable().count(), 1);
        assert_eq!(facts.network_reachable().next().unwrap().port, 445);
    }

    #[cfg(windows)]
    #[test]
    fn reading_the_socket_table_on_this_machine_works() {
        let facts = collect().expect("the socket table should be readable");
        assert!(
            !facts.listeners.is_empty(),
            "a running Windows machine always has listening sockets"
        );
        assert!(facts
            .evidence
            .iter()
            .any(|e| e.contains("GetExtendedTcpTable")));

        // Ports must be sane: the byte-order conversion is easy to get wrong
        // and would silently produce nonsense like 55552 instead of 445.
        for l in &facts.listeners {
            assert!(
                l.port > 0,
                "port 0 means the byte order conversion is wrong"
            );
        }
    }
}

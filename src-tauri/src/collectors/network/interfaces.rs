//! Network adapters, addresses, gateways and DNS servers.
//!
//! Read through `GetAdaptersAddresses` (IP Helper). This is the foundation for
//! everything else in the network engine: it establishes which subnet the
//! machine is actually on, which is what makes a device scan bounded and a
//! "this is your router" claim meaningful.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    /// Adapter GUID, stable across reboots.
    pub id: String,
    /// What the user would recognise, e.g. "Intel(R) Wi-Fi 6E AX211".
    pub description: String,
    pub friendly_name: String,
    /// Formatted as aa:bb:cc:dd:ee:ff; absent for loopback and tunnels.
    pub mac: Option<String>,
    pub ipv4: Vec<InterfaceAddress>,
    pub ipv6: Vec<InterfaceAddress>,
    pub gateways: Vec<String>,
    pub dns_servers: Vec<String>,
    /// True when the adapter is up and has an address.
    pub is_up: bool,
    pub is_loopback: bool,
    /// Ethernet, Wi-Fi, tunnel and so on.
    pub interface_type: String,
}

impl NetworkInterface {
    /// The adapter is usable for scanning: up, not loopback, has an IPv4
    /// address and a gateway.
    pub fn is_scannable(&self) -> bool {
        self.is_up && !self.is_loopback && !self.ipv4.is_empty() && !self.gateways.is_empty()
    }

    /// The primary IPv4 address and prefix, if any.
    pub fn primary_ipv4(&self) -> Option<&InterfaceAddress> {
        self.ipv4.first()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceAddress {
    pub address: String,
    /// CIDR prefix length, e.g. 24 for a 255.255.255.0 subnet.
    pub prefix_length: u8,
}

impl InterfaceAddress {
    /// Every host address in this subnet, excluding the network and broadcast
    /// addresses.
    ///
    /// Returns `None` for anything wider than a /16. A /8 is 16 million hosts;
    /// enumerating it would not be a scan, it would be a denial of service
    /// against the user's own network.
    pub fn host_addresses(&self) -> Option<Vec<Ipv4Addr>> {
        let ip: Ipv4Addr = self.address.parse().ok()?;
        if self.prefix_length < 16 || self.prefix_length > 30 {
            return None;
        }

        let bits = u32::from(ip);
        let mask = u32::MAX
            .checked_shl(32 - u32::from(self.prefix_length))
            .unwrap_or(0);
        let network = bits & mask;
        let broadcast = network | !mask;

        // Skip the network address itself and the broadcast address.
        Some((network + 1..broadcast).map(Ipv4Addr::from).collect())
    }

    /// How many hosts this subnet could contain.
    pub fn host_count(&self) -> Option<u32> {
        if self.prefix_length < 16 || self.prefix_length > 30 {
            return None;
        }
        Some((1u32 << (32 - self.prefix_length)) - 2)
    }

    /// Is `ip` inside this subnet?
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let Ok(own): Result<Ipv4Addr, _> = self.address.parse() else {
            return false;
        };
        let Some(mask) = u32::MAX.checked_shl(32 - u32::from(self.prefix_length)) else {
            return false;
        };
        (u32::from(own) & mask) == (u32::from(ip) & mask)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceFacts {
    pub interfaces: Vec<NetworkInterface>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl InterfaceFacts {
    /// Adapters worth scanning from.
    pub fn scannable(&self) -> impl Iterator<Item = &NetworkInterface> {
        self.interfaces.iter().filter(|i| i.is_scannable())
    }

    /// The default gateway, which on a home network is the router.
    pub fn primary_gateway(&self) -> Option<&str> {
        self.scannable()
            .find_map(|i| i.gateways.first())
            .map(String::as_str)
    }
}

#[cfg(windows)]
pub fn collect() -> Result<InterfaceFacts, CollectorError> {
    use std::ffi::c_void;

    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_OPER_STATUS_UP: i32 = 1;
    const ERROR_BUFFER_OVERFLOW_U32: u32 = 111;

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;

    // Ask for the required size first, then allocate. The table can change
    // between the two calls, so the loop retries on overflow.
    let mut buffer: Vec<u8> = Vec::new();
    let mut size: u32 = 16 * 1024;

    for _ in 0..4 {
        buffer.resize(size as usize, 0);
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };

        match result {
            0 => break,
            ERROR_BUFFER_OVERFLOW_U32 => continue,
            code => {
                return Err(CollectorError::Unavailable(format!(
                    "Windows could not list network adapters (error {code})."
                )))
            }
        }
    }

    let mut facts = InterfaceFacts {
        interfaces: Vec::new(),
        evidence: vec!["Windows API: GetAdaptersAddresses (IP Helper)".to_string()],
        collected_at: chrono::Utc::now().to_rfc3339(),
    };

    unsafe {
        let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

        while !current.is_null() {
            let adapter = &*current;

            let interface_type = describe_if_type(adapter.IfType);
            let is_loopback = adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            let is_up = adapter.OperStatus.0 == IF_OPER_STATUS_UP;

            let mac = (adapter.PhysicalAddressLength > 0).then(|| {
                adapter.PhysicalAddress[..adapter.PhysicalAddressLength as usize]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            });

            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();

            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                let entry = &*unicast;
                if let Some(ip) = sockaddr_to_ip(entry.Address.lpSockaddr as *const c_void) {
                    let address = InterfaceAddress {
                        address: ip.to_string(),
                        prefix_length: entry.OnLinkPrefixLength,
                    };
                    match ip {
                        IpAddr::V4(_) => ipv4.push(address),
                        IpAddr::V6(_) => ipv6.push(address),
                    }
                }
                unicast = entry.Next;
            }

            let mut gateways = Vec::new();
            let mut gateway = adapter.FirstGatewayAddress;
            while !gateway.is_null() {
                let entry = &*gateway;
                if let Some(ip) = sockaddr_to_ip(entry.Address.lpSockaddr as *const c_void) {
                    gateways.push(ip.to_string());
                }
                gateway = entry.Next;
            }

            let mut dns_servers = Vec::new();
            let mut dns = adapter.FirstDnsServerAddress;
            while !dns.is_null() {
                let entry = &*dns;
                if let Some(ip) = sockaddr_to_ip(entry.Address.lpSockaddr as *const c_void) {
                    dns_servers.push(ip.to_string());
                }
                dns = entry.Next;
            }

            let id = pcstr_to_string(adapter.AdapterName.0);
            let description = pwstr_to_string(adapter.Description.0);
            let friendly_name = pwstr_to_string(adapter.FriendlyName.0);

            // Loopback and adapters with no address tell us nothing and would
            // only clutter the evidence trail.
            if !is_loopback && (!ipv4.is_empty() || !ipv6.is_empty()) {
                facts.evidence.push(format!(
                    "{friendly_name}: {} IPv4, {} IPv6, gateway {}",
                    ipv4.len(),
                    ipv6.len(),
                    gateways.first().map(String::as_str).unwrap_or("none")
                ));
            }

            facts.interfaces.push(NetworkInterface {
                id,
                description,
                friendly_name,
                mac,
                ipv4,
                ipv6,
                gateways,
                dns_servers,
                is_up,
                is_loopback,
                interface_type,
            });

            current = adapter.Next;
        }
    }

    if facts.interfaces.is_empty() {
        return Err(CollectorError::Unavailable(
            "Windows reported no network adapters at all, which cannot be right.".into(),
        ));
    }

    Ok(facts)
}

#[cfg(windows)]
unsafe fn sockaddr_to_ip(ptr: *const std::ffi::c_void) -> Option<IpAddr> {
    use std::net::Ipv6Addr;

    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };

    if ptr.is_null() {
        return None;
    }

    let family = (*(ptr as *const SOCKADDR)).sa_family;

    if family == AF_INET {
        let addr = &*(ptr as *const SOCKADDR_IN);
        let octets = addr.sin_addr.S_un.S_addr.to_ne_bytes();
        Some(IpAddr::V4(Ipv4Addr::from(octets)))
    } else if family == AF_INET6 {
        let addr = &*(ptr as *const SOCKADDR_IN6);
        Some(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.u.Byte)))
    } else {
        None
    }
}

#[cfg(windows)]
unsafe fn pwstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

#[cfg(windows)]
unsafe fn pcstr_to_string(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
}

/// IANA interface types, for the handful that matter to a home user.
fn describe_if_type(if_type: u32) -> String {
    match if_type {
        6 => "Ethernet",
        23 => "PPP",
        24 => "Loopback",
        71 => "Wi-Fi",
        131 => "Tunnel",
        144 => "IEEE 1394",
        237 => "Mobile broadband",
        other => return format!("Type {other}"),
    }
    .to_string()
}

#[cfg(not(windows))]
pub fn collect() -> Result<InterfaceFacts, CollectorError> {
    Err(CollectorError::Unsupported(
        "Network adapter enumeration is only available on Windows.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(address: &str, prefix: u8) -> InterfaceAddress {
        InterfaceAddress {
            address: address.to_string(),
            prefix_length: prefix,
        }
    }

    #[test]
    fn a_slash_24_has_254_hosts() {
        let a = addr("192.168.1.42", 24);
        assert_eq!(a.host_count(), Some(254));

        let hosts = a.host_addresses().unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn network_and_broadcast_addresses_are_excluded() {
        let hosts = addr("10.0.0.5", 24).host_addresses().unwrap();
        assert!(
            !hosts.contains(&Ipv4Addr::new(10, 0, 0, 0)),
            "network address"
        );
        assert!(
            !hosts.contains(&Ipv4Addr::new(10, 0, 0, 255)),
            "broadcast address"
        );
    }

    #[test]
    fn oversized_subnets_are_refused() {
        // A /8 is 16 million hosts. Enumerating it would flood the user's own
        // network, so it is refused rather than attempted.
        assert_eq!(addr("10.0.0.1", 8).host_addresses(), None);
        assert_eq!(addr("10.0.0.1", 8).host_count(), None);
        assert_eq!(addr("172.16.0.1", 12).host_addresses(), None);
    }

    #[test]
    fn a_slash_16_is_the_widest_accepted() {
        assert_eq!(addr("192.168.0.1", 16).host_count(), Some(65534));
        assert_eq!(addr("192.168.0.1", 15).host_count(), None);
    }

    #[test]
    fn single_host_prefixes_are_refused() {
        // /31 and /32 have no usable host range.
        assert_eq!(addr("192.168.1.1", 31).host_addresses(), None);
        assert_eq!(addr("192.168.1.1", 32).host_addresses(), None);
    }

    #[test]
    fn subnet_membership_is_computed_from_the_mask() {
        let a = addr("192.168.1.42", 24);
        assert!(a.contains(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(a.contains(Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!a.contains(Ipv4Addr::new(192, 168, 2, 1)));
        assert!(!a.contains(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn an_interface_needs_an_address_and_a_gateway_to_be_scannable() {
        let mut iface = NetworkInterface {
            id: "x".into(),
            description: "d".into(),
            friendly_name: "Wi-Fi".into(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            ipv4: vec![addr("192.168.1.42", 24)],
            ipv6: vec![],
            gateways: vec!["192.168.1.1".into()],
            dns_servers: vec![],
            is_up: true,
            is_loopback: false,
            interface_type: "Wi-Fi".into(),
        };
        assert!(iface.is_scannable());

        iface.gateways.clear();
        assert!(!iface.is_scannable(), "no gateway means no network to scan");

        iface.gateways.push("192.168.1.1".into());
        iface.is_up = false;
        assert!(!iface.is_scannable());

        iface.is_up = true;
        iface.is_loopback = true;
        assert!(!iface.is_scannable());
    }

    #[test]
    fn interface_types_are_named_not_numbered() {
        assert_eq!(describe_if_type(6), "Ethernet");
        assert_eq!(describe_if_type(71), "Wi-Fi");
        assert_eq!(describe_if_type(24), "Loopback");
        assert_eq!(describe_if_type(9999), "Type 9999");
    }

    #[cfg(windows)]
    #[test]
    fn collecting_on_this_machine_finds_adapters() {
        let facts = collect().expect("adapter enumeration should work on Windows");
        assert!(!facts.interfaces.is_empty());
        assert!(facts
            .evidence
            .iter()
            .any(|e| e.contains("GetAdaptersAddresses")));
    }
}

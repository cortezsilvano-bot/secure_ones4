//! Building the device list for the local network.
//!
//! Merges the passive neighbour table with adapter information and the MAC
//! vendor registry. Identity is keyed on MAC rather than IP, because an IP is
//! a DHCP lease that moves between devices -- keying on it would raise a fresh
//! "new device on your network" alert every time a lease rolled over, which is
//! the fastest way to train someone to ignore the alerts that matter.

use serde::{Deserialize, Serialize};

use crate::database::Database;
use crate::security::CollectorError;
use crate::vulnerabilities::feeds::oui;

use super::interfaces::InterfaceFacts;
use super::neighbors::NeighborFacts;

/// What kind of thing a device appears to be. A hint for the user, never a
/// claim of certainty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    Router,
    ThisComputer,
    Unknown,
}

/// The user's own judgement about a device. A scan never changes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// Never assessed by the user.
    None,
    Trusted,
    Flagged,
}

impl Trust {
    fn from_str(raw: &str) -> Trust {
        match raw {
            "trusted" => Trust::Trusted,
            "flagged" => Trust::Flagged,
            _ => Trust::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Trust::None => "none",
            Trust::Trusted => "trusted",
            Trust::Flagged => "flagged",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    /// MAC when known, otherwise `ip:<address>`.
    pub id: String,
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    /// Manufacturer from the IEEE registry. `None` when the registry has not
    /// been downloaded, or the MAC is randomised.
    pub vendor: Option<String>,
    /// Set by the user; wins over hostname and vendor for display.
    pub display_name: Option<String>,
    pub device_type: DeviceType,
    /// A randomised MAC has no manufacturer to look up. Phones do this by
    /// default, so this is normal rather than suspicious.
    pub mac_is_random: bool,
    pub is_gateway: bool,
    pub is_self: bool,
    pub trust: Trust,
    pub first_seen: Option<String>,
    pub last_seen: String,
    pub discovered_via: String,
    /// True when the device answered during this scan. A device known from an
    /// earlier scan stays in the list with this false rather than disappearing.
    pub currently_visible: bool,
}

impl Device {
    /// What to show the user, best available.
    pub fn label(&self) -> String {
        self.display_name
            .clone()
            .or_else(|| self.hostname.clone())
            .or_else(|| self.vendor.clone())
            .or_else(|| self.ip.clone())
            .unwrap_or_else(|| self.id.clone())
    }

    /// A device the user has never assessed and that is not this PC or the
    /// router. These are what "1 new device" counts.
    pub fn is_unreviewed(&self) -> bool {
        self.trust == Trust::None && !self.is_self && !self.is_gateway
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceFacts {
    pub devices: Vec<Device>,
    /// How many of `devices` answered during this scan.
    pub visible_now: usize,
    /// True when the MAC vendor registry has been downloaded. Without it every
    /// vendor is `None`, which must not read as "unidentifiable hardware".
    pub vendor_registry_available: bool,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl DeviceFacts {
    pub fn unreviewed(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter().filter(|d| d.is_unreviewed())
    }

    pub fn gateway(&self) -> Option<&Device> {
        self.devices.iter().find(|d| d.is_gateway)
    }
}

/// Build the device list from already-collected facts.
///
/// Takes the facts rather than collecting them so the caller controls how much
/// of the network engine runs, and so this is testable without a network.
pub fn build(
    db: &Database,
    interfaces: &InterfaceFacts,
    neighbors: &NeighborFacts,
) -> Result<DeviceFacts, CollectorError> {
    let now = chrono::Utc::now().to_rfc3339();

    let vendor_registry_available = oui_count(db).unwrap_or(0) > 0;

    let gateways: Vec<String> = interfaces
        .scannable()
        .flat_map(|i| i.gateways.iter().cloned())
        .collect();

    let own_macs: Vec<String> = interfaces
        .interfaces
        .iter()
        .filter_map(|i| i.mac.clone())
        .map(|m| m.to_ascii_lowercase())
        .collect();

    let own_ips: Vec<String> = interfaces
        .interfaces
        .iter()
        .flat_map(|i| i.ipv4.iter().map(|a| a.address.clone()))
        .collect();

    let mut facts = DeviceFacts {
        devices: Vec::new(),
        visible_now: 0,
        vendor_registry_available,
        evidence: vec![
            "Source: Windows neighbour table plus adapter configuration".to_string(),
            if vendor_registry_available {
                "MAC manufacturer lookup: IEEE registry (local copy)".to_string()
            } else {
                "MAC manufacturer lookup: registry not downloaded, so vendors are unknown"
                    .to_string()
            },
        ],
        collected_at: now.clone(),
    };

    for neighbor in neighbors.devices() {
        let mac = neighbor.mac.clone();
        let id = mac
            .clone()
            .map(|m| m.to_ascii_lowercase())
            .unwrap_or_else(|| format!("ip:{}", neighbor.ip));

        let mac_is_random = mac
            .as_deref()
            .and_then(oui::is_locally_administered)
            .unwrap_or(false);

        // A randomised MAC has no manufacturer, so looking one up would return
        // whichever company happens to own that prefix -- a wrong answer.
        let vendor = if mac_is_random {
            None
        } else {
            mac.as_deref()
                .and_then(oui::prefix_of)
                .and_then(|p| lookup_vendor(db, &p).ok().flatten())
        };

        let is_gateway = gateways.contains(&neighbor.ip);
        let is_self = own_ips.contains(&neighbor.ip)
            || mac
                .as_deref()
                .is_some_and(|m| own_macs.contains(&m.to_ascii_lowercase()));

        facts.devices.push(Device {
            id,
            mac,
            ip: Some(neighbor.ip.clone()),
            hostname: None,
            vendor,
            display_name: None,
            device_type: if is_gateway {
                DeviceType::Router
            } else if is_self {
                DeviceType::ThisComputer
            } else {
                DeviceType::Unknown
            },
            mac_is_random,
            is_gateway,
            is_self,
            trust: Trust::None,
            first_seen: None,
            last_seen: now.clone(),
            discovered_via: "neighbor_table".to_string(),
            currently_visible: true,
        });
    }

    // This PC is on the network whether or not it appears in its own neighbour
    // table, and it normally does not.
    if !facts.devices.iter().any(|d| d.is_self) {
        if let Some(iface) = interfaces.scannable().next() {
            // This PC's own adapter gets the same manufacturer lookup as every
            // other device; leaving it blank made the machine the one entry in
            // its own device list with no identity.
            let own_vendor = iface
                .mac
                .as_deref()
                .filter(|m| !oui::is_locally_administered(m).unwrap_or(false))
                .and_then(oui::prefix_of)
                .and_then(|p| lookup_vendor(db, &p).ok().flatten());

            facts.devices.push(Device {
                id: iface
                    .mac
                    .clone()
                    .map(|m| m.to_ascii_lowercase())
                    .unwrap_or_else(|| "self".to_string()),
                mac: iface.mac.clone(),
                ip: iface.primary_ipv4().map(|a| a.address.clone()),
                hostname: hostname(),
                vendor: own_vendor,
                display_name: None,
                device_type: DeviceType::ThisComputer,
                mac_is_random: false,
                is_gateway: false,
                is_self: true,
                trust: Trust::Trusted,
                first_seen: None,
                last_seen: now.clone(),
                discovered_via: "local_adapter".to_string(),
                currently_visible: true,
            });
        }
    }

    // Restore each device's remembered identity and the user's trust decision.
    for device in &mut facts.devices {
        if let Ok(Some(stored)) = stored_device(db, &device.id) {
            device.trust = stored.trust;
            device.first_seen = stored.first_seen;
            device.display_name = stored.display_name;
            if device.hostname.is_none() {
                device.hostname = stored.hostname;
            }
        }
    }

    facts.visible_now = facts.devices.len();

    // Bring back devices seen on earlier scans that did not answer this time.
    //
    // Windows' ARP cache expires entries after a few minutes of silence, so a
    // printer that is simply idle drops out of the neighbour table. Rebuilding
    // the list purely from what is visible right now would make devices --
    // and any finding about them -- appear and vanish between scans, which is
    // both wrong and the fastest way to teach someone to ignore the alerts.
    if let Ok(remembered) = remembered_devices(db, REMEMBER_FOR_DAYS) {
        for device in remembered {
            if facts.devices.iter().any(|d| d.id == device.id) {
                continue;
            }
            facts.devices.push(device);
        }
    }

    facts.devices.sort_by(|a, b| {
        // Router first, then this PC, then devices answering now, then the rest.
        b.is_gateway
            .cmp(&a.is_gateway)
            .then(b.is_self.cmp(&a.is_self))
            .then(b.currently_visible.cmp(&a.currently_visible))
            .then(a.ip.cmp(&b.ip))
    });

    facts.evidence.push(format!(
        "{} device(s) known, {} answering now, {} not yet reviewed",
        facts.devices.len(),
        facts.visible_now,
        facts.unreviewed().count()
    ));

    Ok(facts)
}

/// What the store already knows about a device.
struct StoredDevice {
    trust: Trust,
    first_seen: Option<String>,
    display_name: Option<String>,
    hostname: Option<String>,
}

fn stored_device(db: &Database, id: &str) -> rusqlite::Result<Option<StoredDevice>> {
    use rusqlite::OptionalExtension;

    db.with(|c| {
        c.query_row(
            "SELECT trust, first_seen, display_name, hostname FROM devices WHERE id = ?1",
            [id],
            |r| {
                Ok(StoredDevice {
                    trust: Trust::from_str(&r.get::<_, String>(0)?),
                    first_seen: r.get(1)?,
                    display_name: r.get(2)?,
                    hostname: r.get(3)?,
                })
            },
        )
        .optional()
    })
}

/// How long a device stays in the list after it was last seen. Long enough to
/// cover a printer that is off overnight or a laptop away for a fortnight.
const REMEMBER_FOR_DAYS: i64 = 30;

/// Devices the store knows about that did not answer during this scan.
fn remembered_devices(db: &Database, within_days: i64) -> rusqlite::Result<Vec<Device>> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(within_days)).to_rfc3339();

    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, mac, ip, hostname, vendor, display_name, device_type, mac_is_random,
                    is_gateway, is_self, trust, first_seen, last_seen, discovered_via
             FROM devices WHERE last_seen >= ?1",
        )?;

        let rows = stmt.query_map([&cutoff], |r| {
            Ok(Device {
                id: r.get(0)?,
                mac: r.get(1)?,
                ip: r.get(2)?,
                hostname: r.get(3)?,
                vendor: r.get(4)?,
                display_name: r.get(5)?,
                device_type: match r.get::<_, String>(6)?.as_str() {
                    "router" => DeviceType::Router,
                    "thiscomputer" => DeviceType::ThisComputer,
                    _ => DeviceType::Unknown,
                },
                mac_is_random: r.get::<_, i32>(7)? != 0,
                is_gateway: r.get::<_, i32>(8)? != 0,
                is_self: r.get::<_, i32>(9)? != 0,
                trust: Trust::from_str(&r.get::<_, String>(10)?),
                first_seen: r.get(11)?,
                last_seen: r.get(12)?,
                discovered_via: r.get::<_, Option<String>>(13)?.unwrap_or_default(),
                currently_visible: false,
            })
        })?;

        rows.collect()
    })
}

fn oui_count(db: &Database) -> rusqlite::Result<i64> {
    db.with(|c| c.query_row("SELECT count(*) FROM oui", [], |r| r.get(0)))
}

fn lookup_vendor(db: &Database, prefix: &str) -> rusqlite::Result<Option<String>> {
    use rusqlite::OptionalExtension;

    db.with(|c| {
        c.query_row(
            "SELECT organization FROM oui WHERE prefix = ?1",
            [prefix],
            |r| r.get(0),
        )
        .optional()
    })
}

#[cfg(windows)]
fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty())
}

#[cfg(not(windows))]
fn hostname() -> Option<String> {
    std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty())
}

/// Persist the device list, preserving trust and first-seen.
pub fn save(db: &Database, facts: &DeviceFacts) -> rusqlite::Result<()> {
    db.with(|c| {
        let tx = c.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO devices (id, mac, ip, hostname, vendor, display_name, device_type,
                        mac_is_random, is_gateway, is_self, trust, first_seen, last_seen,
                        discovered_via)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, ?13)
                 ON CONFLICT (id) DO UPDATE SET
                    ip = ?3,
                    hostname = COALESCE(?4, hostname),
                    vendor = COALESCE(?5, vendor),
                    device_type = ?7,
                    mac_is_random = ?8,
                    is_gateway = ?9,
                    is_self = ?10,
                    last_seen = ?12,
                    discovered_via = ?13",
                // trust and display_name are deliberately absent from the
                // update: they belong to the user, not to a scan.
            )?;

            for d in &facts.devices {
                // A device that did not answer keeps its previous last_seen;
                // re-stamping it would make it look permanently present.
                if !d.currently_visible {
                    continue;
                }
                stmt.execute(rusqlite::params![
                    d.id,
                    d.mac,
                    d.ip,
                    d.hostname,
                    d.vendor,
                    d.display_name,
                    format!("{:?}", d.device_type).to_lowercase(),
                    d.mac_is_random as i32,
                    d.is_gateway as i32,
                    d.is_self as i32,
                    d.trust.as_str(),
                    d.last_seen,
                    d.discovered_via,
                ])?;
            }
        }
        tx.commit()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::network::interfaces::{InterfaceAddress, NetworkInterface};
    use crate::collectors::network::neighbors::{Neighbor, NeighborState};

    fn db() -> Database {
        Database::open_in_memory().unwrap()
    }

    fn interfaces() -> InterfaceFacts {
        InterfaceFacts {
            interfaces: vec![NetworkInterface {
                id: "adapter".into(),
                description: "Wi-Fi".into(),
                friendly_name: "Wi-Fi".into(),
                mac: Some("40:d1:33:00:00:01".into()),
                ipv4: vec![InterfaceAddress {
                    address: "192.168.1.42".into(),
                    prefix_length: 24,
                }],
                ipv6: vec![],
                gateways: vec!["192.168.1.1".into()],
                dns_servers: vec!["192.168.1.1".into()],
                is_up: true,
                is_loopback: false,
                interface_type: "Wi-Fi".into(),
            }],
            evidence: vec![],
            collected_at: String::new(),
        }
    }

    fn neighbor(ip: &str, mac: &str) -> Neighbor {
        Neighbor {
            ip: ip.into(),
            mac: Some(mac.into()),
            state: NeighborState::Reachable,
            interface_index: 1,
            is_multicast: false,
        }
    }

    fn neighbors(list: Vec<Neighbor>) -> NeighborFacts {
        NeighborFacts {
            neighbors: list,
            evidence: vec![],
            collected_at: String::new(),
        }
    }

    #[test]
    fn the_gateway_is_identified_as_the_router() {
        let facts = build(
            &db(),
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.1", "11:22:33:44:55:66")]),
        )
        .unwrap();

        let gw = facts.gateway().expect("gateway should be found");
        assert_eq!(gw.ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(gw.device_type, DeviceType::Router);
        assert!(!gw.is_unreviewed(), "the router is not an unknown device");
    }

    #[test]
    fn this_pc_is_included_even_when_absent_from_the_neighbour_table() {
        // A machine does not normally ARP for itself.
        let facts = build(&db(), &interfaces(), &neighbors(vec![])).unwrap();

        let me = facts
            .devices
            .iter()
            .find(|d| d.is_self)
            .expect("self should appear");
        assert_eq!(me.ip.as_deref(), Some("192.168.1.42"));
        assert_eq!(me.trust, Trust::Trusted, "this PC is trusted by definition");
        assert!(!me.is_unreviewed());
    }

    #[test]
    fn a_locally_administered_adapter_gets_no_vendor_guess() {
        // 0xAA has bit 1 set, so aa:bb:cc is a locally administered address
        // with no manufacturer behind it.
        let db = db();
        db.with(|c| {
            c.execute(
                "INSERT INTO oui (prefix, organization) VALUES ('AABBCC', 'Someone')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

        let mut ifaces = interfaces();
        ifaces.interfaces[0].mac = Some("aa:bb:cc:00:00:01".into());

        let facts = build(&db, &ifaces, &neighbors(vec![])).unwrap();
        let me = facts.devices.iter().find(|d| d.is_self).unwrap();
        assert_eq!(
            me.vendor, None,
            "a randomised address has no manufacturer to report"
        );
    }

    #[test]
    fn this_pc_gets_a_manufacturer_like_any_other_device() {
        let db = db();
        db.with(|c| {
            c.execute(
                "INSERT INTO oui (prefix, organization) VALUES ('40D133', 'Intel Corporate')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

        let facts = build(&db, &interfaces(), &neighbors(vec![])).unwrap();
        let me = facts.devices.iter().find(|d| d.is_self).unwrap();
        assert_eq!(
            me.vendor.as_deref(),
            Some("Intel Corporate"),
            "this PC should not be the one device with no identity"
        );
    }

    #[test]
    fn an_unknown_device_counts_as_unreviewed() {
        let facts = build(
            &db(),
            &interfaces(),
            &neighbors(vec![
                neighbor("192.168.1.1", "11:22:33:44:55:66"),
                neighbor("192.168.1.77", "24:62:ab:11:22:33"),
            ]),
        )
        .unwrap();

        assert_eq!(facts.unreviewed().count(), 1);
        assert_eq!(
            facts.unreviewed().next().unwrap().ip.as_deref(),
            Some("192.168.1.77")
        );
    }

    #[test]
    fn a_randomised_mac_gets_no_vendor_guess() {
        // 02: is locally administered. Looking up whoever owns that prefix
        // would produce a confidently wrong manufacturer.
        let facts = build(
            &db(),
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.90", "02:11:22:33:44:55")]),
        )
        .unwrap();

        let device = facts
            .devices
            .iter()
            .find(|d| d.ip.as_deref() == Some("192.168.1.90"))
            .unwrap();
        assert!(device.mac_is_random);
        assert_eq!(device.vendor, None);
    }

    #[test]
    fn vendors_come_from_the_registry_when_it_is_present() {
        let db = db();
        db.with(|c| {
            c.execute(
                "INSERT INTO oui (prefix, organization) VALUES ('2462AB', 'Espressif Inc.')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

        let facts = build(
            &db,
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.77", "24:62:ab:11:22:33")]),
        )
        .unwrap();

        assert!(facts.vendor_registry_available);
        let device = facts
            .devices
            .iter()
            .find(|d| d.ip.as_deref() == Some("192.168.1.77"))
            .unwrap();
        assert_eq!(device.vendor.as_deref(), Some("Espressif Inc."));
        assert_eq!(device.label(), "Espressif Inc.");
    }

    #[test]
    fn a_missing_registry_is_reported_not_silently_blank() {
        let facts = build(
            &db(),
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.77", "24:62:ab:11:22:33")]),
        )
        .unwrap();

        assert!(!facts.vendor_registry_available);
        assert!(facts
            .evidence
            .iter()
            .any(|e| e.contains("registry not downloaded")));
    }

    #[test]
    fn a_device_keeps_its_identity_when_its_address_changes() {
        // The DHCP-lease case. Same MAC, new IP, must not become a new device.
        let db = db();
        let first = build(
            &db,
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.77", "24:62:ab:11:22:33")]),
        )
        .unwrap();
        save(&db, &first).unwrap();

        let second = build(
            &db,
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.99", "24:62:ab:11:22:33")]),
        )
        .unwrap();
        save(&db, &second).unwrap();

        let count: i64 = db
            .with(|c| {
                c.query_row(
                    "SELECT count(*) FROM devices WHERE mac IS NOT NULL",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(count, 2, "the moved device plus this PC, not three rows");

        let ip: String = db
            .with(|c| {
                c.query_row(
                    "SELECT ip FROM devices WHERE id = '24:62:ab:11:22:33'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(ip, "192.168.1.99", "the address should update in place");
    }

    #[test]
    fn a_device_is_remembered_after_its_arp_entry_expires() {
        // The regression this guards: Windows drops idle devices from the ARP
        // cache after a few minutes. Rebuilding purely from what is visible
        // made a printer -- and the finding about it -- vanish between scans.
        let db = db();

        let seen = build(
            &db,
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.77", "24:62:ab:11:22:33")]),
        )
        .unwrap();
        save(&db, &seen).unwrap();
        assert_eq!(seen.visible_now, 2, "the printer and this PC answered");

        // Next scan: the printer is idle and no longer in the neighbour table.
        let later = build(&db, &interfaces(), &neighbors(vec![])).unwrap();

        let printer = later
            .devices
            .iter()
            .find(|d| d.id == "24:62:ab:11:22:33")
            .expect("the device must still be listed");

        assert!(!printer.currently_visible, "it did not answer this time");
        assert!(
            printer.is_unreviewed(),
            "and it is still an unreviewed device, so the finding must not flap"
        );
        assert_eq!(later.visible_now, 1, "only this PC answered");
    }

    #[test]
    fn a_device_that_did_not_answer_keeps_its_last_seen() {
        let db = db();

        let seen = build(
            &db,
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.77", "24:62:ab:11:22:33")]),
        )
        .unwrap();
        save(&db, &seen).unwrap();

        let original: String = db
            .with(|c| {
                c.query_row(
                    "SELECT last_seen FROM devices WHERE id = '24:62:ab:11:22:33'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        let later = build(&db, &interfaces(), &neighbors(vec![])).unwrap();
        save(&db, &later).unwrap();

        let after: String = db
            .with(|c| {
                c.query_row(
                    "SELECT last_seen FROM devices WHERE id = '24:62:ab:11:22:33'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();

        assert_eq!(
            original, after,
            "last_seen must record when the device was actually seen"
        );
    }

    #[test]
    fn a_users_trust_decision_survives_a_rescan() {
        let db = db();
        let facts = build(
            &db,
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.77", "24:62:ab:11:22:33")]),
        )
        .unwrap();
        save(&db, &facts).unwrap();

        db.with(|c| {
            c.execute(
                "UPDATE devices SET trust = 'trusted', display_name = 'Kitchen plug' WHERE id = '24:62:ab:11:22:33'",
                [],
            )?;
            Ok(())
        })
        .unwrap();

        let rescanned = build(
            &db,
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.77", "24:62:ab:11:22:33")]),
        )
        .unwrap();
        save(&db, &rescanned).unwrap();

        let device = rescanned
            .devices
            .iter()
            .find(|d| d.id == "24:62:ab:11:22:33")
            .unwrap();
        assert_eq!(
            device.trust,
            Trust::Trusted,
            "a scan must not un-trust a device"
        );
        assert_eq!(device.display_name.as_deref(), Some("Kitchen plug"));
        assert_eq!(device.label(), "Kitchen plug");
        assert!(!device.is_unreviewed());

        let (trust, name): (String, String) = db
            .with(|c| {
                c.query_row(
                    "SELECT trust, display_name FROM devices WHERE id = '24:62:ab:11:22:33'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .unwrap();
        assert_eq!(trust, "trusted");
        assert_eq!(name, "Kitchen plug");
    }

    #[test]
    fn first_seen_is_preserved_across_scans() {
        let db = db();
        let facts = build(
            &db,
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.77", "24:62:ab:11:22:33")]),
        )
        .unwrap();
        save(&db, &facts).unwrap();

        let original: String = db
            .with(|c| {
                c.query_row(
                    "SELECT first_seen FROM devices WHERE id = '24:62:ab:11:22:33'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        let again = build(
            &db,
            &interfaces(),
            &neighbors(vec![neighbor("192.168.1.77", "24:62:ab:11:22:33")]),
        )
        .unwrap();
        save(&db, &again).unwrap();

        let (first, last): (String, String) = db
            .with(|c| {
                c.query_row(
                    "SELECT first_seen, last_seen FROM devices WHERE id = '24:62:ab:11:22:33'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .unwrap();

        assert_eq!(
            first, original,
            "first_seen records when the device appeared"
        );
        assert!(last >= first);
    }

    #[test]
    fn the_label_falls_back_through_what_is_known() {
        let mut d = Device {
            id: "aa".into(),
            mac: None,
            ip: Some("192.168.1.5".into()),
            hostname: None,
            vendor: None,
            display_name: None,
            device_type: DeviceType::Unknown,
            mac_is_random: false,
            is_gateway: false,
            is_self: false,
            trust: Trust::None,
            first_seen: None,
            last_seen: String::new(),
            discovered_via: "t".into(),
            currently_visible: true,
        };
        assert_eq!(d.label(), "192.168.1.5");

        d.vendor = Some("Sonos".into());
        assert_eq!(d.label(), "Sonos");

        d.hostname = Some("kitchen-speaker".into());
        assert_eq!(d.label(), "kitchen-speaker");

        d.display_name = Some("Kitchen".into());
        assert_eq!(d.label(), "Kitchen", "the user's name wins");
    }
}

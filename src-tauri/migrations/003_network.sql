-- Network devices, the services found on them, and the MAC vendor registry.

-- IEEE MAC prefix to manufacturer. Downloaded whole and queried locally, so no
-- MAC address from the user's network is ever sent anywhere.
CREATE TABLE oui (
    prefix          TEXT PRIMARY KEY,          -- six uppercase hex chars
    organization    TEXT NOT NULL
);

-- Devices seen on the local network.
--
-- Keyed by MAC where one is known, because an IP address is a lease and moves
-- between devices. A device that changes address is the same device; treating
-- it as a new one would produce a fresh "unknown device" alert every time a
-- DHCP lease rolls over.
CREATE TABLE devices (
    id              TEXT PRIMARY KEY,          -- MAC when known, else "ip:<address>"
    mac             TEXT,
    ip              TEXT,
    hostname        TEXT,
    vendor          TEXT,
    -- Set by the user; overrides hostname and vendor for display.
    display_name    TEXT,
    device_type     TEXT,                      -- router | computer | phone | iot | printer | unknown
    -- randomised MAC, so vendor lookup is meaningless
    mac_is_random   INTEGER NOT NULL DEFAULT 0,
    is_gateway      INTEGER NOT NULL DEFAULT 0,
    is_self         INTEGER NOT NULL DEFAULT 0,
    -- none | trusted | flagged -- the user's own judgement, never overwritten
    -- by a scan.
    trust           TEXT NOT NULL DEFAULT 'none',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    -- How the device was found: neighbor_table | mdns | ssdp | port_scan
    discovered_via  TEXT
);

CREATE INDEX idx_devices_trust ON devices (trust);
CREATE INDEX idx_devices_last_seen ON devices (last_seen DESC);

-- Open ports found on a device.
CREATE TABLE device_ports (
    device_id       TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    port            INTEGER NOT NULL,
    protocol        TEXT NOT NULL,
    service         TEXT,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    PRIMARY KEY (device_id, port, protocol)
);

-- Services advertised on the network by mDNS/DNS-SD or SSDP.
CREATE TABLE network_services (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT REFERENCES devices (id) ON DELETE CASCADE,
    source          TEXT NOT NULL,             -- mdns | ssdp
    service_type    TEXT,
    name            TEXT,
    detail          TEXT,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
);

CREATE INDEX idx_services_device ON network_services (device_id);

-- What this machine itself is listening on, kept so changes over time are
-- visible rather than only the current snapshot.
CREATE TABLE local_listeners (
    port            INTEGER NOT NULL,
    protocol        TEXT NOT NULL,
    local_address   TEXT NOT NULL,
    scope           TEXT NOT NULL,             -- loopback_only | specific_interface | all_interfaces
    process_name    TEXT,
    process_path    TEXT,
    service         TEXT,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    PRIMARY KEY (port, protocol, local_address)
);

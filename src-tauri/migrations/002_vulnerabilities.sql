-- Vulnerability feed caches and the software inventory they are matched against.
-- Everything here is downloaded public data plus the local inventory; no part
-- of it is ever uploaded.

-- When each feed was last fetched, and whether it worked. Drives staleness
-- reporting: results from a feed that has not refreshed in weeks must be
-- labelled as such rather than presented as current.
CREATE TABLE feed_state (
    feed            TEXT    PRIMARY KEY,       -- kev | epss | nvd
    last_attempt    TEXT,
    last_success    TEXT,
    record_count    INTEGER NOT NULL DEFAULT 0,
    version         TEXT,                      -- feed-reported version, e.g. KEV catalogVersion
    last_error      TEXT
);

-- CISA Known Exploited Vulnerabilities.
CREATE TABLE kev (
    cve_id                  TEXT PRIMARY KEY,
    vendor_project          TEXT,
    product                 TEXT,
    vulnerability_name      TEXT,
    date_added              TEXT,
    short_description       TEXT,
    required_action         TEXT,
    due_date                TEXT,
    known_ransomware_use    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_kev_ransomware ON kev (known_ransomware_use);

-- FIRST EPSS scores.
CREATE TABLE epss (
    cve_id      TEXT PRIMARY KEY,
    epss        REAL NOT NULL,
    percentile  REAL NOT NULL,
    fetched_at  TEXT NOT NULL
);

-- NVD CVE records.
CREATE TABLE cve (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT,
    published       TEXT,
    last_modified   TEXT,
    cvss_score      REAL,
    cvss_severity   TEXT,
    cvss_vector     TEXT,
    fetched_at      TEXT NOT NULL
);

CREATE INDEX idx_cve_score ON cve (cvss_score DESC);

-- CPE match rules: which product versions each CVE applies to.
CREATE TABLE cve_cpe_match (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                  TEXT NOT NULL REFERENCES cve (cve_id) ON DELETE CASCADE,
    criteria                TEXT NOT NULL,
    vulnerable              INTEGER NOT NULL DEFAULT 1,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including   TEXT,
    version_end_excluding   TEXT
);

CREATE INDEX idx_cpe_match_cve ON cve_cpe_match (cve_id);
CREATE INDEX idx_cpe_match_criteria ON cve_cpe_match (criteria);

-- Which product keywords have been looked up against NVD, and when. NVD's
-- unauthenticated rate limit is 5 requests per 30 seconds, so re-querying a
-- product SENTRY already knows about is a cost that must be avoided.
CREATE TABLE product_lookup (
    keyword         TEXT PRIMARY KEY,          -- normalised product keyword
    last_attempt    TEXT,
    last_success    TEXT,
    cve_count       INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT
);

-- Which CVEs a given product keyword returned, so a match can be recomputed
-- against a newly installed version without another network call.
CREATE TABLE product_cve (
    keyword     TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    PRIMARY KEY (keyword, cve_id)
);

-- The installed software inventory as of the last scan.
CREATE TABLE software (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL,
    version             TEXT,
    publisher           TEXT,
    scope               TEXT NOT NULL,         -- HKLM64 | HKLM32 | HKCU
    registry_key        TEXT,
    install_location    TEXT,
    install_date        TEXT,
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    UNIQUE (name, version, scope)
);

CREATE INDEX idx_software_name ON software (name);

-- Core tables: scan bookkeeping, raw collected facts, and derived findings.
-- Later phases add their own numbered migrations; this file is immutable once shipped.

CREATE TABLE scan_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type       TEXT    NOT NULL,          -- quick | standard | deep
    started_at      TEXT    NOT NULL,
    finished_at     TEXT,
    status          TEXT    NOT NULL,          -- running | complete | partial | cancelled | failed
    error           TEXT
);

CREATE INDEX idx_scan_runs_started ON scan_runs (started_at DESC);

-- Every value a collector established, kept verbatim so a finding can always
-- be traced back to the observation that produced it.
CREATE TABLE security_facts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id     INTEGER NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    collector       TEXT    NOT NULL,          -- e.g. windows.defender
    fact_key        TEXT    NOT NULL,          -- e.g. real_time_protection_enabled
    state           TEXT    NOT NULL,          -- known | not_scanned | permission_required | unsupported | unavailable
    value_json      TEXT,                      -- payload when state = known
    detail          TEXT,                      -- reason when state != known
    collected_at    TEXT    NOT NULL
);

CREATE INDEX idx_facts_scan ON security_facts (scan_run_id);
CREATE INDEX idx_facts_key  ON security_facts (collector, fact_key);

CREATE TABLE findings (
    id              TEXT    PRIMARY KEY,       -- stable hash of rule_id + affected_asset
    rule_id         TEXT    NOT NULL,
    category        TEXT    NOT NULL,
    severity        TEXT    NOT NULL,          -- Safe | Attention | Warning | Critical
    confidence      REAL    NOT NULL,          -- 0.0 .. 1.0
    title           TEXT    NOT NULL,
    what_happened   TEXT    NOT NULL,
    why_it_matters  TEXT    NOT NULL,
    affected_asset  TEXT,
    remediation     TEXT,
    auto_fix        INTEGER NOT NULL DEFAULT 0,
    auto_fix_risk   TEXT,                      -- safe | caution | manual
    evidence_json   TEXT    NOT NULL,          -- JSON array of evidence lines
    references_json TEXT,                      -- JSON array of URLs
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'open',
    source          TEXT    NOT NULL
);

CREATE INDEX idx_findings_status   ON findings (status, severity);
CREATE INDEX idx_findings_category ON findings (category);

-- Append-only audit trail. Never updated, only inserted.
CREATE TABLE events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at     TEXT    NOT NULL,
    kind            TEXT    NOT NULL,
    subject         TEXT,
    detail_json     TEXT
);

CREATE INDEX idx_events_time ON events (occurred_at DESC);

CREATE TABLE settings (
    key             TEXT    PRIMARY KEY,
    value_json      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

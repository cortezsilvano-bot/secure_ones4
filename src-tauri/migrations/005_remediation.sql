-- A record of every change SENTRY has made to this machine.
--
-- Written before the change is attempted and updated afterwards, so an action
-- that crashed halfway still leaves a trace. `undo_hint` records what would be
-- needed to put the setting back, because a security tool that changes things
-- without a way back is a liability.
CREATE TABLE remediation_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT,
    action          TEXT    NOT NULL,       -- the named, allowlisted verb
    risk            TEXT    NOT NULL,       -- safe | caution | manual
    started_at      TEXT    NOT NULL,
    finished_at     TEXT,
    status          TEXT    NOT NULL,       -- running | succeeded | failed | refused
    detail          TEXT,
    -- What the setting was before, so the change can be described and reversed.
    previous_value  TEXT,
    undo_hint       TEXT,
    -- Whether the user was told what would happen and agreed.
    confirmed       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_remediation_time ON remediation_history (started_at DESC);
CREATE INDEX idx_remediation_finding ON remediation_history (finding_id);

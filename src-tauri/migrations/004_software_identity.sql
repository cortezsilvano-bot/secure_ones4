-- Fix the software table's identity so a program with no recorded version does
-- not duplicate on every scan.
--
-- The original UNIQUE (name, version, scope) silently failed for rows where
-- version was NULL: SQL comparisons against NULL are never true, so the upsert's
-- conflict target never matched and each scan inserted a fresh row. Five
-- version-less programs across sixteen scans produced eighty duplicate rows,
-- and the count would have grown for as long as the app was used.
--
-- The fix is to make "no version" an ordinary value -- the empty string --
-- rather than the absence of one.

-- Rebuild with version NOT NULL.
CREATE TABLE software_new (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL,
    -- Empty string means the program records no version. Deliberately not NULL:
    -- see above.
    version             TEXT NOT NULL DEFAULT '',
    publisher           TEXT,
    scope               TEXT NOT NULL,
    registry_key        TEXT,
    install_location    TEXT,
    install_date        TEXT,
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    UNIQUE (name, version, scope)
);

-- Copy, collapsing the duplicates: keep the earliest first_seen and the latest
-- last_seen for each real program, which is what those columns are meant to say.
INSERT INTO software_new (name, version, publisher, scope, registry_key,
                          install_location, install_date, first_seen, last_seen)
SELECT
    name,
    COALESCE(version, ''),
    -- Prefer a non-null value from whichever duplicate row carried one.
    MAX(publisher),
    scope,
    MAX(registry_key),
    MAX(install_location),
    MAX(install_date),
    MIN(first_seen),
    MAX(last_seen)
FROM software
GROUP BY name, COALESCE(version, ''), scope;

DROP TABLE software;
ALTER TABLE software_new RENAME TO software;

CREATE INDEX idx_software_name ON software (name);

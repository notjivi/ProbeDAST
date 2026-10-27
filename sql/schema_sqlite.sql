-- SQLite variant of sql/schema.sql: same shape, used by store.py for
-- single-process runs and by the test suite (no Postgres dependency).

CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    scope       TEXT NOT NULL,          -- JSON
    status      TEXT NOT NULL DEFAULT 'RUNNING',
    started_at  TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id    TEXT PRIMARY KEY,
    scan_id        TEXT NOT NULL REFERENCES scans(scan_id),
    method         TEXT NOT NULL,
    path_template  TEXT NOT NULL,
    params         TEXT NOT NULL,       -- JSON
    auth_required  INTEGER NOT NULL DEFAULT 0,
    signature      TEXT NOT NULL,
    UNIQUE (scan_id, signature)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id  TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(scan_id),
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id),
    vuln_type   TEXT NOT NULL,
    param       TEXT,
    severity    TEXT NOT NULL,
    confidence  REAL NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('CONFIRMED', 'REJECTED')),
    evidence    TEXT NOT NULL,          -- JSON
    found_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);

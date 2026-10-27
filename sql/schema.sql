-- ProbeDAST data model (design doc Section 3), PostgreSQL.
-- See sql/schema_sqlite.sql for the standalone/test variant.

CREATE TABLE IF NOT EXISTS scans (
    scan_id     UUID PRIMARY KEY,
    target      TEXT NOT NULL,
    scope       JSONB NOT NULL,
    status      TEXT NOT NULL DEFAULT 'RUNNING',  -- RUNNING | PAUSED | COMPLETED | FAILED
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id    UUID PRIMARY KEY,
    scan_id        UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    method         TEXT NOT NULL,
    path_template  TEXT NOT NULL,
    params         JSONB NOT NULL,
    auth_required  BOOLEAN NOT NULL DEFAULT false,
    signature      TEXT NOT NULL,
    UNIQUE (scan_id, signature)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id  UUID PRIMARY KEY,
    scan_id     UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    endpoint_id UUID NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    vuln_type   TEXT NOT NULL,
    param       TEXT,
    severity    TEXT NOT NULL,
    confidence  REAL NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('CONFIRMED', 'REJECTED')),
    evidence    JSONB NOT NULL,
    found_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);

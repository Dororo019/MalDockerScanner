--   psql -h 127.0.0.1 -U docker_security_logs -d docker_security_db -f db/create_tables.sql
--
-- NOTE: Use 127.0.0.1 (TCP), NOT localhost (Unix socket / peer auth).

CREATE TABLE IF NOT EXISTS scans (
    id            SERIAL          PRIMARY KEY,
    scan_id       TEXT            UNIQUE,
    image_name    TEXT            NOT NULL,
    risk_score    NUMERIC(5,1),
    risk_category TEXT,
    trivy_vulns   INTEGER         DEFAULT 0,
    clamav_hits   INTEGER         DEFAULT 0,
    yara_hits     INTEGER         DEFAULT 0,
    falco_alerts  INTEGER         DEFAULT 0,
    scan_duration NUMERIC(8,2),
    scanned_at    TIMESTAMPTZ     DEFAULT NOW()
);

-- Index for fast dashboard queries
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at   ON scans (scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_image_name   ON scans (image_name);
CREATE INDEX IF NOT EXISTS idx_scans_risk_category ON scans (risk_category);

-- Quick verification
SELECT 'scans table ready — ' || COUNT(*) || ' rows' FROM scans;

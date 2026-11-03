-- TRISHUL initial schema.
--
-- Note on `findings`: the primary key is the composite (scan_id, id).
-- A finding id is derived from its content, so the same vulnerability found
-- during two different scans must be storable twice — a global primary key
-- on `id` alone makes the second scan fail.

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    scan_id TEXT NOT NULL,
    id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (scan_id, id),
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(scan_id, severity);

CREATE TABLE IF NOT EXISTS guides (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    data TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_guides_scan ON guides(scan_id);

CREATE TABLE IF NOT EXISTS cache_entries (
    cache_key TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    data TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cache_expiry ON cache_entries(expires_at);

CREATE TABLE IF NOT EXISTS provider_config (
    id TEXT PRIMARY KEY,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integrations (
    name TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

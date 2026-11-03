-- TRISHUL extension schema.
--
-- Chat transcripts are persisted so that the dashboard can restore a
-- conversation and so that operators can audit what the model was asked.

CREATE TABLE IF NOT EXISTS chat_messages (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_chat_scan ON chat_messages(scan_id, created_at);

CREATE TABLE IF NOT EXISTS task_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_task_events_scan ON task_events(scan_id, id);

"""Tests for schema migrations, including upgrade of a legacy database."""

from __future__ import annotations

import sqlite3

from backend.app.core.migrations import current_version, run_migrations


def test_migrations_apply_to_a_fresh_database(tmp_path):
    db_path = tmp_path / "fresh.db"
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "001_base.sql").write_text(
        "CREATE TABLE example (id TEXT PRIMARY KEY, value TEXT);", encoding="utf-8"
    )

    result = run_migrations(db_path, migrations_dir)
    assert result["applied"] == ["001_base.sql"]
    assert current_version(db_path) == "001"


def test_migrations_are_idempotent(tmp_path):
    db_path = tmp_path / "twice.db"
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "001_base.sql").write_text(
        "CREATE TABLE example (id TEXT PRIMARY KEY);", encoding="utf-8"
    )

    run_migrations(db_path, migrations_dir)
    second = run_migrations(db_path, migrations_dir)
    assert second["applied"] == []


def test_legacy_database_gains_missing_columns(tmp_path):
    """A database created by the previous release must be upgraded in place."""
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            data TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()

    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    result = run_migrations(db_path, migrations_dir)

    assert "scans.ai_provider" in result["reconciled_columns"]
    conn = sqlite3.connect(db_path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    conn.close()
    assert "ai_provider" in columns
    assert "ai_model" in columns


def test_real_project_migrations_apply(tmp_path):
    """The shipped migrations must create a working schema."""
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[1]
    db_path = tmp_path / "trishul.db"
    result = run_migrations(db_path, project_root / "migrations")
    assert result["applied"], "the shipped migrations must apply"

    conn = sqlite3.connect(db_path)
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    conn.close()
    assert {"scans", "findings", "guides", "cache_entries", "provider_config", "integrations"} <= tables


# ---------------------------------------------------------------------------
# The legacy findings primary key
# ---------------------------------------------------------------------------


LEGACY_SCHEMA = """
    CREATE TABLE scans (
        id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        data TEXT NOT NULL
    );
    CREATE TABLE findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        title TEXT NOT NULL,
        data TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    );
"""


def _make_legacy_db(db_path, rows=()):
    conn = sqlite3.connect(db_path)
    conn.executescript(LEGACY_SCHEMA)
    for scan_id, finding_id in rows:
        conn.execute(
            "INSERT INTO scans (id, target, status, updated_at, data) VALUES (?,?,?,?,?)",
            (scan_id, "example.com", "completed", "2026-01-01T00:00:00", "{}"),
        )
        conn.execute(
            "INSERT INTO findings (id, scan_id, severity, confidence, title, data) "
            "VALUES (?,?,?,?,?,?)",
            (finding_id, scan_id, "high", 60, "Legacy finding", "{}"),
        )
    conn.commit()
    conn.close()


def _primary_key(db_path) -> list[str]:
    conn = sqlite3.connect(db_path)
    rows = conn.execute("PRAGMA table_info(findings)").fetchall()
    conn.close()
    pk_rows = sorted((row for row in rows if row[5]), key=lambda row: row[5])
    return [row[1] for row in pk_rows]


def test_legacy_findings_primary_key_is_rebuilt(tmp_path):
    """The old global ``id`` key must become the composite ``(scan_id, id)``."""
    db_path = tmp_path / "legacy-key.db"
    _make_legacy_db(db_path, rows=[("scan-1", "finding-1")])

    assert _primary_key(db_path) == ["id"]

    result = run_migrations(db_path, tmp_path / "migrations")

    assert result["rebuilt_findings"] is True
    assert _primary_key(db_path) == ["scan_id", "id"]


def test_the_rebuild_preserves_the_legacy_rows(tmp_path):
    db_path = tmp_path / "legacy-rows.db"
    _make_legacy_db(
        db_path, rows=[("scan-1", "finding-1"), ("scan-2", "finding-2")]
    )

    run_migrations(db_path, tmp_path / "migrations")

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT scan_id, id, severity FROM findings ORDER BY scan_id").fetchall()
    conn.close()
    assert rows == [("scan-1", "finding-1", "high"), ("scan-2", "finding-2", "high")]


def test_the_rebuild_allows_the_same_finding_in_two_scans(tmp_path):
    """The bug the composite key fixes: a second scan of the same target."""
    db_path = tmp_path / "legacy-collision.db"
    _make_legacy_db(db_path, rows=[("scan-1", "finding-1")])

    run_migrations(db_path, tmp_path / "migrations")

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO findings (scan_id, id, severity, confidence, title, data) "
        "VALUES (?,?,?,?,?,?)",
        ("scan-2", "finding-1", "high", 60, "Legacy finding", "{}"),
    )
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM findings WHERE id = 'finding-1'").fetchone()[0]
    conn.close()

    assert count == 2


def test_the_rebuild_is_idempotent(tmp_path):
    db_path = tmp_path / "legacy-twice.db"
    _make_legacy_db(db_path, rows=[("scan-1", "finding-1")])

    run_migrations(db_path, tmp_path / "migrations")
    second = run_migrations(db_path, tmp_path / "migrations")

    assert second["rebuilt_findings"] is False
    assert _primary_key(db_path) == ["scan_id", "id"]


def test_the_rebuild_preserves_unknown_legacy_columns(tmp_path):
    db_path = tmp_path / "legacy-extra.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        LEGACY_SCHEMA
        + "ALTER TABLE findings ADD COLUMN extra_note TEXT NOT NULL DEFAULT '';"
    )
    conn.execute(
        "INSERT INTO findings (id, scan_id, severity, confidence, title, data, extra_note) "
        "VALUES (?,?,?,?,?,?,?)",
        ("finding-1", "scan-1", "high", 60, "Legacy finding", "{}", "kept"),
    )
    conn.commit()
    conn.close()

    run_migrations(db_path, tmp_path / "migrations")

    conn = sqlite3.connect(db_path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    value = conn.execute("SELECT extra_note FROM findings").fetchone()[0]
    conn.close()

    assert "extra_note" in columns
    assert value == "kept"

"""Schema migration runner.

Migrations are plain SQL files named ``NNN_description.sql`` inside the
``migrations/`` directory. Applied versions are recorded in the
``schema_migrations`` table, so running the runner repeatedly is safe and
only new files are executed.

The runner additionally performs a *column reconciliation* pass. That keeps
TRISHUL able to open a database created by an older release (or by the
predecessor project) without requiring the operator to recreate it.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

MIGRATION_PATTERN = re.compile(r"^(\d{3})_([A-Za-z0-9_\-]+)\.sql$")

# Columns that must exist on the given table. Missing ones are added with
# ALTER TABLE, which keeps old databases usable after an upgrade.
REQUIRED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("scans", "ai_provider", "TEXT NOT NULL DEFAULT 'none'"),
    ("scans", "ai_model", "TEXT NOT NULL DEFAULT ''"),
    ("scans", "enrichment", "TEXT NOT NULL DEFAULT '[]'"),
    ("scans", "authorized", "INTEGER NOT NULL DEFAULT 0"),
    ("scans", "authorization_note", "TEXT NOT NULL DEFAULT ''"),
    ("scans", "report_paths", "TEXT NOT NULL DEFAULT '{}'"),
    ("scans", "artifacts", "TEXT NOT NULL DEFAULT '{}'"),
    ("scans", "logs", "TEXT NOT NULL DEFAULT '[]'"),
    ("scans", "findings", "TEXT NOT NULL DEFAULT '[]'"),
    ("scans", "progress", "TEXT NOT NULL DEFAULT '{}'"),
    ("scans", "mode", "TEXT NOT NULL DEFAULT 'deep'"),
    ("scans", "created_at", "TEXT NOT NULL DEFAULT ''"),
    ("scans", "error", "TEXT"),
    ("provider_config", "payload", "TEXT NOT NULL DEFAULT '{}'"),
    ("integrations", "payload", "TEXT NOT NULL DEFAULT '{}'"),
)

# The canonical layout of the findings table. Finding identifiers are derived
# from content, so the key must include the scan: the same finding in two
# scans of the same target must be two rows, not a constraint violation.
FINDINGS_COLUMNS: tuple[tuple[str, str], ...] = (
    ("scan_id", "TEXT NOT NULL"),
    ("id", "TEXT NOT NULL"),
    ("severity", "TEXT NOT NULL"),
    ("confidence", "INTEGER NOT NULL DEFAULT 0"),
    ("title", "TEXT NOT NULL"),
    ("data", "TEXT NOT NULL"),
)


class MigrationError(RuntimeError):
    """Raised when a migration cannot be applied."""


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_migration_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )
    conn.commit()


def _applied_versions(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    return {row["version"] for row in rows}


def _reconcile_columns(conn: sqlite3.Connection) -> list[str]:
    """Add any missing columns required by the current schema."""
    changes: list[str] = []
    for table, column, ddl in REQUIRED_COLUMNS:
        try:
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        except sqlite3.DatabaseError:
            continue
        if not rows:
            # The table does not exist yet; the SQL migration will create it.
            continue
        existing = {row["name"] for row in rows}
        if column in existing:
            continue
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
            changes.append(f"{table}.{column}")
        except sqlite3.DatabaseError as exc:
            raise MigrationError(f"Could not add column {table}.{column}: {exc}") from exc
    if changes:
        conn.commit()
    return changes


def _reconcile_findings_key(conn: sqlite3.Connection) -> bool:
    """Rebuild the findings table when its primary key is the legacy global id.

    Older releases — and the predecessor project — declared ``id`` as the sole
    primary key. Finding identifiers are content-derived, so scanning the same
    target twice would collide on the second run. The table is rebuilt with
    the composite key ``(scan_id, id)``.

    Returns ``True`` when the table was rebuilt.
    """
    try:
        rows = conn.execute("PRAGMA table_info(findings)").fetchall()
    except sqlite3.DatabaseError:
        return False
    if not rows:
        return False

    existing = [row["name"] for row in rows]
    required = {name for name, _ in FINDINGS_COLUMNS}
    if not required.issubset(set(existing)):
        return False

    # The primary key columns, in their declared order.
    pk_rows = sorted((row for row in rows if row["pk"]), key=lambda row: row["pk"])
    pk_columns = [row["name"] for row in pk_rows]
    if pk_columns == ["scan_id", "id"]:
        return False  # already correct

    # Keep any column the legacy table had that the canonical layout does not.
    extra_columns: list[str] = []
    for row in rows:
        if row["name"] in required:
            continue
        ddl = f'"{row["name"]}" {row["type"] or "TEXT"}'
        if row["notnull"]:
            ddl += " NOT NULL"
        if row["dflt_value"] is not None:
            ddl += f" DEFAULT {row['dflt_value']}"
        extra_columns.append(ddl)

    canonical = ",\n    ".join(f'"{name}" {ddl}' for name, ddl in FINDINGS_COLUMNS)
    column_list = ", ".join(f'"{name}"' for name, _ in FINDINGS_COLUMNS)
    select_list = column_list
    if extra_columns:
        extras = ", ".join(f'"{row["name"]}"' for row in rows if row["name"] not in required)
        canonical += ",\n    " + ",\n    ".join(extra_columns)
        select_list = f"{column_list}, {extras}"

    create_sql = f"""
        CREATE TABLE findings (
            {canonical},
            PRIMARY KEY (scan_id, id),
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """

    conn.commit()
    previous_isolation = conn.isolation_level
    conn.isolation_level = None
    try:
        # The foreign-key pragma is a no-op inside a transaction, so the
        # rebuild runs in autocommit mode.
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("ALTER TABLE findings RENAME TO findings_pk_rebuild")
        conn.execute(create_sql)
        conn.execute(
            f"INSERT INTO findings ({select_list}) "
            f"SELECT {select_list} FROM findings_pk_rebuild"
        )
        conn.execute("DROP TABLE findings_pk_rebuild")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(scan_id, severity)"
        )
    finally:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.isolation_level = previous_isolation
    conn.commit()
    return True


def run_migrations(db_path: Path, migrations_dir: Path) -> dict[str, list[str]]:
    """Apply every pending migration and reconcile the schema layout.

    Returns a summary containing the versions that were applied, the columns
    that had to be added and whether the findings key was rebuilt.
    """
    applied: list[str] = []
    reconciled: list[str] = []
    rebuilt_findings = False
    conn = _connect(db_path)
    try:
        _ensure_migration_table(conn)
        already = _applied_versions(conn)

        if migrations_dir.exists():
            files = sorted(
                path
                for path in migrations_dir.iterdir()
                if path.is_file() and MIGRATION_PATTERN.match(path.name)
            )
            for path in files:
                match = MIGRATION_PATTERN.match(path.name)
                assert match is not None
                version = match.group(1)
                if version in already:
                    continue
                sql = path.read_text(encoding="utf-8")
                try:
                    conn.executescript(sql)
                    conn.execute(
                        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, datetime('now'))",
                        (version, match.group(2)),
                    )
                    conn.commit()
                    applied.append(path.name)
                except sqlite3.DatabaseError as exc:
                    conn.rollback()
                    raise MigrationError(f"Migration {path.name} failed: {exc}") from exc

        reconciled = _reconcile_columns(conn)
        rebuilt_findings = _reconcile_findings_key(conn)
    finally:
        conn.close()
    return {
        "applied": applied,
        "reconciled_columns": reconciled,
        "rebuilt_findings": rebuilt_findings,
    }


def current_version(db_path: Path) -> str:
    """Return the highest applied migration version, or ``"none"``."""
    if not db_path.exists():
        return "none"
    conn = _connect(db_path)
    try:
        _ensure_migration_table(conn)
        row = conn.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
        return row["version"] or "none"
    finally:
        conn.close()


def _main() -> None:
    """Entry point for ``python -m backend.app.core.migrations``."""
    import argparse

    from backend.app.core.config import get_settings

    parser = argparse.ArgumentParser(prog="trishul-migrate")
    parser.add_argument("--database", default="", help="Path to the SQLite database.")
    parser.add_argument(
        "--migrations", default="", help="Directory that holds the NNN_*.sql files."
    )
    args = parser.parse_args()

    settings = get_settings()
    db_path = Path(args.database) if args.database else settings.database_path
    migrations_dir = (
        Path(args.migrations)
        if args.migrations
        else Path(__file__).resolve().parents[3] / "migrations"
    )

    result = run_migrations(db_path, migrations_dir)
    print(f"Applied: {result['applied'] or 'nothing new'}")
    print(f"Reconciled columns: {result['reconciled_columns'] or 'none'}")
    print(f"Rebuilt findings key: {'yes' if result['rebuilt_findings'] else 'no (already correct)'}")
    print(f"Schema version: {current_version(db_path)}")


if __name__ == "__main__":
    _main()

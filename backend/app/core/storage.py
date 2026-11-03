"""SQLite persistence layer.

The store keeps a single JSON document per scan (the canonical record) and
mirrors the queryable parts — severity, confidence, title — into the
``findings`` table so that reports and filters do not have to parse JSON.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from backend.app.core.migrations import run_migrations
from backend.app.core.utils import utcnow
from backend.app.models import GuideSession, ScanRecord


class Storage:
    """Thread-safe SQLite store for scans, guides, cache and settings."""

    def __init__(self, db_path: Path, migrations_dir: Path | None = None) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._init_db(migrations_dir)

    # -- connection --------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self, migrations_dir: Path | None = None) -> None:
        if migrations_dir is None:
            migrations_dir = Path(__file__).resolve().parents[3] / "migrations"
        run_migrations(self.db_path, migrations_dir)

    # -- scans -------------------------------------------------------------

    def save_scan(self, scan: ScanRecord) -> None:
        """Persist a scan and re-sync its finding index rows."""
        payload = scan.model_dump(mode="json")
        payload_json = json.dumps(payload)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (id, target, status, updated_at, data)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    target=excluded.target,
                    status=excluded.status,
                    updated_at=excluded.updated_at,
                    data=excluded.data
                """,
                (scan.id, scan.target, scan.status.value, scan.updated_at.isoformat(), payload_json),
            )
            # Replace the index rows for this scan. The composite primary key
            # (scan_id, id) keeps findings from other scans untouched.
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan.id,))
            conn.executemany(
                """
                INSERT INTO findings (scan_id, id, severity, confidence, title, data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan.id,
                        finding.id,
                        finding.severity.value,
                        finding.confidence,
                        finding.title,
                        json.dumps(finding.model_dump(mode="json")),
                    )
                    for finding in scan.findings
                ],
            )
            conn.commit()

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        with self._connect() as conn:
            row = conn.execute("SELECT data FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        try:
            return ScanRecord(**json.loads(row["data"]))
        except (ValueError, TypeError):
            return None

    def list_scans(self, limit: int = 100) -> list[ScanRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data FROM scans ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        scans: list[ScanRecord] = []
        for row in rows:
            try:
                scans.append(ScanRecord(**json.loads(row["data"])))
            except (ValueError, TypeError):
                continue
        return scans

    def delete_scan(self, scan_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM guides WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    def count_scans(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS total FROM scans").fetchone()
        return int(row["total"]) if row else 0

    # -- guides ------------------------------------------------------------

    def save_guide(self, guide: GuideSession) -> None:
        payload_json = json.dumps(guide.model_dump(mode="json"))
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO guides (id, scan_id, finding_id, updated_at, data)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    scan_id=excluded.scan_id,
                    finding_id=excluded.finding_id,
                    updated_at=excluded.updated_at,
                    data=excluded.data
                """,
                (guide.id, guide.scan_id, guide.finding_id, guide.updated_at.isoformat(), payload_json),
            )
            conn.commit()

    def get_guide(self, guide_id: str) -> GuideSession | None:
        with self._connect() as conn:
            row = conn.execute("SELECT data FROM guides WHERE id = ?", (guide_id,)).fetchone()
        if not row:
            return None
        try:
            return GuideSession(**json.loads(row["data"]))
        except (ValueError, TypeError):
            return None

    # -- cache -------------------------------------------------------------

    def cache_get(self, cache_key: str) -> Any | None:
        now = int(time.time())
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data, expires_at FROM cache_entries WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        if not row or row["expires_at"] <= now:
            return None
        try:
            return json.loads(row["data"])
        except json.JSONDecodeError:
            return None

    def cache_set(self, cache_key: str, data: Any, ttl_seconds: int) -> None:
        expires_at = int(time.time()) + max(0, ttl_seconds)
        payload_json = json.dumps(data)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cache_entries (cache_key, expires_at, data)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    expires_at=excluded.expires_at,
                    data=excluded.data
                """,
                (cache_key, expires_at, payload_json),
            )
            conn.commit()

    def purge_expired_cache(self) -> int:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM cache_entries WHERE expires_at <= ?", (int(time.time()),))
            conn.commit()
            return cursor.rowcount or 0

    # -- provider configuration -------------------------------------------

    def get_provider_config(self) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT payload FROM provider_config WHERE id = 'active'").fetchone()
        if not row:
            return None
        try:
            return json.loads(row["payload"])
        except json.JSONDecodeError:
            return None

    def set_provider_config(self, payload: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO provider_config (id, updated_at, payload)
                VALUES ('active', ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    payload=excluded.payload
                """,
                (utcnow().isoformat(), json.dumps(payload)),
            )
            conn.commit()

    # -- integrations ------------------------------------------------------

    def list_integrations(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM integrations ORDER BY created_at").fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            try:
                results.append(json.loads(row["payload"]))
            except json.JSONDecodeError:
                continue
        return results

    def get_integration(self, name: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT payload FROM integrations WHERE name = ?", (name,)).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["payload"])
        except json.JSONDecodeError:
            return None

    def save_integration(self, name: str, payload: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO integrations (name, created_at, payload)
                VALUES (?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    payload=excluded.payload
                """,
                (name, payload.get("created_at") or utcnow().isoformat(), json.dumps(payload)),
            )
            conn.commit()

    def delete_integration(self, name: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM integrations WHERE name = ?", (name,))
            conn.commit()
            return cursor.rowcount > 0

    # -- chat history ------------------------------------------------------

    def save_chat_message(
        self,
        message_id: str,
        role: str,
        content: str,
        scan_id: str | None = None,
        provider: str = "",
        model: str = "",
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO chat_messages (id, scan_id, role, content, created_at, provider, model)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (message_id, scan_id, role, content, utcnow().isoformat(), provider, model),
            )
            conn.commit()

    def list_chat_messages(self, scan_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            if scan_id:
                rows = conn.execute(
                    "SELECT * FROM chat_messages WHERE scan_id = ? ORDER BY created_at DESC LIMIT ?",
                    (scan_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM chat_messages ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(row) for row in reversed(rows)]

    @staticmethod
    def now() -> datetime:
        return utcnow()

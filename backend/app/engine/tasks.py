"""Scan task supervision: concurrency control and cancellation."""

from __future__ import annotations

import asyncio
from typing import Any

from backend.app.core.events import event_bus
from backend.app.core.storage import Storage
from backend.app.models import ScanStatus


class TaskManager:
    """Runs scans as background tasks with a hard concurrency ceiling.

    The manager is the only place that owns running asyncio tasks, which
    makes cancellation reliable: cancelling a task also stops the external
    tool subprocesses because the agent awaits them.
    """

    def __init__(self, storage: Storage, max_concurrent: int = 3) -> None:
        self.storage = storage
        self.max_concurrent = max(1, max_concurrent)
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self._lock = asyncio.Lock()

    @property
    def active_count(self) -> int:
        return sum(1 for task in self._tasks.values() if not task.done())

    def is_active(self, scan_id: str) -> bool:
        task = self._tasks.get(scan_id)
        return bool(task and not task.done())

    async def start(self, scan_id: str, coro_factory) -> None:
        """Register and schedule a scan task.

        Raises
        ------
        RuntimeError
            When the concurrency ceiling has already been reached.
        """
        async with self._lock:
            if self.active_count >= self.max_concurrent:
                raise RuntimeError(
                    f"Too many scans are already running (limit {self.max_concurrent}). "
                    "Wait for one to finish or raise scan.max_concurrent_scans."
                )
            task = asyncio.create_task(coro_factory(), name=f"trishul-scan:{scan_id}")
            self._tasks[scan_id] = task
            task.add_done_callback(lambda _t, sid=scan_id: self._tasks.pop(sid, None))

    async def cancel(self, scan_id: str) -> bool:
        """Cancel a running scan. Returns ``True`` when a task was cancelled."""
        async with self._lock:
            task = self._tasks.get(scan_id)
            if not task or task.done():
                return False
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            scan = self.storage.get_scan(scan_id)
            if scan and scan.status not in {ScanStatus.COMPLETED, ScanStatus.FAILED}:
                scan.status = ScanStatus.CANCELLED
                scan.error = "Scan cancelled by the operator."
                self.storage.save_scan(scan)
                await event_bus.publish(
                    scan_id,
                    {
                        "type": "progress",
                        "timestamp": scan.updated_at.isoformat(),
                        "stage": "cancelled",
                        "percent": scan.progress.percent,
                        "message": scan.error,
                        "payload": {},
                    },
                )
            return True

    async def shutdown(self) -> None:
        """Cancel every running scan (called during application shutdown)."""
        async with self._lock:
            tasks = [task for task in self._tasks.values() if not task.done()]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._tasks.clear()

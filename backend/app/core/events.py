"""In-process publish/subscribe used to stream scan progress to WebSockets."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any


class EventBus:
    """Fan-out bus for per-scan events.

    The bus is deliberately not thread-safe: every publisher and subscriber
    lives on the event loop that owns the FastAPI application.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, channel: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers[channel].add(queue)
        return queue

    def unsubscribe(self, channel: str, queue: asyncio.Queue) -> None:
        subscribers = self._subscribers.get(channel)
        if not subscribers:
            return
        subscribers.discard(queue)
        if not subscribers:
            self._subscribers.pop(channel, None)

    def subscriber_count(self, channel: str) -> int:
        return len(self._subscribers.get(channel, set()))

    async def publish(self, channel: str, event: dict[str, Any]) -> None:
        """Deliver ``event`` to every subscriber of ``channel``.

        A slow consumer must never stall the scan, so each queue is bounded
        and overflowing consumers simply miss intermediate progress frames.
        """
        for queue in list(self._subscribers.get(channel, set())):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop the oldest frame to make room for the newest one.
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass


event_bus = EventBus()

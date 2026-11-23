"""Fire-and-forget tasks that are kept alive until they finish."""

from __future__ import annotations

import asyncio
import logging
from typing import Coroutine

log = logging.getLogger("trapsnmp")

# The event loop only keeps a weak reference to a task, so a task nobody
# holds can be garbage-collected before it finishes.
_RUNNING: set[asyncio.Task] = set()


def spawn(coro: Coroutine, *, name: str | None = None) -> asyncio.Task:
    task = asyncio.get_running_loop().create_task(coro, name=name)
    _RUNNING.add(task)
    task.add_done_callback(_finished)
    return task


def _finished(task: asyncio.Task) -> None:
    _RUNNING.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("background task %s failed", task.get_name(), exc_info=exc)

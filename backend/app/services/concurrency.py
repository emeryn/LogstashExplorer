"""Per-user fairness for Logstash executions.

Many users (and several tabs per user) work concurrently; each Logstash run occupies a runner slot
for several seconds. A user may have at most `max_runs_per_user` runs in flight (manual runs and
agent sessions combined) so that one person cannot starve the shared runners. State is per backend
process (single uvicorn worker by default).
"""

import uuid
from collections import Counter
from contextlib import asynccontextmanager

from fastapi import HTTPException

from app.core.config import get_settings

_in_flight: Counter[uuid.UUID] = Counter()


def in_flight(user_id: uuid.UUID) -> int:
    return _in_flight[user_id]


class RunSlot:
    """One in-flight run for a user. release() is idempotent (safe for streams + background tasks)."""

    def __init__(self, user_id: uuid.UUID):
        limit = get_settings().max_runs_per_user
        if _in_flight[user_id] >= limit:
            raise HTTPException(429, f"You already have {limit} run(s) in progress: wait for one of them to finish.")
        _in_flight[user_id] += 1
        self.user_id = user_id
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        _in_flight[self.user_id] -= 1
        if _in_flight[self.user_id] <= 0:
            del _in_flight[self.user_id]


@asynccontextmanager
async def user_run_slot(user_id: uuid.UUID):
    slot = RunSlot(user_id)
    try:
        yield
    finally:
        slot.release()

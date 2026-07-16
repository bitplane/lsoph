# Filename: src/lsoph/backend/lsof/backend.py
"""Lsof backend implementation using polling and descendant tracking. Works with bytes paths."""

import logging
import shutil

from lsoph.monitor import Monitor

from ..polling import PollingBackend, Snapshot
from .helpers import _lsof_snapshot

log = logging.getLogger(__name__)

DEFAULT_LSOF_POLL_INTERVAL = 1.0
# Check for new children every N polls (lsof is expensive, so less often).
DEFAULT_CHILD_CHECK_INTERVAL_MULTIPLIER = 5


class Lsof(PollingBackend):
    """Polling backend that reads open files via the `lsof` command."""

    backend_name = "lsof"
    description = "polls lsof(8); same sampling blind spots as psutil, but slower"

    def __init__(
        self,
        monitor: Monitor,
        poll_interval: float = DEFAULT_LSOF_POLL_INTERVAL,
        child_check_multiplier: int = DEFAULT_CHILD_CHECK_INTERVAL_MULTIPLIER,
    ):
        super().__init__(monitor)
        self.poll_interval = max(0.1, poll_interval)
        self.child_check_interval = max(1, child_check_multiplier)
        log.info(
            f"{type(self).__name__} initialized. Poll Interval: {self.poll_interval}s, "
            f"Child Check Multiplier: {self.child_check_interval}"
        )

    @staticmethod
    def is_available() -> bool:
        """Check if the lsof executable is available in the system PATH."""
        return shutil.which("lsof") is not None

    async def _snapshot(self, pids: list[int]) -> Snapshot:
        return await _lsof_snapshot(pids)

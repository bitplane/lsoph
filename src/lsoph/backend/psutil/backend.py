# Filename: src/lsoph/backend/psutil/backend.py
"""Psutil backend implementation using polling. Works with bytes paths."""

import logging
import os

from lsoph.monitor import Monitor

from ..polling import OpenFile, PidFiles, PollingBackend, Snapshot
from .helpers import (
    PSUTIL_AVAILABLE,
    _get_process_cwd,
    _get_process_info,
    _get_process_open_files,
)

log = logging.getLogger(__name__)

DEFAULT_PSUTIL_POLL_INTERVAL = 0.5


class Psutil(PollingBackend):
    """Polling backend that reads open files via psutil. Uses bytes paths."""

    backend_name = "psutil"
    description = "polls open fds; misses anything opened and closed between polls"
    # psutil is cheap enough to check for descendants every poll.
    child_check_interval = 1

    def __init__(
        self, monitor: Monitor, poll_interval: float = DEFAULT_PSUTIL_POLL_INTERVAL
    ):
        super().__init__(monitor)
        if not PSUTIL_AVAILABLE:
            raise RuntimeError(
                "psutil library is required for Psutil backend but not installed."
            )
        self.poll_interval = max(0.1, poll_interval)
        # PID -> current working directory (bytes), cached on first sight and
        # used to resolve relative paths reported by psutil.
        self._cwd_cache: dict[int, bytes | None] = {}

    @staticmethod
    def is_available() -> bool:
        """Check if the psutil library is installed."""
        return PSUTIL_AVAILABLE

    def _resolve(self, path: bytes, cwd: bytes | None) -> bytes:
        """Resolve a relative bytes path against a cached CWD."""
        if os.path.isabs(path) or path.startswith((b"<", b"@")):
            return os.path.normpath(path)
        if cwd:
            try:
                return os.path.normpath(os.path.join(cwd, path))
            except ValueError as e:
                log.warning(f"Error joining {path!r} with CWD {cwd!r}: {e}")
        return path

    async def _snapshot(self, pids: list[int]) -> Snapshot:
        snapshot: Snapshot = {}
        for pid in pids:
            proc = _get_process_info(pid)
            if not proc:
                # Process gone or inaccessible -> omit so the base treats it as
                # exited, and forget its cached CWD.
                self._cwd_cache.pop(pid, None)
                continue

            if pid not in self._cwd_cache:
                self._cwd_cache[pid] = _get_process_cwd(proc)
            cwd = self._cwd_cache[pid]

            files = PidFiles()
            for entry in _get_process_open_files(proc):
                fd: int = entry["fd"]
                if fd < 0:
                    continue  # Sockets without a real fd, etc.
                mode: str = entry.get("mode", "")
                files.fds[fd] = OpenFile(
                    fd=fd,
                    path=self._resolve(entry["path"], cwd),
                    read="r" in mode or "+" in mode,
                    write="w" in mode or "a" in mode or "+" in mode,
                    mode=mode,
                )
            snapshot[pid] = files
        return snapshot

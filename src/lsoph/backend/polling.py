# Filename: src/lsoph/backend/polling.py
"""
Shared machinery for backends that monitor by repeatedly snapshotting the set
of open files for a group of PIDs and diffing successive snapshots.

Subclasses implement `_snapshot`; this base owns the poll loop, descendant
discovery, snapshot diffing (open/read/write/close), exit detection and timing.
"""

import asyncio
import logging
import time
from abc import abstractmethod
from dataclasses import dataclass, field

from lsoph.util.pid import get_descendants

from .base import Backend

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class OpenFile:
    """A file descriptor a process holds open, as seen in a single poll."""

    fd: int
    path: bytes  # absolute, bytes
    read: bool
    write: bool
    mode: str = ""


@dataclass
class PidFiles:
    """Everything a single poll observed for one PID."""

    # Open numeric file descriptors, keyed by fd.
    fds: dict[int, OpenFile] = field(default_factory=dict)
    # Non-fd paths a process references (e.g. lsof cwd/mem/txt/DEL entries),
    # reported to the monitor as stat events.
    stats: list[bytes] = field(default_factory=list)


# A poll snapshot maps pid -> PidFiles. A monitored PID that is absent from the
# snapshot is treated as exited. A subclass that cannot poll at all this cycle
# should raise instead, so the cycle is skipped rather than seen as mass-exit.
Snapshot = dict[int, PidFiles]


class PollingBackend(Backend):
    """Base for backends that snapshot open files each cycle and diff them."""

    # Seconds between polls.
    poll_interval: float = 1.0
    # Check for new descendants every Nth poll.
    child_check_interval: int = 1

    @abstractmethod
    async def _snapshot(self, pids: list[int]) -> Snapshot:
        """
        Return the currently-open files for `pids`.

        A PID that is alive but has no open files maps to an empty PidFiles; a
        PID that has exited (or is inaccessible) is omitted entirely. Raise to
        signal that the whole poll is unreliable and should be skipped.
        """
        raise NotImplementedError  # pragma: no cover

    async def attach(self, pids: list[int]):
        """Monitor `pids` and their descendants by polling until stopped."""
        monitored = {p for p in pids if isinstance(p, int) and p > 0}
        if not monitored:
            log.warning(f"{type(self).__name__}.attach called with no valid PIDs.")
            return

        log.info(
            f"Starting {type(self).__name__} polling loop. PIDs: {sorted(monitored)}"
        )
        seen: dict[int, dict[int, OpenFile]] = {}
        poll_count = 0
        try:
            while not self.should_stop:
                start = time.monotonic()
                poll_count += 1

                if poll_count % self.child_check_interval == 0:
                    monitored |= self._discover_descendants(monitored)

                if not monitored:
                    log.info("No monitored PIDs remaining. Exiting poll loop.")
                    break

                try:
                    snapshot = await self._snapshot(sorted(monitored))
                except Exception as e:
                    log.error(
                        f"{type(self).__name__} snapshot failed, skipping cycle: {e}"
                    )
                else:
                    open_fds = sum(len(files.fds) for files in snapshot.values())
                    log.debug(
                        f"poll {poll_count}: {open_fds} open fds "
                        f"across {len(snapshot)} of {len(monitored)} pids"
                    )
                    self._reconcile(snapshot, seen, monitored, time.time())

                if self.should_stop:
                    break
                await self._sleep_until_next(start)

        except asyncio.CancelledError:
            log.info(f"{type(self).__name__} polling cancelled.")
        except Exception as e:
            log.exception(f"Unexpected error in {type(self).__name__} poll loop: {e}")
        finally:
            log.info(f"Exiting {type(self).__name__} polling loop.")

    def _discover_descendants(self, monitored: set[int]) -> set[int]:
        """Return descendant PIDs of the monitored set that aren't tracked yet."""
        found: set[int] = set()
        for pid in list(monitored):
            for child in get_descendants(pid):
                if child > 0 and child not in monitored and child not in found:
                    log.info(f"Found new descendant process: {child} (ancestor: {pid})")
                    found.add(child)
        return found

    def _reconcile(
        self,
        snapshot: Snapshot,
        seen: dict[int, dict[int, OpenFile]],
        monitored: set[int],
        timestamp: float,
    ) -> None:
        """Diff `snapshot` against `seen`, emitting monitor events.

        Mutates `seen` (to become this cycle's state) and `monitored` (dropping
        exited PIDs).
        """
        for pid, files in snapshot.items():
            prev = seen.get(pid, {})
            for fd, current in files.fds.items():
                previous = prev.get(fd)
                if previous is None:
                    self._emit_open(pid, current, timestamp)
                elif previous != current:
                    # Same fd now refers to a different file or mode: close the
                    # old view, then report the new one.
                    self.monitor.close(pid, fd, True, timestamp, source="poll_change")
                    self._emit_open(pid, current, timestamp)
            for fd in prev:
                if fd not in files.fds:
                    self.monitor.close(pid, fd, True, timestamp, source="poll")
            for path in files.stats:
                self.monitor.stat(pid, path, True, timestamp, source="poll")
            seen[pid] = files.fds

        for pid in [p for p in monitored if p not in snapshot]:
            for fd in seen.get(pid, {}):
                self.monitor.close(pid, fd, True, timestamp, source="poll_exit")
            self.monitor.process_exit(pid, timestamp)
            monitored.discard(pid)
            seen.pop(pid, None)

    def _emit_open(self, pid: int, of: OpenFile, timestamp: float) -> None:
        """Report an open (and any implied read/write) to the monitor."""
        self.monitor.open(
            pid, of.path, of.fd, True, timestamp, source="poll", mode=of.mode
        )
        if of.read:
            self.monitor.read(
                pid, of.fd, of.path, True, timestamp, bytes=0, source="poll"
            )
        if of.write:
            self.monitor.write(
                pid, of.fd, of.path, True, timestamp, bytes=0, source="poll"
            )

    async def _sleep_until_next(self, start: float) -> None:
        """Sleep out the remainder of the poll interval, warning on overrun."""
        elapsed = time.monotonic() - start
        sleep_time = self.poll_interval - elapsed
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
        elif elapsed > self.poll_interval * 1.5:
            log.warning(
                f"{type(self).__name__} poll cycle took longer than interval "
                f"({elapsed:.2f}s > {self.poll_interval:.2f}s)"
            )
            await asyncio.sleep(0.01)  # Yield briefly to avoid starving the loop.

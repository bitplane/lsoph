"""Behavioural tests for the shared PollingBackend snapshot/diff machinery.

These drive the real Monitor through PollingBackend._reconcile (and one full
attach loop), covering open, implied read/write, close, same-fd re-path, stat
entries and process exit.
"""

import asyncio

from lsoph.backend.polling import OpenFile, PidFiles, PollingBackend
from lsoph.monitor import Monitor


class ScriptedBackend(PollingBackend):
    """A polling backend whose snapshots come from a scripted list."""

    backend_name = "scripted"
    poll_interval = 0.001
    child_check_interval = 10**9  # never hit the descendant check in tests

    def __init__(self, monitor, snapshots=()):
        super().__init__(monitor)
        self._snapshots = list(snapshots)

    @staticmethod
    def is_available() -> bool:
        return True

    async def _snapshot(self, pids):
        if not self._snapshots:
            await self.stop()  # nothing left to feed; end the loop
            return {}
        return self._snapshots.pop(0)


def _backend():
    return ScriptedBackend(Monitor(identifier="test"))


def test_reconcile_open_emits_open_and_read_write():
    """A newly seen read/write fd is reported as open plus a read and a write."""
    backend = _backend()
    snapshot = {100: PidFiles(fds={3: OpenFile(3, b"/a", read=True, write=True)})}
    seen = {}
    monitored = {100}

    backend._reconcile(snapshot, seen, monitored, timestamp=1.0)

    info = backend.monitor.files[b"/a"]
    assert info.status == "active"  # read/write bumps status past "open"
    assert info.open_by_pids == {100: {3}}
    assert seen[100].fds[3].path == b"/a"


def test_reconcile_close_when_fd_disappears():
    """An fd present last cycle but gone this cycle is closed."""
    backend = _backend()
    seen = {100: PidFiles(fds={3: OpenFile(3, b"/a", read=False, write=False)})}
    backend.monitor.open(100, b"/a", 3, True, 1.0)
    monitored = {100}

    backend._reconcile({100: PidFiles()}, seen, monitored, timestamp=2.0)

    info = backend.monitor.files[b"/a"]
    assert info.status == "closed"
    assert info.open_by_pids == {}


def test_reconcile_same_fd_new_path_closes_old_and_opens_new():
    """When an fd is reused for a different path, the old path closes and the new opens."""
    backend = _backend()
    seen = {}
    monitored = {100}
    backend._reconcile(
        {100: PidFiles(fds={3: OpenFile(3, b"/a", read=False, write=False)})},
        seen,
        monitored,
        timestamp=1.0,
    )

    backend._reconcile(
        {100: PidFiles(fds={3: OpenFile(3, b"/b", read=False, write=False)})},
        seen,
        monitored,
        timestamp=2.0,
    )

    assert backend.monitor.files[b"/a"].status == "closed"
    assert backend.monitor.files[b"/b"].open_by_pids == {100: {3}}


def test_reconcile_stat_entries_are_reported():
    """Non-fd snapshot paths (lsof cwd/mem/DEL) are reported as stat accesses."""
    backend = _backend()
    snapshot = {100: PidFiles(stats=[b"/etc/ld.so.cache"])}

    backend._reconcile(snapshot, {}, {100}, timestamp=1.0)

    assert backend.monitor.files[b"/etc/ld.so.cache"].status == "accessed"


def test_reconcile_unchanged_stat_entries_are_not_re_reported():
    """A library mapped for the whole run is one access, not one per poll."""
    backend = _backend()
    seen = {}
    for ts in (1.0, 2.0, 3.0):
        snapshot = {100: PidFiles(stats=[b"/usr/lib/libc.so.6"])}
        backend._reconcile(snapshot, seen, {100}, timestamp=ts)

    info = backend.monitor.files[b"/usr/lib/libc.so.6"]
    assert info.last_activity_ts == 1.0
    assert len(info.event_history) == 1


def test_reconcile_exited_pid_triggers_process_exit():
    """A monitored pid absent from the snapshot has its fds closed and is dropped."""
    backend = _backend()
    seen = {100: PidFiles(fds={3: OpenFile(3, b"/a", read=False, write=False)})}
    backend.monitor.open(100, b"/a", 3, True, 1.0)
    monitored = {100}

    backend._reconcile({}, seen, monitored, timestamp=2.0)

    assert monitored == set()
    assert 100 not in seen
    assert backend.monitor.files[b"/a"].status == "closed"


def test_attach_drives_reconcile_until_snapshots_exhausted():
    """The full attach loop applies scripted snapshots then exits cleanly."""
    monitor = Monitor(identifier="test")
    backend = ScriptedBackend(
        monitor,
        snapshots=[
            {100: PidFiles(fds={3: OpenFile(3, b"/a", read=True, write=False)})},
            {100: PidFiles()},
        ],
    )

    asyncio.run(backend.attach([100]))

    assert monitor.files[b"/a"].status == "closed"

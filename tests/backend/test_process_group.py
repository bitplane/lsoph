"""The shared spawn/terminate primitives on Backend must tear down the whole
process group, so a run-mode command's children never outlive it (strace's
tracee, watch's cat, ...). Exercised through a minimal concrete Backend so it
covers the path every backend inherits, not one backend's override.
"""

import asyncio
import os
import sys
import time

import pytest

from lsoph.backend.base import Backend
from lsoph.monitor import Monitor

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")


class _Spawner(Backend):
    """Bare Backend that only spawns -- enough to test the shared lifecycle."""

    backend_name = "spawner"

    @staticmethod
    def is_available() -> bool:
        return True

    async def attach(self, pids):
        pass


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)  # signal 0 just probes for existence
        return True
    except ProcessLookupError:
        return False


def test_terminate_kills_the_whole_process_group():
    """A wrapper that forks a long-lived child has the child killed too."""

    async def scenario():
        backend = _Spawner(Monitor(identifier="t"))
        # sh forks `sleep 30` into the new session/group, then waits on it.
        proc = await backend._spawn(
            ["sh", "-c", "sleep 30 & wait"],
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.sleep(0.5)  # let sh fork the child
        assert _group_alive(proc.pid)  # sanity: group is up before we stop it

        # Would time out if _terminate waited on the child (the old bug).
        await asyncio.wait_for(backend._terminate_process(), timeout=5.0)
        return proc

    proc = asyncio.run(asyncio.wait_for(scenario(), timeout=20))

    assert proc.returncode is not None  # leader reaped
    # The sleep child is orphaned by the leader's death; give the subreaper a
    # moment to reap it after SIGTERM before asserting the group is empty.
    deadline = time.monotonic() + 3.0
    while _group_alive(proc.pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _group_alive(proc.pid)

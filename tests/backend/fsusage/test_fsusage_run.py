"""fs_usage run mode: the tracer attaches to a launched target, so its output
lags the target and must still be read after the target exits."""

import asyncio
import sys

import pytest

from lsoph.backend.fsusage.backend import Fsusage
from lsoph.monitor import Monitor

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX spawn")


class _LaggingFsusage(Fsusage):
    """Stands in for fs_usage: delivers one event a moment after starting."""

    delivered = False

    async def attach(self, pids):
        await asyncio.sleep(0.5)  # the target (`true`) has long exited by now
        if not self.should_stop:
            self.delivered = True
        await self._should_stop.wait()


def test_events_arriving_just_after_the_target_exits_are_kept():
    backend = _LaggingFsusage(Monitor(identifier="t"))

    asyncio.run(asyncio.wait_for(backend.run_command(["true"]), timeout=10))

    assert backend.delivered

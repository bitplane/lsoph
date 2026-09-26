"""TracerBackend plumbing shared by the subprocess tracers."""

import asyncio
import sys

import pytest

from lsoph.backend.tracer import OutputChannel, TracerBackend
from lsoph.monitor import Monitor

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFOs")


class _SilentFifoTracer(TracerBackend):
    """A tracer that is told about the FIFO but never opens it -- like a static
    binary under the preload backend, or a tracer dying on a usage error."""

    backend_name = "silent"
    output_channel = OutputChannel.FIFO

    @staticmethod
    def is_available() -> bool:
        return True

    def build_command(self, output_path, attach_pids, run_command):
        return ["sh", "-c", "sleep 0.2"]

    async def process_lines(self, lines, attach_ids):
        async for _ in lines:
            pass


def test_run_finishes_when_the_fifo_is_never_opened():
    """The FIFO open must not block the event loop waiting for a writer."""

    async def scenario():
        backend = _SilentFifoTracer(Monitor(identifier="t"))
        ticks = 0

        async def heartbeat():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.05)
                ticks += 1

        beat = asyncio.create_task(heartbeat())
        await asyncio.wait_for(backend.run_command(["ignored"]), timeout=10)
        beat.cancel()
        return ticks

    ticks = asyncio.run(asyncio.wait_for(scenario(), timeout=20))
    assert ticks > 0  # the loop kept running while the open was pending

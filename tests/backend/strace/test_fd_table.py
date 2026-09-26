"""The fd-table model the shared syscall dispatch keeps across processes:
fork inheritance, threads sharing a table, and fd duplication."""

import asyncio

from lsoph.backend.strace.backend import Strace
from lsoph.monitor import Monitor

# PIDs that don't exist, so no /proc fallback can paper over the model.
P, C = 999990, 999991


def _trace(lines):
    monitor = Monitor(identifier="t")

    async def run():
        async def gen():
            for line in lines:
                yield line.encode()

        await Strace(monitor).process_lines(gen(), None)

    asyncio.run(run())
    return monitor


def test_forked_child_inherits_and_releases_its_copy_of_the_fds():
    monitor = _trace(
        [
            f'{P} openat(AT_FDCWD, "/tmp/a", O_RDONLY) = 3',
            f"{P} fork() = {C}",
            f'{C} read(3, "hello", 5) = 5',
            f"{C} exit_group(0) = ?",
        ]
    )

    info = monitor.files[b"/tmp/a"]
    assert info.bytes_read == 5  # the child's read resolved via inheritance
    assert info.open_by_pids == {P: {3}}  # the child's copy closed on exit

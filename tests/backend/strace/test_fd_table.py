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


T = 999992


def test_threads_share_one_fd_table():
    """An fd opened on one thread and closed on another is one fd; a thread
    exiting on its own doesn't close fds the process still holds."""
    monitor = _trace(
        [
            f"{P} clone3({{flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_THREAD}}, 88) = {T}",
            f'{T} openat(AT_FDCWD, "/tmp/a", O_RDONLY) = 3',
            f"{T} +++ exited with 0 +++",
            f'{P} read(3, "hi", 2) = 2',
        ]
    )
    info = monitor.files[b"/tmp/a"]
    assert info.bytes_read == 2
    assert info.open_by_pids == {P: {3}}

    monitor = _trace(
        [
            f"{P} clone3({{flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_THREAD}}, 88) = {T}",
            f'{T} openat(AT_FDCWD, "/tmp/a", O_RDONLY) = 3',
            f"{P} close(3) = 0",
        ]
    )
    assert monitor.files[b"/tmp/a"].status == "closed"


def test_dup2_onto_an_open_fd_closes_its_file():
    monitor = _trace(
        [
            f'{P} openat(AT_FDCWD, "/tmp/a", O_RDONLY) = 3',
            f'{P} openat(AT_FDCWD, "/tmp/b", O_RDONLY) = 4',
            f"{P} dup2(3, 4) = 4",
        ]
    )

    assert monitor.files[b"/tmp/b"].status == "closed"
    assert monitor.files[b"/tmp/a"].open_by_pids == {P: {3, 4}}

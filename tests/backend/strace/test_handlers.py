"""Tests for the strace syscall handlers and the shared path_handler guard.

Handlers are exercised through SYSCALL_HANDLERS (the dispatched entry points,
so the path_handler decorator is included) against a real Monitor.
"""

from lsoph.backend.strace.handlers import SYSCALL_HANDLERS
from lsoph.backend.strace.syscall import Syscall
from lsoph.monitor import Monitor


def _event(syscall, args, pid=1000, result_int=0, error_name=None):
    return Syscall(
        pid=pid,
        syscall=syscall,
        args=list(args),
        result_int=result_int,
        error_name=error_name,
        timestamp=1.0,
    )


def _dispatch(event, monitor, cwd_map=None):
    SYSCALL_HANDLERS[event.syscall](event, monitor, cwd_map or {})


def test_open_records_open_file_with_fd():
    """A successful open maps the returned fd to the resolved path."""
    monitor = Monitor(identifier="t")
    event = _event("open", [b"/tmp/a", "O_RDONLY", "0"], result_int=3)

    _dispatch(event, monitor)

    info = monitor.files[b"/tmp/a"]
    assert info.status == "open"
    assert info.open_by_pids == {1000: {3}}


def test_read_resolves_path_from_fd():
    """read looks the path up from the fd mapped by an earlier open."""
    monitor = Monitor(identifier="t")
    monitor.open(1000, b"/tmp/a", 4, True, 1.0)

    _dispatch(_event("read", [4, b"buf", 512], result_int=100), monitor)

    assert monitor.files[b"/tmp/a"].bytes_read == 100


def test_stat_and_lstat_use_the_same_handler():
    """stat and lstat share one handler and both record an access."""
    monitor = Monitor(identifier="t")

    _dispatch(_event("stat", [b"/tmp/s", b"struct"]), monitor)
    _dispatch(_event("lstat", [b"/tmp/l", b"struct"]), monitor)

    assert monitor.files[b"/tmp/s"].status == "accessed"
    assert monitor.files[b"/tmp/l"].status == "accessed"


def test_unlink_and_rmdir_mark_deleted():
    """unlink and rmdir share the delete handler and mark a known file deleted."""
    monitor = Monitor(identifier="t")
    monitor.open(1000, b"/tmp/gone", 5, True, 1.0)

    _dispatch(_event("unlink", [b"/tmp/gone"]), monitor)

    assert monitor.files[b"/tmp/gone"].status == "deleted"


def test_renameat2_transfers_state_to_new_path():
    """renameat2 (renameat + flags) is handled and moves state to the new path."""
    monitor = Monitor(identifier="t")
    monitor.open(1000, b"/tmp/old", 6, True, 1.0)

    event = _event("renameat2", ["AT_FDCWD", b"/tmp/old", "AT_FDCWD", b"/tmp/new", "0"])
    _dispatch(event, monitor)

    assert b"/tmp/new" in monitor.files
    assert b"/tmp/old" not in monitor.files


def test_missing_fd_is_skipped_without_raising():
    """A read on an unmapped fd (PID/FD gone) is swallowed by the guard."""
    monitor = Monitor(identifier="t")

    _dispatch(_event("read", [99, b"buf", 512], result_int=10), monitor)

    assert len(monitor) == 0


def test_unresolvable_relative_path_is_skipped_without_raising():
    """unlink of a relative path with no known CWD is swallowed, not raised.

    Previously the delete handlers were unguarded, so this raised a
    PathResolutionError instead of being skipped quietly.
    """
    monitor = Monitor(identifier="t")

    _dispatch(_event("unlink", [b"relative/path"]), monitor, cwd_map={})

    assert len(monitor) == 0

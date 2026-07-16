# Filename: src/lsoph/backend/strace/handlers.py
"""
Syscall handlers and CWD update logic for the strace backend.
Receives Syscall object with parsed args (bytes/str/int) based on parser_defs.
Path arguments are expected to be bytes.
Ensures flags are stored as strings in details.
"""

import functools
import logging
import os
from collections.abc import Callable

from lsoph.monitor import Monitor

from . import helpers
from .syscall import Syscall

log = logging.getLogger(__name__)

# Type alias for handler functions (cwd_map still holds bytes)
SyscallHandler = Callable[[Syscall, Monitor, dict[int, bytes]], None]


def path_handler(fn: SyscallHandler) -> SyscallHandler:
    """
    Wrap a handler so a failed path/FD resolution is logged quietly and skipped.

    Both ``helpers.resolve_path`` (via PathResolutionError) and
    ``monitor.get_path`` raise ``KeyError`` when a PID or FD has already gone.
    That is routine as processes exit mid-trace, so it is logged at debug rather
    than surfaced as a handler error with a full traceback.
    """

    @functools.wraps(fn)
    def wrapper(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]) -> None:
        try:
            fn(event, monitor, cwd_map)
        except KeyError:
            log.debug(f"PID {event.pid} probably already gone during {event.syscall}")

    return wrapper


def _details(event: Syscall, **extra) -> dict:
    """
    Build the details dict for a monitor call: the syscall name, any extra keys,
    and the error name/message when the syscall failed. Forwarding error_name is
    what lets the Monitor flag ENOENT failures (last_error_enoent).
    """
    details = {"syscall": event.syscall, **extra}
    if not event.success:
        details["error_name"] = event.error_name
        details["error_msg"] = event.error_msg
    return details


# --- Open/Create Syscall Handlers ---


@path_handler
def _handle_open(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'open' syscall."""
    pid, success, timestamp = event.pid, event.success, event.timestamp

    path = helpers.resolve_path(pid, event.args[0], cwd_map, monitor)
    details = _details(event, flags=event.args[1], mode=event.args[2])

    fd = event.result_int if success and event.result_int is not None else -1
    monitor.open(pid, path, fd, success, timestamp, **details)


@path_handler
def _handle_openat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'openat' syscall."""
    pid, success, timestamp = event.pid, event.success, event.timestamp
    details = _details(event)

    dirfd = helpers.parse_dirfd(event.args[0])
    details["dirfd"] = event.args[0]

    path = helpers.resolve_path(pid, event.args[1], cwd_map, monitor, dirfd=dirfd)
    details["flags"] = event.args[2]
    if len(event.args) > 3:
        details["mode"] = event.args[3]

    fd = event.result_int if success and event.result_int is not None else -1
    monitor.open(pid, path, fd, success, timestamp, **details)


@path_handler
def _handle_creat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'creat' syscall."""
    pid, success, timestamp = event.pid, event.success, event.timestamp

    path = helpers.resolve_path(pid, event.args[0], cwd_map, monitor)
    details = _details(event, mode=event.args[1])

    fd = event.result_int if success and event.result_int is not None else -1
    monitor.open(pid, path, fd, success, timestamp, **details)


# --- Close Syscall Handler ---


def _handle_close(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'close' syscall."""
    fd_arg = event.args[0]
    monitor.close(event.pid, fd_arg, event.success, event.timestamp, **_details(event))


# --- Read/Write Syscall Handlers ---


@path_handler
def _handle_read(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'read' syscall."""
    _handle_read_write_common(event, monitor, is_read=True)


@path_handler
def _handle_pread64(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'pread64' syscall."""
    _handle_read_write_common(event, monitor, is_read=True, has_offset=True)


@path_handler
def _handle_readv(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'readv' syscall."""
    _handle_read_write_common(event, monitor, is_read=True)


@path_handler
def _handle_write(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'write' syscall."""
    _handle_read_write_common(event, monitor, is_read=False)


@path_handler
def _handle_pwrite64(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'pwrite64' syscall."""
    _handle_read_write_common(event, monitor, is_read=False, has_offset=True)


@path_handler
def _handle_writev(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'writev' syscall."""
    _handle_read_write_common(event, monitor, is_read=False)


def _handle_read_write_common(
    event: Syscall, monitor: Monitor, is_read: bool, has_offset: bool = False
):
    """Common logic for read/write syscalls. Raises KeyError if the FD is gone."""
    pid, success, timestamp = event.pid, event.success, event.timestamp

    fd_arg = event.args[0]
    path = monitor.get_path(pid, fd_arg)

    details = _details(event, requested_bytes=event.args[2])
    if has_offset:
        details["offset"] = event.args[3]
    details["bytes"] = (
        event.result_int if success and event.result_int is not None else 0
    )

    if is_read:
        monitor.read(pid, fd_arg, path, success, timestamp, **details)
    else:
        monitor.write(pid, fd_arg, path, success, timestamp, **details)


# --- Stat Syscall Handlers ---


@path_handler
def _handle_access(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'access' syscall."""
    pid, success, timestamp = event.pid, event.success, event.timestamp

    path = helpers.resolve_path(pid, event.args[0], cwd_map, monitor)
    details = _details(event, mode=event.args[1])

    monitor.stat(pid, path, success, timestamp, **details)


@path_handler
def _handle_stat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'stat' and 'lstat' syscalls (identical shape)."""
    pid, success, timestamp = event.pid, event.success, event.timestamp

    path = helpers.resolve_path(pid, event.args[0], cwd_map, monitor)
    details = _details(event, struct_buffer=event.args[1])

    monitor.stat(pid, path, success, timestamp, **details)


@path_handler
def _handle_newfstatat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'newfstatat' syscall."""
    pid, success, timestamp = event.pid, event.success, event.timestamp
    details = _details(event)

    dirfd = helpers.parse_dirfd(event.args[0])
    details["dirfd"] = event.args[0]

    path = helpers.resolve_path(pid, event.args[1], cwd_map, monitor, dirfd=dirfd)
    details["struct_buffer"] = event.args[2]

    flags_arg = event.args[3]
    if flags_arg is not None:
        details["flags"] = str(flags_arg)

    monitor.stat(pid, path, success, timestamp, **details)


@path_handler
def _handle_fstat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'fstat' syscall."""
    pid, success, timestamp = event.pid, event.success, event.timestamp

    fd_arg = event.args[0]
    path = monitor.get_path(pid, fd_arg)
    details = _details(event, fd=fd_arg, struct_buffer=event.args[1])

    monitor.stat(pid, path, success, timestamp, **details)


# --- Delete Syscall Handlers ---


@path_handler
def _handle_delete(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'unlink' and 'rmdir' syscalls (single path, no dirfd)."""
    path = helpers.resolve_path(event.pid, event.args[0], cwd_map, monitor)
    monitor.delete(event.pid, path, event.success, event.timestamp, **_details(event))


@path_handler
def _handle_unlinkat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'unlinkat' syscall."""
    pid, success, timestamp = event.pid, event.success, event.timestamp
    details = _details(event)

    dirfd = helpers.parse_dirfd(event.args[0])
    details["dirfd"] = event.args[0]

    path = helpers.resolve_path(pid, event.args[1], cwd_map, monitor, dirfd=dirfd)

    flags_arg = event.args[2]
    if flags_arg is not None:
        details["flags"] = str(flags_arg)

    monitor.delete(pid, path, success, timestamp, **details)


# --- Rename Syscall Handlers ---


@path_handler
def _handle_rename(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'rename' syscall."""
    pid, success, timestamp = event.pid, event.success, event.timestamp

    old_path = helpers.resolve_path(pid, event.args[0], cwd_map, monitor)
    new_path = helpers.resolve_path(pid, event.args[1], cwd_map, monitor)

    monitor.rename(pid, old_path, new_path, success, timestamp, **_details(event))


@path_handler
def _handle_renameat(event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes]):
    """Handles 'renameat' and 'renameat2' syscalls (renameat2 adds a flags arg)."""
    pid, success, timestamp = event.pid, event.success, event.timestamp
    details = _details(event)

    old_dirfd = helpers.parse_dirfd(event.args[0])
    details["old_dirfd"] = event.args[0]
    new_dirfd = helpers.parse_dirfd(event.args[2])
    details["new_dirfd"] = event.args[2]

    old_path = helpers.resolve_path(
        pid, event.args[1], cwd_map, monitor, dirfd=old_dirfd
    )
    new_path = helpers.resolve_path(
        pid, event.args[3], cwd_map, monitor, dirfd=new_dirfd
    )

    if len(event.args) > 4 and event.args[4] is not None:
        details["flags"] = str(event.args[4])

    monitor.rename(pid, old_path, new_path, success, timestamp, **details)


# --- CWD Update Logic ---
def update_cwd(pid: int, cwd_map: dict[int, bytes], monitor: Monitor, event: Syscall):
    """Updates the CWD map (bytes) based on chdir or fchdir syscalls."""
    if event.syscall == "chdir":
        _handle_chdir(pid, cwd_map, monitor, event)
    elif event.syscall == "fchdir":
        _handle_fchdir(pid, cwd_map, monitor, event)


def _handle_chdir(
    pid: int, cwd_map: dict[int, bytes], monitor: Monitor, event: Syscall
):
    """Handle chdir syscall for CWD updating."""
    success, timestamp = event.success, event.timestamp
    details = _details(event)

    if success:
        path = helpers.resolve_path(pid, event.args[0], cwd_map, monitor)
        cwd_map[pid] = path
        log.info(f"PID {pid} changed CWD via chdir to: {os.fsdecode(path)!r}")
        monitor.stat(pid, path, success, timestamp, **details)
    else:
        # For failed chdir, still call stat with original path
        monitor.stat(pid, event.args[0], success, timestamp, **details)


def _handle_fchdir(
    pid: int, cwd_map: dict[int, bytes], monitor: Monitor, event: Syscall
):
    """Handle fchdir syscall for CWD updating."""
    success, timestamp = event.success, event.timestamp
    details = _details(event)

    fd_arg = event.args[0]
    details["fd"] = fd_arg
    target_path = monitor.get_path(pid, fd_arg)

    if success and target_path:
        cwd_map[pid] = target_path
        log.info(f"PID {pid} changed CWD via fchdir to: {os.fsdecode(target_path)!r}")
        monitor.stat(pid, target_path, success, timestamp, **details)
    elif not target_path:
        log.warning(f"fchdir(fd={fd_arg}) target path unknown for PID {pid}")


# --- SYSCALL_HANDLERS dictionary ---
SYSCALL_HANDLERS: dict[str, SyscallHandler] = {
    # Open/Create handlers
    "open": _handle_open,
    "openat": _handle_openat,
    "creat": _handle_creat,
    # Close handler
    "close": _handle_close,
    # Read/Write handlers
    "read": _handle_read,
    "pread64": _handle_pread64,
    "readv": _handle_readv,
    "write": _handle_write,
    "pwrite64": _handle_pwrite64,
    "writev": _handle_writev,
    # Stat handlers
    "access": _handle_access,
    "stat": _handle_stat,
    "lstat": _handle_stat,
    "newfstatat": _handle_newfstatat,
    "fstat": _handle_fstat,
    # Delete handlers
    "unlink": _handle_delete,
    "unlinkat": _handle_unlinkat,
    "rmdir": _handle_delete,
    # Rename handlers
    "rename": _handle_rename,
    "renameat": _handle_renameat,
    "renameat2": _handle_renameat,
}

# Filename: src/lsoph/backend/syscall_dispatch.py
"""
Shared dispatch from a parsed Syscall event to the Monitor.

Both syscall-level tracer backends (strace, truss) produce Syscall objects with
the same argument vocabulary; this turns one into Monitor updates, tracking CWD
(fork inheritance, chdir/fchdir) and process exit. The Syscall dataclass and the
per-syscall handlers are the shared syscall model, which currently lives in the
`strace` package.
"""

import logging

import psutil

from lsoph.monitor import Monitor
from lsoph.util.pid import get_cwd as pid_get_cwd

from .strace import handlers
from .strace.syscall import EXIT_SYSCALLS, PROCESS_SYSCALLS, Syscall

log = logging.getLogger(__name__)


async def process_syscall_event(
    event: Syscall,
    monitor: Monitor,
    cwd_map: dict[int, bytes],
    initial_pids: set[int],
):
    """Update Monitor and CWD state (bytes) from a single Syscall event."""
    pid = event.pid
    syscall_name = event.syscall

    # 1. Process creation: the child inherits the parent's CWD.
    if (
        syscall_name in PROCESS_SYSCALLS
        and event.success
        and event.child_pid is not None
    ):
        child_pid = event.child_pid
        parent_cwd = cwd_map.get(pid)
        if parent_cwd:
            cwd_map[child_pid] = parent_cwd
        else:
            child_cwd = pid_get_cwd(child_pid)
            if child_cwd:
                cwd_map[child_pid] = child_cwd
            else:
                log.warning(f"Could not determine CWD for new child PID {child_pid}.")
        return

    # 2. Ensure CWD is known for other syscalls (needed to resolve relative paths).
    if pid not in cwd_map and syscall_name not in EXIT_SYSCALLS:
        cwd = pid_get_cwd(pid)
        if cwd:
            cwd_map[pid] = cwd
        elif psutil.pid_exists(pid):
            log.warning(
                f"Could not determine CWD for PID {pid} (still exists). "
                "Relative paths may be incorrect."
            )

    # 3. chdir/fchdir update the CWD map.
    if syscall_name in ["chdir", "fchdir"]:
        handlers.update_cwd(pid, cwd_map, monitor, event)
        return

    # 4. Process exit.
    if syscall_name in EXIT_SYSCALLS:
        monitor.process_exit(pid, event.timestamp)
        cwd_map.pop(pid, None)
        return

    # 5. Dispatch to the per-syscall handler.
    handler = handlers.SYSCALL_HANDLERS.get(syscall_name)
    if handler:
        try:
            handler(event, monitor, cwd_map)
        except Exception:
            log.exception(f"Handler error for {syscall_name} (event: {event!r})")
    else:
        log.debug(f"No specific handler found for syscall: {syscall_name}")

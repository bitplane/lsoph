# Filename: src/lsoph/backend/syscall_dispatch.py
"""
Shared dispatch from a parsed Syscall event to the Monitor.

Both syscall-level tracer backends (strace, truss) produce Syscall objects with
the same argument vocabulary; this turns one into Monitor updates, tracking CWD
(fork inheritance, chdir/fchdir) and process exit. The Syscall dataclass and the
per-syscall handlers are the shared syscall model, which currently lives in the
`strace` package.
"""

import dataclasses
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
    default_cwd: bytes | None = None,
    fd_owners: dict[int, int] | None = None,
):
    """Update Monitor and CWD state (bytes) from a single Syscall event.

    default_cwd is the fallback working directory used when a PID's own CWD can't
    be read from /proc (e.g. the process already exited). In run mode this is the
    directory the command was launched in, which it inherits -- so relative paths
    resolve even for short-lived processes that are gone by the time we dispatch.

    fd_owners maps a thread id to the task whose fd table it shares, for tracers
    that report per-thread ids (strace): its events are applied to that owner,
    so an fd opened on one thread and closed on another is one fd.
    """
    owners = fd_owners if fd_owners is not None else {}
    tid = event.pid
    if tid in owners:
        event = dataclasses.replace(event, pid=owners[tid])
    pid = event.pid
    syscall_name = event.syscall

    # 1. Process creation: the child inherits the parent's CWD.
    if (
        syscall_name in PROCESS_SYSCALLS
        and event.success
        and event.child_pid is not None
    ):
        child_pid = event.child_pid
        child_cwd = cwd_map.get(pid) or pid_get_cwd(child_pid) or default_cwd
        if child_cwd:
            cwd_map[child_pid] = child_cwd
        else:
            log.warning(f"Could not determine CWD for new child PID {child_pid}.")
        # A forked child gets a copy of the fd table; one cloned with
        # CLONE_FILES (a thread) shares it instead.
        if b"CLONE_FILES" in event.raw_line and fd_owners is not None:
            fd_owners[child_pid] = pid
        else:
            monitor.inherit_fds(pid, child_pid)
        return

    # 2. Ensure CWD is known for other syscalls (needed to resolve relative paths).
    if pid not in cwd_map and syscall_name not in EXIT_SYSCALLS:
        cwd = pid_get_cwd(pid) or default_cwd
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

    # 4. Exit. A thread leaving on its own (exit) leaves the shared table as
    # is; the owner exiting, or any exit_group, ends the whole process.
    if syscall_name in EXIT_SYSCALLS:
        if tid != pid and syscall_name != "exit_group":
            del owners[tid]
            return
        monitor.process_exit(pid, event.timestamp)
        cwd_map.pop(pid, None)
        for thread in [t for t, owner in owners.items() if owner == pid]:
            del owners[thread]
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

# Filename: src/lsoph/backend/strace/backend.py
"""Strace backend: drives `strace` via the shared TracerBackend pipeline."""

import asyncio
import logging
import shutil
from collections.abc import AsyncIterator
from typing import Set

import psutil

from lsoph.backend.strace import handlers
from lsoph.monitor import Monitor
from lsoph.util.pid import get_cwd as pid_get_cwd

from ..tracer import OutputChannel, TracerBackend
from .parse import parse_strace_stream_pyparsing as parse_strace_stream
from .syscall import EXIT_SYSCALLS, PROCESS_SYSCALLS, Syscall

log = logging.getLogger(__name__)

STRACE_BASE_OPTIONS = ["-f", "-qq", "-s", "4096"]

FILE_STRUCT_SYSCALLS = [
    "open",
    "openat",
    "creat",
    "access",
    "stat",
    "lstat",
    "newfstatat",
    "close",
    "unlink",
    "unlinkat",
    "rmdir",
    "rename",
    "renameat",
    "renameat2",
    "chdir",
    "fchdir",
]
IO_SYSCALLS = ["read", "pread64", "readv", "write", "pwrite64", "writev"]
DEFAULT_SYSCALLS = sorted(
    set(PROCESS_SYSCALLS)
    | set(FILE_STRUCT_SYSCALLS)
    | set(IO_SYSCALLS)
    | set(EXIT_SYSCALLS)
)


async def _process_single_event(
    event: Syscall, monitor: Monitor, cwd_map: dict[int, bytes], initial_pids: Set[int]
):
    """
    Processes a single Syscall event, updating state and CWD map (bytes).
    Handles CWD inheritance for new processes.
    """
    pid = event.pid
    syscall_name = event.syscall

    # 1. Handle process creation CWD inheritance
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

    # 2. Ensure CWD is known for other syscalls
    if pid not in cwd_map and syscall_name not in EXIT_SYSCALLS:
        cwd = pid_get_cwd(pid)
        if cwd:
            cwd_map[pid] = cwd
        elif psutil.pid_exists(pid):
            log.warning(
                f"Could not determine CWD for PID {pid} (still exists). "
                "Relative paths may be incorrect."
            )

    # 3. Handle chdir/fchdir
    if syscall_name in ["chdir", "fchdir"]:
        handlers.update_cwd(pid, cwd_map, monitor, event)
        return

    # 4. Handle exit
    if syscall_name in EXIT_SYSCALLS:
        monitor.process_exit(pid, event.timestamp)
        cwd_map.pop(pid, None)
        return

    # 5. Dispatch to generic handlers
    handler = handlers.SYSCALL_HANDLERS.get(syscall_name)
    if handler:
        try:
            handler(event, monitor, cwd_map)
        except Exception:
            log.exception(f"Handler error for {syscall_name} (event: {event!r})")
    else:
        log.debug(f"No specific handler found for syscall: {syscall_name}")


class Strace(TracerBackend):
    """Async backend implementation using strace. Works with bytes paths."""

    backend_name = "strace"
    output_channel = OutputChannel.FIFO

    def __init__(self, monitor: Monitor, syscalls: list[str] = DEFAULT_SYSCALLS):
        super().__init__(monitor)
        self.syscalls = sorted(
            set(syscalls) | set(PROCESS_SYSCALLS) | set(EXIT_SYSCALLS)
        )

    @staticmethod
    def is_available() -> bool:
        """Check if the strace executable is available in the system PATH."""
        return shutil.which("strace") is not None

    def build_command(
        self,
        output_path: str | None,
        attach_pids: list[int] | None,
        run_command: list[str] | None,
    ) -> list[str] | None:
        strace_path = shutil.which("strace")
        if not strace_path:
            log.error("Could not find 'strace' executable.")
            return None

        # -o must precede -p/-- so it applies to strace, not the traced command.
        argv = [
            strace_path,
            *STRACE_BASE_OPTIONS,
            "-e",
            f"trace={','.join(self.syscalls)}",
            "-o",
            output_path,
        ]

        if attach_pids:
            valid = [str(p) for p in attach_pids if psutil.pid_exists(p)]
            if not valid:
                log.error("No valid PIDs/TIDs provided to attach to.")
                return None
            argv += ["-p", ",".join(valid)]
        else:
            argv += ["--", *run_command]
        return argv

    async def process_lines(
        self, lines: AsyncIterator[bytes], attach_ids: list[int] | None
    ) -> None:
        initial_pids: Set[int] = set(attach_ids or [])
        cwd_map: dict[int, bytes] = {}
        for pid in initial_pids:
            cwd = pid_get_cwd(pid)
            if cwd:
                cwd_map[pid] = cwd
            else:
                log.warning(f"Could not get initial CWD for attached PID {pid}.")

        event_stream = parse_strace_stream(
            lines,
            self.monitor,
            self._should_stop,
            syscalls=self.syscalls,
            attach_ids=attach_ids,
        )

        processed = 0
        async for event in event_stream:
            if self.should_stop:
                break
            processed += 1
            await _process_single_event(event, self.monitor, cwd_map, initial_pids)
            await asyncio.sleep(0)  # Yield control for UI responsiveness.
        log.info(f"Strace event processing finished. Processed {processed} events.")

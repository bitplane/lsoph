# Filename: src/lsoph/backend/strace/backend.py
"""Strace backend: drives `strace` via the shared TracerBackend pipeline."""

import asyncio
import logging
import os
import shutil
from collections.abc import AsyncIterator
from typing import Set

import psutil

from lsoph.monitor import Monitor
from lsoph.util.pid import get_cwd as pid_get_cwd

from ..syscall_dispatch import process_syscall_event
from ..tracer import OutputChannel, TracerBackend
from .parse import parse_strace_stream_pyparsing as parse_strace_stream
from .syscall import EXIT_SYSCALLS, PROCESS_SYSCALLS

log = logging.getLogger(__name__)

STRACE_BASE_OPTIONS = ["-f", "-qq", "-s", "4096"]

FILE_STRUCT_SYSCALLS = [
    # open / create
    "open", "openat", "openat2", "creat",
    # access / stat
    "access", "faccessat", "faccessat2",
    "stat", "lstat", "fstat", "newfstatat", "statx",
    "readlink", "readlinkat",
    # close
    "close",
    # delete
    "unlink", "unlinkat", "rmdir",
    # rename
    "rename", "renameat", "renameat2",
    # create (dir / link) and truncate
    "mkdir", "mkdirat", "link", "symlink", "truncate", "ftruncate",
    # fd duplication
    "dup", "dup2", "dup3",
    # cwd
    "chdir", "fchdir",
]  # fmt: skip
IO_SYSCALLS = [
    "read", "pread64", "readv", "preadv", "preadv2",
    "write", "pwrite64", "writev", "pwritev", "pwritev2",
    "splice", "copy_file_range", "sendfile",
]  # fmt: skip
DEFAULT_SYSCALLS = sorted(
    set(PROCESS_SYSCALLS)
    | set(FILE_STRUCT_SYSCALLS)
    | set(IO_SYSCALLS)
    | set(EXIT_SYSCALLS)
)


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
        # In run mode the traced command inherits our launch directory; use it as
        # the CWD fallback so relative paths still resolve even if the process is
        # gone by the time we dispatch its events.
        default_cwd = None if attach_ids else os.fsencode(os.getcwd())
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
            await process_syscall_event(
                event, self.monitor, cwd_map, initial_pids, default_cwd
            )
            await asyncio.sleep(0)  # Yield control for UI responsiveness.
        log.info(f"Strace event processing finished. Processed {processed} events.")

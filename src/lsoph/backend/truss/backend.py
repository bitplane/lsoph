# Filename: src/lsoph/backend/truss/backend.py
"""
FreeBSD truss backend, built on the shared TracerBackend pipeline.

truss is a FreeBSD/Solaris tool, so is_available() returns False on Linux and
the backend simply won't be offered there. This is built against the documented
truss(1) output format and unit-tested against it, but has not yet been
smoke-tested on a real FreeBSD host.
"""

import asyncio
import logging
import os
import shutil
import time
from collections.abc import AsyncIterator

from lsoph.util.pid import get_cwd as pid_get_cwd

from ..syscall_dispatch import process_syscall_event
from ..tracer import OutputChannel, TracerBackend
from .parse import parse_truss_line

log = logging.getLogger(__name__)


class Truss(TracerBackend):
    """Async backend driving FreeBSD `truss`. Works with bytes paths."""

    backend_name = "truss"
    description = "FreeBSD syscall tracer; not yet validated on a real BSD host"
    output_channel = OutputChannel.FIFO

    @staticmethod
    def is_available() -> bool:
        """Check if the truss executable is available (FreeBSD/Solaris)."""
        return shutil.which("truss") is not None

    def build_command(
        self,
        output_path: str | None,
        attach_pids: list[int] | None,
        run_command: list[str] | None,
    ) -> list[str] | None:
        truss_path = shutil.which("truss")
        if not truss_path:
            log.error("Could not find 'truss' executable.")
            return None

        # truss has no syscall filter; it traces everything and we filter while
        # dispatching. -f follows children, -o writes the trace to our FIFO.
        argv = [truss_path, "-f", "-s", "4096", "-o", output_path]

        if attach_pids:
            valid = [p for p in attach_pids if p > 0]
            if not valid:
                log.error("No valid PIDs provided to attach to.")
                return None
            # truss -p attaches to a single process (it will still follow forks).
            if len(valid) > 1:
                log.warning(
                    f"truss attaches to one PID; using {valid[0]}, ignoring {valid[1:]}."
                )
            argv += ["-p", str(valid[0])]
        else:
            argv += list(run_command)
        return argv

    async def process_lines(
        self, lines: AsyncIterator[bytes], attach_ids: list[int] | None
    ) -> None:
        initial_pids: set[int] = set(attach_ids or [])
        cwd_map: dict[int, bytes] = {}
        # Run mode: the command inherits our launch directory; use it as the CWD
        # fallback for relative paths from processes we can't look up.
        default_cwd = None if attach_ids else os.fsencode(os.getcwd())
        for pid in initial_pids:
            cwd = pid_get_cwd(pid)
            if cwd:
                cwd_map[pid] = cwd
            else:
                log.warning(f"Could not get initial CWD for attached PID {pid}.")

        processed = 0
        async for raw_line in lines:
            if self.should_stop:
                break
            line = raw_line.decode("utf-8", "surrogateescape")
            event = parse_truss_line(line, time.time())
            if event is None:
                continue
            processed += 1
            await process_syscall_event(
                event, self.monitor, cwd_map, initial_pids, default_cwd
            )
            await asyncio.sleep(0)  # Yield control for UI responsiveness.
        log.info(f"Truss event processing finished. Processed {processed} events.")

# Filename: src/lsoph/backend/dtruss/backend.py
"""
macOS/BSD dtruss backend, built on the shared TracerBackend pipeline.

dtruss is a DTrace script (strace-equivalent) shipped on macOS and available on
DTrace platforms. It is syscall-level with strace-compatible argument positions,
so it reuses the shared syscall dispatch and handlers -- only the line parser
differs.

is_available() returns False where dtruss isn't installed. Built against the
documented dtruss output format (verified against the dtruss source), but NOT
yet smoke-tested on a real macOS/DTrace host.

Runtime notes to validate on a real host:
  - Needs root (`sudo`); on macOS, System Integrity Protection restricts DTrace
    and may block it entirely.
  - -f follows children and enables the "<pid>/0x<tid>:" line prefix, giving the
    real PID (unlike fs_usage).
  - dtruss writes its trace to stderr; the traced program's own stderr can mingle
    with it (those lines simply don't parse and are skipped).
"""

import asyncio
import logging
import os
import shlex
import shutil
import tempfile
import time
from collections.abc import AsyncIterator

from ..syscall_dispatch import process_syscall_event
from ..tracer import OutputChannel, TracerBackend
from .parse import parse_dtruss_line

log = logging.getLogger(__name__)


class Dtruss(TracerBackend):
    """Async backend driving macOS/BSD `dtruss`. Works with bytes paths."""

    backend_name = "dtruss"
    description = (
        "dtrace tracer (macOS/BSD); needs root; not yet validated on real host"
    )
    # dtruss writes its trace stream to stderr (via dtrace -o /dev/stderr).
    output_channel = OutputChannel.STDERR

    def __init__(self, monitor):
        super().__init__(monitor)
        self._wrapper: str | None = None  # see _run_argv

    @staticmethod
    def is_available() -> bool:
        """Check if the dtruss executable is available (macOS / DTrace hosts)."""
        return shutil.which("dtruss") is not None

    def build_command(
        self,
        output_path: str | None,
        attach_pids: list[int] | None,
        run_command: list[str] | None,
    ) -> list[str] | None:
        dtruss = shutil.which("dtruss")
        if not dtruss:
            log.error("Could not find 'dtruss' executable.")
            return None

        # -f follows children and turns on the "<pid>/0x<tid>:" line prefix.
        argv = [dtruss, "-f"]

        if attach_pids:
            valid = [p for p in attach_pids if p > 0]
            if not valid:
                log.error("No valid PIDs provided to attach to.")
                return None
            # dtruss -p attaches to a single process (it still follows forks).
            if len(valid) > 1:
                log.warning(
                    f"dtruss attaches to one PID; using {valid[0]}, ignoring {valid[1:]}."
                )
            argv += ["-p", str(valid[0])]
        else:
            argv += self._run_argv(run_command)
        return argv

    def _run_argv(self, command: list[str]) -> list[str]:
        """dtruss hands the command to dtrace -c as one string, which dtrace
        splits on whitespace: an argument with spaces or quotes would come out
        mangled. Such commands run via an exec wrapper script instead."""
        if all(arg and shlex.quote(arg) == arg for arg in command):
            return list(command)
        fd, self._wrapper = tempfile.mkstemp(prefix="lsoph_dtruss_", suffix=".sh")
        with os.fdopen(fd, "w") as script:
            script.write(f"#!/bin/sh\nexec {shlex.join(command)}\n")
        os.chmod(self._wrapper, 0o700)
        return [self._wrapper]

    async def _run(self, attach_pids, run_command):
        try:
            await super()._run(attach_pids, run_command)
        finally:
            if self._wrapper:
                os.unlink(self._wrapper)
                self._wrapper = None

    async def process_lines(
        self, lines: AsyncIterator[bytes], attach_ids: list[int] | None
    ) -> None:
        initial_pids: set[int] = set(attach_ids or [])
        # dtruss reports absolute paths, but keep a CWD fallback (our launch dir in
        # run mode) for consistency with the other tracers.
        cwd_map: dict[int, bytes] = {}
        default_cwd = None if attach_ids else os.fsencode(os.getcwd())

        processed = 0
        async for raw_line in lines:
            if self.should_stop:
                break
            line = raw_line.decode("utf-8", "surrogateescape")
            event = parse_dtruss_line(line, time.time())
            if event is None:
                continue
            processed += 1
            await process_syscall_event(
                event, self.monitor, cwd_map, initial_pids, default_cwd
            )
            await asyncio.sleep(0)  # Yield control for UI responsiveness.
        log.info(f"dtruss event processing finished. Processed {processed} events.")

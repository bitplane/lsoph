# Filename: src/lsoph/backend/ktrace/backend.py
"""
BSD ktrace/kdump backend, built on the shared TracerBackend pipeline.

ktrace/kdump is a two-process tracer: `ktrace` enables kernel tracing and writes
binary records to a file, and `kdump -l` tails that file and decodes it to text
on stdout. We run both and read kdump's stdout (which TracerBackend handles as an
ordinary STDOUT tracer); ktrace is spawned/torn down around it.

is_available() requires both executables, so it is offered only on BSD hosts.
Built against the documented kdump format (FreeBSD) and unit-tested via the
parser, but NOT yet smoke-tested on a real BSD host. Notes to validate there:
  - Needs privilege to trace processes you don't own.
  - The trace file grows for the monitored duration (a temp file, cleaned up).
  - OpenBSD/NetBSD kdump output differs slightly from FreeBSD's.
  - A multithreaded process can interleave CALL/RET for one PID and confuse the
    per-PID correlation (kdump -H thread ids would be needed to disambiguate).
"""

import asyncio
import logging
import os
import shutil
import tempfile
import time
from collections.abc import AsyncIterator

from ..syscall_dispatch import process_syscall_event
from ..tracer import OutputChannel, TracerBackend
from .parse import KdumpParser

log = logging.getLogger(__name__)

# ktrace trace points: c = system calls (CALL/RET), n = namei (NAMI paths).
KTRACE_POINTS = "cn"


class Ktrace(TracerBackend):
    """Async backend driving BSD `ktrace` + `kdump`. Works with bytes paths."""

    backend_name = "ktrace"
    description = "BSD ktrace+kdump tracer; not yet validated on a real BSD host"
    # We read kdump's decoded text from its stdout.
    output_channel = OutputChannel.STDOUT

    def __init__(self, monitor):
        super().__init__(monitor)
        self._tracefile: str | None = None
        self._run_proc: asyncio.subprocess.Process | None = None

    @staticmethod
    def is_available() -> bool:
        """Check that both ktrace and kdump are available (BSD hosts)."""
        return shutil.which("ktrace") is not None and shutil.which("kdump") is not None

    def build_command(
        self,
        output_path: str | None,
        attach_pids: list[int] | None,
        run_command: list[str] | None,
    ) -> list[str] | None:
        # The tracer subprocess is kdump, tailing the trace file ktrace writes.
        kdump = shutil.which("kdump")
        if not kdump or not self._tracefile:
            return None
        argv = [kdump, "-l", "-f", self._tracefile]
        # kdump -p filters a single PID; only useful for single-PID attach.
        if attach_pids and len(attach_pids) == 1:
            argv += ["-p", str(attach_pids[0])]
        return argv

    async def _run(self, attach_pids, run_command):
        fd, self._tracefile = tempfile.mkstemp(prefix="lsoph_ktrace_", suffix=".out")
        os.close(fd)
        try:
            if attach_pids:
                if not await self._enable_attach(attach_pids):
                    return
            else:
                if not await self._spawn_run(run_command):
                    return
            # Run kdump (STDOUT tracer) reading the trace file.
            await self._launch(None, attach_pids, run_command)
        finally:
            if attach_pids:
                await self._disable_attach(attach_pids)
            await self._terminate_run_proc()
            self._remove_tracefile()

    async def _enable_attach(self, pids: list[int]) -> bool:
        """Enable ktrace on each PID (ktrace exits; the kernel keeps tracing)."""
        ktrace = shutil.which("ktrace")
        enabled = False
        for pid in pids:
            if pid <= 0:
                continue
            rc = await self._run_to_completion(
                [
                    ktrace,
                    "-i",
                    "-t",
                    KTRACE_POINTS,
                    "-f",
                    self._tracefile,
                    "-p",
                    str(pid),
                ]
            )
            if rc == 0:
                enabled = True
            else:
                log.error(f"ktrace failed to attach to PID {pid} (exit {rc}).")
        return enabled

    async def _disable_attach(self, pids: list[int]):
        """Clear ktrace on the attached PIDs."""
        ktrace = shutil.which("ktrace")
        for pid in pids:
            if pid > 0:
                await self._run_to_completion([ktrace, "-c", "-p", str(pid)])

    async def _spawn_run(self, command: list[str]) -> bool:
        """Run the command under ktrace; it stays alive as the traced process."""
        ktrace = shutil.which("ktrace")
        argv = [ktrace, "-i", "-t", KTRACE_POINTS, "-f", self._tracefile, *command]
        try:
            # Own session (process-group leader) so _terminate can signal the
            # whole traced tree; matches how the shared base spawns processes.
            self._run_proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
        except (FileNotFoundError, OSError) as e:
            log.error(f"Failed to launch ktrace command: {e}")
            return False

        async def _stop_when_target_exits():
            await self._run_proc.wait()
            log.info("Traced command exited; stopping ktrace backend.")
            await self.stop()

        asyncio.create_task(_stop_when_target_exits(), name="ktrace_target_watch")
        return True

    async def process_lines(
        self, lines: AsyncIterator[bytes], attach_ids: list[int] | None
    ) -> None:
        parser = KdumpParser()
        cwd_map: dict[int, bytes] = {}
        initial_pids: set[int] = set(attach_ids or [])
        # Run mode: fall back to our launch directory for relative paths.
        default_cwd = None if attach_ids else os.fsencode(os.getcwd())

        processed = 0
        async for raw_line in lines:
            if self.should_stop:
                break
            line = raw_line.decode("utf-8", "surrogateescape")
            event = parser.feed(line, time.time())
            if event is None:
                continue
            processed += 1
            await process_syscall_event(
                event, self.monitor, cwd_map, initial_pids, default_cwd
            )
            await asyncio.sleep(0)  # Yield control for UI responsiveness.
        log.info(f"kdump event processing finished. Processed {processed} events.")

    # --- helpers ---

    async def _run_to_completion(self, argv: list[str]) -> int | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except (FileNotFoundError, OSError) as e:
            log.error(f"Failed to run {argv[0]}: {e}")
            return None
        return await proc.wait()

    async def _terminate_run_proc(self):
        # Reuse the shared group SIGTERM -> SIGKILL ladder so the traced tree is
        # torn down the same way everywhere.
        await self._terminate(self._run_proc)
        self._run_proc = None

    def _remove_tracefile(self):
        if self._tracefile:
            try:
                os.remove(self._tracefile)
            except OSError:
                pass
            self._tracefile = None

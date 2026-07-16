# Filename: src/lsoph/backend/fsusage/backend.py
"""
macOS fs_usage backend, built on the shared TracerBackend pipeline.

fs_usage is macOS-only and needs root, so is_available() returns False elsewhere
and it isn't offered. Built against the documented fs_usage output format and
unit-tested against it, but NOT yet smoke-tested on a real macOS host.

Limitations (inherent to fs_usage, to validate on a real Mac):
  - Needs root (`sudo`); without it fs_usage errors at runtime.
  - It does not follow forks, so only the given PIDs are watched.
  - `-w` prints a thread id, not a pid, so file state is keyed by thread; a file
    whose open and later read/close happen on different threads won't correlate.
  - Run mode launches the command and then attaches, so it can miss the earliest
    events (dylib loads at startup).
"""

import asyncio
import logging
import shutil
import time
from collections.abc import AsyncIterator

from lsoph.monitor import Monitor

from ..tracer import OutputChannel, TracerBackend
from .parse import FsEvent, parse_fsusage_line

log = logging.getLogger(__name__)


class Fsusage(TracerBackend):
    """Async backend driving macOS `fs_usage`. Works with bytes paths."""

    backend_name = "fsusage"
    output_channel = OutputChannel.STDOUT

    @staticmethod
    def is_available() -> bool:
        """Check if the fs_usage executable is available (macOS)."""
        return shutil.which("fs_usage") is not None

    def build_command(
        self,
        output_path: str | None,
        attach_pids: list[int] | None,
        run_command: list[str] | None,
    ) -> list[str] | None:
        fs_usage = shutil.which("fs_usage")
        if not fs_usage:
            log.error("Could not find 'fs_usage' executable.")
            return None

        # -w: wide output (full paths); -f filesys: filesystem events only.
        # fs_usage cannot launch a command, so only attach_pids is used here;
        # run mode is handled by run_command below.
        argv = [fs_usage, "-w", "-f", "filesys"]
        pids = attach_pids or []
        valid = [p for p in pids if p > 0]
        if not valid:
            log.error("fs_usage backend requires at least one PID to watch.")
            return None
        argv += [str(p) for p in valid]
        return argv

    async def run_command(self, command: list[str]):
        """Launch `command`, then attach fs_usage to its PID.

        fs_usage cannot exec the target itself, so we start it and watch its PID;
        early startup events may be missed.
        """
        if not command:
            log.error("Fsusage.run_command called with empty command.")
            return

        # Own session (process-group leader) so _terminate can tear down the
        # whole tree; matches how the shared base spawns processes.
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
        except (FileNotFoundError, OSError) as e:
            log.error(f"Failed to launch command {command[0]}: {e}")
            return
        log.info(f"Launched command PID {process.pid}; attaching fs_usage.")

        async def _stop_when_target_exits():
            await process.wait()
            log.info(f"Traced command {process.pid} exited; stopping fs_usage.")
            await self.stop()

        watcher = asyncio.create_task(_stop_when_target_exits())
        try:
            await self.attach([process.pid])
        finally:
            watcher.cancel()
            await self._terminate(process)  # shared group SIGTERM -> SIGKILL

    async def process_lines(
        self, lines: AsyncIterator[bytes], attach_ids: list[int] | None
    ) -> None:
        processed = 0
        async for raw_line in lines:
            if self.should_stop:
                break
            line = raw_line.decode("utf-8", "surrogateescape")
            event = parse_fsusage_line(line)
            if event is None:
                continue
            try:
                self._apply(event, self.monitor)
            except KeyError:
                log.debug(f"fs_usage: fd not mapped for {event.op} (tid {event.tid})")
            processed += 1
            await asyncio.sleep(0)  # Yield control for UI responsiveness.
        log.info(f"fs_usage event processing finished. Processed {processed} events.")

    def _apply(self, ev: FsEvent, monitor: Monitor) -> None:
        """Apply one parsed fs_usage event to the Monitor (thread id as the key)."""
        ts = time.time()
        details = {"source": "fs_usage"}
        if ev.error_name:
            details["error_name"] = ev.error_name

        if ev.op == "open":
            if ev.path is None:
                return
            fd = ev.fd if ev.fd is not None else -1
            monitor.open(ev.tid, ev.path, fd, ev.success, ts, **details)
        elif ev.op == "close":
            if ev.fd is not None:
                monitor.close(ev.tid, ev.fd, ev.success, ts, **details)
        elif ev.op == "read":
            if ev.fd is not None:
                monitor.read(
                    ev.tid, ev.fd, None, ev.success, ts, bytes=ev.byte_count, **details
                )
        elif ev.op == "write":
            if ev.fd is not None:
                monitor.write(
                    ev.tid, ev.fd, None, ev.success, ts, bytes=ev.byte_count, **details
                )
        elif ev.op == "stat":
            if ev.path is not None:
                monitor.stat(ev.tid, ev.path, ev.success, ts, **details)
        elif ev.op == "delete":
            if ev.path is not None:
                monitor.delete(ev.tid, ev.path, ev.success, ts, **details)

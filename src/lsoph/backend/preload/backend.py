# Filename: src/lsoph/backend/preload/backend.py
"""
LD_PRELOAD shim backend.

Runs a command with a small C shim (compiled on demand) preloaded; the shim
interposes libc file calls and writes tab-separated records to a FIFO we read.
No privilege required. is_available() is "a C compiler is present" -- the shim
is compiled from the shipped shim.c on first use and cached, so lsoph stays a
pure-Python package.

Run mode only: LD_PRELOAD affects newly-launched, dynamically-linked, non-setuid
programs that use libc for file access. Static/setuid binaries and raw-syscall
programs (e.g. Go) are not covered; attach mode is impossible.
"""

import asyncio
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path

from platformdirs import user_cache_dir

from lsoph.util.pid import get_cwd as pid_get_cwd

from ..tracer import OutputChannel, TracerBackend

log = logging.getLogger(__name__)

_SHIM_SRC = Path(__file__).with_name("shim.c")
_COMPILERS = ("cc", "gcc", "clang")

_ERRNO_NAMES = {
    2: "ENOENT",
    9: "EBADF",
    13: "EACCES",
    17: "EEXIST",
    20: "ENOTDIR",
    21: "EISDIR",
    22: "EINVAL",
    36: "ENAMETOOLONG",
}


def _find_compiler() -> str | None:
    for name in _COMPILERS:
        found = shutil.which(name)
        if found:
            return found
    return None


def _compile_shim() -> str | None:
    """Compile shim.c to a cached shared object, returning its path (or None)."""
    compiler = _find_compiler()
    if not compiler or not _SHIM_SRC.is_file():
        return None

    # Per-user cache dir: a shared /tmp would collide (or hand us a .so we
    # didn't compile) on multi-user machines.
    # Keyed on the source hash, not mtimes: installed files keep their build
    # time, so an upgrade would otherwise keep running an older cached shim.
    digest = hashlib.sha256(_SHIM_SRC.read_bytes()).hexdigest()[:16]
    so_path = Path(user_cache_dir("lsoph")) / f"preload-{digest}.so"
    if so_path.is_file():
        return str(so_path)
    so_path.parent.mkdir(parents=True, exist_ok=True)

    # Build to a private name and rename into place, so a concurrent lsoph
    # never preloads a half-written object.
    tmp_path = so_path.with_name(f"{so_path.name}.{os.getpid()}.tmp")
    cmd = [
        compiler,
        "-shared",
        "-fPIC",
        "-O2",
        str(_SHIM_SRC),
        "-o",
        str(tmp_path),
        "-ldl",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        log.error(f"Failed to run compiler for preload shim: {e}")
        return None
    if result.returncode != 0:
        log.error(f"Failed to compile preload shim:\n{result.stderr}")
        tmp_path.unlink(missing_ok=True)
        return None
    os.replace(tmp_path, so_path)
    return str(so_path)


class Preload(TracerBackend):
    """Run a command under an LD_PRELOAD shim that reports file access."""

    backend_name = "preload"
    description = "LD_PRELOAD shim; run mode only; blind to static/raw-syscall programs"
    output_channel = OutputChannel.FIFO

    def __init__(self, monitor):
        super().__init__(monitor)
        self._shim_path: str | None = None

    @staticmethod
    def is_available() -> bool:
        """Available on LD_PRELOAD platforms (not macOS/Windows), with a compiler
        and the shipped shim source."""
        if sys.platform in ("darwin", "win32"):
            return False  # macOS uses DYLD_INSERT_LIBRARIES; Windows has no equivalent
        return _SHIM_SRC.is_file() and _find_compiler() is not None

    async def attach(self, pids: list[int]):
        log.error(
            "preload backend supports run mode only "
            "(LD_PRELOAD cannot attach to a running process)."
        )

    def build_command(
        self,
        output_path: str | None,
        attach_pids: list[int] | None,
        run_command: list[str] | None,
    ) -> list[str] | None:
        if not run_command:
            return None
        self._shim_path = _compile_shim()
        if not self._shim_path:
            log.error("Could not build the preload shim (no compiler?).")
            return None
        return list(run_command)  # we launch the command itself, shim preloaded

    def build_env(self, output_path: str | None) -> dict[str, str] | None:
        # The shim opens $LSOPH_PIPE and writes records there.
        preload = self._shim_path or ""
        existing = os.environ.get("LD_PRELOAD")
        if existing:
            preload = f"{preload} {existing}"
        return {"LD_PRELOAD": preload, "LSOPH_PIPE": output_path or ""}

    async def process_lines(
        self, lines: AsyncIterator[bytes], attach_ids: list[int] | None
    ) -> None:
        processed = 0
        async for raw_line in lines:
            if self.should_stop:
                break
            parts = raw_line.split(b"\t")
            if len(parts) < 6:
                continue
            try:
                self._apply(parts)
            except (ValueError, KeyError):
                continue
            processed += 1
            await asyncio.sleep(0)  # Yield control for UI responsiveness.
        log.info(f"preload event processing finished. Processed {processed} events.")

    def _apply(self, parts: list[bytes]) -> None:
        op = parts[0]
        pid = int(parts[1])
        fd = int(parts[2])
        ret = int(parts[3])
        err = int(parts[4])
        path = parts[5]
        path2 = parts[6] if len(parts) > 6 else None

        ts = time.time()
        success = err == 0
        details = {"source": "preload"}
        if err:
            details["error_name"] = _ERRNO_NAMES.get(err, f"ERR#{err}")

        if op == b"OPEN":
            if not path:
                return
            fd_val = ret if success and ret >= 0 else -1
            self.monitor.open(
                pid, self._resolve(pid, path), fd_val, success, ts, **details
            )
        elif op == b"CLOSE":
            self.monitor.close(pid, fd, success, ts, **details)
        elif op == b"READ":
            self.monitor.read(pid, fd, None, success, ts, bytes=max(ret, 0), **details)
        elif op == b"WRITE":
            self.monitor.write(pid, fd, None, success, ts, bytes=max(ret, 0), **details)
        elif op == b"STAT":
            if path:
                self.monitor.stat(pid, self._resolve(pid, path), success, ts, **details)
        elif op == b"UNLINK":
            if path:
                self.monitor.delete(
                    pid, self._resolve(pid, path), success, ts, **details
                )
        elif op == b"RENAME":
            if path and path2:
                self.monitor.rename(
                    pid,
                    self._resolve(pid, path),
                    self._resolve(pid, path2),
                    success,
                    ts,
                    **details,
                )

    @staticmethod
    def _resolve(pid: int, path: bytes) -> bytes:
        """Make a path absolute (bytes). Relative paths resolve against the
        process's CWD, falling back to our launch directory (which the traced
        command inherits in run mode) if the process is already gone."""
        if os.path.isabs(path):
            return os.path.normpath(path)
        cwd = pid_get_cwd(pid) or os.fsencode(os.getcwd())
        return os.path.normpath(os.path.join(cwd, path))

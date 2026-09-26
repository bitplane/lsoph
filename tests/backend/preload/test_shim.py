"""Behaviour of the compiled LD_PRELOAD shim itself, observed from a small C
program run under it (no lsoph reader attached)."""

import errno
import os
import subprocess

import pytest

from lsoph.backend.preload.backend import Preload, _compile_shim, _find_compiler

pytestmark = pytest.mark.skipif(
    not Preload.is_available(),
    reason="preload backend unavailable (no compiler / wrong OS)",
)


def _run_under_shim(tmp_path, c_source: str, env=None) -> subprocess.CompletedProcess:
    src = tmp_path / "prog.c"
    exe = tmp_path / "prog"
    src.write_text(c_source)
    subprocess.run([_find_compiler(), str(src), "-o", str(exe)], check=True)
    return subprocess.run(
        [str(exe)],
        env={**os.environ, "LD_PRELOAD": _compile_shim(), **(env or {})},
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_successful_calls_leave_errno_alone(tmp_path):
    """POSIX: a successful call must not zero errno set by an earlier failure."""
    result = _run_under_shim(
        tmp_path,
        r"""
        #include <errno.h>
        #include <fcntl.h>
        #include <stdio.h>
        #include <unistd.h>
        int main(void) {
            if (open("/nonexistent/lsoph", O_RDONLY) >= 0) return 2;
            write(1, "", 0);
            close(open("/dev/null", O_RDONLY));
            printf("%d\n", errno);
            return 0;
        }
        """,
    )
    assert result.stdout.strip() == str(errno.ENOENT)

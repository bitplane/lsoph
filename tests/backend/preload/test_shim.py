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


_CLOSE_ALL_THEN_WRITE = r"""
    #include <fcntl.h>
    #include <string.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    int main(int argc, char **argv) {
        for (int fd = 3; fd < 1024; fd++)
            RAW ? syscall(SYS_close, fd) : close(fd);
        int fd = open(argv[0], O_WRONLY | O_TRUNC);
        write(fd, "DATA", 4);
        close(fd);
        return 0;
    }
"""


@pytest.mark.parametrize("raw", [False, True], ids=["libc-close", "raw-syscall"])
def test_program_closing_all_fds_never_receives_records(tmp_path, raw):
    """A daemon-style close-all loop must not let the next file the program
    opens inherit the shim's pipe fd (records would land in that file)."""
    log_file = tmp_path / "records"
    log_file.write_text("")
    victim = tmp_path / "victim"
    source = _CLOSE_ALL_THEN_WRITE.replace("RAW", "1" if raw else "0")
    source = source.replace("argv[0]", f'"{victim}"')
    victim.write_text("")

    result = _run_under_shim(tmp_path, source, env={"LSOPH_PIPE": str(log_file)})

    assert result.returncode == 0
    assert victim.read_text() == "DATA"
    if not raw:
        # A libc close() of our fd is ignored, so tracing carries on.
        assert f"\t{victim}" in log_file.read_text()

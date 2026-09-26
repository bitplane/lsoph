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


def test_records_escape_separators_and_drop_oversized_paths(tmp_path):
    """A tab/newline/backslash in a path can't split or corrupt a record, and
    a path too long for one atomic write is dropped rather than cut short."""
    from lsoph.backend.preload.backend import _unescape

    log_file = tmp_path / "records"
    log_file.write_text("")
    odd = tmp_path / "a\tb\nc\\d"
    result = _run_under_shim(
        tmp_path,
        rf"""
        #include <fcntl.h>
        #include <string.h>
        #include <unistd.h>
        int main(void) {{
            char longpath[6000];
            memset(longpath, 'x', sizeof longpath - 1);
            longpath[0] = '/';
            longpath[sizeof longpath - 1] = 0;
            open(longpath, O_RDONLY);
            close(open("{str(odd).encode("unicode_escape").decode()}",
                       O_WRONLY | O_CREAT, 0600));
            return 0;
        }}
        """,
        env={"LSOPH_PIPE": str(log_file)},
    )
    assert result.returncode == 0

    records = log_file.read_bytes().splitlines()
    opens = [r.split(b"\t") for r in records if r.startswith(b"OPEN\t")]
    assert [_unescape(r[5]) for r in opens] == [bytes(odd)]
    assert all(len(r) < 4096 for r in records)


def test_o_tmpfile_gets_the_requested_mode(tmp_path):
    result = _run_under_shim(
        tmp_path,
        rf"""
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <stdio.h>
        #include <sys/stat.h>
        int main(void) {{
            int fd = open("{tmp_path}", O_TMPFILE | O_RDWR, 0640);
            struct stat st;
            if (fd < 0 || fstat(fd, &st) != 0) return 2;
            printf("%o\n", st.st_mode & 0777);
            return 0;
        }}
        """,
    )
    assert result.stdout.strip() == "640"


def test_program_survives_lsoph_closing_the_fifo(tmp_path):
    """If lsoph goes away first, the program's next record must not kill it
    with SIGPIPE."""
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    src, exe = tmp_path / "prog.c", tmp_path / "prog"
    src.write_text(
        r"""
        #include <fcntl.h>
        #include <unistd.h>
        int main(void) {
            usleep(300000);  /* lsoph closes the read end meanwhile */
            for (int i = 0; i < 10; i++)
                close(open("/dev/null", O_RDONLY));
            return 0;
        }
        """
    )
    subprocess.run([_find_compiler(), str(src), "-o", str(exe)], check=True)
    proc = subprocess.Popen(
        [str(exe)],
        env={**os.environ, "LD_PRELOAD": _compile_shim(), "LSOPH_PIPE": str(fifo)},
    )
    os.close(os.open(fifo, os.O_RDONLY))  # unblocks the shim, then goes away

    assert proc.wait(timeout=10) == 0


def test_relative_paths_are_recorded_absolute_as_of_the_call(tmp_path):
    """openat(dirfd, ...) and a relative open before a chdir must record the
    path they actually opened, not one joined to a later cwd."""
    from lsoph.backend.preload.backend import _unescape

    log_file = tmp_path / "records"
    log_file.write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x").write_text("")
    (tmp_path / "y").write_text("")
    result = _run_under_shim(
        tmp_path,
        rf"""
        #include <fcntl.h>
        #include <unistd.h>
        int main(void) {{
            chdir("{tmp_path}");
            int dir = open("sub", O_RDONLY | O_DIRECTORY);
            close(openat(dir, "x", O_RDONLY));
            close(open("y", O_RDONLY));
            chdir("/");
            return 0;
        }}
        """,
        env={"LSOPH_PIPE": str(log_file)},
    )
    assert result.returncode == 0

    opened = [
        _unescape(r.split(b"\t")[5])
        for r in log_file.read_bytes().splitlines()
        if r.startswith(b"OPEN\t")
    ]
    assert opened[-3:] == [
        bytes(tmp_path / "sub"),
        bytes(tmp_path / "sub" / "x"),
        bytes(tmp_path / "y"),
    ]


def _opens_and_closes(log_file):
    records = [r.split(b"\t") for r in log_file.read_bytes().splitlines()]
    return [(r[0], r[2], r[5]) for r in records if r[0] in (b"OPEN", b"CLOSE")]


def test_stdio_and_fortified_opens_are_recorded(tmp_path):
    """fopen/fclose and _FORTIFY_SOURCE's __open_2 bypass the plain wrappers."""
    log_file = tmp_path / "records"
    log_file.write_text("")
    target = tmp_path / "t"
    target.write_text("x")
    result = _run_under_shim(
        tmp_path,
        rf"""
        #include <fcntl.h>
        #include <stdio.h>
        #include <unistd.h>
        int __open_2(const char *, int);
        int main(void) {{
            FILE *f = fopen("{target}", "r");
            int fd = fileno(f);
            fclose(f);
            close(__open_2("{target}", O_RDONLY));
            return fd < 0;
        }}
        """,
        env={"LSOPH_PIPE": str(log_file)},
    )
    assert result.returncode == 0

    events = _opens_and_closes(log_file)
    opens = [
        i for i, e in enumerate(events) if e[:1] + e[2:] == (b"OPEN", bytes(target))
    ]
    assert len(opens) == 2  # fopen, __open_2
    for i in opens:
        fd = events[i][1]
        assert (b"CLOSE", fd) in [e[:2] for e in events[i + 1 :]]


def test_at_and_64_bit_path_calls_are_recorded(tmp_path):
    """glibc >= 2.33 programs call stat64/fstatat/statx/unlinkat/renameat
    directly; each must produce a record with the resolved path."""
    from lsoph.backend.preload.backend import _unescape

    log_file = tmp_path / "records"
    log_file.write_text("")
    for name in ("a", "b", "c"):
        (tmp_path / name).write_text("")
    result = _run_under_shim(
        tmp_path,
        rf"""
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <stdio.h>
        #include <sys/stat.h>
        #include <unistd.h>
        int main(void) {{
            struct stat st;
            struct stat64 st64;
            struct statx stx;
            int dir = open("{tmp_path}", O_RDONLY | O_DIRECTORY);
            stat64("{tmp_path}/a", &st64);
            fstatat(dir, "a", &st, 0);
            statx(dir, "b", 0, STATX_BASIC_STATS, &stx);
            renameat(dir, "b", dir, "b2");
            unlinkat(dir, "c", 0);
            return 0;
        }}
        """,
        env={"LSOPH_PIPE": str(log_file)},
    )
    assert result.returncode == 0

    records = [r.split(b"\t") for r in log_file.read_bytes().splitlines()]
    seen = [
        (r[0], *(_unescape(p) for p in r[5:]))
        for r in records
        if r[0] in (b"STAT", b"RENAME", b"UNLINK") and r[5].startswith(bytes(tmp_path))
    ]
    t = bytes(tmp_path)
    assert seen == [
        (b"STAT", t + b"/a"),
        (b"STAT", t + b"/a"),
        (b"STAT", t + b"/b"),
        (b"RENAME", t + b"/b", t + b"/b2"),
        (b"UNLINK", t + b"/c"),
    ]


def test_positional_and_vectored_io_is_recorded(tmp_path):
    log_file = tmp_path / "records"
    log_file.write_text("")
    target = tmp_path / "t"
    target.write_text("0123456789")
    result = _run_under_shim(
        tmp_path,
        rf"""
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <sys/uio.h>
        #include <unistd.h>
        int main(void) {{
            char buf[4];
            struct iovec iov = {{buf, 3}};
            int fd = open("{target}", O_RDWR);
            pread(fd, buf, 2, 0);
            pwrite(fd, "ab", 2, 0);
            readv(fd, &iov, 1);
            writev(fd, &iov, 1);
            return 0;
        }}
        """,
        env={"LSOPH_PIPE": str(log_file)},
    )
    assert result.returncode == 0

    records = [r.split(b"\t") for r in log_file.read_bytes().splitlines()]
    fd = next(r[2] for r in records if r[0] == b"OPEN" and r[5] == bytes(target))
    io = [
        (r[0], int(r[3])) for r in records if r[0] in (b"READ", b"WRITE") and r[2] == fd
    ]
    assert io == [(b"READ", 2), (b"WRITE", 2), (b"READ", 3), (b"WRITE", 3)]


def test_dup_family_tracks_fds_through_the_monitor(tmp_path):
    """dup'd fds keep the file open; dup2 over an open fd closes its file."""
    import asyncio

    from lsoph.monitor import Monitor

    log_file = tmp_path / "records"
    log_file.write_text("")
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_text("")
    b.write_text("")
    result = _run_under_shim(
        tmp_path,
        rf"""
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <unistd.h>
        int main(void) {{
            int fa = open("{a}", O_RDONLY);
            int fa2 = dup(fa);
            int fb = open("{b}", O_RDONLY);
            dup2(fa, fb);  /* b is closed, fb now refers to a */
            close(fa);
            close(fa2);
            return 0;  /* fb is left open */
        }}
        """,
        env={"LSOPH_PIPE": str(log_file)},
    )
    assert result.returncode == 0

    monitor = Monitor(identifier="t")

    async def feed():
        async def lines():
            for line in log_file.read_bytes().splitlines():
                yield line

        await Preload(monitor).process_lines(lines(), None)

    asyncio.run(feed())

    assert monitor.files[bytes(b)].status == "closed"
    info_a = monitor.files[bytes(a)]
    assert info_a.is_open  # still held via the dup2'd fd
    assert sum(len(fds) for fds in info_a.open_by_pids.values()) == 1

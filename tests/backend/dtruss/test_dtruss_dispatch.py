"""End-to-end-minus-subprocess test for the dtruss backend: feed documented
dtruss lines through Dtruss.process_lines and check the resulting Monitor state.
Exercises parse + the shared syscall dispatch without needing macOS/DTrace.
"""

import asyncio
import os
import subprocess

import lsoph.backend.dtruss.backend as dtruss_backend
from lsoph.backend.dtruss.backend import Dtruss
from lsoph.monitor import Monitor


def _run(lines):
    async def gen():
        for line in lines:
            yield line.encode()

    async def collect():
        monitor = Monitor(identifier="dtruss")
        backend = Dtruss(monitor)
        await backend.process_lines(gen(), attach_ids=None)
        return monitor

    return asyncio.run(collect())


def test_open_read_close_is_tracked():
    """An open/read/close run leaves the file closed with the read bytes counted."""
    monitor = _run(
        [
            r' 100/0x1:  open("/etc/hosts\0", 0x0, 0x0)		 = 3 0',
            r' 100/0x1:  read(0x3, "data", 0x80)		 = 128 0',
            r" 100/0x1:  close(0x3)		 = 0 0",
        ]
    )

    info = monitor.files[b"/etc/hosts"]
    assert info.status == "closed"
    assert info.bytes_read == 128


def test_failed_open_is_enoent_error():
    """A failed open ( = -1 Err#2) records the path as an ENOENT error."""
    monitor = _run([r' 100/0x1:  open("/nope\0", 0x0, 0x0)		 = -1 Err#2'])

    info = monitor.files[b"/nope"]
    assert info.status == "error"
    assert info.last_error_enoent is True


def test_stat_records_accessed_file():
    """stat64 records the path as accessed."""
    monitor = _run([r' 100/0x1:  stat64("/tmp/x\0", 0x0, 0x0)		 = 0 0'])

    assert monitor.files[b"/tmp/x"].status == "accessed"


def test_openat_with_hex_at_fdcwd_resolves_against_cwd(tmp_path, monkeypatch):
    """dtruss prints macOS AT_FDCWD (-2) as 0xFFFFFFFFFFFFFFFE; it means cwd."""
    monkeypatch.chdir(tmp_path)
    monitor = _run(
        [
            r' 100/0x1:  openat(0xFFFFFFFFFFFFFFFE, "rel\0", 0x0, 0x0)		 = 3 0',
        ]
    )

    assert bytes(tmp_path / "rel") in monitor.files


def test_run_command_args_with_spaces_survive_dtraces_split(monkeypatch):
    """dtrace -c splits the command on whitespace; quoting-sensitive commands
    go through an exec wrapper that preserves each argument."""
    monkeypatch.setattr(dtruss_backend.shutil, "which", lambda name: "/usr/bin/dtruss")
    backend = Dtruss(Monitor(identifier="t"))

    plain = backend.build_command(None, None, ["ls", "-l", "/tmp"])
    assert plain == ["/usr/bin/dtruss", "-f", "ls", "-l", "/tmp"]

    command = ["printf", "%s|", "a b", "it's", ""]
    argv = backend.build_command(None, None, command)
    try:
        assert argv[:2] == ["/usr/bin/dtruss", "-f"] and len(argv) == 3
        assert " " not in argv[2]  # survives dtrace's split
        out = subprocess.run([argv[2]], capture_output=True, text=True).stdout
        assert out == "a b|it's||"
    finally:
        os.unlink(argv[2])

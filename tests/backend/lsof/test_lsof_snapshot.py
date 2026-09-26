"""lsof -F output (captured from real lsof 4.99 on Linux) into poll snapshots."""

import asyncio

import lsoph.backend.lsof.helpers as lsof_helpers
from lsoph.backend.lsof.parse import _parse_lsof_f_output

REAL_OUTPUT = rb"""p4242
cpython3
fcwd
a
tDIR
n/home/me
f0
ar
tCHR
n/dev/null
f1
aw
tREG
n/tmp/out.log
f3
aw
tREG
n/tmp/dtest (deleted)
f4
ar
tFIFO
npipe
f6
au
tsock
nprotocol: TCP
f7
aw
tREG
n/tmp/bad\xffname
f8
au
tREG
n/tmp/back\\slash\ttab
""".splitlines()


def _snapshot(monkeypatch):
    async def fake_lsof(pids):
        for line in REAL_OUTPUT:
            yield line

    monkeypatch.setattr(lsof_helpers, "_run_lsof_command_async", fake_lsof)
    return asyncio.run(lsof_helpers._lsof_snapshot([4242]))[4242]


def test_access_mode_comes_from_the_a_field(monkeypatch):
    fds = _snapshot(monkeypatch).fds

    assert (fds[0].read, fds[0].write) == (True, False)
    assert (fds[1].read, fds[1].write) == (False, True)
    assert (fds[8].read, fds[8].write) == (True, True)


def test_names_are_unescaped_and_deleted_suffix_dropped(monkeypatch):
    fds = _snapshot(monkeypatch).fds

    assert fds[3].path == b"/tmp/dtest"
    assert fds[7].path == b"/tmp/bad\xffname"
    assert fds[8].path == b"/tmp/back\\slash\ttab"


def test_pipes_and_sockets_are_not_files(monkeypatch):
    files = _snapshot(monkeypatch)

    assert 4 not in files.fds
    assert 6 not in files.fds
    assert files.stats == [b"/home/me"]


def test_parser_yields_mode_per_record():
    records = list(_parse_lsof_f_output(iter(REAL_OUTPUT)))
    assert [r["mode"] for r in records][:3] == ["", "r", "w"]

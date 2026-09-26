"""The ktrace/kdump command lines the backend builds (no BSD needed)."""

import asyncio

import lsoph.backend.ktrace.backend as ktrace_backend
from lsoph.backend.ktrace.backend import Ktrace
from lsoph.monitor import Monitor


def _backend(monkeypatch):
    monkeypatch.setattr(ktrace_backend.shutil, "which", lambda name: f"/usr/bin/{name}")
    backend = Ktrace(Monitor(identifier="t"))
    backend._tracefile = "/tmp/trace.out"
    return backend


def test_kdump_shows_inherited_children_of_a_single_pid(monkeypatch):
    """No kdump -p: children traced via -i must not be filtered out."""
    argv = _backend(monkeypatch).build_command(None, [123], None)

    assert argv == ["/usr/bin/kdump", "-l", "-f", "/tmp/trace.out"]


def test_detach_clears_tracing_on_descendants(monkeypatch):
    backend = _backend(monkeypatch)
    ran = []

    async def fake_run(argv):
        ran.append(argv)
        return 0

    backend._run_to_completion = fake_run
    asyncio.run(backend._disable_attach([123]))

    assert ran == [["/usr/bin/ktrace", "-c", "-d", "-p", "123"]]

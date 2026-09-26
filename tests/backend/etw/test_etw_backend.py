"""Tests for the ETW backend's thread/loop plumbing (session faked, so these
run anywhere; the real session needs Windows)."""

import asyncio
import time

import lsoph.backend.etw.backend as etw_backend
import lsoph.backend.etw.session as etw_session
from lsoph.backend.etw.backend import Etw
from lsoph.monitor import Monitor


def test_attach_stops_cleanly_when_the_session_fails(monkeypatch):
    """A session that dies at start (no ETW, no privilege) is logged and the
    backend stops instead of hanging or spewing a raw thread traceback --
    exactly what happens under Wine, where OpenTraceW is not implemented."""

    class FailingSession:
        def __init__(self, name, on_event, want_pid=None):
            pass

        def run(self):
            raise OSError("OpenTraceW failed")

        def stop(self):
            pass

    monkeypatch.setattr(etw_session, "KernelFileSession", FailingSession)
    backend = Etw(Monitor(identifier="t"))

    asyncio.run(asyncio.wait_for(backend.attach([123]), timeout=10))

    # attach returned on its own: the dead consumer thread ended the loop.


def test_attach_dispatches_events_from_the_session_thread(monkeypatch):
    """Events emitted by the session (on its own thread) reach the monitor."""
    from lsoph.backend.etw.parse import CREATE, FileEvent

    class OneEventSession:
        def __init__(self, name, on_event, want_pid=None):
            self.on_event = on_event
            self.stopped = False

        def run(self):
            self.on_event(FileEvent(CREATE, 123, 1.0, 0xBEEF, path=rb"C:\seen"))
            while not self.stopped:  # stay alive until the backend stops us
                time.sleep(0.01)

        def stop(self):
            self.stopped = True

    monkeypatch.setattr(etw_session, "KernelFileSession", OneEventSession)
    monitor = Monitor(identifier="t")
    backend = Etw(monitor)

    async def scenario():
        attach = asyncio.create_task(backend.attach([123]))
        await asyncio.sleep(0.5)
        await backend.stop()
        await asyncio.wait_for(attach, timeout=10)

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))

    assert rb"C:\seen" in monitor.files


def test_attach_filters_unwatched_events_on_the_session_thread(monkeypatch):
    """System-wide events are discarded before entering the asyncio queue."""
    from lsoph.backend.etw.parse import CREATE, FileEvent

    class TwoEventSession:
        def __init__(self, name, on_event, want_pid=None):
            self.on_event = on_event
            self.want_pid = want_pid
            self.stopped = False

        def run(self):
            # Like the real session: consult want_pid on the header first.
            for event in (
                FileEvent(CREATE, 999, 1.0, 0xBAD, path=rb"C:\other"),
                FileEvent(CREATE, 123, 1.0, 0xBEEF, path=rb"C:\seen"),
            ):
                if self.want_pid(event.pid):
                    self.on_event(event)
            while not self.stopped:
                time.sleep(0.01)

        def stop(self):
            self.stopped = True

    dispatched = []
    monkeypatch.setattr(etw_session, "KernelFileSession", TwoEventSession)
    monkeypatch.setattr(
        etw_backend,
        "process_file_event",
        lambda event, monitor, watched: dispatched.append(event),
    )
    backend = Etw(Monitor(identifier="t"))

    async def scenario():
        attach = asyncio.create_task(backend.attach([123]))
        await asyncio.sleep(0.5)
        await backend.stop()
        await asyncio.wait_for(attach, timeout=10)

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))

    assert [event.pid for event in dispatched] == [123]

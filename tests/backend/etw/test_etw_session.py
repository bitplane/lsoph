"""KernelFileSession lifecycle against a fake advapi32 (runs anywhere)."""

import ctypes
import threading
import time

import lsoph.backend.etw.session as etw_session


class FakeAdvapi32:
    """ETW sessions as a flag: ProcessTrace blocks until the session stops."""

    def __init__(self, start_delay=0.0):
        self.start_delay = start_delay
        self.running = threading.Event()
        self.stopped = threading.Event()
        self.started = 0

    def StartTraceW(self, handle, name, props):
        time.sleep(self.start_delay)
        self.started += 1
        self.stopped.clear()
        self.running.set()
        return 0

    def ControlTraceW(self, handle, name, props, code):
        if self.running.is_set():
            self.running.clear()
            self.stopped.set()
        return 0

    def EnableTraceEx2(self, *args):
        return 0

    def OpenTraceW(self, logfile):
        return 1

    def ProcessTrace(self, handles, count, start, end):
        if self.running.is_set():
            self.stopped.wait()
        return 0

    def CloseTrace(self, handle):
        return 0


def _session(monkeypatch, fake):
    monkeypatch.setattr(etw_session, "_advapi32", lambda: fake)
    monkeypatch.setattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE, raising=False)
    return etw_session.KernelFileSession("t", lambda event: None)


def _run_in_thread(session):
    thread = threading.Thread(target=session.run, daemon=True)
    thread.start()
    return thread


def test_stop_before_run_never_starts_a_session(monkeypatch):
    fake = FakeAdvapi32()
    session = _session(monkeypatch, fake)

    session.stop()
    session.run()

    assert fake.started == 0


def test_stop_during_start_still_tears_the_session_down(monkeypatch):
    """A stop() landing while StartTraceW is in flight must not leave run()
    blocked in ProcessTrace on a session nobody will stop."""
    fake = FakeAdvapi32(start_delay=0.3)
    session = _session(monkeypatch, fake)

    thread = _run_in_thread(session)
    time.sleep(0.05)  # run() is now inside StartTraceW
    session.stop()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert not fake.running.is_set()

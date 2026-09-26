"""Regression tests for the detail-screen focus/selection wiring in LsophApp.

These guard three bugs found in the original code:
  * a handler for a non-existent DataTable.RowActivated event,
  * _ensure_table_focused calling a non-existent focused_descendant_is_widget,
  * _ensure_table_focused comparing the app to its own screen, so 'i' never fired.
"""

import asyncio
import time

from lsoph.backend.base import Backend
from lsoph.log import LogBuffer
from lsoph.monitor import Monitor
from lsoph.ui.app import LsophApp
from lsoph.ui.detail_screen import DetailScreen


class StubBackend(Backend):
    """Backend that idles until stopped, so the UI can be driven in isolation."""

    backend_name = "stub"

    @staticmethod
    def is_available() -> bool:
        return True

    async def attach(self, pids):
        await self._should_stop.wait()


def _drive(scenario):
    """Build an app with one tracked file and run `scenario(app, pilot)` under a Pilot."""

    async def _run():
        monitor = Monitor(identifier="test")
        monitor.open(
            pid=999, path=b"/tmp/example.txt", fd=3, success=True, timestamp=time.time()
        )
        app = LsophApp(
            monitor=monitor,
            log_queue=LogBuffer(maxlen=10),
            backend_instance=StubBackend(monitor),
            backend_coroutine=StubBackend(monitor).attach([999]),
        )
        async with app.run_test() as pilot:
            app._file_table.update_data(list(monitor))
            await pilot.pause()
            return await scenario(app, pilot)

    return asyncio.run(_run())


def test_pressing_i_on_focused_table_opens_detail_screen():
    """Pressing 'i' while the file table is focused shows the file's detail screen."""

    async def scenario(app, pilot):
        app._file_table.focus()
        await pilot.pause()

        await pilot.press("i")
        await pilot.pause()

        return isinstance(app.screen, DetailScreen)

    assert _drive(scenario) is True


def test_pressing_enter_on_focused_table_opens_detail_screen():
    """Selecting a row with Enter shows the detail screen (RowSelected, no RowActivated)."""

    async def scenario(app, pilot):
        app._file_table.focus()
        await pilot.pause()

        await pilot.press("enter")
        await pilot.pause()

        return isinstance(app.screen, DetailScreen)

    assert _drive(scenario) is True


def test_pressing_i_while_unfocused_does_not_open_detail_screen():
    """Pressing 'i' with nothing focused is a harmless no-op, not a crash."""

    async def scenario(app, pilot):
        app.screen.set_focus(None)
        await pilot.pause()

        await pilot.press("i")
        await pilot.pause()

        return isinstance(app.screen, DetailScreen)

    assert _drive(scenario) is False

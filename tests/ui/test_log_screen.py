"""The log buffer, its handler, and the log screen that reads it."""

import asyncio
import logging

from textual.widgets import RichLog

from lsoph.backend.base import Backend
from lsoph.log import LogBuffer, TextualLogHandler
from lsoph.monitor import Monitor
from lsoph.ui.app import LsophApp
from lsoph.ui.log_screen import LogScreen


class StubBackend(Backend):
    backend_name = "stub"

    @staticmethod
    def is_available() -> bool:
        return True

    async def attach(self, pids):
        await self._should_stop.wait()


def test_log_buffer_since_returns_only_new_lines():
    buffer = LogBuffer(maxlen=3)
    for line in "abcd":
        buffer.append(line)

    assert buffer.since(0) == (["b", "c", "d"], 4)  # oldest fell off
    assert buffer.since(3) == (["d"], 4)
    assert buffer.since(4) == ([], 4)


def test_handler_escapes_markup_in_messages():
    buffer = LogBuffer(maxlen=5)
    handler = TextualLogHandler(buffer)
    record = logging.LogRecord("x", logging.INFO, "", 0, "path [/y] [bold]", None, None)

    handler.emit(record)

    assert r"\[/y]" in buffer[0]
    assert r"\[bold]" in buffer[0]


def _log_text(app) -> list[str]:
    return [strip.text for strip in app.screen.query_one(RichLog).lines]


def test_log_screen_shows_each_line_once_and_again_on_reopen():
    async def run():
        buffer = LogBuffer(maxlen=10)
        buffer.append("line-A")
        buffer.append("line-B")
        monitor = Monitor(identifier="t")
        app = LsophApp(
            monitor=monitor,
            log_queue=buffer,
            backend_instance=StubBackend(monitor),
            backend_coroutine=StubBackend(monitor).attach([1]),
        )
        async with app.run_test() as pilot:
            app.push_screen(LogScreen(buffer))
            await pilot.pause(0.3)
            first = _log_text(app)

            app.pop_screen()
            buffer.append("line-C")
            app.push_screen(LogScreen(buffer))
            await pilot.pause(0.3)
            second = _log_text(app)
        return first, second

    first, second = asyncio.run(run())

    assert first == ["line-A", "line-B"]
    assert second == ["line-A", "line-B", "line-C"]

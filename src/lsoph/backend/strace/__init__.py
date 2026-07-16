# Filename: src/lsoph/backend/strace/__init__.py
"""Strace backend package."""

__all__ = ["Strace"]


def __getattr__(name):
    # Export Strace lazily. The shared syscall infrastructure (strace.handlers,
    # strace.syscall) is imported by backend.syscall_dispatch; loading it must
    # not eagerly import strace.backend, which imports syscall_dispatch back and
    # would form an import cycle. Deferring the Strace import here avoids that.
    if name == "Strace":
        from .backend import Strace

        return Strace
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

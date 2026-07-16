# Filename: src/lsoph/backend/__init__.py
"""
LSOPH Backend Package.
"""

import logging
from typing import Type

from .base import Backend
from .dtruss import Dtruss
from .fsusage import Fsusage
from .ktrace import Ktrace
from .lsof import Lsof
from .preload import Preload
from .psutil import Psutil
from .strace import Strace
from .truss import Truss

log = logging.getLogger("lsoph.backend")

# --- Backend Discovery ---

log.debug("Starting backend discovery...")
# Order sets the default backend (the CLI picks the first available). Prefer
# event-stream tracers over pollers, so e.g. the default is strace on Linux.
BACKENDS: dict[str, Type[Backend]] = {
    backend.__name__.lower(): backend
    for backend in (Strace, Truss, Dtruss, Ktrace, Fsusage, Preload, Psutil, Lsof)
    if backend.is_available()
}

__all__ = ["Backend", "BACKENDS"]

# Filename: src/lsoph/backend/__init__.py
"""
LSOPH Backend Package.
"""

import logging
from typing import Type

from .base import Backend
from .lsof import Lsof
from .psutil import Psutil
from .strace import Strace
from .truss import Truss

log = logging.getLogger("lsoph.backend")

# --- Backend Discovery ---

log.debug("Starting backend discovery...")
BACKENDS: dict[str, Type[Backend]] = {
    backend.__name__.lower(): backend
    for backend in (Lsof, Psutil, Strace, Truss)
    if backend.is_available()
}

__all__ = ["Backend", "BACKENDS"]

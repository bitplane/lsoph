"""Tests for the CLI's backend help: every backend states its limitations,
and --help surfaces them so users know what each backend cannot see."""

import pytest

from lsoph.backend import BACKENDS
from lsoph.backend.dtruss import Dtruss
from lsoph.backend.etw import Etw
from lsoph.backend.fsusage import Fsusage
from lsoph.backend.ktrace import Ktrace
from lsoph.backend.lsof import Lsof
from lsoph.backend.preload import Preload
from lsoph.backend.psutil import Psutil
from lsoph.backend.strace import Strace
from lsoph.backend.truss import Truss
from lsoph.cli import parse_arguments

# All backend classes, not just the ones available on this host.
ALL_BACKENDS = (Strace, Truss, Dtruss, Ktrace, Fsusage, Etw, Preload, Psutil, Lsof)


def test_every_backend_declares_a_description():
    """Each backend class states what it is and what it misses, for --help."""
    for cls in ALL_BACKENDS:
        assert cls.description, f"{cls.__name__} has no description"


def test_help_lists_each_available_backend_with_its_description(capsys):
    """--help shows one line per available backend including its limitations."""
    with pytest.raises(SystemExit):
        parse_arguments(BACKENDS, ["--help"])

    out = capsys.readouterr().out
    for name, cls in BACKENDS.items():
        assert name in out
        assert cls.description in out

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


def test_help_examples_parse(capsys):
    """Every example in --help is a valid command line (backend aside, since
    which backends exist depends on the host)."""
    with pytest.raises(SystemExit):
        parse_arguments(BACKENDS, ["--help"])
    examples = [
        line.split("#")[0].split()[1:]
        for line in capsys.readouterr().out.splitlines()
        if line.strip().startswith("lsoph ")
    ]
    assert examples

    for argv in examples:
        if "-b" in argv:
            i = argv.index("-b")
            del argv[i : i + 2]
        parse_arguments(BACKENDS, argv)


def test_log_level_is_case_insensitive():
    assert parse_arguments(BACKENDS, ["--log", "debug", "-p", "1"]).log == "DEBUG"

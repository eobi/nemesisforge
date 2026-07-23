"""P2: drcov module-relative coverage parsing + graceful degradation."""
import struct
from pathlib import Path

from forge import triage
from forge.targets.base import Observation
from forge.targets.win_coverage import DrcovCoverage, parse_drcov


def _drcov(blocks):
    hdr = (b"DRCOV VERSION: 2\n"
           b"Module Table: version 2, count 1\n"
           b" 0, 0x1000, 0x2000, 0x0, 0, 0, app.exe\n")
    bb = ("BB Table: %d bbs\n" % len(blocks)).encode()
    blob = b"".join(struct.pack("<IHH", s, sz, m) for s, sz, m in blocks)
    return hdr + bb + blob


def test_parse_drcov_module_relative_blocks():
    edges = parse_drcov(_drcov([(0x100, 5, 0), (0x200, 3, 0), (0x300, 8, 1)]))
    assert len(edges) == 3
    assert ((0 << 32) | 0x100) in edges and ((1 << 32) | 0x300) in edges


def test_parse_drcov_empty_on_garbage():
    assert parse_drcov(b"not a drcov file at all") == set()


def test_drcov_degrades_without_drrun():
    class _T:
        def _run_exitcode(self, binary, *, stdin=b"", timeout=30.0):
            return Observation(crashed=False, crash=triage.CrashInfo())
    b = DrcovCoverage(_T(), drrun=None)
    assert b.available() is False
    run = b.run_with_coverage(Path("x"), stdin=b"a")
    assert run.instrumented is False and run.edges == set()

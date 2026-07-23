"""ControllabilityOracle — crash → controlled OOB-write primitive (rung 4)."""
import shutil

import pytest

from forge.context import JobContext
from forge.ladder import Candidate, Outcome, PrimitiveKind, Rung
from forge.oracles.controllability import ControllabilityOracle, decide
from forge.sandbox import LocalSandbox
from forge.targets.source import SourceTarget


# ── pure decision (no toolchain) ──
def test_decide_proven_when_write_scales():
    o, _ = decide("heap-buffer-overflow", 8, "heap-buffer-overflow", 32)
    assert o is Outcome.PROVEN


def test_decide_inconclusive_when_fixed_size():
    o, _ = decide("heap-buffer-overflow", 8, "heap-buffer-overflow", 8)
    assert o is Outcome.INCONCLUSIVE


def test_decide_inconclusive_on_different_bug():
    o, _ = decide("heap-buffer-overflow", 8, "stack-buffer-overflow", 32)
    assert o is Outcome.INCONCLUSIVE


# ── real escalation (needs clang) ──
VULN = r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void){ char*b=malloc(1); char in[256]; long n=read(0,in,sizeof(in));
 if(n<0)n=0; memcpy(b,in,(unsigned long)n); int r=b[0]; free(b); return r; }
"""


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not available")
def test_real_controllability_proves_primitive(tmp_path):
    target = SourceTarget(tmp_path / "w", name="lab", sandbox=LocalSandbox())
    ctx = JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)
    # base input 8 bytes; the oracle also tries a 16-byte input → write scales
    cand = Candidate(bug_class="memory_safety", title="memcpy overflow",
                     proposed_check={"harness": VULN, "input": "A" * 8})
    v = ControllabilityOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN
    assert v.rung is Rung.PROVEN_PRIMITIVE
    assert v.primitive.kind is PrimitiveKind.OOB_WRITE and v.primitive.controlled
    # the write extent grew with the input
    assert v.evidence["sizes"][1] > v.evidence["sizes"][0]


def test_length_field_scan_finds_declared_length(tmp_path):
    """A3: for a length-prefixed format, doubling the buffer doesn't scale a
    declared length; the header scan finds the field that governs the OOB write."""
    import struct
    from pathlib import Path
    from forge.oracles.controllability import ControllabilityOracle
    from forge.targets.base import BuildResult, Observation
    from forge.triage import CrashInfo

    class _T:
        def run(self, binary, *, stdin=b"", symbolize=False, timeout=60.0):
            length = struct.unpack_from("<I", (bytes(stdin) + b"\0" * 8))[0]
            return Observation(crashed=True, crash=CrashInfo(
                crashed=True, bug_type="heap-buffer-overflow",
                access="WRITE", access_size=length))

    base = struct.pack("<I", 32) + b"A" * 32
    o1 = _T().run(None, stdin=base)
    hit = ControllabilityOracle()._scan_length_field(
        _T(), BuildResult(ok=True, binary=Path("x")), base, o1.crash, 60.0)
    assert hit is not None
    off, width, big = hit
    assert off == 0 and big > 32

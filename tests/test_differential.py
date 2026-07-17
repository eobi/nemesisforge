"""DifferentialOracle — the universal reward: crashes vuln build, clean on patched."""
import shutil

import pytest

from forge.context import JobContext
from forge.ladder import Candidate, Outcome, Rung
from forge.oracles.differential import DifferentialOracle, decide
from forge.sandbox import LocalSandbox
from forge.targets.source import SourceTarget


# ── pure decision logic (no toolchain) ──
def test_decide_proven_when_vuln_crashes_patched_clean():
    o, r, _ = decide(vuln_crashed=True, vuln_bug="heap-buffer-overflow",
                     patched_crashed=False)
    assert o is Outcome.PROVEN and r is Rung.PROVEN_EXPLOIT


def test_decide_refuted_when_patch_also_crashes():
    o, r, _ = decide(True, "heap-buffer-overflow", True)
    assert o is Outcome.REFUTED


def test_decide_inconclusive_when_vuln_does_not_crash():
    o, r, _ = decide(False, "", False)
    assert o is Outcome.INCONCLUSIVE


def test_verify_needs_patched_harness(tmp_path):
    target = SourceTarget(tmp_path / "w", name="lab", sandbox=LocalSandbox())
    ctx = JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)
    cand = Candidate(bug_class="memory_safety", title="x",
                     proposed_check={"harness": "int main(){return 0;}"})  # no patch
    v = DifferentialOracle().verify(ctx, cand)
    assert v.outcome is Outcome.INCONCLUSIVE
    assert "patched_harness" in v.feedback


# ── real differential proof (needs clang) ──
VULN = r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void){ char*b=malloc(1); char in[256]; long n=read(0,in,sizeof(in));
 if(n<0)n=0; memcpy(b,in,(unsigned long)n); int r=b[0]; free(b); return r; }
"""
PATCHED = r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void){ char*b=malloc(1); char in[256]; long n=read(0,in,sizeof(in));
 if(n<0)n=0; if(n>1)n=1; memcpy(b,in,(unsigned long)n); int r=b[0]; free(b); return r; }
"""


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not available")
def test_real_differential_proves_exploit(tmp_path):
    target = SourceTarget(tmp_path / "w", name="lab", sandbox=LocalSandbox())
    ctx = JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)
    cand = Candidate(bug_class="memory_safety", title="heap overflow",
                     proposed_check={"harness": VULN, "patched_harness": PATCHED,
                                     "input": "A" * 32})
    v = DifferentialOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN
    assert v.rung is Rung.PROVEN_EXPLOIT          # rung 5 — a working PoC
    assert v.evidence["vuln_crashed"] and not v.evidence["patched_crashed"]
    from pathlib import Path
    assert v.reproducer and Path(v.reproducer).exists()

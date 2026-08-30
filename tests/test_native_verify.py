"""NativeVerifyOracle — the anti-false-positive gate: only crashes that
reproduce in a fresh un-instrumented process are real (the Little-CMS lesson)."""
import shutil

import pytest

from forge.context import JobContext
from forge.ladder import Candidate, Outcome, Rung
from forge.oracles.native_verify import NativeVerifyOracle, decide
from forge.sandbox import LocalSandbox
from forge.targets.binary import BinaryTarget


# ── pure decision (no process) ──
def test_decide_refutes_when_never_reproduces_natively():
    # instrumented run "crashed" but 5 native replays are all clean → artifact.
    o, modal, reason = decide(["", "", "", "", ""])
    assert o is Outcome.REFUTED and modal == ""
    assert "instrumentation artifact" in reason


def test_decide_proves_when_reproduces_every_run():
    o, modal, reason = decide(["segv", "segv", "segv"])
    assert o is Outcome.PROVEN and modal == "segv"
    assert "every run" in reason


def test_decide_proves_on_flaky_native_repro():
    # even one native reproduction is dispositive: a Stalker artifact is 0/5.
    o, modal, _ = decide(["", "segv", "", "", ""])
    assert o is Outcome.PROVEN and modal == "segv"


def test_decide_picks_modal_bug_type():
    o, modal, _ = decide(["segv", "segv", "bus-error"])
    assert o is Outcome.PROVEN and modal == "segv"


def test_decide_inconclusive_with_no_replays():
    o, _, _ = decide([])
    assert o is Outcome.INCONCLUSIVE


# ── real replay against a bare binary ──
def _build(tmp_path, src: str, name: str):
    cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler")
    src_p = tmp_path / f"{name}.c"
    src_p.write_text(src)
    exe = tmp_path / name
    import subprocess
    r = subprocess.run([cc, "-O0", str(src_p), "-o", str(exe)],
                       capture_output=True)
    if r.returncode != 0:
        pytest.skip("compile failed: " + r.stderr.decode("utf-8", "replace"))
    return exe


# A crasher that faults natively on a long input — a REAL bug, must be PROVEN.
#
# DELIBERATELY A LARGE HEAP OVERFLOW, not a stack one. The original wrote 400 bytes past a
# 16-byte stack buffer, which faults on some hosts and not others: it corrupts the frame,
# and whether it ever touches an unmapped page depends on stack layout, hardening flags and
# ASLR. It faulted on macOS (SIGSEGV) and in a local Ubuntu container (SIGBUS), and did not
# fault at all on the CI runner — so the oracle correctly reported "native replay clean" and
# the test read that as the oracle being wrong. Four megabytes past a 16-byte allocation
# crosses into unmapped memory on any platform, which is what a test asserting "a real fault
# is PROVEN" needs: the fault must be the constant and the platform the variable.
_CRASHER = r"""
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
int main(void){ char in[512];
 long n=read(0,in,sizeof(in)); if(n<0)n=0;
 if(n < 64) return 0;                  /* a short input is clean, so the fault is input-borne */
 char *b = (char*)malloc(16);
 if(!b) return 0;
 memset(b,in[0],1u<<22);               /* 4 MB into a 16-byte allocation → fatal signal */
 return b[0]; }
"""

# A clean program that never crashes — stands in for an instrumentation artifact
# (the "crash" only ever existed under Stalker; native replay is always clean).
_CLEAN = r"""
#include <unistd.h>
int main(void){ char in[512]; long n=read(0,in,sizeof(in)); (void)n; return 0; }
"""


def test_real_native_verify_proves_a_reproducible_crash(tmp_path):
    exe = _build(tmp_path, _CRASHER, "crasher")
    target = BinaryTarget(exe, name="crasher", sandbox=LocalSandbox())
    ctx = JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)
    cand = Candidate(bug_class="instrumented_crash", title="stalker crash",
                     proposed_check={"input": "A" * 400, "instrumented_bug": "segv",
                                     "native_replays": 3})
    v = NativeVerifyOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN             # real bug, not an artifact
    # A memory-safety crash from untrusted stdin proves a real fault; the exact
    # rung tracks the OS-delivered signal (SIGSEGV→SECURITY, stack-smash trap/
    # abort→FAULT), which is platform-dependent, so we only pin ≥ PROVEN_FAULT.
    assert v.rung >= Rung.PROVEN_FAULT
    assert v.evidence["native_reproductions"] >= 1
    assert v.reproducer


def test_real_native_verify_refutes_an_instrumentation_artifact(tmp_path):
    exe = _build(tmp_path, _CLEAN, "clean")
    target = BinaryTarget(exe, name="clean", sandbox=LocalSandbox())
    ctx = JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)
    # The fuzzer claims a crash under instrumentation; native replay is clean.
    cand = Candidate(bug_class="instrumented_crash", title="stalker artifact",
                     proposed_check={"input": "A" * 400, "instrumented_bug": "segv",
                                     "native_replays": 5})
    v = NativeVerifyOracle().verify(ctx, cand)
    assert v.outcome is Outcome.REFUTED
    assert v.evidence["native_reproductions"] == 0

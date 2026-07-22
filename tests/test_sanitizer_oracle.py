"""The real, deterministic proof path: SourceTarget builds under ASan, the
SanitizerOracle runs an input, a crash becomes a ladder verdict. Needs clang."""
import shutil

import pytest

from forge.context import JobContext
from forge.ladder import Candidate, Outcome, PrimitiveKind, Rung
from forge.oracles.sanitizer import SanitizerOracle
from forge.sandbox import LocalSandbox
from forge.targets.source import SourceTarget

pytestmark = pytest.mark.skipif(shutil.which("clang") is None,
                                reason="clang not available")

# A genuinely vulnerable harness: unchecked memcpy into a 16-byte HEAP buffer
# (heap dest + stack src → no region overlap → a clean heap-buffer-overflow,
# not ASan's memcpy-param-overlap check).
VULN_HARNESS = r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    char *buf = malloc(16);
    char in[256];
    long n = read(0, in, sizeof(in));
    if (n < 0) n = 0;
    memcpy(buf, in, (unsigned long)n);   /* heap-buffer-overflow if n > 16 */
    int r = buf[0];
    free(buf);
    return r;
}
"""


def _ctx(tmp_path):
    target = SourceTarget(tmp_path / "work", name="lab", sandbox=LocalSandbox())
    return JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)


def test_overflow_input_yields_proven_fault(tmp_path):
    ctx = _ctx(tmp_path)
    cand = Candidate(bug_class="memory_safety", title="stack overflow via read",
                     proposed_check={"harness": VULN_HARNESS, "input": "A" * 64})
    v = SanitizerOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN
    assert v.rung == Rung.PROVEN_FAULT          # crash is in the harness itself
    assert "heap-buffer-overflow" in v.evidence["crash"]["bug_type"]
    # a controllable WRITE → primitive hypothesis for the escalation tier
    assert v.primitive and v.primitive.kind == PrimitiveKind.OOB_WRITE
    # the reproducer was captured to the per-job artifact store
    from pathlib import Path
    assert v.reproducer and Path(v.reproducer).exists()
    assert Path(v.reproducer).read_bytes() == b"A" * 64


def test_crash_inside_target_source_is_proven_security(tmp_path):
    # A separate "target" source with the bug; the harness only drives input into
    # it. A crash whose top frame is in the target = the fuzzed function IS the
    # untrusted input surface → PROVEN_SECURITY (rung 3), not a mere harness fault.
    work = tmp_path / "work"
    work.mkdir(parents=True)
    (work / "parser.c").write_text(r"""
#include <stdlib.h>
#include <string.h>
int parse(const char *in, unsigned long n) {
    char *buf = malloc(16);
    memcpy(buf, in, n);            /* heap-buffer-overflow in the TARGET */
    int r = buf[0]; free(buf); return r;
}
""")
    harness = r"""
#include <unistd.h>
int parse(const char *, unsigned long);
int main(void) {
    char in[256];
    long n = read(0, in, sizeof(in));
    if (n < 0) n = 0;
    return parse(in, (unsigned long)n);
}
"""
    target = SourceTarget(work, name="lab", sandbox=LocalSandbox())
    ctx = JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)
    cand = Candidate(bug_class="memory_safety", title="overflow in parse()",
                     proposed_check={"harness": harness, "input": "A" * 64,
                                     "target_sources": [work / "parser.c"]})
    v = SanitizerOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN
    assert v.rung == Rung.PROVEN_SECURITY          # crash frame is in parser.c
    assert any(f["file"].endswith("parser.c")
               for f in v.evidence["crash"]["frames"])


def test_safe_input_is_refuted(tmp_path):
    ctx = _ctx(tmp_path)
    cand = Candidate(bug_class="memory_safety", title="maybe overflow",
                     proposed_check={"harness": VULN_HARNESS, "input": "A" * 4})
    v = SanitizerOracle().verify(ctx, cand)
    assert v.outcome is Outcome.REFUTED           # no crash on a safe input
    assert "no sanitizer crash" in v.feedback


def test_build_failure_is_inconclusive(tmp_path):
    ctx = _ctx(tmp_path)
    cand = Candidate(bug_class="memory_safety", title="broken",
                     proposed_check={"harness": "this is not valid C {{{",
                                     "input": "x"})
    v = SanitizerOracle().verify(ctx, cand)
    assert v.outcome is Outcome.INCONCLUSIVE
    assert "build failed" in v.feedback


# ── regression: LF_DRIVER must size the input buffer EXACTLY to the input ──
# A libFuzzer harness that reads past `size` is an out-of-bounds READ of the
# input buffer. libFuzzer sizes `data` tightly (redzone right after), so it
# faults; the replay driver must too. A slack read buffer silently absorbs the
# read and the oracle FALSELY refutes a real crash (fixed 2026-07-22).
OOB_READ_HARNESS = r"""
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
  if (size < 1) return 0;
  volatile int s = 0;
  for (int i = 0; i < 64; i++) s += data[i];   /* reads past `size` → OOB */
  return s;
}
"""


def test_libfuzzer_oob_read_past_input_is_proven_not_refuted(tmp_path):
    import base64
    ctx = _ctx(tmp_path)
    cand = Candidate(
        bug_class="memory_safety", title="libfuzzer oob read past input",
        proposed_check={"harness": OOB_READ_HARNESS, "libfuzzer": True,
                        "input_b64": base64.b64encode(b"\x01").decode()})
    v = SanitizerOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN, f"driver masked the OOB read: {v.feedback}"
    assert v.rung >= Rung.PROVEN_FAULT

"""Phase G — real coverage-guided fuzzing. The libFuzzer agent must (a) drive
through a magic-byte guard the legacy length-sweep can't, then (b) hand its crash
to the SanitizerOracle, which independently rebuilds + replays it under a stdin
driver and certifies the rung (writer ≠ validator). Needs a libFuzzer-capable clang."""
import asyncio
import shutil

import pytest

from forge import fuzzengine
from forge.agents.libfuzzer_discovery import LibFuzzerDiscoveryAgent
from forge.context import JobContext
from forge.ladder import Outcome, Rung
from forge.oracles.sanitizer import SanitizerOracle
from forge.sandbox import LocalSandbox
from forge.targets.source import SourceTarget

pytestmark = pytest.mark.skipif(
    fuzzengine.find_libfuzzer_clang() is None,
    reason="no libFuzzer-capable clang (need Homebrew LLVM on macOS)")

# A bug GUARDED by a 4-byte magic — a blind length-sweep of "AAAA…" never enters
# the branch; a coverage-guided fuzzer (with the dictionary) discovers FUZZ and
# then overflows the 4-byte heap buffer. This is the capability jump Phase G adds.
GUARDED_HARNESS = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size >= 4 && data[0]=='F' && data[1]=='U' && data[2]=='Z' && data[3]=='Z') {
        char *b = malloc(4);
        memcpy(b, data, size);          /* heap-buffer-overflow when size > 4 */
        volatile int r = b[0]; (void)r;
        free(b);
    }
    return 0;
}
"""


def _ctx(tmp_path):
    target = SourceTarget(tmp_path / "work", name="lab", sandbox=LocalSandbox())
    return JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)


def test_coverage_guided_fuzz_beats_the_guard_and_oracle_certifies(tmp_path):
    ctx = _ctx(tmp_path)
    corpus = tmp_path / "corpus"
    dic = tmp_path / "f.dict"
    dic.write_text('kw1="FUZZ"\n')          # the LLM/harness-synth would supply this
    agent = LibFuzzerDiscoveryAgent(
        ctx, harness=GUARDED_HARNESS, corpus_dir=corpus, dict_path=dic,
        max_total_time=25, max_len=32)

    cands = asyncio.run(agent.execute())
    assert cands, "coverage-guided fuzzer should have found the guarded crash"
    cand = cands[0]
    assert cand.proposed_check["libfuzzer"] is True
    assert "heap-buffer-overflow" in (cand.crash.get("bug_type") or "")

    # writer ≠ validator: the oracle rebuilds under a stdin driver + replays.
    v = SanitizerOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN
    assert v.rung in (Rung.PROVEN_FAULT, Rung.PROVEN_SECURITY)
    assert "heap-buffer-overflow" in v.evidence["crash"]["bug_type"]


def test_no_harness_is_noop(tmp_path):
    ctx = _ctx(tmp_path)
    agent = LibFuzzerDiscoveryAgent(ctx, harness="")
    assert asyncio.run(agent.execute()) == []

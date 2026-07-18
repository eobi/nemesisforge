"""Phase J — the co-driving loop, the novel core. The bug sits behind an FNV-hash
guard: a coverage-guided fuzzer gets NO per-byte gradient from a hash equality, so
blind fuzzing effectively never enters the branch. The loop must STALL, ask the LLM
for a guard-passing seed, inject it, and crash on the next round. The control case
(no model) proves the LLM is what unlocked it. Needs a libFuzzer-capable clang."""
import asyncio
import base64
import json

import pytest

from forge import fuzzengine
from forge.agents.codrive import CoDrivingFuzzAgent
from forge.context import JobContext
from forge.events import EventType
from forge.ladder import Outcome
from forge.llm import NullLLM
from forge.oracles.sanitizer import SanitizerOracle
from forge.sandbox import LocalSandbox
from forge.targets.source import SourceTarget

pytestmark = pytest.mark.skipif(
    fuzzengine.find_libfuzzer_clang() is None,
    reason="no libFuzzer-capable clang")

# The magic "UNLOCKME" is checked via an FNV hash → no gradient for the fuzzer to
# climb, so it cannot guess the 8-byte preimage. Past the guard, an unchecked
# memcpy overflows a 4-byte heap buffer.
GUARDED = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
static unsigned long fnv(const uint8_t *d, size_t n){
    unsigned long h = 1469598103934665603UL;
    for(size_t i=0;i<n;i++){ h ^= d[i]; h *= 1099511628211UL; }
    return h;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    if(size >= 8 && fnv(data, 8) == fnv((const uint8_t*)"UNLOCKME", 8)){
        char *b = malloc(4);
        memcpy(b, data, size);           /* heap-buffer-overflow past the guard */
        volatile int r = b[0]; (void)r; free(b);
    }
    return 0;
}
"""

# base64 of "UNLOCKME" + padding → satisfies the guard AND overflows.
UNLOCK_SEED = base64.b64encode(b"UNLOCKME" + b"A" * 16).decode()


class MockLLM:
    name, model, available = "mock", "mock-1", True

    def complete(self, system, user, *, max_tokens=2048):
        return json.dumps({"input_b64": UNLOCK_SEED, "why": "magic"})

    def complete_json(self, system, user, *, max_tokens=4096):
        return {"input_b64": UNLOCK_SEED, "why": "satisfies the FNV magic"}, {}


def _ctx(tmp_path):
    target = SourceTarget(tmp_path / "work", name="guard", sandbox=LocalSandbox())
    return JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)


def test_llm_seed_unlocks_the_guard_and_oracle_certifies(tmp_path):
    ctx = _ctx(tmp_path)
    agent = CoDrivingFuzzAgent(
        ctx, harness=GUARDED, corpus_dir=tmp_path / "corpus", llm=MockLLM(),
        focus_function="LLVMFuzzerTestOneInput", guard_context=GUARDED,
        sanitizer="address", rounds=3, round_time=5)
    cands = asyncio.run(agent.execute())
    assert cands, "the co-driving loop should crack the guard via the LLM seed"

    # the loop actually consulted the LLM on a stall (crafted a guard-passing seed);
    # a seed is SEED, not POC_WRITTEN (which is reserved for real authored exploits)
    assert any(e.type == EventType.SEED for e in ctx.bus.all())
    assert not any(e.type == EventType.POC_WRITTEN for e in ctx.bus.all())

    v = SanitizerOracle().verify(ctx, cands[0])
    assert v.outcome is Outcome.PROVEN
    assert "heap-buffer-overflow" in v.evidence["crash"]["bug_type"]


def test_without_model_the_guard_holds(tmp_path):
    # Same harness, no model: blind fuzzing can't invert the hash guard, so the
    # loop finds nothing. This is the control that proves the LLM did the unlocking.
    ctx = _ctx(tmp_path)
    agent = CoDrivingFuzzAgent(
        ctx, harness=GUARDED, corpus_dir=tmp_path / "corpus", llm=NullLLM(),
        focus_function="LLVMFuzzerTestOneInput", sanitizer="address",
        rounds=2, round_time=5)
    assert asyncio.run(agent.execute()) == []

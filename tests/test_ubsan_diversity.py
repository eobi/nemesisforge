"""Phase I — sanitizer diversity. With ASan+UBSan the engine catches an
undefined-behavior bug (signed-overflow shift) that ASan alone would miss, and the
oracle re-verifies it under the same sanitizer set. Needs a libFuzzer-capable clang."""
import asyncio

import pytest

from forge import fuzzengine
from forge.agents.libfuzzer_discovery import LibFuzzerDiscoveryAgent
from forge.context import JobContext
from forge.ladder import Outcome
from forge.oracles.sanitizer import SanitizerOracle
from forge.sandbox import LocalSandbox
from forge.targets.source import SourceTarget

pytestmark = pytest.mark.skipif(
    fuzzengine.find_libfuzzer_clang() is None,
    reason="no libFuzzer-capable clang")

# A pure UB bug: signed-integer overflow with NO out-of-bounds access → ASan alone
# is silent, UBSan flags it. Trivially reachable (any non-zero first byte) so this
# test isolates the SANITIZER wiring, not libFuzzer's guard-solving (Phase G's job).
UB_HARNESS = r"""
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    if(size >= 1 && data[0] != 0){
        int x = 2147483647;                /* INT_MAX */
        x += (int)data[0];                 /* signed integer overflow (UB) */
        volatile int z = x; (void)z;
    }
    return 0;
}
"""


def _ctx(tmp_path):
    target = SourceTarget(tmp_path / "work", name="ub", sandbox=LocalSandbox())
    return JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)


def test_ubsan_finds_and_oracle_certifies_ub_bug(tmp_path):
    ctx = _ctx(tmp_path)
    agent = LibFuzzerDiscoveryAgent(
        ctx, harness=UB_HARNESS, corpus_dir=tmp_path / "corpus",
        sanitizer="address,undefined", max_total_time=15, max_len=16)
    cands = asyncio.run(agent.execute())
    assert cands, "ASan+UBSan should catch the signed-overflow UB bug"
    cand = cands[0]
    assert cand.proposed_check["sanitizer"] == "address,undefined"

    v = SanitizerOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN
    assert v.reproducer                      # captured trigger for the packet

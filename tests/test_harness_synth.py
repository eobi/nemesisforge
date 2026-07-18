"""Phase H — the LLM-writes-a-harness path, hermetic (no network, no real model).

A planted-bug mini "library" stands in for a cloned repo; a MockLLM returns a
harness that drives fuzz bytes into its parser. The agent must compile the harness
against the target SOURCE + HEADER (include path), coverage-validate it (dead
harnesses discarded), fuzz it, and surface a crash the SanitizerOracle certifies —
landing inside the target source (PROVEN_SECURITY), which is the whole point of
pointing at a real repo. Live git-clone ingestion is covered separately.
"""
import asyncio
import json
import shutil

import pytest

from forge import fuzzengine
from forge.agents.harness_synth import HarnessSynthAgent
from forge.context import JobContext
from forge.ingest.repo import RepoInfo
from forge.ladder import Outcome, Rung
from forge.oracles.sanitizer import SanitizerOracle
from forge.sandbox import LocalSandbox
from forge.targets.source import SourceTarget

pytestmark = pytest.mark.skipif(
    fuzzengine.find_libfuzzer_clang() is None,
    reason="no libFuzzer-capable clang")

# A tiny "library" with a length-field bug in its parser (untrusted input surface).
LIB_H = r"""
#ifndef MINI_H
#define MINI_H
#include <stddef.h>
int mini_parse(const unsigned char *data, size_t size);
#endif
"""
LIB_C = r"""
#include "mini.h"
#include <stdlib.h>
#include <string.h>
int mini_parse(const unsigned char *data, size_t size) {
    if (size < 1) return 0;
    unsigned want = data[0];             /* declared length, trusted */
    char *buf = malloc(8);
    memcpy(buf, data + 1, want);         /* heap-buffer-overflow when want > 8 */
    int r = buf[0];
    free(buf);
    return r;
}
"""
# What a competent model would return for this library.
GOOD_HARNESS = r"""
#include "mini.h"
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return mini_parse((const unsigned char *)data, size);
}
"""


class MockLLM:
    name, model, available = "mock", "mock-1", True

    def __init__(self, harness):
        self._h = harness

    def complete(self, system, user, *, max_tokens=2048):
        return f"```c\n{self._h}\n```"          # real models return raw C

    def complete_json(self, system, user, *, max_tokens=4096):
        return {"harness": self._h, "entry": "mini_parse"}, {"cost_usd": 0.0}


def _repo_and_ctx(tmp_path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "mini.h").write_text(LIB_H)
    src = repo_root / "mini.c"
    src.write_text(LIB_C)
    info = RepoInfo(root=repo_root, url="file://mini", ref="test",
                    sources=[src], headers=[repo_root / "mini.h"])
    target = SourceTarget(tmp_path / "work", name="mini", sandbox=LocalSandbox())
    ctx = JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)
    ctx.repo = info
    return info, ctx


def test_synth_validate_fuzz_finds_bug_in_target_source(tmp_path):
    info, ctx = _repo_and_ctx(tmp_path)
    agent = HarnessSynthAgent(ctx, repo=info, llm=MockLLM(GOOD_HARNESS),
                              max_targets=1, fuzz_time=25, probe_time=6)
    cands = asyncio.run(agent.execute())
    assert cands, "a live harness on a buggy parser should yield a crash candidate"
    cand = cands[0]
    assert cand.proposed_check["libfuzzer"] is True
    assert cand.proposed_check["target_sources"]        # built against the repo src

    v = SanitizerOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN
    # crash frame is inside the TARGET source → reachable attack surface, rung 3.
    assert v.rung == Rung.PROVEN_SECURITY
    assert any(f["file"].endswith("mini.c")
               for f in v.evidence["crash"]["frames"])


def test_dead_harness_is_discarded(tmp_path):
    # A harness that never calls the target reaches trivial coverage → discarded,
    # so the agent surfaces nothing rather than a useless "finding".
    info, ctx = _repo_and_ctx(tmp_path)
    dead = ("#include <stdint.h>\n#include <stddef.h>\n"
            "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){(void)d;(void)n;"
            "return 0;}\n")
    agent = HarnessSynthAgent(ctx, repo=info, llm=MockLLM(dead),
                              max_targets=1, fuzz_time=10, probe_time=5)
    assert asyncio.run(agent.execute()) == []


def test_noop_without_model(tmp_path):
    info, ctx = _repo_and_ctx(tmp_path)
    from forge.llm import NullLLM
    agent = HarnessSynthAgent(ctx, repo=info, llm=NullLLM())
    assert asyncio.run(agent.execute()) == []

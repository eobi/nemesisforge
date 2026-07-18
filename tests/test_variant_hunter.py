"""Phase I — the reasoning tier end to end (hermetic). VariantHunter must analyze
a multi-source "repo", let the (mock) model nominate the buggy sink, AIM harness
synth at that source, fuzz it, and surface a crash the oracle certifies inside the
target. Needs a libFuzzer-capable clang; no network, no real model."""
import asyncio
import json

import pytest

from forge import fuzzengine
from forge.agents.variant_hunter import VariantHunterAgent
from forge.context import JobContext
from forge.ingest.repo import RepoInfo
from forge.ladder import Outcome, Rung
from forge.oracles.sanitizer import SanitizerOracle
from forge.sandbox import LocalSandbox
from forge.targets.source import SourceTarget

pytestmark = pytest.mark.skipif(
    fuzzengine.find_libfuzzer_clang() is None,
    reason="no libFuzzer-capable clang")

# Two sources: a decoy (safe) and the real buggy parser. The reasoning tier must
# steer the fuzzer to the buggy one.
SAFE_H = "#ifndef SAFE_H\n#define SAFE_H\n#include <stddef.h>\nint safe_sum(const unsigned char*,size_t);\n#endif\n"
SAFE_C = r"""
#include "safe.h"
int safe_sum(const unsigned char *d, size_t n){ int s=0; for(size_t i=0;i<n;i++) s+=d[i]; return s; }
"""
VULN_H = "#ifndef VULN_H\n#define VULN_H\n#include <stddef.h>\nint decode_frame(const unsigned char*,size_t);\n#endif\n"
VULN_C = r"""
#include "vuln.h"
#include <stdlib.h>
#include <string.h>
int decode_frame(const unsigned char *data, size_t size){
    if(size<1) return 0;
    unsigned len = data[0];              /* attacker-declared length */
    char *buf = malloc(8);
    memcpy(buf, data+1, len);            /* heap-buffer-overflow when len>8 */
    int r = buf[0]; free(buf); return r;
}
"""
HARNESS = r"""
#include "vuln.h"
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    return decode_frame((const unsigned char*)data, size);
}
"""


class MockLLM:
    name, model, available = "mock", "mock-1", True

    def complete(self, system, user, *, max_tokens=2048):
        r = self._reply(user)
        if isinstance(r, dict) and "harness" in r:   # synth → raw C, like a real model
            return f"```c\n{r['harness']}\n```"
        return json.dumps(r)

    def complete_json(self, system, user, *, max_tokens=4096):
        return self._reply(user), {"cost_usd": 0.0}

    def _reply(self, user):
        # variant-analysis call → nominate the buggy source; synth call → harness.
        if "Nominate" in user or "sinks" in user:
            return [{"file": "vuln.c", "function": "decode_frame",
                     "why": "attacker-controlled length feeds memcpy"}]
        return {"harness": HARNESS, "entry": "decode_frame"}


def test_reasoning_aims_fuzzer_at_the_bug(tmp_path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "safe.h").write_text(SAFE_H)
    (repo_root / "safe.c").write_text(SAFE_C)
    (repo_root / "vuln.h").write_text(VULN_H)
    vuln = repo_root / "vuln.c"
    vuln.write_text(VULN_C)
    info = RepoInfo(root=repo_root, url="file://repo", ref="t",
                    sources=[repo_root / "safe.c", vuln],
                    headers=[repo_root / "safe.h", repo_root / "vuln.h"])
    target = SourceTarget(tmp_path / "work", name="repo", sandbox=LocalSandbox())
    ctx = JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)
    ctx.repo = info

    agent = VariantHunterAgent(ctx, repo=info, llm=MockLLM(), max_targets=1,
                               fuzz_time=25)
    cands = asyncio.run(agent.execute())
    assert cands, "reasoning tier should have driven the fuzzer to the bug"
    v = SanitizerOracle().verify(ctx, cands[0])
    assert v.outcome is Outcome.PROVEN
    assert v.rung == Rung.PROVEN_SECURITY
    assert any(f["file"].endswith("vuln.c") for f in v.evidence["crash"]["frames"])


def test_noop_without_model(tmp_path):
    repo_root = tmp_path / "repo"; repo_root.mkdir()
    info = RepoInfo(root=repo_root, url="file://repo", sources=[], headers=[])
    target = SourceTarget(tmp_path / "work", name="repo", sandbox=LocalSandbox())
    ctx = JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)
    from forge.llm import NullLLM
    agent = VariantHunterAgent(ctx, repo=info, llm=NullLLM())
    assert asyncio.run(agent.execute()) == []

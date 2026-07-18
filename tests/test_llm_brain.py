"""The LLM brain: multi-subagent discovery + LLM-synthesized exploits, all
certified by deterministic oracles. Uses a MockLLM (no network, no clang)."""
import asyncio
import base64
import json
from types import SimpleNamespace

from forge.agents.llm_strategist import LLMStrategistAgent
from forge.agents.llm_synth import LLMSynthAgent
from forge.context import JobContext
from forge.events import EventType
from forge.ladder import (
    Candidate, Outcome, Primitive, PrimitiveKind, Rung, Verdict,
)
from forge.llm import list_providers, make_client, NullLLM
from forge.sandbox import LocalSandbox


class MockLLM:
    name, model, available = "mock", "mock-1", True

    def __init__(self, resp):
        self.resp = resp

    def complete(self, system, user, *, max_tokens=2048):
        return json.dumps(self.resp)

    def complete_json(self, system, user, *, max_tokens=4096):
        return self.resp, {"cost_usd": 0.0}


def _ctx(tmp_path):
    (tmp_path / "src.c").write_text("void f(char*in,int n){char b[8];memcpy(b,in,n);}")
    target = SimpleNamespace(workdir=tmp_path, sandbox=LocalSandbox(),
                             name="t", target_type="source")
    return JobContext(f"job-{tmp_path.name}", target=target, artifacts_root=tmp_path)


def test_provider_registry():
    ids = {p["id"] for p in list_providers()}
    assert {"anthropic", "openai", "openrouter", "ollama", "local"} <= ids
    # provider absence / unknown → NullLLM (key-independent)
    assert isinstance(make_client(None), NullLLM)
    assert isinstance(make_client("nope"), NullLLM)


def test_strategist_spawns_lens_subagents(tmp_path):
    ctx = _ctx(tmp_path)
    llm = MockLLM([{"input_b64": base64.b64encode(b"A" * 32).decode(),
                    "why": "overflow the fixed buffer"}])
    strat = LLMStrategistAgent(ctx, harness="int main(){}", llm=llm,
                               lenses=["overflow", "integer", "novel"], n_per_lens=1)
    cands = asyncio.run(strat.execute())
    # one hypothesis per lens → the brain fanned out real sub-agents
    assert len(cands) == 3
    spawns = {e.data.get("name") for e in ctx.bus.all()
              if e.type == EventType.AGENT_SPAWNED}
    assert "llm-brain" in spawns
    assert any(":overflow" in s for s in spawns) and any(":novel" in s for s in spawns)
    # every hypothesis is a Candidate for the oracle to prove (not a claim)
    assert all(c.proposed_check.get("input_b64") for c in cands)


def test_strategist_idle_without_model(tmp_path):
    ctx = _ctx(tmp_path)
    strat = LLMStrategistAgent(ctx, harness="", llm=NullLLM())
    assert asyncio.run(strat.execute()) == []       # deterministic side unaffected


class _StubEsc:
    name = "stub-esc"
    handles = {"memory_safety"}
    target_rung = Rung.PROVEN_PRIMITIVE

    def verify(self, ctx, cand):
        # certifies whatever the LLM proposed (in a real run this is ASan/diff)
        return Verdict(Outcome.PROVEN, Rung.PROVEN_PRIMITIVE, self.name,
                       primitive=Primitive(kind=PrimitiveKind.OOB_WRITE, controlled=True))


def test_synth_agent_llm_writes_oracle_proves(tmp_path):
    ctx = _ctx(tmp_path)
    llm = MockLLM({"input_b64": base64.b64encode(b"A" * 64).decode(),
                   "rationale": "wider write"})
    cand = Candidate(bug_class="memory_safety", title="overflow",
                     crash={"bug_type": "heap-buffer-overflow"},
                     proposed_check={"harness": "", "input_b64": base64.b64encode(b"AA").decode()})
    synth = LLMSynthAgent(ctx, candidate=cand, llm=llm, oracles=[_StubEsc()])
    v = asyncio.run(synth.execute())
    assert v is not None and v.outcome is Outcome.PROVEN
    assert v.rung is Rung.PROVEN_PRIMITIVE
    types = [e.type for e in ctx.bus.all()]
    assert EventType.POC_WRITTEN in types and EventType.VALIDATED in types


def test_synth_idle_without_model(tmp_path):
    ctx = _ctx(tmp_path)
    cand = Candidate(bug_class="memory_safety", title="x")
    synth = LLMSynthAgent(ctx, candidate=cand, llm=NullLLM(), oracles=[_StubEsc()])
    assert asyncio.run(synth.execute()) is None

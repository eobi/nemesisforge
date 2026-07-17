"""ValidatorAgent (writer≠validator) + the LLM seam."""
import asyncio
from types import SimpleNamespace

from forge.agents.validator import ValidatorAgent
from forge.context import JobContext
from forge.events import EventType
from forge.ladder import Candidate, Outcome, Rung, Verdict
from forge.llm import NullLLM, make_client


class StubOracle:
    name = "stub"
    handles = {"memory_safety"}

    def __init__(self, rung=Rung.PROVEN_PRIMITIVE, outcome=Outcome.PROVEN):
        self.rung, self.outcome = rung, outcome

    def verify(self, ctx, cand):
        return Verdict(self.outcome, self.rung, self.name)


def _ctx(tmp_path):
    return JobContext(f"job-{tmp_path.name}", target=SimpleNamespace(name="t"),
                      artifacts_root=tmp_path)


def _cand():
    return Candidate(bug_class="memory_safety", title="overflow")


def test_validator_confirms_reproducible_finding(tmp_path):
    ctx = _ctx(tmp_path)
    a = ValidatorAgent(ctx, candidate=_cand(),
                       oracle=StubOracle(rung=Rung.PROVEN_PRIMITIVE),
                       expected_rung=Rung.PROVEN_PRIMITIVE)
    v = asyncio.run(a.execute())
    assert v is not None and v.rung is Rung.PROVEN_PRIMITIVE
    assert any(e.type == EventType.VALIDATED and e.data.get("confirmed")
               for e in ctx.bus.all())


def test_validator_rejects_when_reverify_is_weaker(tmp_path):
    ctx = _ctx(tmp_path)
    # certified at rung 4, but re-verification only reaches rung 1 → not confirmed
    a = ValidatorAgent(ctx, candidate=_cand(),
                       oracle=StubOracle(rung=Rung.PROVEN_FAULT),
                       expected_rung=Rung.PROVEN_PRIMITIVE)
    v = asyncio.run(a.execute())
    assert v is None
    assert not any(e.type == EventType.VALIDATED for e in ctx.bus.all())


def test_validator_rejects_refuted(tmp_path):
    ctx = _ctx(tmp_path)
    a = ValidatorAgent(ctx, candidate=_cand(),
                       oracle=StubOracle(outcome=Outcome.REFUTED),
                       expected_rung=Rung.PROVEN_FAULT)
    assert asyncio.run(a.execute()) is None


def test_llm_seam_defaults_to_null():
    c = make_client()
    assert isinstance(c, NullLLM) and c.available is False
    parsed, meta = c.complete_json("sys", "user")
    assert parsed is None and "no LLM" in meta["error"]

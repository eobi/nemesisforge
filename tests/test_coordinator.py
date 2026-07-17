"""End-to-end orchestration: Coordinator → discovery sub-agents → oracle → ladder.

Uses stub discovery agents + a stub oracle so the wiring (agent tree, activity
stream, ladder climbs, finding gating) is proven now; the real SourceTarget +
sanitizer oracle plug into the same seams next.
"""
import asyncio
from functools import partial
from types import SimpleNamespace

from forge.agents.base import Agent
from forge.context import JobContext
from forge.coordinator import Coordinator
from forge.events import EventType
from forge.ladder import Candidate, CodeLoc, Outcome, Rung, Verdict


class StubDiscovery(Agent):
    kind = "discovery"

    def __init__(self, ctx, name="discovery", parent_id="", cands=None):
        super().__init__(ctx, name=name, parent_id=parent_id)
        self._cands = cands or []

    async def run(self):
        self.objective("hunt for memory-safety bugs")
        self.think(0, "grep for memcpy/strcpy")
        return self._cands


class StubOracle:
    name = "stub-sanitizer"
    handles = {"memory_safety"}

    def __init__(self, rung=Rung.PROVEN_FAULT, outcome=Outcome.PROVEN):
        self.rung, self.outcome = rung, outcome

    def verify(self, ctx, cand):
        return Verdict(outcome=self.outcome, rung=self.rung, oracle=self.name,
                       evidence={"crash": "heap-buffer-overflow"})


def _ctx(tmp_path, name="curl"):
    # tmp_path is unique per test → a unique job id, matching real jobs (uuid)
    # and avoiding the process-global event-bus registry leaking across tests.
    return JobContext(f"job-{tmp_path.name}", target=SimpleNamespace(name=name),
                      artifacts_root=tmp_path)


def _cand(line=42):
    return Candidate(bug_class="memory_safety", title=f"overflow@{line}",
                     location=CodeLoc(path="src/x.c", line=line), agent="stub")


def test_finding_produced_and_ladder_climbs(tmp_path):
    ctx = _ctx(tmp_path)
    cand = _cand()
    coord = Coordinator(
        ctx,
        discovery=[partial(StubDiscovery, cands=[cand])],
        oracles=[StubOracle(rung=Rung.PROVEN_SECURITY)],
    )
    findings = asyncio.run(coord.execute())
    assert len(findings) == 1
    assert findings[0].rung == Rung.PROVEN_SECURITY
    assert ctx.ladder.rung_of(cand) == Rung.PROVEN_SECURITY


def test_agent_tree_parentage_in_events(tmp_path):
    ctx = _ctx(tmp_path)
    coord = Coordinator(ctx, discovery=[partial(StubDiscovery, cands=[_cand()])],
                        oracles=[StubOracle(rung=Rung.PROVEN_SECURITY)])
    asyncio.run(coord.execute())
    evs = ctx.bus.all()
    spawns = {e.data.get("name"): e for e in evs if e.type == EventType.AGENT_SPAWNED}
    assert "coordinator" in spawns and "discovery" in spawns
    # the discovery agent hangs off the coordinator → that edge draws the tree
    assert spawns["discovery"].parent_id == coord.agent_id
    assert spawns["coordinator"].parent_id == ""   # root
    # the climb + board were streamed
    assert any(e.type == EventType.RUNG_UP for e in evs)
    assert any(e.type == EventType.LADDER for e in evs)


def test_proven_fault_below_reportable_is_not_a_finding(tmp_path):
    ctx = _ctx(tmp_path)
    cand = _cand()
    coord = Coordinator(ctx, discovery=[partial(StubDiscovery, cands=[cand])],
                        oracles=[StubOracle(rung=Rung.PROVEN_FAULT)])  # rung 1 < REPORTABLE
    findings = asyncio.run(coord.execute())
    assert findings == []                          # climbed, but not reportable
    assert ctx.ladder.rung_of(cand) == Rung.PROVEN_FAULT
    assert any(e.type == EventType.RUNG_UP for e in ctx.bus.all())


def test_no_oracle_for_bug_class(tmp_path):
    ctx = _ctx(tmp_path)
    cand = Candidate(bug_class="logic_bug", title="weird", agent="stub")
    coord = Coordinator(ctx, discovery=[partial(StubDiscovery, cands=[cand])],
                        oracles=[StubOracle()])     # only handles memory_safety
    findings = asyncio.run(coord.execute())
    assert findings == []
    verdicts = [e for e in ctx.bus.all() if e.type == EventType.ORACLE_VERDICT]
    assert verdicts and verdicts[0].data["outcome"] == "no_oracle"


def test_parallel_discovery_agents_merge_candidates(tmp_path):
    ctx = _ctx(tmp_path)
    coord = Coordinator(
        ctx,
        discovery=[partial(StubDiscovery, cands=[_cand(1)]),
                   partial(StubDiscovery, cands=[_cand(2), _cand(3)])],
        oracles=[StubOracle(rung=Rung.PROVEN_SECURITY)],
    )
    findings = asyncio.run(coord.execute())
    assert len(findings) == 3        # 1 + 2 from the two parallel discovery agents

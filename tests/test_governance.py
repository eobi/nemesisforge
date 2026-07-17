"""Phase F — scale + governance: dedup, novelty, fleet fan-out."""
import asyncio
from functools import partial
from types import SimpleNamespace

from forge.agents.base import Agent
from forge.context import JobContext
from forge.dedup import canonical_key, dedupe
from forge.fleet import run_fleet
from forge.ladder import (
    Candidate, CodeLoc, Finding, Outcome, Rung, Verdict,
)
from forge.novelty import classify, N_DAY, CANDIDATE


def _finding(bug="memory_safety", path="x.c", line=10, rung=Rung.PROVEN_FAULT,
             stack_hash="h1", cve=None):
    ev = {"crash": {"stack_hash": stack_hash,
                    "frames": [{"file": path, "func": "f"}]}}
    if cve:
        ev["cve_ids"] = [cve]
    cand = Candidate(bug_class=bug, title=f"{bug}@{line}",
                     location=CodeLoc(path=path, line=line))
    return Finding(candidate=cand, verdict=Verdict(Outcome.PROVEN, rung, "o", evidence=ev),
                   rung=rung)


# ── dedup ──
def test_dedupe_collapses_same_bug_keeps_highest_rung():
    a = _finding(rung=Rung.PROVEN_FAULT, stack_hash="same")
    b = _finding(rung=Rung.PROVEN_PRIMITIVE, stack_hash="same")   # same bug, higher
    kept, removed = dedupe([a, b])
    assert removed == 1 and len(kept) == 1
    assert kept[0].rung is Rung.PROVEN_PRIMITIVE


def test_dedupe_keeps_distinct_bugs():
    kept, removed = dedupe([_finding(stack_hash="h1"), _finding(stack_hash="h2")])
    assert removed == 0 and len(kept) == 2


def test_canonical_key_stable():
    assert canonical_key(_finding()) == canonical_key(_finding(line=999))  # line not in key


# ── novelty (never auto-zero-day) ──
def test_novelty_ndays_on_cve_else_candidate():
    assert classify(_finding(cve="CVE-2024-1234")) == N_DAY
    assert classify(_finding()) == CANDIDATE
    assert classify(_finding(), seed_cves=["CVE-2020-0001"]) == N_DAY


# ── fleet fan-out ──
class _StubDiscovery(Agent):
    kind = "discovery"

    def __init__(self, ctx, name="discovery", parent_id="", cands=None):
        super().__init__(ctx, name=name, parent_id=parent_id)
        self._c = cands or []

    async def run(self):
        return self._c


class _StubOracle:
    name = "stub"
    handles = {"memory_safety"}

    def verify(self, ctx, cand):
        return Verdict(Outcome.PROVEN, Rung.PROVEN_SECURITY, self.name)


def test_run_fleet_runs_targets_concurrently(tmp_path):
    def factory(i):
        def make():
            ctx = JobContext(f"fleet-{tmp_path.name}-{i}",
                             target=SimpleNamespace(name=f"t{i}", target_type="source"),
                             artifacts_root=tmp_path)
            cand = Candidate(bug_class="memory_safety", title=f"bug{i}",
                             location=CodeLoc(path="x.c", line=i))
            return (ctx, [partial(_StubDiscovery, cands=[cand])], [_StubOracle()], [])
        return make

    results = asyncio.run(run_fleet([factory(1), factory(2), factory(3)],
                                    concurrency=2))
    assert len(results) == 3
    assert all(len(r) == 1 for r in results)          # one finding per target
    assert {r[0].candidate.title for r in results} == {"bug1", "bug2", "bug3"}

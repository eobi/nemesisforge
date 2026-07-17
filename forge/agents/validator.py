"""ValidatorAgent — the writer≠validator gate.

The single most important discipline in this space (MAPTA/XBOW): the agent that
authored/escalated a finding must NOT be the one that certifies it for the
report. The ValidatorAgent takes a finding's candidate and *independently*
re-runs the oracle that certified it, in a fresh build, and only emits VALIDATED
if it reproduces the same PROVEN rung. A discrepancy demotes the finding — a
guard against a flaky reproducer or (once the LLM exploit-synthesizer lands) a
hallucinated PoC.

Deterministic oracles re-run identically by construction, so for them this is a
reproducibility gate; it becomes load-bearing the moment a non-deterministic
(LLM) writer is in the loop.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from ..events import EventType
from ..ladder import Candidate, Outcome, Rung, Verdict
from .base import Agent


class ValidatorAgent(Agent):
    kind = "validator"

    def __init__(self, ctx, name: str = "validator", parent_id: str = "", *,
                 candidate: Optional[Candidate] = None, oracle=None,
                 expected_rung: Rung = Rung.UNVERIFIED) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.candidate = candidate
        self.oracle = oracle
        self.expected_rung = expected_rung

    async def run(self) -> Optional[Verdict]:
        cand, oracle = self.candidate, self.oracle
        if cand is None or oracle is None:
            return None
        self.objective(f"independently re-verify «{cand.title}» "
                       f"(expect {self.expected_rung.name})")
        # a fresh oracle instance re-executes the build+run — never trusts the
        # authoring agent's result.
        verdict = await asyncio.to_thread(oracle.verify, self.ctx, cand)
        ok = (verdict.outcome is Outcome.PROVEN
              and verdict.rung >= self.expected_rung)
        self.em.emit(
            EventType.VALIDATED if ok else EventType.ORACLE_VERDICT,
            title=cand.title, oracle=oracle.name,
            outcome=verdict.outcome.value, rung=int(verdict.rung),
            confirmed=ok,
            note="" if ok else f"re-verify got {verdict.rung.name} "
                               f"< expected {self.expected_rung.name}")
        return verdict if ok else None

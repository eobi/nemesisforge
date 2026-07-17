"""EscalationAgent — takes a proven fault up the weaponization rungs.

The Coordinator spawns one of these per proven memory-safety candidate. It runs
the escalation oracles in ascending rung order (controllability → rung 4,
differential → rung 5, …) and lets the candidate climb as far as the oracles can
certify. Each strategy is a separate oracle so the "sub-agents each try a
different escalation strategy" shape is preserved; the LLM exploit-synthesizer
plugs in here as just another escalation strategy.

Returns the highest PROVEN verdict it reached (or None), so the Coordinator can
upgrade the finding's rung + primitive.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from ..events import EventType
from ..ladder import Candidate, Outcome, Verdict
from .base import Agent


class EscalationAgent(Agent):
    kind = "escalation"

    def __init__(self, ctx, name: str = "escalation", parent_id: str = "", *,
                 candidate: Optional[Candidate] = None,
                 escalation_oracles: Optional[list] = None) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.candidate = candidate
        self.oracles = list(escalation_oracles or [])

    async def run(self) -> Optional[Verdict]:
        cand = self.candidate
        if cand is None:
            return None
        self.objective(f"escalate «{cand.title}» toward a vendor-grade primitive")
        best: Optional[Verdict] = None
        # ascending target rung so the ladder climbs monotonically
        ordered = sorted(self.oracles,
                         key=lambda o: int(getattr(o, "target_rung", 0)))
        for i, oracle in enumerate(ordered):
            self.think(i, f"try {oracle.name}")
            verdict = await asyncio.to_thread(oracle.verify, self.ctx, cand)
            self.em.emit(EventType.ORACLE_VERDICT, title=cand.title,
                         oracle=oracle.name, outcome=verdict.outcome.value,
                         rung=int(verdict.rung), feedback=verdict.feedback)
            if verdict.outcome is Outcome.PROVEN:
                climbed = self.ctx.ladder.apply(cand, verdict)
                if climbed:
                    self.em.emit(EventType.RUNG_UP, title=cand.title,
                                 rung=int(verdict.rung), rung_name=verdict.rung.name)
                    if verdict.reproducer:
                        self.em.emit(EventType.POC_WRITTEN, title=cand.title,
                                     oracle=oracle.name)
                    best = verdict
        return best

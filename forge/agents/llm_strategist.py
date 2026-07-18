"""LLMStrategistAgent — the brain that spawns the specialist fleet.

This is the "LLM spans multiple sub-agents doing powerful stuff" layer. Given a
target, the strategist fans out a squad of LLMHypothesisAgents — one per lens
(overflow / integer / parser / use-after-free / NOVEL) — in parallel, each
reasoning about the asset through its own angle to surface candidate bugs,
including novel ones no signature knows for that asset. It aggregates their
hypotheses and hands them back as Candidates for the deterministic oracles to
prove. The brain reasons; the oracles adjudicate; nothing ships unproven.

Runs as a discovery agent alongside the deterministic fuzzer, so a run blends the
undeterministic (LLM intuition) and deterministic (fuzz + sanitizer) sides.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from ..ladder import Candidate
from .base import Agent
from .llm_hypothesis import LENSES, LLMHypothesisAgent


class LLMStrategistAgent(Agent):
    kind = "llm_strategist"

    def __init__(self, ctx, name: str = "llm-brain", parent_id: str = "", *,
                 harness: str = "", llm=None,
                 lenses: Optional[list[str]] = None, n_per_lens: int = 3) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.harness = harness
        self.llm = llm
        self.lenses = lenses or list(LENSES.keys())
        self.n_per_lens = n_per_lens

    async def run(self) -> list[Candidate]:
        if self.llm is None or not getattr(self.llm, "available", False):
            self.log("no model configured — LLM brain idle (deterministic side runs)")
            return []
        self.objective(f"LLM brain: fan out {len(self.lenses)} specialist "
                       f"bug-hunting sub-agents across lenses")
        squad = [self.child(LLMHypothesisAgent, lens=lens, harness=self.harness,
                            llm=self.llm, n=self.n_per_lens)
                 for lens in self.lenses]
        results = await asyncio.gather(*[a.execute() for a in squad],
                                       return_exceptions=True)
        cands: list[Candidate] = []
        for r in results:
            if isinstance(r, list):
                cands.extend(c for c in r if isinstance(c, Candidate))
        self.log(f"LLM brain gathered {len(cands)} hypotheses across "
                 f"{len(self.lenses)} lenses → handing to the oracles to prove")
        return cands

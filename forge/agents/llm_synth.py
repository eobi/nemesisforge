"""LLMSynthAgent — the LLM writes an exploit, the oracle proves it.

The intuition layer on top of the deterministic core. Fuzzing finds *a* crash;
this agent hands the LLM the crash + the current primitive and asks it to craft a
sharper input — one that widens the controlled write, reaches a cleaner primitive,
or satisfies a guard the blind fuzzer can't. Crucially, the LLM's output is never
trusted: the crafted input is fed straight to a deterministic oracle
(controllability / differential), and only a PROVEN climb counts. So the LLM adds
reach without adding hallucinated findings — model proposes, oracle disposes.

This is a sub-agent the escalation tier spawns when a model is configured; with
NullLLM it no-ops (and says so), so the deterministic pipeline is unaffected.
"""
from __future__ import annotations

import asyncio
import base64
import copy
from typing import Optional

from ..events import EventType
from ..ladder import Candidate, Outcome, Verdict
from .base import Agent

# Each payload-crafter attacks the primitive from a different angle.
STRATEGIES = {
    "widen": "maximize the out-of-bounds write EXTENT (longest controlled write)",
    "control": "make the faulting ADDRESS or overwritten VALUE attacker-chosen "
               "(toward write-what-where / PC control)",
    "guarded": "satisfy any length/magic/structure guards in the input so the "
               "payload reaches DEEPER code before crashing",
}

_SYSTEM = (
    "You are an exploit-development specialist. Given a proven crash, craft a "
    "single stdin input whose GOAL is: {goal}. You do NOT decide success — a "
    "sanitizer oracle checks your input. Reply ONLY with JSON: "
    "{{\"input_b64\": \"<base64 raw bytes>\", \"rationale\": \"<one line>\"}}.")


class LLMSynthAgent(Agent):
    kind = "llm_synth"

    def __init__(self, ctx, name: str = "synth", parent_id: str = "", *,
                 candidate: Optional[Candidate] = None, llm=None,
                 oracles: Optional[list] = None, rounds: int = 2,
                 strategy: str = "widen") -> None:
        super().__init__(ctx, name=f"{name}:{strategy}", parent_id=parent_id)
        self.candidate = candidate
        self.llm = llm
        self.oracles = list(oracles or [])
        self.rounds = rounds
        self.strategy = strategy

    async def run(self) -> Optional[Verdict]:
        cand, llm = self.candidate, self.llm
        if cand is None or llm is None or not getattr(llm, "available", False):
            self.log("no model configured — skipping LLM synthesis")
            return None
        goal = STRATEGIES.get(self.strategy, "deepen the bug")
        self.objective(f"LLM payload-crafter [{self.strategy}]: {goal}")
        system = _SYSTEM.format(goal=goal)

        crash = (cand.crash or {}) or {}
        best: Optional[Verdict] = None
        feedback = ""
        for i in range(self.rounds):
            prompt = self._prompt(cand, crash, feedback)
            self.think(i, "crafting a custom exploit payload")
            parsed, _meta = await asyncio.to_thread(llm.complete_json, system, prompt)
            b64 = (parsed or {}).get("input_b64") if isinstance(parsed, dict) else None
            if not b64:
                feedback = "your last reply was not valid JSON with input_b64"
                continue
            self.em.emit(EventType.POC_WRITTEN, title=cand.title,
                         rationale=(parsed.get("rationale") or "")[:120])
            new_cand = self._with_input(cand, b64)
            v = await self._certify(new_cand)
            if v is not None and v.outcome is Outcome.PROVEN:
                climbed = self.ctx.ladder.apply(new_cand, v)
                if climbed:
                    self.em.emit(EventType.RUNG_UP, title=cand.title,
                                 rung=int(v.rung), rung_name=v.rung.name)
                self.em.emit(EventType.VALIDATED, title=cand.title,
                             oracle=v.oracle, confirmed=True)
                best = v
                break
            feedback = "that input did not climb; try a longer/more-structured one"
        if best is None:
            self.log("LLM inputs did not certify a higher rung this run")
        return best

    async def _certify(self, cand: Candidate) -> Optional[Verdict]:
        for oracle in self.oracles:
            v = await asyncio.to_thread(oracle.verify, self.ctx, cand)
            if v.outcome is Outcome.PROVEN:
                return v
        return None

    @staticmethod
    def _with_input(cand: Candidate, b64: str) -> Candidate:
        new = copy.deepcopy(cand)
        new.proposed_check = {**(cand.proposed_check or {}), "input_b64": b64}
        return new

    @staticmethod
    def _prompt(cand: Candidate, crash: dict, feedback: str) -> str:
        cur = ""
        if cand.proposed_check and cand.proposed_check.get("input_b64"):
            cur = f"Current crashing input (base64): {cand.proposed_check['input_b64'][:120]}\n"
        fb = f"\nFeedback on your last attempt: {feedback}\n" if feedback else ""
        return (f"Bug: {cand.title}\nClass: {crash.get('bug_type', 'memory-safety')}\n"
                f"{cur}{fb}Craft one input that maximizes the out-of-bounds write.")

"""LLMHypothesisAgent — one specialist bug-hunting lens.

A single sub-agent under the LLM brain. It reads the actual asset (source via the
ACI, or binary strings) through its assigned *lens* — overflow, integer,
parser-confusion, use-after-free, or NOVEL (a pattern generic scanners miss) —
and proposes crafted inputs likely to trigger a bug of that kind. Its proposals
are just Candidates; the deterministic oracle builds + runs them and decides. So
each lens adds intuition about where novel bugs hide, without any power to assert
a finding on its own.

Many of these run in parallel (one per lens) — that's the "spawns multiple
sub-agents doing powerful stuff" layer, all proven deterministically.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from ..ladder import Candidate
from .base import Agent

LENSES = {
    "overflow": "buffer overflows — length/size taken from input without bounds "
                "checking, memcpy/strcpy/sprintf into fixed buffers",
    "integer": "integer overflow/underflow or signedness bugs whose result feeds "
               "an allocation size or array index",
    "parser": "parser/length-field confusion — a declared length driving a copy "
              "or seek, off-by-one on record boundaries",
    "uaf": "use-after-free / double-free / lifetime bugs across allocation and "
           "free paths",
    "novel": "a NOVEL, asset-specific weakness that generic signatures miss — "
             "reason about THIS code's unique assumptions and break one",
}

_SYSTEM = (
    "You are a world-class vulnerability researcher hunting for a {lens_desc}. "
    "You are shown snippets of a real target. Propose distinct stdin inputs that "
    "could trigger such a bug. You never decide success — a sanitizer oracle runs "
    "your inputs. Reply ONLY with JSON: a list of "
    "{{\"input_b64\": \"<base64 raw bytes>\", \"why\": \"<one line>\"}}.")


class LLMHypothesisAgent(Agent):
    kind = "llm_hypothesis"

    def __init__(self, ctx, name: str = "hypo", parent_id: str = "", *,
                 lens: str = "overflow", harness: str = "", llm=None,
                 n: int = 3, bug_class: str = "memory_safety") -> None:
        super().__init__(ctx, name=f"{name}:{lens}", parent_id=parent_id)
        self.lens = lens
        self.harness = harness
        self.llm = llm
        self.n = n
        self.bug_class = bug_class

    async def run(self) -> list[Candidate]:
        if self.llm is None or not getattr(self.llm, "available", False):
            return []
        self.objective(f"LLM[{self.lens}]: hypothesize {self.n} crashing inputs")
        context = self._context()
        self.think(0, f"read {len(context.splitlines())} risky-sink line(s) from the asset")
        system = _SYSTEM.format(lens_desc=LENSES.get(self.lens, self.lens))
        prompt = (f"Target snippets (risky sinks):\n{context}\n\n"
                  f"Propose {self.n} inputs to trigger a {self.lens} bug.")
        parsed, _meta = await asyncio.to_thread(self.llm.complete_json, system, prompt)
        cands: list[Candidate] = []
        for item in (parsed or []):
            if not isinstance(item, dict) or not item.get("input_b64"):
                continue
            cands.append(Candidate(
                bug_class=self.bug_class,
                title=f"[{self.lens}] {(item.get('why') or 'LLM hypothesis')[:80]}",
                rationale=item.get("why", ""), agent=self.name,
                proposed_check={"harness": self.harness,
                                "input_b64": item["input_b64"]}))
        self.log(f"{len(cands)} hypothesis input(s) from the {self.lens} lens")
        return cands

    def _context(self) -> str:
        """Pull risky-sink lines from the asset via the ACI (source targets)."""
        try:
            hits = self.aci.grep(r"memcpy|strcpy|strcat|sprintf|malloc|alloca|"
                                 r"read\(|recv\(|parse|memmove|\[[a-z_]+\]")
            return "\n".join(hits[:25]) or "(no source available; reason from the bug class)"
        except Exception:
            return "(no source available; reason from the bug class)"

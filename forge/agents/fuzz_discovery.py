"""A deterministic fuzzing discovery agent — finds a crash with no LLM.

Discovery agents produce Candidates for the oracles to certify. This one is the
LLM-free workhorse (and the Phase-A end-to-end driver): it builds a harness once,
then drives inputs into it until a sanitizer crash appears, and emits the
crashing input as a Candidate. The Coordinator then routes that candidate to the
SanitizerOracle, which *independently* rebuilds and re-runs to certify it — so
the finder never certifies its own find (writer ≠ validator).

The mutation strategy here is deliberately simple (length-growth over seeds);
smarter fuzzers / LLM harness-synth agents plug into the same Agent seam later.
Every attempt is streamed (think/tool events) so the fuzz loop is visible.
"""
from __future__ import annotations

import asyncio
import base64
from typing import Optional, Sequence

from ..ladder import Candidate, CodeLoc
from .base import Agent


class FuzzDiscoveryAgent(Agent):
    kind = "fuzz_discovery"

    def __init__(self, ctx, name: str = "fuzz", parent_id: str = "", *,
                 harness: str = "", seeds: Optional[Sequence[bytes]] = None,
                 max_tries: int = 24, max_len: int = 4096,
                 bug_class: str = "memory_safety") -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.harness = harness
        self.seeds = list(seeds or [b"A"])
        self.max_tries = max_tries
        self.max_len = max_len
        self.bug_class = bug_class

    async def run(self) -> list[Candidate]:
        self.objective("fuzz the harness for a memory-safety crash")
        target = self.ctx.target
        build = await asyncio.to_thread(target.build, self.harness)
        if not build.ok:
            self.log("harness build failed", log=build.log[-400:])
            return []
        self.tool_result("build", ok=True)

        size = 1
        for i in range(self.max_tries):
            if self.ctx.budget.expired():
                self.log("budget expired mid-fuzz")
                break
            inp = self._mutate(i, size)
            self.think(i, f"run input len={len(inp)}")
            # discovery only needs "did it crash + class" → skip symbolization
            # (the oracle re-runs with symbols to certify + locate the frame).
            obs = await asyncio.to_thread(target.run, build.binary, stdin=inp,
                                          symbolize=False, timeout=30.0)
            if obs.crashed:
                self.tool_result("run", crashed=True, bug=obs.crash.bug_type,
                                 summary=obs.crash.summary)
                self.log(f"crash found: {obs.crash.summary}")
                return [self._candidate(inp, obs.crash)]
            size = min(size * 2, self.max_len)
        self.log("no crash within fuzz budget")
        return []

    def _candidate(self, inp: bytes, crash) -> Candidate:
        top = crash.top
        return Candidate(
            bug_class=self.bug_class,
            title=crash.summary or f"{crash.bug_type} crash",
            rationale=f"fuzzing found an input ({len(inp)} bytes) that triggers "
                      f"{crash.bug_type}",
            location=CodeLoc(path=top.file if top else "", line=top.line if top else 0,
                             symbol=top.func if top else ""),
            agent=self.name,
            proposed_check={"harness": self.harness,
                            "input_b64": base64.b64encode(inp).decode()},
            crash={"bug_type": crash.bug_type, "stack_hash": crash.stack_hash},
        )

    def _mutate(self, i: int, size: int) -> bytes:
        seed = self.seeds[i % len(self.seeds)]
        return (seed * (size // max(1, len(seed)) + 1))[:size]

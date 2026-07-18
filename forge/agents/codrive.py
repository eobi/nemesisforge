"""CoDrivingFuzzAgent — the closed loop where reasoning and fuzzing co-drive.

This is Phase J, the novel core. A coverage-guided fuzzer is superb at exploring
once it's past a guard, but stalls on magic bytes / length fields / checksums it
can't guess. An LLM is superb at *reading the guard and satisfying it*, but has no
throughput. Neither alone beats a SQLite-class target. This agent fuses them:

  1. Fuzz — aimed (`-focus_function` at the sink the reasoning tier nominated,
     plus a targeted dictionary of the guard's literals).
  2. If it crashes → done (the oracle proves it).
  3. If it STALLS (a round adds ~no new coverage), hand the LLM the harness, the
     sink's guard code, and the current coverage, and ask for a structured input
     that satisfies the guard to REACH the sink. Inject that input into the corpus.
  4. Resume fuzzing — now mutating onward from the guard-passing seed.

So reasoning picks *where*, crafts the *key* that unlocks the guard, and fuzzing
does the massively-parallel *reaching* past it. Every crash is still oracle-proven;
the LLM never asserts a finding.
"""
from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from typing import Optional, Sequence

from .. import fuzzengine, triage
from ..analysis import cscan
from ..events import EventType
from ..ladder import Candidate
from .base import Agent
from .libfuzzer_discovery import build_candidate


class CoDrivingFuzzAgent(Agent):
    kind = "codrive_fuzz"

    def __init__(self, ctx, name: str = "codrive", parent_id: str = "", *,
                 harness: str = "", target_sources: Optional[Sequence[Path]] = None,
                 include_dirs: Optional[Sequence[Path]] = None,
                 corpus_dir: Optional[Path] = None, llm=None,
                 focus_function: str = "", guard_context: str = "",
                 dict_tokens: Optional[Sequence[str]] = None,
                 sanitizer: str = "address", bug_class: str = "memory_safety",
                 rounds: int = 4, round_time: int = 15, max_len: int = 4096) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.harness = harness
        self.target_sources = list(target_sources or [])
        self.include_dirs = list(include_dirs or [])
        self.corpus_dir = Path(corpus_dir) if corpus_dir else ctx.artifacts / "corpus"
        self.llm = llm
        self.focus_function = focus_function
        self.guard_context = guard_context
        self.dict_tokens = list(dict_tokens or [])
        self.sanitizer = sanitizer
        self.bug_class = bug_class
        self.rounds = rounds
        self.round_time = round_time
        self.max_len = max_len

    async def run(self) -> list[Candidate]:
        if fuzzengine.find_libfuzzer_clang() is None or not self.harness:
            return []
        aim = f" aimed at {self.focus_function}()" if self.focus_function else ""
        self.objective(f"co-driving fuzz{aim}: reasoning unlocks guards, fuzzing "
                       f"reaches past them")
        target = self.ctx.target
        build = await asyncio.to_thread(
            target.build, self.harness, fuzzer=True, sanitizer=self.sanitizer,
            target_sources=self.target_sources or None,
            include_dirs=self.include_dirs or None)
        if not build.ok:
            self.log("co-driving harness build failed", log=build.log[-300:])
            return []

        dpath = cscan.write_dict(self.dict_tokens,
                                 self.corpus_dir.parent / f"{self.name}.dict") \
            if self.dict_tokens else None
        seeds: list[bytes] = []
        asked: set[bytes] = set()            # LLM seeds already tried (dedup)
        best_cov = -1

        for i in range(self.rounds):
            if self.ctx.budget.expired():
                self.log("budget expired mid-loop")
                break
            fr = await asyncio.to_thread(
                target.fuzz, build.binary, corpus_dir=self.corpus_dir,
                dict_path=dpath, focus_function=self.focus_function, seeds=seeds,
                max_total_time=self.round_time, max_len=self.max_len)
            injected, seeds = bool(seeds), []
            # A focus function libFuzzer can't resolve (static/inlined/entry) makes
            # the round a no-op — drop it and fuzz un-focused from here on.
            if self.focus_function and "Failed to set focus function" in fr.output:
                self.log(f"focus '{self.focus_function}' not resolvable — "
                         f"continuing un-focused")
                self.focus_function = ""
            self.em.emit(EventType.COVERAGE, engine="libFuzzer", round=i,
                         cov=fr.coverage, features=fr.features, execs=fr.execs,
                         corpus=fr.corpus, crashed=fr.crashed,
                         focus=self.focus_function)

            if fr.crashed and fr.crash_input is not None:
                crash = triage.parse(fr.output)
                how = "LLM-seeded" if injected else "blind"
                self.log(f"crash on round {i} ({how}, cov={fr.coverage}): "
                         f"{crash.summary or crash.bug_type}")
                return [build_candidate(
                    inp=fr.crash_input, crash=crash, harness=self.harness,
                    target_sources=self.target_sources,
                    include_dirs=self.include_dirs, sanitizer=self.sanitizer,
                    bug_class=self.bug_class, agent=self.name,
                    rationale=f"co-driving loop: round {i} ({how}), cov="
                              f"{fr.coverage}, focus={self.focus_function or 'none'} "
                              f"→ {crash.bug_type}")]

            best_cov = max(best_cov, fr.coverage)
            # No crash: the guard hasn't been passed. Ask the reasoning tier for an
            # input that satisfies it, so the next round mutates from past the gate.
            if self.llm is None or not getattr(self.llm, "available", False):
                self.think(i, f"cov={fr.coverage}, no model to unlock the guard")
                continue                     # blind fuzzing only; keep trying
            self.think(i, f"cov={fr.coverage}, no crash — asking the LLM for an "
                          f"input that satisfies the guard")
            seed = await self._craft_seed(fr, best_cov)
            if seed and seed not in asked:
                asked.add(seed)
                seeds = [seed]
                self.em.emit(EventType.POC_WRITTEN, title="guard-passing seed",
                             rationale=f"reach {self.focus_function or 'sink'} "
                                       f"(round {i}, {len(seed)} bytes)")

        self.log(f"co-driving loop ended without a crash (best cov={best_cov})")
        return []

    async def _craft_seed(self, fr, best_cov: int) -> Optional[bytes]:
        system = (
            "You are an exploit developer helping a fuzzer get PAST an input guard. "
            "Given the harness and the target function's source, produce ONE input "
            "(raw bytes) that satisfies the guards (magic bytes, length fields, "
            "checksums) so execution REACHES the vulnerable code. The fuzzer will "
            "mutate onward from your input — you don't need to trigger the bug, just "
            'get past the gate. Reply ONLY JSON: {"input_b64":"<base64>","why":"<one line>"}.')
        prompt = (
            f"Harness:\n```c\n{self.harness[:1500]}\n```\n"
            f"Target function to reach ({self.focus_function or 'the sink'}):\n"
            f"```c\n{self.guard_context[:1800]}\n```\n"
            f"The coverage-guided fuzzer stalled at cov={fr.coverage} and cannot "
            f"guess the guard. Give one input that gets past it.")
        try:
            parsed, _meta = await asyncio.to_thread(
                self.llm.complete_json, system, prompt)
        except Exception as e:
            self.log(f"seed-craft call failed: {type(e).__name__}")
            return None
        b64 = parsed.get("input_b64") if isinstance(parsed, dict) else None
        if not b64:
            return None
        try:
            return base64.b64decode(b64)
        except Exception:
            return None

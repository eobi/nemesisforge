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
                 format_hints=None,
                 sanitizer: str = "address", bug_class: str = "memory_safety",
                 rounds: int = 4, round_time: int = 15, max_len: int = 4096,
                 campaign_minutes: int = 0) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.harness = harness
        self.target_sources = list(target_sources or [])
        self.include_dirs = list(include_dirs or [])
        self.corpus_dir = Path(corpus_dir) if corpus_dir else ctx.artifacts / "corpus"
        self.llm = llm
        self.focus_function = focus_function
        self.guard_context = guard_context
        self.dict_tokens = list(dict_tokens or [])
        # LLM format-aware inputs (format dictionary + structured seeds) — the
        # structure blind mutation lacks. Empty when no model / not generated.
        from .format_seeds import FormatHints
        self.format_hints = format_hints or FormatHints()
        self.sanitizer = sanitizer
        self.bug_class = bug_class
        self.max_len = max_len
        # Campaign mode (Phase L): spread a long budget over more, longer rounds so
        # the fuzzer can reach deep code — with the LLM still co-driving on stalls.
        if campaign_minutes:
            self.rounds = max(rounds, 8)
            self.round_time = max(30, (campaign_minutes * 60) // self.rounds)
        else:
            self.rounds = rounds
            self.round_time = round_time

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

        # Seed the corpus from the repo's own test/sample inputs (harvested once at
        # job start) — a cold empty corpus barely reaches shallow code; real inputs
        # jump straight into deep, valid-structure paths.
        seeded = self._seed_corpus()
        if seeded:
            self.log(f"seeded corpus with {seeded} repo test input(s)")

        # Merge cscan source-literal tokens with the LLM's binary FORMAT tokens into
        # one libFuzzer dictionary — gives the mutator the format's structure.
        from . import format_seeds as _fs
        dpath = _fs.write_dict(self.dict_tokens, self.format_hints.dict_tokens,
                               self.corpus_dir.parent / f"{self.name}.dict") \
            if (self.dict_tokens or self.format_hints.dict_tokens) else None
        # Inject the LLM's structured seeds (valid + bug-class edge cases) so round 0
        # starts NEAR the deep parsing frontier instead of cold.
        seeds: list[bytes] = list(self.format_hints.seeds)
        if seeds:
            self.log(f"injecting {len(seeds)} LLM structured seed(s) + "
                     f"{len(self.format_hints.dict_tokens)} format dict token(s)")
        asked: set[bytes] = set()            # LLM seeds already tried (dedup)
        best_cov = -1
        regen = 0                            # coverage-feedback regenerations (bounded)

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
                    coverage=fr.coverage, fuzz_output=fr.output,
                    rationale=f"co-driving loop: round {i} ({how}), cov="
                              f"{fr.coverage}, focus={self.focus_function or 'none'} "
                              f"→ {crash.bug_type}")]

            improved = fr.coverage > best_cov
            best_cov = max(best_cov, fr.coverage)
            # No crash: the guard hasn't been passed. Ask the reasoning tier for an
            # input that satisfies it, so the next round mutates from past the gate.
            if self.llm is None or not getattr(self.llm, "available", False):
                self.think(i, f"cov={fr.coverage}, no model to unlock the guard")
                continue                     # blind fuzzing only; keep trying
            batch: list[bytes] = []
            # Imp.1c: on a coverage PLATEAU, ask the LLM for STRUCTURED inputs that
            # reach format paths the fuzzer hasn't (OSS-Fuzz-Gen coverage feedback).
            # Bounded regenerations so a stuck target can't burn the budget on tokens.
            if not improved and regen < 2:
                fresh = [s for s in await self._coverage_seeds(fr)
                         if s and s not in asked]
                if fresh:
                    regen += 1
                    asked.update(fresh)
                    batch.extend(fresh)
                    self.em.emit(EventType.SEED, title="coverage-gap structured seeds",
                                 rationale=f"plateau cov={fr.coverage} → "
                                           f"{len(fresh)} new structured input(s)")
            self.think(i, f"cov={fr.coverage}, no crash — asking the LLM for an "
                          f"input that satisfies the guard")
            seed = await self._craft_seed(fr, best_cov)
            if seed and seed not in asked:
                asked.add(seed)
                batch.append(seed)
                # A guard-passing SEED is corpus fuel to reach deeper — NOT an
                # exploit. Emit SEED, not POC_WRITTEN, so crash/PoC counts (and the
                # monitor) never false-positive on co-driving seeds.
                self.em.emit(EventType.SEED, title="guard-passing seed",
                             rationale=f"reach {self.focus_function or 'sink'} "
                                       f"(round {i}, {len(seed)} bytes)")
            if batch:
                seeds = batch

        self.log(f"co-driving loop ended without a crash (best cov={best_cov})")
        return []

    def _seed_corpus(self) -> int:
        """Copy the repo's harvested test/sample inputs into the (possibly
        persistent) corpus. Content-hash names → idempotent across resumed runs."""
        import hashlib
        files = getattr(self.ctx, "seed_files", None) or []
        if not files:
            return 0
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        n = 0
        for p in files:
            try:
                data = Path(p).read_bytes()
                if not data or len(data) > self.max_len * 8:
                    continue
                dest = self.corpus_dir / f"seed_{hashlib.sha1(data).hexdigest()[:16]}"
                if not dest.exists():
                    dest.write_bytes(data)
                    n += 1
            except Exception:
                continue
        return n

    async def _coverage_seeds(self, fr) -> list[bytes]:
        """Imp.1c — on a coverage plateau, ask the LLM for a few STRUCTURED inputs
        that exercise format paths the fuzzer hasn't reached (different type tags,
        nesting, field sizes) plus a couple of bug-class edge cases. Returns decoded
        raw-byte seeds (validated); empty on any failure."""
        system = (
            "You are a fuzzing expert. A coverage-guided fuzzer has PLATEAUED on this "
            "parser. Produce 3-6 NEW, structurally-different valid inputs for this "
            "format that likely reach code paths the fuzzer hasn't (vary type tags, "
            "nesting depth, field sizes, optional features), plus 1-2 edge cases "
            "(declared length larger than the bytes present, truncation, zero-length). "
            'Reply ONLY JSON: {"seeds_b64":["<base64 raw bytes>", ...]}.')
        prompt = (
            f"Harness:\n```c\n{self.harness[:1400]}\n```\n"
            f"Target/parse function:\n```c\n{self.guard_context[:1600]}\n```\n"
            f"The fuzzer plateaued at cov={fr.coverage}. Give diverse structured "
            f"inputs to reach new code.")
        try:
            parsed, _ = await asyncio.to_thread(self.llm.complete_json, system, prompt)
        except Exception:
            parsed = None
        if not isinstance(parsed, dict):
            return []
        from .format_seeds import _decode
        return _decode(parsed.get("seeds_b64"), 8, max_len=self.max_len * 8)

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

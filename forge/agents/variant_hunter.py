"""VariantHunterAgent — the reasoning tier (Big Sleep's method).

Instead of fuzzing blindly, this agent first UNDERSTANDS the code: a dependency-
free static pass (forge.analysis.cscan) recovers functions, a call graph, and the
memory-safety sinks that are REACHABLE from an untrusted-input entry point and
INFLUENCED by that input. It hands that ranked evidence to the LLM, which does
variant analysis — "which of these sinks most likely hides a bug, and why (what
assumption could break, which known bug class does it resemble)?" — and nominates
targets. Each nomination then AIMS a harness-synth sub-agent at that exact source,
so the fuzzer's muscle is pointed where reasoning suspects a bug, not sprayed.

This is the seed of the co-driving loop (Phase J closes it with directed fuzzing +
coverage feedback). Reasoning proposes; the sanitizer oracle still proves.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from .. import fuzzengine
from ..analysis import cscan
from ..events import EventType
from ..ingest import repo as _repo
from ..ladder import Candidate
from .base import Agent
from .harness_synth import HarnessSynthAgent

_SYSTEM = (
    "You are a vulnerability researcher doing variant analysis on a C library. "
    "You are given the memory-safety sinks that are reachable from untrusted input, "
    "ranked by a static pass. Pick the ones MOST likely to hide a real "
    "memory-safety bug a fuzzer should target. For each, say which function to "
    "reach and one line on WHY (the assumption that could break, or the known bug "
    "class it resembles). Prefer input-influenced length/size math feeding a copy. "
    'Reply ONLY with JSON: a list of {"file":"<name>","function":"<fn>",'
    '"why":"<one line>"}.')


class VariantHunterAgent(Agent):
    kind = "variant_hunter"

    def __init__(self, ctx, name: str = "variant-hunter", parent_id: str = "", *,
                 repo: Optional[_repo.RepoInfo] = None, llm=None,
                 max_sources: int = 8, max_targets: int = 3, fuzz_time: int = 30,
                 sanitizer: str = "address,undefined",
                 corpus_root: Optional[Path] = None) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.repo = repo or getattr(ctx, "repo", None)
        self.llm = llm
        self.max_sources = max_sources
        self.max_targets = max_targets
        self.fuzz_time = fuzz_time
        self.sanitizer = sanitizer          # ASan + UBSan by default on repos
        self.corpus_root = Path(corpus_root) if corpus_root else ctx.artifacts / "corpus"

    async def run(self) -> list[Candidate]:
        if self.llm is None or not getattr(self.llm, "available", False):
            self.log("no model — reasoning tier idle")
            return []
        if self.repo is None or not self.repo.sources:
            self.log("no repo to analyze")
            return []
        if fuzzengine.find_libfuzzer_clang() is None:
            self.log("no libFuzzer-capable clang")
            return []

        self.objective(f"variant analysis on {self.repo.url} — rank reachable "
                       f"sinks, aim the fuzzer where a bug likely hides")

        # 1. static understanding — functions, call graph, reachable sinks.
        srcs = self.repo.sources[:self.max_sources]
        ci = await asyncio.to_thread(cscan.scan_repo, srcs)
        ranked = ci.ranked_sinks(limit=30)
        self.think(0, f"analyzed {len(ci.funcs)} functions, "
                      f"{len(ci.entry_points())} entry points, "
                      f"{len(ranked)} ranked reachable sinks")
        self.em.emit(EventType.COVERAGE, engine="cscan", functions=len(ci.funcs),
                     sinks=len(ci.sinks), entry_points=len(ci.entry_points()))
        if not ranked:
            return await self._fallback(srcs)

        # 2. LLM variant analysis over the ranked evidence → nominations.
        nominated = await self._reason(ranked)
        if not nominated:
            self.log("reasoning produced no nominations — harnessing top sinks")
            nominated = self._auto_nominate(ranked)

        # 3. aim a harness-synth sub-agent at each nominated source.
        by_file: dict[str, str] = {}
        for nom in nominated:
            f = self._resolve_src(nom.get("file", ""))
            if f and str(f) not in by_file:
                by_file[str(f)] = f"reach {nom.get('function','?')}() — {nom.get('why','')}"
                self.em.emit(EventType.CANDIDATE, title=f"suspect: {nom.get('function','?')}",
                             bug_class="memory_safety", agent=self.name,
                             why=nom.get("why", ""))

        candidates: list[Candidate] = []
        for i, (fpath, note) in enumerate(list(by_file.items())[:self.max_targets]):
            child = self.child(
                HarnessSynthAgent, repo=self.repo, llm=self.llm,
                sources=[Path(fpath)], focus_note=note, fuzz_time=self.fuzz_time,
                sanitizer=self.sanitizer, corpus_root=self.corpus_root,
                corpus_tag=f"v{i}_")
            candidates.extend(await child.execute() or [])

        self.log(f"{len(candidates)} candidate(s) from {len(by_file)} reasoned target(s)")
        return candidates

    async def _reason(self, ranked: list[cscan.Sink]) -> list[dict]:
        prompt = ("Reachable, input-influenced sinks (ranked):\n"
                  + cscan.summarize_sinks(ranked, limit=20)
                  + "\n\nNominate the most suspicious targets.")
        try:
            parsed, _meta = await asyncio.to_thread(
                self.llm.complete_json, _SYSTEM, prompt)
        except Exception as e:
            self.log(f"reasoning call failed: {type(e).__name__}")
            return []
        return [x for x in (parsed or []) if isinstance(x, dict)]

    @staticmethod
    def _auto_nominate(ranked: list[cscan.Sink]) -> list[dict]:
        seen, out = set(), []
        for s in ranked:
            if s.file in seen:
                continue
            seen.add(s.file)
            out.append({"file": Path(s.file).name, "function": s.func,
                        "why": f"{s.kind} sink, input-influenced"})
        return out

    def _resolve_src(self, name: str) -> Optional[Path]:
        name = Path(name).name
        for s in self.repo.sources:
            if s.name == name:
                return s
        return self.repo.sources[0] if self.repo.sources else None

    async def _fallback(self, srcs) -> list[Candidate]:
        """No sinks found (unusual) — fall back to plain harness synth."""
        child = self.child(HarnessSynthAgent, repo=self.repo, llm=self.llm,
                           max_targets=self.max_targets, fuzz_time=self.fuzz_time,
                           sanitizer=self.sanitizer, corpus_root=self.corpus_root)
        return await child.execute() or []

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

def _slug(x) -> str:
    """A filesystem-safe, STABLE corpus key per entry function (→ persistent corpus)."""
    import re as _re
    s = _re.sub(r"[^A-Za-z0-9_]", "_", str(x))[:48]
    return f"fn_{s}_"


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
                 campaign_minutes: int = 0, parallel: int = 3,
                 sanitizer: str = "address,undefined",
                 changed_functions: Optional[set] = None, seed_patch: str = "",
                 corpus_root: Optional[Path] = None, symbolic: bool = False) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.repo = repo or getattr(ctx, "repo", None)
        self.llm = llm
        self.max_sources = max_sources
        self.max_targets = max_targets
        self.fuzz_time = fuzz_time
        self.campaign_minutes = campaign_minutes   # Phase L: long persistent runs
        self.parallel = max(1, parallel)           # concurrent harness campaigns
        # Phase L3: seed from a real bug-fix patch → hunt UN-patched variants of
        # that exact pattern (Big Sleep's actual zero-day method).
        self.seed_patch = seed_patch
        self.symbolic = symbolic                   # also run the angr path lens
        self.sanitizer = sanitizer          # ASan + UBSan by default on repos
        # Continuous mode: when set, hunt ONLY sinks in functions changed by a diff
        # (catch the regression the day the commit lands — variant analysis's edge).
        self.changed_functions = set(changed_functions) if changed_functions else None
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

        mode = ("patch-seeded variant hunt — find un-patched twins of a known bug"
                if self.seed_patch else "rank reachable sinks + aim the fuzzer")
        self.objective(f"variant analysis on {self.repo.url} — {mode}")

        # 1. static understanding — functions, call graph, reachable sinks.
        srcs = self.repo.sources[:self.max_sources]
        ci = await asyncio.to_thread(cscan.scan_repo, srcs)
        ranked = ci.ranked_sinks(limit=30)
        if self.changed_functions:
            focused = [s for s in ranked if s.func in self.changed_functions]
            self.think(0, f"continuous mode: {len(self.changed_functions)} changed "
                          f"function(s) → {len(focused)}/{len(ranked)} sinks in scope")
            ranked = focused or ranked      # fall back to all if diff touched no sink
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

        # 3. Fan out by ENTRY FUNCTION (breadth): one harness per nominated
        # function — so even a single-file target yields MANY harnesses across
        # distinct APIs, each aimed + guard-seeded — and fuzz them in PARALLEL.
        targets: list[dict] = []
        seen: set[tuple] = set()
        for nom in nominated:
            f = self._resolve_src(nom.get("file", ""))
            fn = nom.get("function", "") or ""
            key = (str(f), fn)
            if not f or key in seen:
                continue
            seen.add(key)
            guard = cscan.func_body(ci, fn)
            targets.append({
                "src": f, "focus": fn if fn in ci.funcs else "",
                "note": f"reach {fn or '?'}() — {nom.get('why','')}",
                "guard": guard, "dict": cscan.guard_tokens(guard) if guard else []})
            self.em.emit(EventType.CANDIDATE, title=f"suspect: {fn or '?'}",
                         bug_class="memory_safety", agent=self.name,
                         why=nom.get("why", ""))
        targets = targets[:self.max_targets]

        # Imp.1 (structure-aware inputs): generate a format dictionary + structured
        # seed corpus ONCE per campaign — the format is target-level, so all harnesses
        # share it. This is the top lever: it gives the fuzzer the valid-but-
        # pathological structured inputs blind byte-mutation can't build.
        fh = await self._format_hints(ci, targets)
        if fh and not fh.empty():
            self.log(f"format-aware inputs: {len(fh.dict_tokens)} dict token(s), "
                     f"{len(fh.seeds)} structured seed(s)")

        async def _hunt(t, i):
            child = self.child(
                HarnessSynthAgent, repo=self.repo, llm=self.llm,
                sources=[t["src"]], lib_sources=self.repo.library,
                focus_note=t["note"], focus_function=t["focus"],
                guard_context=t["guard"], dict_tokens=t["dict"],
                fuzz_time=self.fuzz_time, campaign_minutes=self.campaign_minutes,
                sanitizer=self.sanitizer, corpus_root=self.corpus_root,
                symbolic=self.symbolic, format_hints=fh,
                corpus_tag=_slug(t["focus"] or i))
            return await child.execute() or []

        sem = asyncio.Semaphore(self.parallel)
        async def _guarded(t, i):
            async with sem:
                return await _hunt(t, i)
        results = await asyncio.gather(*[_guarded(t, i) for i, t in enumerate(targets)],
                                       return_exceptions=True)
        candidates: list[Candidate] = []
        for r in results:
            if isinstance(r, list):
                candidates.extend(r)

        self.log(f"{len(candidates)} candidate(s) from {len(targets)} reasoned "
                 f"entry-point(s), fuzzed in parallel")
        return candidates

    async def _reason(self, ranked: list[cscan.Sink]) -> list[dict]:
        sinks = cscan.summarize_sinks(ranked, limit=20)
        if self.seed_patch:
            # Variant analysis: find UN-patched twins of a known, just-fixed bug.
            system = (
                "You are doing variant analysis. A memory-safety bug was just FIXED "
                "by the patch below. Bugs like it often have un-fixed TWINS — the "
                "same mistake copy-pasted or repeated elsewhere. Given the target's "
                "sinks, nominate functions that contain the SAME pattern the patch "
                "fixed but do NOT appear to be fixed. "
                'Reply ONLY JSON: a list of {"file":"<name>","function":"<fn>",'
                '"why":"<the shared pattern>"}.')
            prompt = (f"The bug-fix patch:\n```diff\n{self.seed_patch[:5000]}\n```\n\n"
                      f"Target sinks (reachable, input-influenced):\n{sinks}\n\n"
                      f"Nominate un-patched variants of the fixed bug.")
            try:
                parsed, _m = await asyncio.to_thread(
                    self.llm.complete_json, system, prompt)
            except Exception as e:
                self.log(f"variant reasoning failed: {type(e).__name__}")
                return []
            return [x for x in (parsed or []) if isinstance(x, dict)]
        prompt = ("Reachable, input-influenced sinks (ranked):\n"
                  + sinks
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

    async def _format_hints(self, ci, targets):
        """LLM format dictionary + structured seeds, once per campaign (Imp.1)."""
        from .format_seeds import generate, FormatHints
        if self.llm is None or not getattr(self.llm, "available", False):
            return FormatHints()
        header = ""
        for h in (getattr(self.repo, "headers", None) or []):
            try:
                header = Path(h).read_text(errors="replace")[:3000]
                break
            except Exception:
                continue
        top = targets[0] if targets else {}
        entry = ""
        if top.get("src"):
            try:
                entry = _repo.entry_snippet(top["src"])
            except Exception:
                entry = ""
        try:
            return await generate(self.llm, library=getattr(self.repo, "url", ""),
                                  header=header, entry=entry,
                                  guard=top.get("guard", ""), bug_class="memory_safety")
        except Exception:
            return FormatHints()

    async def _fallback(self, srcs) -> list[Candidate]:
        """No sinks found (unusual) — fall back to plain harness synth."""
        child = self.child(HarnessSynthAgent, repo=self.repo, llm=self.llm,
                           max_targets=self.max_targets, fuzz_time=self.fuzz_time,
                           campaign_minutes=self.campaign_minutes,
                           sanitizer=self.sanitizer, corpus_root=self.corpus_root,
                           symbolic=self.symbolic)
        return await child.execute() or []

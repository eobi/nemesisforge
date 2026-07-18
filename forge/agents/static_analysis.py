"""StaticAnalysisAgent — the SOURCE-code lens, run alongside the fuzzer.

Fuzzing only sees code it can drive into; this reads the source and reasons over
every path (Clang Static Analyzer). Its warnings are LEADS, not proofs — so they
don't enter the proven-findings ladder; they're surfaced as visible source-level
suspects, persisted for review, and (crucially) they CORROBORATE dynamic findings:
when static and the fuzzer point at the same function, confidence jumps. A lead
that a human/next pass then confirms dynamically becomes a real finding.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from ..analysis import clang_static
from ..events import EventType
from ..ladder import Candidate
from .base import Agent


class StaticAnalysisAgent(Agent):
    kind = "static_analysis"

    def __init__(self, ctx, name: str = "static", parent_id: str = "", *,
                 repo=None, compiler: str = "clang", max_files: int = 40) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.repo = repo or getattr(ctx, "repo", None)
        self.compiler = compiler
        self.max_files = max_files

    async def run(self) -> list[Candidate]:
        if self.repo is None or not getattr(self.repo, "library", None):
            self.log("no repo sources for static analysis")
            return []
        if not clang_static.available(self.compiler):
            self.log("clang static analyzer unavailable")
            return []
        self.objective("static-analysis lens: read the source, flag memory-safety "
                       "leads on paths the fuzzer may never reach")
        incs = [self.repo.root] + sorted({p.parent for p in self.repo.headers})
        findings = await asyncio.to_thread(
            clang_static.analyze, self.repo.library, include_dirs=incs,
            compiler=self.compiler, max_files=self.max_files)

        mem = [f for f in findings if f.kind != "static-warning"]
        for f in findings[:40]:
            self.em.emit(EventType.CANDIDATE, title=f"static: {f.kind}",
                         bug_class="static_lead", agent=self.name,
                         why=f"{Path(f.file).name}:{f.line} — {f.message[:80]}")
        # persist as leads (NOT proven findings — they need dynamic confirmation)
        try:
            import json
            (self.ctx.artifacts / "static_leads.json").write_text(
                json.dumps([f.to_dict() for f in findings], indent=2))
        except Exception:
            pass
        self.log(f"static analysis: {len(findings)} lead(s) "
                 f"({len(mem)} memory-safety) — leads, need dynamic confirmation")
        return []                            # leads, not oracle-provable candidates

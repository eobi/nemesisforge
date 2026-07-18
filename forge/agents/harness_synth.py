"""HarnessSynthAgent — the LLM writes a fuzz harness for a real repo, coverage
proves it's alive. This is what turns "a git URL" into "a fuzzable target".

For each ranked entry-point source in an ingested repo, the model writes an
`LLVMFuzzerTestOneInput` harness that includes the right header and drives the
fuzz bytes into the library's untrusted-input function (parse/decode/load/…). The
harness is never trusted on the model's say-so: Forge compiles it and runs a short
libFuzzer probe, and only a harness that reaches NON-TRIVIAL COVERAGE (i.e. it
actually executes target code) survives — the exact quality gate OSS-Fuzz-Gen uses
to throw away dead harnesses. Survivors are handed to LibFuzzerDiscoveryAgent for a
full coverage-guided session; every crash is still proven by the SanitizerOracle.

With no model configured it no-ops cleanly.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Optional

from .. import fuzzengine
from ..events import EventType
from ..ingest import repo as _repo
from ..ladder import Candidate
from .base import Agent
from .libfuzzer_discovery import LibFuzzerDiscoveryAgent

# A harness that never enters target code stalls at a handful of edges; a live one
# exploring a parser climbs fast. Below this after a probe → dead, discarded.
_LIVE_COV = 3

_SYSTEM = (
    "You are a fuzzing engineer. Write a libFuzzer harness in C for the given "
    "library so it exercises an UNTRUSTED-INPUT function (a parser/decoder/loader "
    "that takes a buffer). Requirements:\n"
    "- Define `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.\n"
    "- #include the library's public header (given).\n"
    "- Feed data/size into the most attacker-facing entry point. NUL-terminate "
    "into a heap copy if the API needs a C string. Free what you allocate.\n"
    "- No main(), no I/O, no network. Must compile against ONLY the given "
    "header + source.\n"
    'Reply ONLY with JSON: {"harness":"<full C source>","entry":"<function you '
    'called>"}.')


class HarnessSynthAgent(Agent):
    kind = "harness_synth"

    def __init__(self, ctx, name: str = "harness-synth", parent_id: str = "", *,
                 repo: Optional[_repo.RepoInfo] = None, llm=None,
                 max_targets: int = 3, fuzz_time: int = 30,
                 probe_time: int = 6, corpus_root: Optional[Path] = None,
                 sources: Optional[list] = None, focus_note: str = "",
                 corpus_tag: str = "h") -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.repo = repo or getattr(ctx, "repo", None)
        self.llm = llm
        self.max_targets = max_targets
        self.fuzz_time = fuzz_time
        self.probe_time = probe_time
        self.corpus_root = Path(corpus_root) if corpus_root else ctx.artifacts / "corpus"
        # When the reasoning tier aims us at specific sources/sinks (Phase I), we
        # harness exactly those with the suspect sink emphasized in the prompt.
        self.sources = [Path(s) for s in sources] if sources else None
        self.focus_note = focus_note
        self.corpus_tag = corpus_tag

    async def run(self) -> list[Candidate]:
        if self.llm is None or not getattr(self.llm, "available", False):
            self.log("no model configured — cannot synthesize harnesses")
            return []
        if self.repo is None or not self.repo.sources:
            self.log("no ingested repo / no candidate sources to harness")
            return []
        if fuzzengine.find_libfuzzer_clang() is None:
            self.log("no libFuzzer-capable clang — cannot fuzz synthesized harnesses")
            return []

        self.objective(f"synthesize + coverage-validate fuzz harnesses for "
                       f"{self.repo.url} ({self.repo.ref})")
        incs = [self.repo.root] + sorted({p.parent for p in self.repo.headers})
        candidates: list[Candidate] = []

        targets = self.sources or self.repo.sources[:self.max_targets]
        for i, src in enumerate(targets):
            header = self._header_for(src)
            self.think(i, f"harnessing {src.name}"
                          + (f" via {header.name}" if header else ""))
            harness = await self._synth(src, header)
            if not harness:
                continue

            corpus = self.corpus_root / f"{self.corpus_tag}{i}"
            live, cov, why = await self._validate(harness, src, incs, corpus)
            self.em.emit(EventType.HARNESS, source=src.name,
                         entry=header.name if header else "", built=live,
                         coverage=cov, reason=why)
            if not live:
                self.log(f"discarded dead/uncompilable harness for {src.name}: {why}")
                continue

            self.log(f"live harness for {src.name} (probe cov={cov}) — full fuzz")
            child = self.child(
                LibFuzzerDiscoveryAgent, harness=harness, target_sources=[src],
                include_dirs=incs, corpus_dir=corpus, max_total_time=self.fuzz_time)
            candidates.extend(await child.execute() or [])

        self.log(f"{len(candidates)} candidate(s) from {self.max_targets} "
                 f"synthesized harness(es)")
        return candidates

    async def _synth(self, src: Path, header: Optional[Path]) -> str:
        hdr_txt = ""
        if header:
            try:
                hdr_txt = header.read_text(errors="replace")[:6000]
            except Exception:
                hdr_txt = ""
        focus = (f"\nPRIORITY TARGET (the reasoning tier flagged this as the most "
                 f"likely bug): {self.focus_note}\nWrite the harness so the fuzzer "
                 f"REACHES that code path.\n") if self.focus_note else ""
        prompt = (
            f"Library: {self.repo.url}\n"
            f"Public header ({header.name if header else 'none'}):\n"
            f"```c\n{hdr_txt}\n```\n"
            f"Entry-point-bearing source: {src.name}\n"
            f"```c\n{_repo.entry_snippet(src)}\n```\n"
            f"{focus}"
            f"Write the libFuzzer harness.")
        try:
            parsed, _meta = await asyncio.to_thread(
                self.llm.complete_json, _SYSTEM, prompt)
        except Exception as e:
            self.log(f"harness synth call failed: {type(e).__name__}")
            return ""
        harness = ""
        if isinstance(parsed, dict):
            harness = parsed.get("harness") or ""
        if not harness and isinstance(parsed, str):
            harness = _extract_c(parsed)
        harness = _extract_c(harness) if "```" in harness else harness
        if header and header.name not in harness:
            harness = f'#include "{header.name}"\n' + harness
        return harness if "LLVMFuzzerTestOneInput" in harness else ""

    async def _validate(self, harness: str, src: Path, incs, corpus: Path
                        ) -> tuple[bool, int, str]:
        """Build the harness against the target source, then a short libFuzzer
        probe. Live iff it compiles AND reaches non-trivial coverage (or crashes)."""
        target = self.ctx.target
        build = await asyncio.to_thread(
            target.build, harness, fuzzer=True, target_sources=[src],
            include_dirs=incs)
        if not build.ok:
            return False, 0, "build failed: " + (build.log or "")[-300:]
        fr = await asyncio.to_thread(
            target.fuzz, build.binary, corpus_dir=corpus,
            max_total_time=self.probe_time)
        if fr.crashed:
            return True, fr.coverage, "crashed during probe"
        if fr.coverage >= _LIVE_COV:
            return True, fr.coverage, "reaches target coverage"
        return False, fr.coverage, f"trivial coverage ({fr.coverage}) — dead harness"

    def _header_for(self, src: Path) -> Optional[Path]:
        stem = src.with_suffix(".h")
        if stem.exists():
            return stem
        # public header often shares a prefix (e.g. cJSON.c → cJSON.h)
        for h in self.repo.headers:
            if h.stem.lower() == src.stem.lower():
                return h
        return self.repo.headers[0] if self.repo.headers else None


def _extract_c(text: str) -> str:
    m = re.search(r"```(?:c|cpp|c\+\+)?\s*(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip()

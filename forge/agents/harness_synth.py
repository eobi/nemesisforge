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
from .codrive import CoDrivingFuzzAgent
from .symbolic_hunter import SymbolicHunterAgent, angr_available

# A harness that never enters target code stalls at a handful of edges; a live one
# exploring a parser climbs fast. Below this after a probe → dead, discarded.
_LIVE_COV = 3

# Anti-artifact rules keep the harness from crashing on ITS OWN mistakes (NULL
# required args, mis-sized buffers, fuzz bytes used as a size/filename) instead of a
# real library bug — the exact false positives the misuse-triage exists to catch.
_ANTI_ARTIFACT = (
    "- Fuzz ONLY the untrusted INPUT DATA (data/size). NEVER pass the fuzz bytes as "
    "a size, length, count, capacity, index, or filename — those are caller- "
    "controlled, not attacker-controlled, and using them creates FALSE crashes.\n"
    "- Provide VALID, non-NULL arguments for every REQUIRED parameter (parser/context "
    "objects, callback/handler structs, output buffers). If a function takes a "
    "callbacks/handlers struct, pass a real zero-initialized struct (declare a local, "
    "`memset(&cb,0,sizeof cb)`, pass `&cb`), NOT NULL — a required pointer passed as "
    "NULL is a HARNESS bug, not a library bug. Only omit params the docs call optional.\n"
    "- Size any OUTPUT buffer correctly and generously for the ONE decode/parse call "
    "you make; never reuse one buffer across calls that need different sizes.\n"
    "- Prefer ONE documented entry point per harness with correct setup. A crash must "
    "be the LIBRARY's fault on untrusted input, not the harness mis-using the API.\n"
    "- Call ONLY functions DECLARED in the given public header. NEVER call internal or "
    "static helper functions (they are not visible/linkable from a separate harness "
    "translation unit and the build fails with 'undeclared function'). Reach internal "
    "code THROUGH the public entry point, not by calling it directly.\n")

_SYSTEM = (
    "You are a fuzzing engineer. Write a libFuzzer harness in C for the given "
    "library so it exercises an UNTRUSTED-INPUT function (a parser/decoder/loader "
    "that takes a buffer). Requirements:\n"
    "- Define `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.\n"
    "- #include the library's public header (given).\n"
    "- Feed data/size into the most attacker-facing entry point. NUL-terminate "
    "into a heap copy if the API needs a C string. Free what you allocate.\n"
    + _ANTI_ARTIFACT +
    "- No main(), no I/O, no network. Must compile against ONLY the given "
    "header + source.\n"
    'Reply ONLY with JSON: {"harness":"<full C source>","entry":"<function you '
    'called>"}.')

# Same brief, but for models that answer better in raw code than strict JSON.
_SYSTEM_RAW = (
    "You are a fuzzing engineer. Write ONE complete libFuzzer harness in PURE C "
    "(C99) for the given library so it exercises an UNTRUSTED-INPUT function "
    "(a parser/decoder/loader/exec that takes a buffer or string). Rules:\n"
    "- Define exactly `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.\n"
    "- #include the library's public header (given) and any libc headers you use.\n"
    "- If the API needs a C string, COPY the input into a malloc'd buffer of "
    "size+1 and NUL-terminate it; free everything you allocate.\n"
    + _ANTI_ARTIFACT +
    "- Guard against size==0.\n"
    "- PURE C ONLY: no C++ — do NOT use nullptr (use NULL), reinterpret_cast (use a "
    "C cast), lambdas, templates, `extern \"C\"`, or `//`-only C++ idioms.\n"
    "- No main(), no I/O, no network. Must compile as C against the header+source.\n"
    "Output ONLY the C code inside a ```c code block — no prose.")


class HarnessSynthAgent(Agent):
    kind = "harness_synth"

    def __init__(self, ctx, name: str = "harness-synth", parent_id: str = "", *,
                 repo: Optional[_repo.RepoInfo] = None, llm=None,
                 max_targets: int = 3, fuzz_time: int = 30,
                 probe_time: int = 6, corpus_root: Optional[Path] = None,
                 sources: Optional[list] = None, lib_sources: Optional[list] = None,
                 focus_note: str = "",
                 focus_function: str = "", guard_context: str = "",
                 dict_tokens: Optional[list] = None, repairs: int = 2,
                 campaign_minutes: int = 0, symbolic: bool = False,
                 format_hints=None,
                 sanitizer: str = "address", corpus_tag: str = "h") -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.repo = repo or getattr(ctx, "repo", None)
        self.llm = llm
        # Link the harness against the WHOLE library (multi-file libs need every .c
        # to resolve symbols), not just the nominated file.
        self.lib_sources = [Path(s) for s in lib_sources] if lib_sources else None
        self.max_targets = max_targets
        self.fuzz_time = fuzz_time
        self.probe_time = probe_time
        self._repairs = repairs           # build-repair rounds for weak models
        self.campaign_minutes = campaign_minutes
        self.focus_function = focus_function      # Phase J: aim the fuzzer here
        self.guard_context = guard_context        # sink source for LLM seed-craft
        self.dict_tokens = list(dict_tokens or [])
        self.sanitizer = sanitizer
        self.corpus_root = Path(corpus_root) if corpus_root else ctx.artifacts / "corpus"
        # When the reasoning tier aims us at specific sources/sinks (Phase I), we
        # harness exactly those with the suspect sink emphasized in the prompt.
        self.sources = [Path(s) for s in sources] if sources else None
        self.focus_note = focus_note
        self.corpus_tag = corpus_tag
        self.symbolic = symbolic          # also run the angr PATH lens per harness
        self.format_hints = format_hints  # LLM format dict + structured seeds (Imp.1)

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
                # surface it — a model that can't write a harness is a real
                # outcome, not a silent zero.
                self.em.emit(EventType.HARNESS, source=src.name, built=False,
                             coverage=0, reason="model produced no usable harness")
                self.log(f"no usable harness synthesized for {src.name} "
                         f"(model: {getattr(self.llm, 'model', '?')})")
                continue

            corpus = self.corpus_root / f"{self.corpus_tag}{i}"
            # Build + probe with a repair loop: a weak model's first harness often
            # has a small C bug (undeclared var, wrong API arity). Feed the compiler
            # error back and let it fix — a couple of rounds turns "0 findings" into
            # a real fuzz session.
            live = False
            for attempt in range(self._repairs + 1):
                ok, live, cov, why, log = await self._build_probe(harness, src, incs, corpus)
                self.em.emit(EventType.HARNESS, source=src.name,
                             entry=header.name if header else "", built=ok,
                             coverage=cov, reason=why, attempt=attempt)
                if ok:
                    break
                if attempt < self._repairs:
                    # Deterministic first: drop any include the compiler couldn't
                    # find (hallucinated, or a real-but-wrong-platform header like
                    # minmea's ti-rtos compat). Cheaper + more reliable than an LLM
                    # round, and it doesn't cost a model call.
                    stripped = _drop_missing_includes(harness, log)
                    if stripped != harness:
                        self.think(i, f"harness for {src.name}: dropping unresolved "
                                      f"include(s), rebuilding")
                        harness = stripped
                        continue
                    self.think(i, f"harness for {src.name} didn't compile — "
                                  f"repairing (round {attempt + 1})")
                    fixed = await self._repair(harness, log)
                    if not fixed or fixed == harness:
                        break
                    harness = fixed
            # Imp.2b: the harness COMPILES but reaches little coverage — instead of
            # discarding it, ask the LLM to EXPAND it to exercise more of the API
            # surface (OSS-Fuzz-Gen coverage improvement), then rebuild+probe once.
            if ok and not live:
                improved = await self._improve_coverage(harness, src, cov)
                if improved and improved != harness:
                    self.think(i, f"harness for {src.name}: expanding to raise coverage")
                    ok2, live2, cov2, _why2, _lg = await self._build_probe(
                        improved, src, incs, corpus)
                    self.em.emit(EventType.HARNESS, source=src.name, built=ok2,
                                 coverage=cov2, reason="coverage-improved", attempt=99)
                    if ok2 and live2:
                        harness, live, cov = improved, live2, cov2
            if not live:
                self.log(f"no live harness for {src.name} after "
                         f"{self._repairs} repair(s): {why}")
                continue

            self.log(f"live harness for {src.name} (probe cov={cov}) — co-driving fuzz"
                     + (f" aimed at {self.focus_function}()" if self.focus_function else ""))
            rounds = 4
            child = self.child(
                CoDrivingFuzzAgent, harness=harness,
                target_sources=self.lib_sources or [src],
                include_dirs=incs, corpus_dir=corpus, llm=self.llm,
                focus_function=self.focus_function, guard_context=self.guard_context,
                dict_tokens=self.dict_tokens, sanitizer=self.sanitizer,
                campaign_minutes=self.campaign_minutes,
                format_hints=self.format_hints,
                rounds=rounds, round_time=max(6, self.fuzz_time // rounds))
            # Multi-lens: run the SYMBOLIC (angr) path lens in parallel with the
            # co-driving fuzzer on the SAME harness — it solves guards the fuzzer
            # stalls on and flags attacker-controlled states, all confirmed by the
            # same oracle. No-ops cleanly if angr is absent.
            tasks = [child.execute()]
            if self.symbolic and angr_available():
                # Bound angr's budget to the fuzz budget so it finishes alongside
                # the co-driving fuzzer and never dominates wall-time. (angr is
                # most effective on Linux/ELF; on macOS Mach-O it degrades and
                # no-ops cleanly.)
                sym_budget = min(300, (self.campaign_minutes * 60)
                                 or max(30, self.fuzz_time))
                sym = self.child(
                    SymbolicHunterAgent, harness=harness,
                    target_sources=self.lib_sources or [src],
                    include_dirs=incs, sanitizer=self.sanitizer,
                    corpus_dir=corpus,       # Imp.4b: symbolic inputs → fuzzer corpus
                    max_seconds=sym_budget)
                tasks.append(sym.execute())
            for res in await asyncio.gather(*tasks):
                candidates.extend(res or [])

        self.log(f"{len(candidates)} candidate(s) from {len(targets)} "
                 f"harnessed source(s)")
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

        # Local coder models (Ollama) reliably write C but NOT strict JSON, so ask
        # for raw C first and extract it; frontier models can also answer as JSON.
        harness = ""
        try:
            raw = await asyncio.to_thread(self.llm.complete, _SYSTEM_RAW, prompt,
                                          max_tokens=1600)
            harness = _extract_c(raw or "")
        except Exception as e:
            self.log(f"harness synth (raw) failed: {type(e).__name__}")
        if "LLVMFuzzerTestOneInput" not in harness:
            try:
                parsed, _m = await asyncio.to_thread(
                    self.llm.complete_json, _SYSTEM, prompt)
                if isinstance(parsed, dict) and parsed.get("harness"):
                    harness = _extract_c(str(parsed["harness"]))
            except Exception:
                pass
        if not harness or "LLVMFuzzerTestOneInput" not in harness:
            return ""
        harness = self._strip_bad_includes(harness)
        if header and header.name not in harness:
            harness = f'#include "{header.name}"\n' + harness
        return harness

    def _strip_bad_includes(self, harness: str) -> str:
        """Drop hallucinated LOCAL includes (#include "config.h" and friends) that
        don't correspond to any header in the repo — a frequent LLM slip that fails
        the build on line 1 before the repair loop even helps. Keeps every system
        <...> include and every real repo header (matched by basename)."""
        valid = {h.name for h in (self.repo.headers or [])}
        if not valid:                        # unknown header set → don't touch it
            return harness
        out = []
        for line in harness.splitlines():
            m = re.match(r'\s*#\s*include\s*"([^"]+)"', line)
            if m and m.group(1).split("/")[-1] not in valid:
                continue                     # hallucinated / unresolvable local include
            out.append(line)
        return "\n".join(out)

    async def _build_probe(self, harness: str, src: Path, incs, corpus: Path
                           ) -> tuple[bool, bool, int, str, str]:
        """Build the harness against the target, then a short libFuzzer probe.
        Returns (build_ok, live, cov, reason, build_log). Live iff it compiles AND
        reaches non-trivial coverage (or crashes)."""
        target = self.ctx.target
        build = await asyncio.to_thread(
            target.build, harness, fuzzer=True, sanitizer=self.sanitizer,
            target_sources=self.lib_sources or [src], include_dirs=incs)
        if not build.ok:
            return False, False, 0, "build failed", build.log or ""
        fr = await asyncio.to_thread(
            target.fuzz, build.binary, corpus_dir=corpus,
            max_total_time=self.probe_time)
        if fr.crashed:
            return True, True, fr.coverage, "crashed during probe", ""
        if fr.coverage >= _LIVE_COV:
            return True, True, fr.coverage, "reaches target coverage", ""
        return True, False, fr.coverage, f"trivial coverage ({fr.coverage})", ""

    async def _repair(self, harness: str, build_log: str) -> str:
        """Hand the compiler errors back to the model to fix the harness."""
        errs = "\n".join(l for l in build_log.splitlines()
                         if "error:" in l or "warning:" in l)[:1200] \
            or build_log[-1200:]
        system = ("You are fixing a C libFuzzer harness that failed to compile. "
                  "Return the CORRECTED complete harness as pure C in a ```c block "
                  "— keep LLVMFuzzerTestOneInput, declare every variable, match the "
                  "real API signatures, no C++.")
        prompt = (f"Harness:\n```c\n{harness}\n```\n\nCompiler errors:\n{errs}\n\n"
                  f"Return the fixed harness.")
        try:
            raw = await asyncio.to_thread(self.llm.complete, system, prompt,
                                          max_tokens=1600)
        except Exception:
            return ""
        fixed = _extract_c(raw or "")
        return fixed if "LLVMFuzzerTestOneInput" in fixed else ""

    async def _improve_coverage(self, harness: str, src: Path, cov: int) -> str:
        """Imp.2b — the harness compiles but reaches little coverage. Ask the LLM to
        EXPAND it to exercise more of the library's untrusted-input API (OSS-Fuzz-Gen
        coverage improvement). Keeps the anti-artifact rules. Returns "" on failure."""
        if self.llm is None or not getattr(self.llm, "available", False):
            return ""
        system = (
            "You are a fuzzing engineer. This libFuzzer harness COMPILES but reaches "
            "very little coverage — it exercises too little of the library. Rewrite it "
            "to call MORE of the library's untrusted-input API (additional parse/"
            "decode/read entry points, and follow-up calls that CONSUME the parsed "
            "result) so the fuzzer reaches deeper code. Keep the exact signature "
            "`int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`. Keep the "
            "anti-artifact rules: fuzz ONLY the input data, valid non-NULL required "
            "args, correct buffer sizing, no fuzz-as-size/filename. Pure C. Output "
            "ONLY the C code in a ```c block.")
        prompt = (
            f"Current harness (coverage only {cov}):\n```c\n{harness[:2500]}\n```\n"
            f"Source under test:\n```c\n{_repo.entry_snippet(src)[:1800]}\n```\n"
            "Rewrite the harness to reach more of the API.")
        try:
            raw = await asyncio.to_thread(self.llm.complete, system, prompt,
                                          max_tokens=1600)
        except Exception:
            return ""
        out = self._strip_bad_includes(_extract_c(raw or ""))
        return out if "LLVMFuzzerTestOneInput" in out else ""

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


def _drop_missing_includes(harness: str, log: str) -> str:
    """Remove #include lines for headers the compiler reported as not found, using
    the build log's `'foo.h' file not found` diagnostics. Handles hallucinated
    includes AND real-but-unreachable platform headers (minmea's ti-rtos compat).
    Returns the harness unchanged if there is nothing to drop."""
    missing = set(re.findall(r"['\"]([^'\"]+\.h)['\"] file not found", log or ""))
    if not missing:
        return harness
    bases = {m.split("/")[-1] for m in missing}
    out = []
    for line in harness.splitlines():
        m = re.match(r'\s*#\s*include\s*[<"]([^>"]+)[>"]', line)
        if m and m.group(1).split("/")[-1] in bases:
            continue
        out.append(line)
    return "\n".join(out)

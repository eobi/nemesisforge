"""LibFuzzerDiscoveryAgent — real coverage-guided fuzzing muscle.

The workhorse that replaces the legacy length-sweep. It compiles an
`LLVMFuzzerTestOneInput` harness with the libFuzzer runtime and lets libFuzzer
explore the input space with COVERAGE FEEDBACK, a persistent corpus, and a
dictionary — the same engine OSS-Fuzz runs. Coverage growth is streamed so the
visibility plane shows the fuzzer actually learning the target (cov: N climbing),
not a blind byte-sweep.

Like every discovery agent it only PROPOSES: the crashing input libFuzzer finds
becomes a Candidate whose crash the SanitizerOracle independently rebuilds +
replays under a stdin driver (writer ≠ validator). When no libFuzzer-capable
clang is present it no-ops cleanly, and the Coordinator keeps the legacy fuzzer as
the fallback — so the pipeline degrades instead of breaking.
"""
from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from typing import Optional, Sequence

from .. import fuzzengine, triage
from ..events import EventType
from ..ladder import Candidate, CodeLoc
from .base import Agent


class LibFuzzerDiscoveryAgent(Agent):
    kind = "libfuzzer_discovery"

    def __init__(self, ctx, name: str = "libfuzzer", parent_id: str = "", *,
                 harness: str = "", corpus_dir: Optional[Path] = None,
                 dict_path: Optional[Path] = None, max_total_time: int = 20,
                 max_len: int = 4096,
                 target_sources: Optional[Sequence[Path]] = None,
                 include_dirs: Optional[Sequence[Path]] = None,
                 sanitizer: str = "address",
                 bug_class: str = "memory_safety") -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.harness = harness
        self.corpus_dir = Path(corpus_dir) if corpus_dir else None
        self.dict_path = Path(dict_path) if dict_path else None
        self.max_total_time = max_total_time
        self.max_len = max_len
        self.target_sources = list(target_sources or [])
        self.include_dirs = list(include_dirs or [])
        self.sanitizer = sanitizer
        self.bug_class = bug_class

    async def run(self) -> list[Candidate]:
        if fuzzengine.find_libfuzzer_clang() is None:
            self.log("no libFuzzer-capable clang — deferring to the fallback fuzzer")
            return []
        if not self.harness:
            self.log("no harness to fuzz")
            return []
        self.objective("coverage-guided fuzz (libFuzzer) for a memory-safety crash")
        target = self.ctx.target

        build = await asyncio.to_thread(
            target.build, self.harness, fuzzer=True, sanitizer=self.sanitizer,
            target_sources=self.target_sources or None,
            include_dirs=self.include_dirs or None)
        if not build.ok:
            # A BUILD FAILURE IS NOT A CLEAN RUN, and reporting it as one is the worst
            # thing this agent can do. Until this was recorded, a harness that failed to
            # link produced "0 finding(s)" in under two seconds -- syntactically identical
            # to a full campaign that genuinely found nothing, and distinguishable only by
            # noticing the elapsed time. Recorded on the context so the CLI can exit
            # non-zero and print the compiler's own words.
            self.log("libFuzzer harness build failed", log=build.log[-400:])
            try:
                self.ctx.build_failure = build.log or "the harness did not build"
            except Exception:                                    # noqa: BLE001
                pass
            return []
        self.em.emit(EventType.HARNESS, engine="libFuzzer", built=True,
                     sinks=len(self.target_sources))

        self.think(0, f"fuzzing ≤{self.max_total_time}s with coverage feedback"
                      + (" + dictionary" if self.dict_path else ""))
        fr = await asyncio.to_thread(
            target.fuzz, build.binary, corpus_dir=self.corpus_dir,
            dict_path=self.dict_path, max_total_time=self.max_total_time,
            max_len=self.max_len)
        # Stream what the fuzzer learned — coverage climbing is the whole point.
        self.em.emit(EventType.COVERAGE, engine="libFuzzer", cov=fr.coverage,
                     features=fr.features, execs=fr.execs,
                     exec_per_s=fr.exec_per_s, corpus=fr.corpus,
                     crashed=fr.crashed)

        if fr.crashed and fr.crash_input is not None:
            crash = triage.parse(fr.output)
            self.tool_result("fuzz", crashed=True, bug=crash.bug_type,
                             cov=fr.coverage, execs=fr.execs)
            self.log(f"crash after {fr.execs:,} execs (cov={fr.coverage}): "
                     f"{crash.summary or crash.bug_type}")
            return [self._candidate(fr.crash_input, crash, fr)]

        self.log(f"no crash in fuzz budget (cov={fr.coverage}, "
                 f"execs={fr.execs:,}, corpus={fr.corpus})")
        return []

    def _candidate(self, inp: bytes, crash, fr: fuzzengine.FuzzResult) -> Candidate:
        return build_candidate(
            inp=inp, crash=crash, harness=self.harness,
            target_sources=self.target_sources, include_dirs=self.include_dirs,
            sanitizer=self.sanitizer, bug_class=self.bug_class, agent=self.name,
            coverage=fr.coverage, fuzz_output=fr.output,
            rationale=f"coverage-guided fuzzing reached cov={fr.coverage} in "
                      f"{fr.execs:,} execs and found a {len(inp)}-byte input "
                      f"triggering {crash.bug_type}")


def build_candidate(*, inp: bytes, crash, harness: str, target_sources,
                    include_dirs, sanitizer: str, bug_class: str, agent: str,
                    rationale: str = "", coverage: int = -1,
                    fuzz_output: str = "") -> Candidate:
    """Shared: turn a libFuzzer crash into a Candidate the SanitizerOracle can
    independently rebuild + replay. Used by both the plain and co-driving fuzzers.

    `coverage` (edges reached when the crash was found) and `fuzz_output` (the
    discovery-time fuzzer/sanitizer tail) are carried so the multi-vote triage panel
    can see the RUNTIME signal, not just the crash text — a real bug reached through
    deep coverage reads very differently from a shallow harness artifact."""
    top = crash.top
    return Candidate(
        bug_class=bug_class,
        title=crash.summary or f"{crash.bug_type} crash (libFuzzer)",
        rationale=rationale or f"fuzzing found a {len(inp)}-byte input triggering "
                               f"{crash.bug_type}",
        location=CodeLoc(path=top.file if top else "",
                         line=top.line if top else 0,
                         symbol=top.func if top else ""),
        agent=agent,
        proposed_check={"harness": harness,
                        "input_b64": base64.b64encode(inp).decode(),
                        "libfuzzer": True,
                        "sanitizer": sanitizer,
                        "target_sources": [str(p) for p in target_sources] or None,
                        "include_dirs": [str(p) for p in include_dirs] or None,
                        "coverage": coverage,
                        "fuzz_output": (fuzz_output or "")[-1500:] or None},
        crash={"bug_type": crash.bug_type, "stack_hash": crash.stack_hash},
    )

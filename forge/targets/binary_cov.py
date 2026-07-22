"""Closed-binary coverage — the missing capability (Move 3).

Forge fuzzes *source* with real coverage (libFuzzer under `-fsanitize=fuzzer`),
but a closed binary had only blind concrete runs — no coverage signal, so the
fuzzer wanders. This module adds coverage-guided fuzzing of a *closed* binary via
dynamic instrumentation, cross-platform, behind one small backend contract:

    CoverageBackend.run_with_coverage(binary, stdin) -> (Observation, edges)

with a Frida-Stalker backend (Win/mac/Linux/mobile) as the first implementation
and room for QEMU-user (foreign-arch / firmware) and DynamoRIO as alternates. The
coverage-novelty bookkeeping (`CoverageMap`) is pure and testable with no target.

The load-bearing discipline lives next door: a crash discovered *under
instrumentation* is emitted as a Candidate of bug_class ``instrumented_crash``,
never trusted directly. `NativeVerifyOracle` replays it un-instrumented and only
then does it climb the ladder. Instrumentation *finds*; the native oracle *judges*
(the Little-CMS lesson, encoded structurally).

Graceful degradation: if no instrumentation engine is present the backend reports
`available() == False` and the campaign falls back to the existing concrete fuzzer
— coverage is a speed multiplier, never a hard dependency.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

from ..ladder import Candidate
from .base import Observation


class CoverageMap:
    """Accumulated block/edge coverage across a campaign. Pure bookkeeping: feed it
    the edge ids a run touched, it tells you how many are new and remembers them.
    An input that adds coverage is worth keeping + mutating; one that doesn't is
    discarded. This is the whole engine of coverage-guided fuzzing."""

    def __init__(self) -> None:
        self._seen: set[int] = set()

    def __len__(self) -> int:
        return len(self._seen)

    def observe(self, edges) -> int:
        """Record the edges a run hit; return how many were NEW (novelty gain)."""
        before = len(self._seen)
        self._seen.update(edges or ())
        return len(self._seen) - before

    def is_new(self, edges) -> bool:
        return bool(set(edges or ()) - self._seen)


@dataclass
class CoverageRun:
    """One instrumented execution: what happened + the coverage it produced."""
    observation: Observation
    edges: set = field(default_factory=set)
    instrumented: bool = True


@runtime_checkable
class CoverageBackend(Protocol):
    name: str

    def available(self) -> bool:
        ...

    def run_with_coverage(self, binary: Path, *, stdin: bytes = b"",
                          timeout: float = 30.0) -> CoverageRun:
        ...


# The Frida agent that records basic-block coverage on the target thread. Stalker
# is armed only around the input-processing call (Interceptor-bracketed) so the
# coverage reflects real parsing, not process startup. Emitted here as the source
# of truth; the Python side spawns it via the `frida` bindings when present.
FRIDA_STALKER_AGENT = r"""
'use strict';
const seen = new Set();
function armStalker(tid) {
  Stalker.follow(tid, {
    events: { compile: true },
    onReceive: function (events) {
      const parsed = Stalker.parse(events, {stringify:false, annotate:false});
      for (const ev of parsed) { if (ev.length >= 2) seen.add(ev[1].toString()); }
    }
  });
}
rpc.exports = {
  arm: function () { armStalker(Process.getCurrentThreadId()); },
  drain: function () { const a = Array.from(seen); seen.clear(); return a; }
};
"""


class FridaStalkerCoverage:
    """Coverage-guided execution of a closed binary via Frida-Stalker. Guarded:
    if the `frida` bindings (or the frida-server on a mobile target) are absent,
    `available()` is False and the caller degrades to the concrete fuzzer."""

    name = "frida-stalker"

    def __init__(self, target, *, spawn_argv: Optional[list] = None) -> None:
        self.target = target
        self.spawn_argv = spawn_argv

    def available(self) -> bool:
        try:
            import frida  # noqa: F401
            return True
        except Exception:
            return False

    def run_with_coverage(self, binary: Path, *, stdin: bytes = b"",
                          timeout: float = 30.0) -> CoverageRun:
        """Spawn the app under Frida, arm Stalker around the parse, deliver the
        input as a file argument, collect (observation, block-edges). ANY
        instrumentation failure degrades to a plain concrete run so the campaign
        keeps progressing — the crash, if any, is still caught by the target.

        The Frida path is validated on the Windows agent (needs frida + the
        target); the argv-mode fallback is the tested baseline."""
        if not self.available():
            obs = self.target.run(binary, stdin=stdin, timeout=timeout)
            return CoverageRun(observation=obs, edges=set(), instrumented=False)
        try:
            return self._frida_run(binary, stdin, timeout)
        except Exception:
            obs = self.target.run(binary, stdin=stdin, timeout=timeout)
            return CoverageRun(observation=obs, edges=set(), instrumented=False)

    def _frida_run(self, binary: Path, stdin: bytes, timeout: float) -> CoverageRun:
        """Real Frida-Stalker driver (Windows agent). Spawn suspended → inject the
        Stalker agent → arm → resume → let the parser run → drain block coverage →
        report a crash if Frida saw one. Best-effort; validated live on the VM."""
        import os
        import tempfile
        import time

        import frida

        from .. import triage
        from .base import Observation

        # Deliver the input as a file, argv from the target's template (a GUI app
        # opens a file, not stdin) — mirror WindowsBinaryTarget.run().
        suffix = getattr(self.target, "input_suffix", "")
        tmpl = getattr(self.target, "argv_template", ["{file}"])
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "wb") as fh:
            fh.write(stdin or b"")
        argv = [str(binary)] + [a.replace("{file}", path) for a in tmpl]

        edges: set = set()
        crash = {"hit": False, "report": ""}
        try:
            device = frida.get_local_device()
            pid = device.spawn(argv)
            session = device.attach(pid)

            def _on_detached(reason, crashinfo, *_):
                if crashinfo is not None:
                    crash["hit"] = True
                    crash["report"] = getattr(crashinfo, "report", "") or str(crashinfo)
            session.on("detached", _on_detached)

            script = session.create_script(FRIDA_STALKER_AGENT)
            script.load()
            _exports = getattr(script, "exports_sync", None) or script.exports
            try:
                _exports.arm()
            except Exception:
                pass
            device.resume(pid)

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and not crash["hit"]:
                time.sleep(0.05)
            try:
                edges = set(_exports.drain() or [])
            except Exception:
                edges = set()
            try:
                device.kill(pid)
            except Exception:
                pass
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

        ci = triage.parse(crash["report"])
        if crash["hit"] and not ci.crashed:      # Frida saw a crash it couldn't classify
            ci = triage.parse("", win_exit=0xC0000005)   # default: access-violation
        obs = Observation(crashed=ci.crashed, crash=ci, rc=0, output=crash["report"])
        return CoverageRun(observation=obs, edges=edges, instrumented=True)


def to_instrumented_candidate(inp: bytes, run: CoverageRun, *,
                              title: str = "coverage-guided crash") -> Candidate:
    """Wrap a crash seen under instrumentation as a Candidate the NativeVerifyOracle
    must clear before it is trusted. bug_class is ``instrumented_crash`` so the
    router sends it to native-verify, never straight to the ladder."""
    return Candidate(
        bug_class="instrumented_crash", title=title,
        rationale="crash observed under dynamic instrumentation; must reproduce "
                  "un-instrumented to be trusted",
        proposed_check={"input_b64": base64.b64encode(inp).decode(),
                        "instrumented_bug": run.observation.crash.bug_type,
                        "native_replays": 5},
        crash={"bug_type": run.observation.crash.bug_type,
               "summary": run.observation.crash.summary})


def select_corpus(binary: Path, seeds, backend: CoverageBackend, *,
                  timeout: float = 30.0) -> list[bytes]:
    """Coverage-minimize a seed set: keep only inputs that each add new coverage
    (plus the first, to never return empty). A small, coverage-diverse corpus
    fuzzes far better than a big redundant one. Pure control flow over the
    backend contract; testable with a fake backend."""
    cov = CoverageMap()
    kept: list[bytes] = []
    for s in seeds:
        run = backend.run_with_coverage(Path(binary), stdin=s, timeout=timeout)
        if cov.observe(run.edges) > 0 or not kept:
            kept.append(s)
    return kept

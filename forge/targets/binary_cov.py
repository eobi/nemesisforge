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
// First-chance exception handler — the load-bearing part for Windows GUI
// file-parsers. Delphi/native apps wrap parsing in an SEH try/except and SWALLOW
// access-violations (no process exit-code crash), so exit-code detection misses
// real memory-safety bugs. Frida's handler runs BEFORE the app's SEH, so it sees
// the fault first. We only observe (return false) — never alter behavior.
Process.setExceptionHandler(function (d) {
  var pc = '';
  try { pc = d.context ? d.context.pc.toString() : ''; } catch (e) {}
  send({ event: 'crash', kind: d.type,
         address: d.address ? d.address.toString() : '', pc: pc });
  return false;
});
function norm(addr) {
  // MODULE-RELATIVE block id (name+offset) so coverage is ASLR-invariant across
  // process-per-input spawns — the fix for "every run looks all-new".
  try {
    var m = Process.findModuleByAddress(addr);
    if (m) return m.name + '+' + addr.sub(m.base).toString();
  } catch (e) {}
  return addr.toString();
}
function armStalker(tid) {
  Stalker.follow(tid, {
    events: { compile: true },
    onReceive: function (events) {
      const parsed = Stalker.parse(events, {stringify:false, annotate:false});
      for (const ev of parsed) { if (ev.length >= 2) seen.add(norm(ev[1])); }
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
        crash = {"hit": False, "report": "", "addr": ""}
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

            def _on_message(msg, data):
                p = msg.get("payload") if isinstance(msg, dict) else None
                if p and p.get("event") == "crash":     # first-chance exception (SEH-swallowed)
                    crash["hit"] = True
                    crash["addr"] = p.get("address") or p.get("pc") or ""
                    crash["report"] = ("%s at %s (first-chance)"
                                       % (p.get("kind", "access-violation"), crash["addr"]))
            script.on("message", _on_message)
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
        if crash["hit"] and crash["addr"]:
            ci.summary = (f"access-violation at {crash['addr']} "
                          f"(first-chance, SEH-swallowed)")
            ci.stack_hash = ("fc" + crash["addr"].replace("0x", ""))[:16]
        obs = Observation(crashed=ci.crashed, crash=ci, rc=0, output=crash["report"])
        return CoverageRun(observation=obs, edges=edges, instrumented=True)


# Exception-observer agent: ONLY a first-chance handler, no Stalker code-rewriting.
# This is the RELIABLE, low-artifact Windows crash signal — it catches an
# SEH-swallowed access-violation with its real access type (d.memory.operation),
# faulting operand (d.memory.address), instruction (d.context.pc), and registers,
# without rewriting the target (so its crashes are trustworthy, unlike Stalker's).
FRIDA_EXCEPTION_AGENT = r"""
'use strict';
Process.setExceptionHandler(function (d) {
  var out = { event: 'crash', kind: d.type };
  try { out.pc = (d.context && d.context.pc) ? d.context.pc.toString() : ''; } catch (e) {}
  try {
    if (d.memory) {
      out.op = d.memory.operation;
      out.addr = d.memory.address ? d.memory.address.toString() : '';
    }
  } catch (e) {}
  if (!out.addr) { try { out.addr = d.address ? d.address.toString() : ''; } catch (e) {} }
  try {
    var c = d.context, regs = {};
    ['pc','sp','rax','rbx','rcx','rdx','rsi','rdi','rbp','r8','r9','r10','r11',
     'eax','ebx','ecx','edx','esi','edi','ebp','esp'].forEach(function (r) {
      try { if (c && c[r] !== undefined && c[r] !== null) regs[r] = c[r].toString(); } catch (e) {}
    });
    out.regs = regs;
  } catch (e) {}
  send(out);
  return false;
});
"""

# Frida exception types that are real faults worth reporting (not app control-flow
# exceptions the parser raises and handles normally, which would over-trigger).
_REPORTABLE_FRIDA_EXC = {
    "access-violation", "illegal-instruction", "stack-overflow",
    "abort", "arithmetic", "breakpoint", "system",
}


class FridaExceptionObserver:
    """Reliable Windows crash detection via a Frida first-chance exception handler
    ONLY (no Stalker rewriting). Used for BOTH discovery and verification, so an
    SEH-swallowed crash is caught the same way each time and is never refuted as an
    'instrumentation artifact' (the native-verify contradiction fix). Provides the
    faulting address + access type + registers straight into CrashInfo for the
    exploitability oracle.

    Degrades to the target's exit-code path when frida is absent."""

    name = "frida-exception"

    def __init__(self, target) -> None:
        self.target = target

    def available(self) -> bool:
        try:
            import frida  # noqa: F401
            return True
        except Exception:
            return False

    def observe(self, binary: Path, *, stdin: bytes = b"",
                timeout: float = 15.0) -> Observation:
        if not self.available():
            return self.target._run_exitcode(binary, stdin=stdin, timeout=timeout)
        try:
            return self._run(binary, stdin, timeout)
        except Exception:
            return self.target._run_exitcode(binary, stdin=stdin, timeout=timeout)

    def _run(self, binary: Path, stdin: bytes, timeout: float) -> Observation:
        import os
        import tempfile
        import time

        import frida

        from .. import triage

        suffix = getattr(self.target, "input_suffix", "")
        tmpl = getattr(self.target, "argv_template", ["{file}"])
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "wb") as fh:
            fh.write(stdin or b"")
        argv = [str(binary)] + [a.replace("{file}", path) for a in tmpl]

        exc: dict = {}
        try:
            device = frida.get_local_device()
            pid = device.spawn(argv)
            session = device.attach(pid)
            script = session.create_script(FRIDA_EXCEPTION_AGENT)

            def _on_message(msg, data):
                p = msg.get("payload") if isinstance(msg, dict) else None
                if not p or p.get("event") != "crash":
                    return
                kind = (p.get("kind") or "").lower()
                if kind and kind not in _REPORTABLE_FRIDA_EXC:
                    return                       # benign app control-flow exception
                if not exc:
                    exc.update(p)
            script.on("message", _on_message)
            script.load()
            device.resume(pid)

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and not exc:
                time.sleep(0.03)
            try:
                device.kill(pid)
            except Exception:
                pass
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

        if exc:
            return Observation(crashed=True, crash=triage.crashinfo_from_frida(exc),
                               rc=0, output=str(exc))
        # No fault within the window: a GUI viewer legitimately stays open, so this
        # is benign — NOT a hang/DoS (DoS needs the persistent harness's parse-done
        # signal to distinguish). Reported as clean, not timed_out, to avoid FPs.
        return Observation(crashed=False, crash=triage.CrashInfo(), rc=0)


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

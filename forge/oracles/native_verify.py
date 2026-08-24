"""NativeVerifyOracle — the anti-false-positive gate for instrumented discovery.

Coverage-guided fuzzing of a *closed* binary needs dynamic instrumentation
(Frida-Stalker / DynamoRIO / QEMU-user) to observe block coverage on a real
target thread. But instrumentation is not free of side effects: a rewriting
engine like Stalker can itself trip on certain fixed-point / SSE / self-modifying
code and produce a "crash" that has nothing to do with a real bug. Reporting
those is the single fastest way to lose a vendor's (or a reviewer's) trust — the
lesson burned in during the Little-CMS hunt, where every Frida "crash" vanished
under native replay (0 real across 130k+ native runs).

So a crash discovered under instrumentation is NEVER trusted directly. It is a
`Candidate` of bug_class ``instrumented_crash`` whose *only* claim is "the
instrumented process died". This oracle discharges that claim the one honest way:
replay the exact reproducer in a fresh, **un-instrumented** process K times.

  - reproduces natively at least once  → the fault is real (not an instrumentation
    artifact). PROVEN — a memory-signal crash from untrusted input is
    PROVEN_SECURITY, any other fatal signal is PROVEN_FAULT (mirrors
    BinaryCrashOracle). The native reproduction *rate* is recorded for the report
    and for exploit-reliability follow-up; even a single native repro is
    dispositive that the bug exists, because a Stalker artifact reproduces
    natively exactly zero times.
  - never reproduces natively across K clean replays → REFUTED: an
    instrumentation artifact, discarded. This is the discipline.

Deterministic: the decision is a pure function of the native replay bug types.
The BinaryTarget already runs the bare binary with no instrumentation, so a
"native replay" here is just re-running the target — no special mode needed.
"""
from __future__ import annotations

import base64
from collections import Counter

from ..context import JobContext
from ..ladder import Candidate, Outcome, Rung, Verdict

# Fatal signals that indicate a memory-safety-relevant fault (mirror
# BinaryCrashOracle so the two paths grade a binary crash identically).
_MEMORY_BUGS = {"segv", "bus-error"}

# How many times to replay natively before declaring an instrumentation artifact.
# More replays lowers the chance a rarely-firing real bug is wrongly refuted; the
# cost is K bare runs, which are cheap.
DEFAULT_REPLAYS = 5


def decide(native_bugs: list[str]) -> tuple[Outcome, str, str]:
    """Pure/testable core: given the bug_type seen on each native replay
    ("" = the replay did not crash), decide the outcome.

    Returns (outcome, modal_bug_type, human_reason). ``modal_bug_type`` is the
    most common non-empty bug seen natively (drives the rung); empty when nothing
    reproduced.
    """
    k = len(native_bugs)
    if k == 0:
        return (Outcome.INCONCLUSIVE, "", "no native replays were run")
    reproduced = [b for b in native_bugs if b]
    if not reproduced:
        return (Outcome.REFUTED, "",
                f"reproduced only under instrumentation; native replay clean "
                f"across {k} runs → instrumentation artifact, discarded")
    modal, count = Counter(reproduced).most_common(1)[0]
    rate = f"{len(reproduced)}/{k}"
    if len(reproduced) == k:
        note = f"reproduces natively every run ({rate}) → stable, real fault"
    else:
        note = (f"reproduces natively {rate} runs → real fault (not an "
                f"instrumentation artifact); flaky repro noted for reliability")
    return (Outcome.PROVEN, modal, note)


class NativeVerifyOracle:
    """The anti-false-positive gate: replays natively, so instrumentation artifacts do not survive."""
    name = "native-verify"
    # A crash surfaced by an instrumented (coverage) run. Kept distinct from
    # ``binary_crash`` so this oracle is purely additive and never shadows the
    # existing BinaryCrashOracle in the router.
    handles = {"instrumented_crash"}

    def verify(self, ctx: JobContext, cand: Candidate) -> Verdict:
        target = ctx.target
        if target is None:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="no target to replay natively")
        pc = cand.proposed_check or {}
        inp = self._input(pc)
        replays = int(pc.get("native_replays", DEFAULT_REPLAYS))
        timeout = float(pc.get("timeout", 30.0))

        build = target.build()
        if not build.ok:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback=build.log or "binary unavailable for replay")

        native_bugs: list[str] = []
        for _ in range(max(1, replays)):
            obs = target.run(build.binary, stdin=inp, timeout=timeout)
            native_bugs.append(obs.crash.bug_type if obs.crashed else "")

        outcome, modal, reason = decide(native_bugs)
        instrumented_bug = pc.get("instrumented_bug", "")
        evidence = {
            "native_replays": len(native_bugs),
            "native_reproductions": sum(1 for b in native_bugs if b),
            "native_bug_types": native_bugs,
            "instrumented_bug": instrumented_bug,
            "reason": reason,
        }

        if outcome is Outcome.REFUTED:
            return Verdict(Outcome.REFUTED, Rung.UNVERIFIED, self.name,
                           evidence=evidence, feedback=reason)
        if outcome is not Outcome.PROVEN:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           evidence=evidence, feedback=reason)

        mem = modal in _MEMORY_BUGS
        rung = Rung.PROVEN_SECURITY if mem else Rung.PROVEN_FAULT
        repro = ctx.artifacts / f"repro-native-{modal or 'x'}.bin"
        repro.write_bytes(inp)
        evidence["memory_relevant"] = mem
        return Verdict(Outcome.PROVEN, rung, self.name,
                       evidence=evidence, reproducer=str(repro))

    @staticmethod
    def _input(pc: dict) -> bytes:
        if pc.get("input_b64"):
            return base64.b64decode(pc["input_b64"])
        v = pc.get("input", b"")
        return v.encode() if isinstance(v, str) else bytes(v)

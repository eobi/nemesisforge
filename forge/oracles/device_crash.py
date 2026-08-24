"""DeviceCrashOracle — prove an Android native crash from a tombstone.

The proof object on Android is the debuggerd tombstone: a memory signal
(SIGSEGV/SIGBUS) with a symbolized backtrace is a security-relevant memory-safety
fault → PROVEN_SECURITY; a non-memory fatal signal → PROVEN_FAULT. Works from a
tombstone captured off a device OR one supplied directly, so the proof + vendor
packet come together even without live hardware in the loop. Deterministic.
"""
from __future__ import annotations

from dataclasses import asdict

from ..android import parse_tombstone
from ..context import JobContext
from ..ladder import Candidate, Outcome, Rung, Verdict

_MEMORY_BUGS = {"segv", "bus-error"}


class DeviceCrashOracle:
    """Proves an Android native crash from a tombstone. Certifies rung 1 on device."""
    name = "device-crash"
    handles = {"android_crash"}

    def verify(self, ctx: JobContext, cand: Candidate) -> Verdict:
        pc = cand.proposed_check or {}
        tomb = pc.get("tombstone")
        target = ctx.target
        if not tomb and target is not None and getattr(target, "available", False):
            tomb = target.latest_tombstone()
        if not tomb:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="no tombstone (attach a device or supply one)")

        ci = parse_tombstone(tomb)
        if not ci.crashed:
            return Verdict(Outcome.REFUTED, Rung.UNVERIFIED, self.name,
                           feedback="tombstone shows no fatal crash")

        mem = ci.bug_type in _MEMORY_BUGS
        rung = Rung.PROVEN_SECURITY if mem else Rung.PROVEN_FAULT
        # persist the tombstone as the reproduction evidence
        tpath = ctx.artifacts / f"tombstone-{ci.stack_hash or 'x'}.txt"
        tpath.write_text(tomb)
        return Verdict(
            Outcome.PROVEN, rung, self.name,
            evidence={"crash": asdict(ci), "summary": ci.summary,
                      "memory_relevant": mem, "sanitizer_output": ci.summary},
            reproducer=str(tpath))

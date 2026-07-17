"""BinaryCrashOracle — proves a crash in a closed-source binary via concrete run.

For a bare binary there is no sanitizer report, so the proof object is the fatal
signal the process dies on when fed attacker input. A memory signal (SIGSEGV /
SIGBUS) reached from untrusted stdin is a security-relevant memory-safety fault
on the input surface → PROVEN_SECURITY; a non-memory fatal signal (abort/assert)
proves a fault but not (yet) exploitability → PROVEN_FAULT. Exploitability of a
binary crash is what the symbolic oracle (angr) escalates when available.

Deterministic: it re-runs the binary on the candidate's reproducer and reads the
signal. Captures the reproducer to the artifact store.
"""
from __future__ import annotations

import base64

from ..context import JobContext
from ..ladder import Candidate, Outcome, Rung, Verdict

_MEMORY_BUGS = {"segv", "bus-error"}


class BinaryCrashOracle:
    name = "binary-crash"
    handles = {"binary_crash"}

    def verify(self, ctx: JobContext, cand: Candidate) -> Verdict:
        target = ctx.target
        if target is None:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="no target")
        pc = cand.proposed_check or {}
        inp = self._input(pc)

        build = target.build()
        if not build.ok:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback=build.log or "binary unavailable")
        obs = target.run(build.binary, stdin=inp, timeout=pc.get("timeout", 30.0))
        if not obs.crashed:
            return Verdict(Outcome.REFUTED, Rung.UNVERIFIED, self.name,
                           feedback="binary did not crash on this input")

        mem = obs.crash.bug_type in _MEMORY_BUGS
        rung = Rung.PROVEN_SECURITY if mem else Rung.PROVEN_FAULT
        repro = ctx.artifacts / f"repro-bin-{obs.crash.stack_hash or 'x'}.bin"
        repro.write_bytes(inp)
        return Verdict(
            Outcome.PROVEN, rung, self.name,
            evidence={"crash": {"bug_type": obs.crash.bug_type,
                                "summary": obs.crash.summary},
                      "signal_rc": obs.rc,
                      "memory_relevant": mem},
            reproducer=str(repro))

    @staticmethod
    def _input(pc: dict) -> bytes:
        if pc.get("input_b64"):
            return base64.b64decode(pc["input_b64"])
        v = pc.get("input", b"")
        return v.encode() if isinstance(v, str) else bytes(v)

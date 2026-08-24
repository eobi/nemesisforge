"""DifferentialOracle — the universal reward signal.

The load-bearing definition of "proof" across OSS-Fuzz, syzbot, CyberGym and
K-Repro: a PoC *passes* iff it triggers the same typed sanitizer crash on the
VULNERABLE build and produces NO crash on the PATCHED build. That single test is
also exactly what a vendor triager checks. So when a patch (or a fixed variant)
is available, this oracle is the strongest, cheapest certification we have — it
proves the input is a working PoC for the *specific* bug the patch fixes, which
lands a candidate at PROVEN_EXPLOIT (rung 5).

Deterministic. The decision is a pure function of (vuln crashed?, patched
crashed?) so it's unit-testable without a toolchain; `verify` just drives the
target twice.
"""
from __future__ import annotations

import base64

from ..context import JobContext
from ..ladder import Candidate, Outcome, Rung, Verdict


def decide(vuln_crashed: bool, vuln_bug: str, patched_crashed: bool) -> tuple[Outcome, Rung, str]:
    """The differential verdict. Pure/testable."""
    if not vuln_crashed:
        return (Outcome.INCONCLUSIVE, Rung.UNVERIFIED,
                "reproducer did not crash the vulnerable build")
    if patched_crashed:
        return (Outcome.REFUTED, Rung.UNVERIFIED,
                "the patched build ALSO crashes on this input — not the fixed "
                "bug (or the patch is incomplete)")
    return (Outcome.PROVEN, Rung.PROVEN_EXPLOIT,
            f"crashes the vulnerable build ({vuln_bug}) and is clean on the "
            f"patched build — a working PoC for exactly the patched bug")


class DifferentialOracle:
    """The universal reward: faults on the vulnerable build, clean on the patched one."""
    name = "differential"
    handles = {"memory_safety"}

    def verify(self, ctx: JobContext, cand: Candidate) -> Verdict:
        pc = cand.proposed_check or {}
        target = ctx.target
        harness = pc.get("harness")
        patched = pc.get("patched_harness")
        if not harness or not patched or target is None:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="differential needs harness + patched_harness")
        inp = self._input(pc)

        vb = target.build(harness, sanitizer=pc.get("sanitizer", "address"),
                          target_sources=pc.get("target_sources"))
        if not vb.ok:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="vulnerable build failed: " + vb.log[-400:])
        vuln_obs = target.run(vb.binary, stdin=inp, timeout=pc.get("timeout", 60.0),
                              symbolize=False)

        pbuild = target.build(patched, sanitizer=pc.get("sanitizer", "address"),
                              target_sources=pc.get("patched_sources"))
        if not pbuild.ok:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="patched build failed: " + pbuild.log[-400:])
        patched_obs = target.run(pbuild.binary, stdin=inp,
                                 timeout=pc.get("timeout", 60.0), symbolize=False)

        outcome, rung, reason = decide(
            vuln_obs.crashed, vuln_obs.crash.bug_type, patched_obs.crashed)

        repro = ctx.artifacts / f"poc-diff-{vuln_obs.crash.stack_hash or 'x'}.bin"
        if outcome is Outcome.PROVEN:
            repro.write_bytes(inp)
        return Verdict(
            outcome, rung, self.name, feedback="" if outcome is Outcome.PROVEN else reason,
            evidence={"reason": reason,
                      "vuln_bug": vuln_obs.crash.bug_type,
                      "vuln_crashed": vuln_obs.crashed,
                      "patched_crashed": patched_obs.crashed},
            reproducer=str(repro) if outcome is Outcome.PROVEN else None)

    @staticmethod
    def _input(pc: dict) -> bytes:
        if pc.get("input_b64"):
            return base64.b64decode(pc["input_b64"])
        v = pc.get("input", b"")
        return v.encode() if isinstance(v, str) else bytes(v)

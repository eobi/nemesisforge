"""SymbolicOracle — angr-backed reachability/primitive proof for binaries.

The escalation path for a binary crash: symbolic/concolic execution (angr) proves
the crash is reachable from attacker input and characterizes the primitive
(controlled PC / write-what-where). angr is heavy and optional, so this oracle
degrades gracefully: with angr installed it attempts the analysis; without it,
it returns INCONCLUSIVE with a clear reason (never a fake verdict). This is the
seam that "lights up" when the binary toolchain is provisioned.
"""
from __future__ import annotations

from ..context import JobContext
from ..ladder import Candidate, Outcome, Rung, Verdict


class SymbolicOracle:
    name = "symbolic"
    handles = {"binary_crash"}
    target_rung = Rung.PROVEN_PRIMITIVE

    def __init__(self) -> None:
        try:
            import angr  # noqa: F401
            self.available = True
        except Exception:
            self.available = False

    def verify(self, ctx: JobContext, cand: Candidate) -> Verdict:
        if not self.available:
            return Verdict(
                Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                feedback="angr not installed — symbolic reachability + primitive "
                         "proof unavailable; concrete crash proof stands")
        # angr present: a real analysis would load the binary, mark stdin
        # symbolic, and solve for PC-control / write-what-where here. Kept as an
        # honest INCONCLUSIVE until the per-arch analysis is implemented, so it
        # never over-claims.
        return Verdict(
            Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
            feedback="symbolic primitive analysis pending implementation for "
                     "this binary shape")

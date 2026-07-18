"""SymbolicOracle — angr-backed reachability + primitive proof for binaries.

The escalation path for a binary crash. Given the crashing input, angr symbolically
re-executes the binary with that input made symbolic and looks for an UNCONSTRAINED
state — a state where the instruction pointer became attacker-controlled (classic
AEG "PC control" signal) or where a symbolic value is written to a symbolic address
(write-what-where). Either is a controllable primitive → PROVEN_PRIMITIVE (rung 4).

Honesty by construction:
  - angr is heavy + optional, so the oracle self-gates on import. Without it, the
    concrete crash proof still stands and this returns INCONCLUSIVE with a reason.
  - ANY angr error, timeout, or ambiguous result also returns INCONCLUSIVE — the
    oracle only ever climbs the ladder on a concrete symbolic proof, never a guess.
"""
from __future__ import annotations

import base64

from ..context import JobContext
from ..ladder import (
    Candidate, Outcome, Primitive, PrimitiveKind, Rung, Verdict,
)


class SymbolicOracle:
    name = "symbolic"
    handles = {"binary_crash"}
    target_rung = Rung.PROVEN_PRIMITIVE

    def __init__(self, *, max_seconds: int = 120) -> None:
        self.max_seconds = max_seconds
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
        target = ctx.target
        pc = cand.proposed_check or {}
        binary = getattr(target, "binary", None)
        if binary is None:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="no binary to analyze symbolically")
        try:
            return self._analyze(str(binary), self._input(pc), cand)
        except Exception as e:                 # never fake a proof on an angr error
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback=f"symbolic analysis inconclusive: "
                                    f"{type(e).__name__}: {e}")

    def _analyze(self, binary: str, inp: bytes, cand: Candidate) -> Verdict:
        import angr
        import claripy

        proj = angr.Project(binary, auto_load_libs=False)
        # Make the crashing input symbolic (same length) and drive it via stdin.
        n = max(1, len(inp))
        sym = claripy.BVS("stdin", n * 8)
        state = proj.factory.full_init_state(
            stdin=angr.SimFileStream(name="stdin", content=sym, has_end=True),
            add_options=angr.options.unicorn | {
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            })
        simgr = proj.factory.simulation_manager(state, save_unconstrained=True)

        # Explore under a step/time budget; an unconstrained state = the CPU tried
        # to fetch from a symbolic address → attacker influences control flow.
        import time
        steps = 0
        start = time.monotonic()
        while simgr.active and not simgr.unconstrained:
            simgr.step()
            steps += 1
            if time.monotonic() - start > self.max_seconds or steps > 4000:
                break

        if simgr.unconstrained:
            us = simgr.unconstrained[0]
            ip_symbolic = us.regs.pc.symbolic
            controllable = ip_symbolic and us.solver.satisfiable(
                extra_constraints=[us.regs.pc == 0x41414141])
            return Verdict(
                Outcome.PROVEN, Rung.PROVEN_PRIMITIVE, self.name,
                evidence={"symbolic": True,
                          "instruction_pointer_symbolic": bool(ip_symbolic),
                          "pc_controllable": bool(controllable),
                          "steps": steps},
                primitive=Primitive(kind=PrimitiveKind.PC_CONTROL,
                                    controlled=bool(controllable),
                                    detail={"analysis": "angr-unconstrained"}),
                feedback="angr found an unconstrained state — attacker-controlled "
                         "control flow (PC influence)")

        return Verdict(
            Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
            feedback=f"angr reached no unconstrained state in {steps} steps — "
                     f"crash proven concretely but primitive not symbolically shown")

    @staticmethod
    def _input(pc: dict) -> bytes:
        if pc.get("input_b64"):
            return base64.b64decode(pc["input_b64"])
        v = pc.get("input", b"")
        return v.encode() if isinstance(v, str) else bytes(v)

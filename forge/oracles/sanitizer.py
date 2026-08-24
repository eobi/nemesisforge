"""SanitizerOracle — the first real, deterministic prover.

Given a candidate carrying a harness + a triggering input, it builds the target
under AddressSanitizer, runs the input, and reads the crash. A sanitizer crash is
a genuine memory-safety proof (not a model's claim), so:

  - no crash                 → REFUTED (with feedback so an agent can refine)
  - crash in harness/test    → PROVEN_FAULT (rung 1): a real fault exists
  - crash inside the target  → PROVEN_SECURITY (rung 3): the fuzzed function *is*
                               the untrusted input surface, so the fault is
                               reachable + attacker-influenced by construction
                               (the Nemesis Zero fuzz-ladder rule)

It also stamps a `Primitive` hypothesis for a controllable WRITE / UAF (the raw
material the escalation tier tries to prove into rung 4), and writes the
reproducer to the per-job artifact store.
"""
from __future__ import annotations

import base64
from dataclasses import asdict

from ..context import JobContext
from ..ladder import (
    Candidate, Outcome, Primitive, PrimitiveKind, Rung, Verdict,
)


class SanitizerOracle:
    """The first deterministic prover: a typed sanitizer report is the evidence. Certifies rung 1."""
    name = "sanitizer"
    handles = {"memory_safety"}

    def verify(self, ctx: JobContext, cand: Candidate) -> Verdict:
        target = ctx.target
        pc = cand.proposed_check or {}
        harness = pc.get("harness")
        if not harness or target is None:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="no harness or no target to build")
        input_bytes = self._input(pc)

        # A libFuzzer candidate carries an LLVMFuzzerTestOneInput harness; replay
        # it under a stdin driver on the default compiler (no fuzzer runtime).
        build = target.build(harness, sanitizer=pc.get("sanitizer", "address"),
                             target_sources=pc.get("target_sources"),
                             include_dirs=pc.get("include_dirs"),
                             libfuzzer_driver=bool(pc.get("libfuzzer")))
        if not build.ok:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="build failed: " + build.log[-600:])

        # symbolized so we get frames for the rung decision (slower on macOS).
        obs = target.run(build.binary, stdin=input_bytes,
                         timeout=pc.get("timeout", 60.0), symbolize=True)
        if not obs.crashed:
            return Verdict(Outcome.REFUTED, Rung.UNVERIFIED, self.name,
                           feedback="no sanitizer crash on this input")

        crash = obs.crash
        top = crash.top
        # PROVEN_SECURITY (rung 3) only when the crash lands inside an actual
        # TARGET source — the fuzzed function is then the untrusted input surface,
        # so the fault is reachable + attacker-influenced by construction. A
        # crash with no target sources (or only in the harness itself) proves a
        # fault exists but not that it ships → PROVEN_FAULT (rung 1).
        from pathlib import Path as _P
        harness_name = target.harness_path().name
        tgt_names = {_P(p).name for p in (pc.get("target_sources") or [])}
        top_in_target = bool(
            top and tgt_names and harness_name not in top.file
            and any(n in top.file for n in tgt_names))
        rung = Rung.PROVEN_SECURITY if top_in_target else Rung.PROVEN_FAULT

        primitive = None
        if crash.is_write_primitive():
            primitive = Primitive(
                kind=PrimitiveKind.USE_AFTER_FREE
                if "use-after-free" in crash.bug_type else PrimitiveKind.OOB_WRITE,
                controlled=False,   # controllability is what the escalation tier proves
                detail={"bug_type": crash.bug_type, "access_size": crash.access_size})

        repro = ctx.artifacts / f"repro-{crash.stack_hash or 'x'}.bin"
        repro.write_bytes(input_bytes)

        return Verdict(
            Outcome.PROVEN, rung, self.name,
            evidence={"crash": asdict(crash), "summary": crash.summary,
                      "sanitizer_output": obs.output[-2000:]},
            reproducer=str(repro), primitive=primitive)

    @staticmethod
    def _input(pc: dict) -> bytes:
        if pc.get("input_b64"):
            return base64.b64decode(pc["input_b64"])
        v = pc.get("input", b"")
        return v.encode() if isinstance(v, str) else bytes(v)

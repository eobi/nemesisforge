"""ControllabilityOracle — crash → *controlled* primitive (rung 4), deterministically.

PROVEN_FAULT/SECURITY says "a memory-safety bug exists". PROVEN_PRIMITIVE (rung 4)
says something stronger a vendor cares about: the attacker *controls* the
corruption. Proving control usually needs an escalation agent, but there is a
cheap deterministic slice we can certify without an LLM:

  vary the input length and watch the sanitizer's reported WRITE size. For a
  bulk-copy overflow (memcpy/strcpy-class), a longer attacker input produces a
  larger out-of-bounds WRITE — so the attacker controls *how far* past the buffer
  the write goes (the OOB-write extent). That is a controllable OOB write, the
  raw material for write-what-where.

If the write size scales with input → PROVEN_PRIMITIVE with a controlled
OOB_WRITE primitive. If it doesn't (fixed-size single-byte overflow, or the
inputs don't crash the same way) → INCONCLUSIVE, and the LLM escalation agent
takes over. Deterministic; the decision is a pure function of two crash sizes.
"""
from __future__ import annotations

import base64

from ..context import JobContext
from ..ladder import (
    Candidate, Outcome, Primitive, PrimitiveKind, Rung, Verdict,
)


def decide(bug1: str, size1: int, bug2: str, size2: int) -> tuple[Outcome, str]:
    """Pure/testable: does a longer input widen the OOB write?"""
    if not bug1 or not bug2:
        return (Outcome.INCONCLUSIVE, "one of the two inputs did not crash")
    if bug1 != bug2:
        return (Outcome.INCONCLUSIVE, f"different bug on the two inputs "
                f"({bug1} vs {bug2}) — not the same primitive")
    if size2 > size1:
        return (Outcome.PROVEN,
                f"OOB write size scales with input ({size1} → {size2} bytes) — "
                f"the attacker controls the out-of-bounds write extent")
    return (Outcome.INCONCLUSIVE,
            f"write size did not scale ({size1} vs {size2}) — controllability "
            "not shown by length variation")


class ControllabilityOracle:
    name = "controllability"
    handles = {"memory_safety"}
    target_rung = Rung.PROVEN_PRIMITIVE   # what a PROVEN verdict certifies

    def verify(self, ctx: JobContext, cand: Candidate) -> Verdict:
        pc = cand.proposed_check or {}
        target = ctx.target
        harness = pc.get("harness")
        if not harness or target is None:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="no harness/target to probe controllability")

        base = self._input(pc)
        longer = base * 2 if base else b"A" * 64   # a strictly longer input

        build = target.build(harness, sanitizer=pc.get("sanitizer", "address"),
                             target_sources=pc.get("target_sources"))
        if not build.ok:
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback="build failed: " + build.log[-400:])

        # write size is in the ASan header — no symbolization needed (fast).
        o1 = target.run(build.binary, stdin=base, symbolize=False,
                        timeout=pc.get("timeout", 60.0))
        o2 = target.run(build.binary, stdin=longer, symbolize=False,
                        timeout=pc.get("timeout", 60.0))

        outcome, reason = decide(o1.crash.bug_type, o1.crash.access_size,
                                 o2.crash.bug_type, o2.crash.access_size)
        if outcome is not Outcome.PROVEN:
            # Length-prefixed formats (the CWPack/mpack class): doubling the buffer
            # doesn't change a DECLARED length, so the write doesn't scale. Scan the
            # header for the integer field that governs the OOB-write extent.
            hit = self._scan_length_field(
                target, build, base, o1.crash, pc.get("timeout", 60.0))
            if hit:
                off, width, big = hit
                primitive = Primitive(
                    kind=PrimitiveKind.OOB_WRITE, controlled=True,
                    where=f"declared-length field at input offset {off} ({width}B)",
                    what="attacker-supplied bytes",
                    detail={"bug_type": o1.crash.bug_type, "length_offset": off,
                            "size_base": o1.crash.access_size, "size_scaled": big})
                return Verdict(
                    Outcome.PROVEN, Rung.PROVEN_PRIMITIVE, self.name,
                    evidence={"reason": f"OOB write extent scales with the declared-"
                              f"length field at offset {off} ({o1.crash.access_size}"
                              f" → {big} bytes)", "sizes": [o1.crash.access_size, big]},
                    primitive=primitive)
            return Verdict(Outcome.INCONCLUSIVE, Rung.UNVERIFIED, self.name,
                           feedback=reason)

        primitive = Primitive(
            kind=PrimitiveKind.OOB_WRITE, controlled=True,
            where="out-of-bounds write extent (attacker-controlled length)",
            what="attacker-supplied bytes",
            detail={"bug_type": o1.crash.bug_type,
                    "size_short": o1.crash.access_size,
                    "size_long": o2.crash.access_size})
        return Verdict(Outcome.PROVEN, Rung.PROVEN_PRIMITIVE, self.name,
                       evidence={"reason": reason,
                                 "sizes": [o1.crash.access_size, o2.crash.access_size]},
                       primitive=primitive)

    def _scan_length_field(self, target, build, base: bytes, base_crash,
                           timeout: float):
        """Find the header integer field that governs the OOB-write extent: bump a
        u16/u32 at each small offset and keep the first whose bump grows the write
        size (same bug). Bounded; only runs when length-doubling was inconclusive.
        Returns (offset, width, scaled_size) or None."""
        import struct
        if not base_crash.crashed or not base_crash.access_size:
            return None
        base_size, base_bug = base_crash.access_size, base_crash.bug_type
        for width, fmt in ((2, "<H"), (4, "<I")):
            hi = (1 << (8 * width)) - 1
            for off in range(0, max(1, min(len(base), 32) - width + 1)):
                cur = struct.unpack_from(fmt, base, off)[0]
                if cur >= hi:
                    continue
                planted = bytearray(base)
                struct.pack_into(fmt, planted, off, min(hi, cur + 4096))
                try:
                    o = target.run(build.binary, stdin=bytes(planted),
                                   symbolize=False, timeout=timeout)
                except Exception:
                    continue
                if (o.crashed and o.crash.bug_type == base_bug
                        and o.crash.access_size > base_size):
                    return off, width, o.crash.access_size
        return None

    @staticmethod
    def _input(pc: dict) -> bytes:
        if pc.get("input_b64"):
            return base64.b64decode(pc["input_b64"])
        v = pc.get("input", b"")
        return v.encode() if isinstance(v, str) else bytes(v)

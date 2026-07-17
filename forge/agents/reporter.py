"""ReporterAgent — assembles the vendor packet and promotes to VENDOR_READY.

The terminal sub-agent: for a finding that has climbed to a controlled primitive
(rung >= PROVEN_PRIMITIVE), it assembles the six-artifact disclosure packet (a
byproduct of the proof, not a fresh writing task) and promotes the finding to
rung 6, VENDOR_READY — the only rung that ships to a vendor. Reaching rung 6 is a
packaging act over already-certified evidence, which is exactly what a vendor
accepts (proven primitive + root cause), so it does not require full
weaponization.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from ..events import EventType
from ..ladder import Finding, Outcome, Rung, Verdict, VENDOR_MIN
from ..packager import assemble_packet
from .base import Agent


class ReporterAgent(Agent):
    kind = "reporter"

    def __init__(self, ctx, name: str = "reporter", parent_id: str = "", *,
                 finding: Optional[Finding] = None, llm=None) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.finding = finding
        self.llm = llm

    async def run(self) -> Optional[Finding]:
        f = self.finding
        if f is None or f.rung < VENDOR_MIN:
            return f
        self.objective(f"assemble the vendor-disclosure packet for «{f.candidate.title}»")
        manifest = await asyncio.to_thread(assemble_packet, f, self.ctx, llm=self.llm)
        f.artifacts["packet"] = manifest
        # promote to VENDOR_READY — a packaging climb over certified evidence.
        f.rung = Rung.VENDOR_READY
        self.ctx.ladder.apply(f.candidate,
                              Verdict(Outcome.PROVEN, Rung.VENDOR_READY, "packager"))
        self.em.emit(EventType.RUNG_UP, title=f.candidate.title,
                     rung=int(Rung.VENDOR_READY), rung_name="VENDOR_READY")
        self.em.emit(EventType.VENDOR_PACKET, title=f.candidate.title,
                     severity=manifest["severity"], advisory=manifest["advisory"],
                     complete=manifest["artifacts_complete"])
        return f

"""Agentic build-and-reproduce with a debugger in the loop (K-REPRO / Big Sleep).

Given a proven candidate, rebuild the driver binary and re-run the reproducer under a
batch debugger via the ACI toolbelt (build/run/debug), capturing the backtrace + fault
registers — the root-cause context a vendor report needs, beyond "it crashed". Uses the
in-process ACI (no external MCP server) and emits TOOL_CALL/TOOL_RESULT for visibility.

Deterministic and best-effort: on any failure (no debugger, build fails) it returns
None and the report ships without the extra root-cause section — it never gates a
finding, only enriches it.
"""
from __future__ import annotations

import asyncio
import base64
from typing import Optional

from .base import Agent


class ReproduceAgent(Agent):
    kind = "reproduce"

    def __init__(self, ctx, name: str = "reproduce", parent_id: str = "", *,
                 candidate=None) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.candidate = candidate

    async def run(self) -> Optional[str]:
        cand = self.candidate
        pc = getattr(cand, "proposed_check", None) or {}
        harness = pc.get("harness")
        if not harness:
            return None
        inp = self._input(pc)
        self.tool("build", target=getattr(self.ctx.target, "name", ""))
        build = await asyncio.to_thread(
            self.aci.build, harness, libfuzzer_driver=True,
            target_sources=pc.get("target_sources"),
            include_dirs=pc.get("include_dirs"),
            sanitizer=pc.get("sanitizer", "address"))
        if not getattr(build, "ok", False):
            self.tool_result("build", ok=False)
            return None
        self.tool_result("build", ok=True)
        self.tool("debug", bytes=len(inp))
        trace = await asyncio.to_thread(self.aci.debug, build.binary, stdin=inp)
        self.tool_result("debug", chars=len(trace or ""))
        if trace and "debug unavailable" not in trace:
            self.log("captured root-cause backtrace")
            return trace
        return None

    @staticmethod
    def _input(pc: dict) -> bytes:
        if pc.get("input_b64"):
            try:
                return base64.b64decode(pc["input_b64"])
            except Exception:
                return b""
        v = pc.get("input", b"")
        return v.encode() if isinstance(v, str) else bytes(v)

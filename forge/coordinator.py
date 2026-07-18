"""The Coordinator — the root of the agent tree.

It ingests the target (+ optional seed: a crash / CVE / patch), dispatches
discovery sub-agents in parallel, routes every candidate they produce through the
deterministic oracles to climb the proof ladder, and (Phase B) spawns escalation
+ validator sub-agents to drive a proven fault up to a vendor-grade primitive.
It owns no bug-class knowledge — discovery agents and oracles are injected, so the
Coordinator is the same on source, binary, and device targets.

Everything it does is streamed: candidates, oracle verdicts, rung climbs, and a
ladder-board snapshot, so the visibility plane shows the whole run.
"""
from __future__ import annotations

import asyncio
from typing import Callable, Optional

from .agents.base import Agent
from .events import EventType
from .ladder import Candidate, Finding, Outcome, VENDOR_MIN
from .oracles.base import Oracle, OracleRouter

DiscoveryFactory = Callable[..., Agent]


class Coordinator(Agent):
    kind = "coordinator"

    def __init__(self, ctx, *, discovery: list[DiscoveryFactory],
                 oracles: list[Oracle], escalation: list[Oracle] | None = None,
                 validate: bool = False, package: bool = True, llm=None,
                 llm_discovery: list[DiscoveryFactory] | None = None,
                 harness: str = "", name: str = "coordinator") -> None:
        super().__init__(ctx, name=name, parent_id="")
        self.discovery = discovery
        self.router = OracleRouter(oracles)
        self.escalation = list(escalation or [])
        self.package = package          # assemble the vendor packet at rung >= 4
        self.llm = llm                  # the brain (None/NullLLM → deterministic only)
        self.llm_discovery = list(llm_discovery or [])
        self.harness = harness          # passed to LLM discovery/synth for source
        # writer≠validator: independently re-verify reportable findings before
        # they ship. Off by default (re-running a deterministic oracle is
        # redundant); turn on when a non-deterministic/LLM writer is in the loop.
        self.validate = validate
        self.findings: list[Finding] = []

    async def _escalate(self, cand: Candidate, finding: Finding) -> Finding:
        """Spawn an escalation sub-agent to climb a proven fault toward a
        vendor-grade primitive; upgrade the finding to the highest rung reached."""
        from .agents.escalation import EscalationAgent
        agent = self.child(EscalationAgent, candidate=cand,
                           escalation_oracles=self.escalation)
        best = await agent.execute()
        # LLM synthesis: when a model is configured, it writes sharper exploit
        # inputs the deterministic escalation oracles then certify — pushing past
        # what the fuzzer reached. Model proposes, oracle proves.
        if self.llm is not None and getattr(self.llm, "available", False) and self.escalation:
            from .agents.llm_synth import LLMSynthAgent, STRATEGIES
            # a SQUAD of payload-crafters, each attacking the primitive from a
            # different angle, in parallel — the oracle certifies whoever wins.
            squad = [self.child(LLMSynthAgent, candidate=cand, llm=self.llm,
                                oracles=self.escalation, strategy=s)
                     for s in STRATEGIES]
            verdicts = await asyncio.gather(*[a.execute() for a in squad],
                                            return_exceptions=True)
            for v in verdicts:
                from .ladder import Verdict as _V
                if isinstance(v, _V) and v.outcome is Outcome.PROVEN and (
                        best is None or v.rung > best.rung):
                    best = v
        if best is not None and best.outcome is Outcome.PROVEN and best.rung > finding.rung:
            # Carry the base proof's reproducer + symbolized crash forward: the
            # escalation oracle certified a higher rung, but the richest crash
            # evidence (symbolized frames, the captured trigger) was produced by
            # the initial symbolized proof. The packet needs both.
            base_ev = finding.verdict.evidence or {}
            if not best.reproducer and finding.verdict.reproducer:
                best.reproducer = finding.verdict.reproducer
            if "crash" not in (best.evidence or {}) and base_ev.get("crash"):
                best.evidence = {**(best.evidence or {}),
                                 "crash": base_ev["crash"],
                                 "sanitizer_output": base_ev.get("sanitizer_output", "")}
            return Finding(candidate=cand, verdict=best, rung=best.rung,
                           primitive=best.primitive or finding.primitive)
        return finding

    def _oracle_by_name(self, name: str) -> Optional[Oracle]:
        for o in list(self.router.oracles) + self.escalation:
            if getattr(o, "name", None) == name:
                return o
        return None

    async def _validate(self, cand: Candidate, finding: Finding) -> Finding:
        """Independently re-verify a reportable finding (writer≠validator)."""
        from .agents.validator import ValidatorAgent
        oracle = self._oracle_by_name(finding.verdict.oracle)
        if oracle is None:
            return finding
        agent = self.child(ValidatorAgent, candidate=cand, oracle=oracle,
                           expected_rung=finding.rung)
        confirmed = await agent.execute()
        finding.artifacts["validated"] = confirmed is not None
        return finding

    async def _package(self, cand: Candidate, finding: Finding) -> Finding:
        """Assemble the vendor-disclosure packet → promote to VENDOR_READY."""
        from .agents.reporter import ReporterAgent
        agent = self.child(ReporterAgent, finding=finding, llm=self.llm)
        return await agent.execute() or finding

    async def run(self) -> list[Finding]:
        tname = getattr(self.ctx.target, "name", None) or self.ctx.job_id
        self.objective(f"hunt + prove exploitable bugs on {tname}")

        candidates = await self._discover()
        self.log(f"{len(candidates)} candidate(s) from discovery")
        await self._verify_and_climb(candidates)

        self.em.emit(EventType.LADDER, board=self.ctx.ladder.board())
        return self.findings

    # ── 1. parallel discovery ──
    async def _discover(self) -> list[Candidate]:
        agents = [f(self.ctx, parent_id=self.agent_id) for f in self.discovery]
        # the LLM brain runs ALONGSIDE the deterministic fuzzer: it fans out
        # specialist lens sub-agents whose hypotheses the oracles then prove.
        if self.llm is not None and getattr(self.llm, "available", False):
            from .agents.llm_strategist import LLMStrategistAgent
            agents.append(LLMStrategistAgent(self.ctx, parent_id=self.agent_id,
                                             harness=self.harness, llm=self.llm))
        results = await asyncio.gather(*[a.execute() for a in agents],
                                       return_exceptions=True)
        candidates: list[Candidate] = []
        for r in results:
            if isinstance(r, list):
                candidates.extend(c for c in r if isinstance(c, Candidate))
        return candidates

    # ── 2. route each candidate through its oracle, record ladder climbs ──
    async def _verify_and_climb(self, candidates: list[Candidate]) -> None:
        for cand in candidates:
            if self.ctx.budget.expired():
                self.log("budget expired — stopping verification")
                break
            self.em.emit(EventType.CANDIDATE, title=cand.title,
                         bug_class=cand.bug_class, agent=cand.agent)
            # Oracles are synchronous + may shell out — keep the loop responsive.
            verdict = await asyncio.to_thread(self.router.verify, self.ctx, cand)
            if verdict is None:
                self.em.emit(EventType.ORACLE_VERDICT, title=cand.title,
                             outcome="no_oracle", bug_class=cand.bug_class)
                continue
            climbed = self.ctx.ladder.apply(cand, verdict)
            self.em.emit(EventType.ORACLE_VERDICT, title=cand.title,
                         oracle=verdict.oracle, outcome=verdict.outcome.value,
                         rung=int(verdict.rung), feedback=verdict.feedback)
            if climbed:
                self.em.emit(EventType.RUNG_UP, title=cand.title,
                             rung=int(verdict.rung), rung_name=verdict.rung.name)
            if verdict.outcome is Outcome.PROVEN:
                # A proven candidate becomes a finding; then an escalation
                # sub-agent drives it up the weaponization rungs
                # (PROVEN_PRIMITIVE → PROVEN_EXPLOIT → …). Finding.reportable /
                # vendor_shippable gate what a report/vendor ultimately sees.
                finding = Finding(candidate=cand, verdict=verdict,
                                  rung=verdict.rung, primitive=verdict.primitive)
                if self.escalation:
                    finding = await self._escalate(cand, finding)
                if self.validate and finding.reportable:
                    finding = await self._validate(cand, finding)
                if self.package and finding.rung >= VENDOR_MIN:
                    finding = await self._package(cand, finding)
                self.findings.append(finding)

"""Job runner — assembles the fleet for one engagement and runs it to findings.

Brackets a run with JOB_START / JOB_DONE on the event bus (so the UI knows when
to stop streaming), routes discovery + oracles through the Coordinator, and
persists findings to the per-job artifact store. `lab_job` is the LLM-free
end-to-end used for Phase-A demos/tests: a SourceTarget + a fuzzing discovery
agent + the sanitizer oracle.
"""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from functools import partial
from pathlib import Path
from typing import Callable, Optional

from .agents.fuzz_discovery import FuzzDiscoveryAgent
from .context import JobContext
from .coordinator import Coordinator
from .events import EventType
from .ladder import Finding
from .oracles.base import Oracle
from .oracles.controllability import ControllabilityOracle
from .oracles.sanitizer import SanitizerOracle
from .targets.source import SourceTarget


def _jsonable(obj):
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if hasattr(obj, "value"):            # enums
        return obj.value
    return obj


def _persist(ctx: JobContext, findings: list[Finding]) -> None:
    out = ctx.artifacts / "findings.json"
    out.write_text(json.dumps([_jsonable(f) for f in findings], indent=2,
                              default=str))


async def run_job(ctx: JobContext, *, discovery: list[Callable],
                  oracles: list[Oracle], escalation: list[Oracle] | None = None,
                  llm=None, harness: str = "") -> list[Finding]:
    ctx.bus.append(EventType.JOB_START,
                   target=getattr(ctx.target, "name", "") or ctx.job_id,
                   target_type=getattr(ctx.target, "target_type", ""),
                   llm=getattr(llm, "model", None) if getattr(llm, "available", False) else None)
    findings: list[Finding] = []
    try:
        coord = Coordinator(ctx, discovery=discovery, oracles=oracles,
                            escalation=escalation, llm=llm, harness=harness)
        findings = await coord.execute() or []
        # governance: collapse duplicate bugs, classify novelty (never auto-0day)
        from .dedup import dedupe
        from .novelty import classify
        findings, removed = dedupe(findings)
        if removed:
            ctx.bus.append(EventType.LOG,
                           text=f"deduped {removed} duplicate finding(s)")
        for f in findings:
            f.novelty = classify(f)
    except Exception as e:               # a job must fail loud but clean
        ctx.bus.append(EventType.ERROR, error=f"{type(e).__name__}: {e}")
    _persist(ctx, findings)
    ctx.bus.append(
        EventType.JOB_DONE,
        findings=len(findings),
        reportable=sum(1 for f in findings if f.reportable),
        vendor_ready=sum(1 for f in findings if f.vendor_shippable),
        board=ctx.ladder.board(),
    )
    return findings


def lab_job(job_id: str, harness: str, *, artifacts_root: Optional[Path] = None,
            name: str = "lab-target", max_tries: int = 8, escalate: bool = True,
            provider: Optional[str] = None, model: Optional[str] = None,
            api_key: Optional[str] = None, base_url: Optional[str] = None):
    """Assemble the end-to-end: fuzz + (optional) LLM brain → sanitizer-prove →
    escalate (+ LLM synthesis) toward a controlled primitive.

    Returns (ctx, discovery, oracles, escalation, llm). With a provider selected,
    the LLM brain runs alongside the fuzzer and LLM synthesis aids escalation;
    without one it's NullLLM and the deterministic pipeline is unchanged.
    """
    from .llm import make_client
    root = artifacts_root or (Path.cwd() / "runs")
    target = SourceTarget(root / job_id / "work", name=name)
    ctx = JobContext(job_id, target=target, artifacts_root=root)
    discovery = [partial(FuzzDiscoveryAgent, harness=harness, max_tries=max_tries)]
    oracles: list[Oracle] = [SanitizerOracle()]
    escalation: list[Oracle] = [ControllabilityOracle()] if escalate else []
    llm = make_client(provider, model, api_key, base_url)
    return ctx, discovery, oracles, escalation, llm


def binary_lab_job(job_id: str, binary_path: str, *,
                   artifacts_root: Optional[Path] = None,
                   name: str = "binary-target", max_tries: int = 8
                   ) -> tuple[JobContext, list[Callable], list[Oracle], list[Oracle]]:
    """Assemble a job for a closed-source binary: fuzz it concretely → prove the
    crash by signal → (symbolic escalation lights up if angr is present)."""
    from .oracles.binary_crash import BinaryCrashOracle
    from .oracles.symbolic import SymbolicOracle
    from .targets.binary import BinaryTarget

    root = artifacts_root or (Path.cwd() / "runs")
    target = BinaryTarget(binary_path, name=name)
    ctx = JobContext(job_id, target=target, artifacts_root=root)
    discovery = [partial(FuzzDiscoveryAgent, harness="", bug_class="binary_crash",
                         max_tries=max_tries)]
    oracles: list[Oracle] = [BinaryCrashOracle()]
    escalation: list[Oracle] = [SymbolicOracle()]
    return ctx, discovery, oracles, escalation

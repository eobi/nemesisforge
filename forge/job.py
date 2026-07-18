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

from . import fuzzengine
from .agents.fuzz_discovery import FuzzDiscoveryAgent
from .agents.libfuzzer_discovery import LibFuzzerDiscoveryAgent
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


def _meta(ctx: JobContext, **kw) -> None:
    """Persist run metadata for the history view."""
    path = ctx.artifacts / "metadata.json"
    cur = {}
    if path.exists():
        try:
            cur = json.loads(path.read_text())
        except Exception:
            cur = {}
    cur.update(kw)
    path.write_text(json.dumps(cur, default=str))


async def run_job(ctx: JobContext, *, discovery: list[Callable],
                  oracles: list[Oracle], escalation: list[Oracle] | None = None,
                  llm=None, harness: str = "") -> list[Finding]:
    tname = getattr(ctx.target, "name", "") or ctx.job_id
    ttype = getattr(ctx.target, "target_type", "")
    llm_name = getattr(llm, "model", None) if getattr(llm, "available", False) else None
    ctx.bus.append(EventType.JOB_START, target=tname, target_type=ttype, llm=llm_name)
    _meta(ctx, job_id=ctx.job_id, target=tname, target_type=ttype, llm=llm_name,
          status="running")
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
    top = max((int(f.rung) for f in findings), default=0)
    _meta(ctx, status="done", findings=len(findings),
          vendor_ready=sum(1 for f in findings if f.vendor_shippable),
          top_rung=top)
    ctx.bus.append(
        EventType.JOB_DONE,
        findings=len(findings),
        reportable=sum(1 for f in findings if f.reportable),
        vendor_ready=sum(1 for f in findings if f.vendor_shippable),
        board=ctx.ladder.board(),
    )
    return findings


def _dict_from(harness: str, root: Path, job_id: str) -> Optional[Path]:
    """Cheap structure hint: seed a libFuzzer dictionary from quoted string /
    magic-byte literals in the harness so it clears guards faster."""
    import re
    toks = set(re.findall(r'"([ -~]{2,32})"', harness))
    toks |= {t for t in re.findall(r"'([ -~]{2,8})'", harness)}
    if not toks:
        return None
    d = root / job_id / "fuzz.dict"
    d.parent.mkdir(parents=True, exist_ok=True)
    d.write_text("\n".join(f'kw{i}="{t}"' for i, t in enumerate(sorted(toks))))
    return d


def lab_job(job_id: str, harness: str, *, artifacts_root: Optional[Path] = None,
            name: str = "lab-target", max_tries: int = 8, escalate: bool = True,
            fuzz_time: int = 20,
            provider: Optional[str] = None, model: Optional[str] = None,
            api_key: Optional[str] = None, base_url: Optional[str] = None):
    """Assemble the end-to-end: fuzz + (optional) LLM brain → sanitizer-prove →
    escalate (+ LLM synthesis) toward a controlled primitive.

    Discovery auto-routes: an `LLVMFuzzerTestOneInput` harness on a machine with a
    libFuzzer-capable clang runs the real coverage-guided engine; otherwise the
    legacy length-sweep fuzzer (so it always degrades, never breaks).

    Returns (ctx, discovery, oracles, escalation, llm). With a provider selected,
    the LLM brain runs alongside the fuzzer and LLM synthesis aids escalation;
    without one it's NullLLM and the deterministic pipeline is unchanged.
    """
    from .llm import make_client
    root = artifacts_root or (Path.cwd() / "runs")
    target = SourceTarget(root / job_id / "work", name=name)
    ctx = JobContext(job_id, target=target, artifacts_root=root)

    if "LLVMFuzzerTestOneInput" in harness and fuzzengine.find_libfuzzer_clang():
        discovery = [partial(LibFuzzerDiscoveryAgent, harness=harness,
                             corpus_dir=root / job_id / "corpus",
                             dict_path=_dict_from(harness, root, job_id),
                             max_total_time=fuzz_time)]
    else:
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

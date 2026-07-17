"""Vendor-disclosure packager + ReporterAgent (rung 6, VENDOR_READY)."""
import asyncio
from pathlib import Path

from forge.agents.reporter import ReporterAgent
from forge.context import JobContext
from forge.events import EventType
from forge.ladder import (
    Candidate, Finding, Outcome, Primitive, PrimitiveKind, Rung, Verdict,
)
from forge.llm import NullLLM
from forge.packager import assemble_packet


def _finding(tmp_path) -> Finding:
    repro = tmp_path / "r.bin"
    repro.write_bytes(b"A" * 32)
    crash = {"bug_type": "heap-buffer-overflow", "access": "WRITE",
             "summary": "heap-buffer-overflow (WRITE) at parser.c:88",
             "frames": [{"func": "parse", "file": "/src/parser.c", "line": 88}]}
    verdict = Verdict(Outcome.PROVEN, Rung.PROVEN_PRIMITIVE, "controllability",
                      evidence={"crash": crash,
                                "sanitizer_output": "==ERROR: AddressSanitizer: "
                                "heap-buffer-overflow ... WRITE of size 32"},
                      reproducer=str(repro))
    prim = Primitive(kind=PrimitiveKind.OOB_WRITE, controlled=True,
                     where="out-of-bounds write extent",
                     detail={"bug_type": "heap-buffer-overflow"})
    return Finding(candidate=Candidate(bug_class="memory_safety",
                                       title="overflow in parse()"),
                   verdict=verdict, rung=Rung.PROVEN_PRIMITIVE, primitive=prim)


def _ctx(tmp_path):
    return JobContext(f"job-{tmp_path.name}", artifacts_root=tmp_path)


def test_assemble_packet_writes_six_artifacts(tmp_path):
    ctx = _ctx(tmp_path)
    m = assemble_packet(_finding(tmp_path), ctx, llm=NullLLM())
    # controlled OOB write → critical
    assert m["severity"] == "critical"
    assert m["bug_type"] == "heap-buffer-overflow"
    assert m["reproducer_len"] == 32 and m["artifacts_complete"] is True
    assert m["root_cause"] and m["suggested_patch"]
    pkt = ctx.artifacts / "packet"
    for name in ("reproducer.bin", "sanitizer.txt", "advisory.md",
                 "run.sh", "manifest.json"):
        assert (pkt / name).exists(), name
    advisory = (pkt / "advisory.md").read_text()
    assert "CRITICAL" in advisory and "parser.c:88" in advisory
    assert "Suggested patch" in advisory


def test_reporter_promotes_to_vendor_ready(tmp_path):
    ctx = _ctx(tmp_path)
    finding = _finding(tmp_path)
    agent = ReporterAgent(ctx, finding=finding, llm=NullLLM())
    out = asyncio.run(agent.execute())
    assert out.rung is Rung.VENDOR_READY and out.vendor_shippable is True
    assert out.artifacts.get("packet")
    assert any(e.type == EventType.VENDOR_PACKET for e in ctx.bus.all())


def test_reporter_skips_below_primitive(tmp_path):
    ctx = _ctx(tmp_path)
    f = _finding(tmp_path)
    f.rung = Rung.PROVEN_SECURITY          # rung 3 < VENDOR_MIN (4)
    out = asyncio.run(ReporterAgent(ctx, finding=f).execute())
    assert out.rung is Rung.PROVEN_SECURITY   # not packaged/promoted
    assert not any(e.type == EventType.VENDOR_PACKET for e in ctx.bus.all())

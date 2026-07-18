"""Audit trail + health tracking — the "nothing fails silently" layer.

Asserts: the audit log persists + reads back; the health tracker attributes an
agent's error to its section (learned from AGENT_SPAWNED), keeps a healthy section
green, and flags a section that went quiet as SILENT."""
import time

from forge.audit import (AuditLog, HealthTracker, FAILING, DEGRADED, SILENT,
                         HEALTHY)
from forge.events import Event, EventType


def _ev(type, *, agent_id="", ts=None, **data):
    return Event(type=type, job_id="j", agent_id=agent_id, data=data,
                 ts=ts if ts is not None else time.time())


def test_audit_log_persists_and_reads_back(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("login", actor="alice", ok=True, ip="1.2.3.4")
    log.record("scan", actor="alice", target="cJSON", job_id="forge-1")
    log.record("login_failed", actor="mallory", ok=False)
    entries = log.recent(10)
    assert [e["action"] for e in entries] == ["login_failed", "scan", "login"]
    assert log.recent(10, action="scan")[0]["target"] == "cJSON"


def test_health_attributes_error_to_the_right_section():
    h = HealthTracker()
    # the fleet learns agent_id → section from the spawn event
    h.feed(_ev(EventType.AGENT_SPAWNED, agent_id="a1", kind="harness_synth"))
    h.feed(_ev(EventType.THINK, agent_id="a1", text="synthesizing"))
    h.feed(_ev(EventType.ERROR, agent_id="a1", error="clang segfault"))
    h.feed(_ev(EventType.ERROR, agent_id="a1", error="clang segfault"))
    h.feed(_ev(EventType.ERROR, agent_id="a1", error="clang segfault"))
    summ = h.summary()
    sec = next(s for s in summ["sections"] if s["section"] == "harness_synth")
    assert sec["status"] == FAILING and sec["errors"] == 3
    assert "clang segfault" in sec["last_error"]
    assert summ["overall"] == FAILING


def test_healthy_section_and_oracle_attribution():
    h = HealthTracker()
    h.feed(_ev(EventType.AGENT_SPAWNED, agent_id="c", kind="coordinator"))
    h.feed(_ev(EventType.THINK, agent_id="c", text="hunting"))
    h.feed(_ev(EventType.ORACLE_VERDICT, oracle="sanitizer", outcome="proven"))
    summ = h.summary()
    kinds = {s["section"] for s in summ["sections"]}
    assert "coordinator" in kinds
    assert "oracle:sanitizer" in kinds       # oracle health tracked by name
    assert summ["overall"] == HEALTHY


def test_silent_section_is_surfaced():
    h = HealthTracker()
    old = time.time() - 600                   # active 10 minutes ago, then quiet
    h.feed(_ev(EventType.AGENT_SPAWNED, agent_id="v", kind="variant_hunter", ts=old))
    h.feed(_ev(EventType.THINK, agent_id="v", text="analyzing", ts=old))
    sec = next(s for s in h.summary()["sections"] if s["section"] == "variant_hunter")
    assert sec["status"] == SILENT            # we KNOW it stopped, not guessing

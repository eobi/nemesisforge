"""Audit trail + live health tracking — so nothing fails silently.

Two cross-cutting observers fed by every event on the bus (plus explicit web
actions like logins and scans):

  - AuditLog: an append-only JSONL trail of security-relevant actions (who ran
    what, when, and how it ended). Durable — survives restarts, so there is always
    a record of what the engine did.
  - HealthTracker: a live per-SECTION health view (each agent kind, each oracle,
    ingestion, the LLM, the web layer). It counts activity + failures, remembers
    the last error, and — crucially — flags a section that has STOPPED producing
    events as `silent`. That directly answers the operator's fear: "a part of the
    app is failing and I don't know." Now you know: it turns amber/red.

The tracker learns which agent_id belongs to which section from AGENT_SPAWNED, then
attributes later events (errors, verdicts) to the right section.
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from .events import Event, EventType, add_event_sink

# How long a section can be idle (after being active) before it reads as silent.
_SILENT_AFTER = 90.0        # seconds

# Status severity order (worst first) for sorting/rollup.
FAILING, DEGRADED, SILENT, HEALTHY, IDLE = (
    "failing", "degraded", "silent", "healthy", "idle")
_SEVERITY = {FAILING: 0, DEGRADED: 1, SILENT: 2, HEALTHY: 3, IDLE: 4}


class AuditLog:
    """Append-only JSONL audit trail."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(self, action: str, *, actor: str = "system", ok: bool = True,
               **fields: Any) -> dict:
        entry = {"ts": time.time(), "action": action, "actor": actor,
                 "ok": ok, **fields}
        line = json.dumps(entry, default=str)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as fh:
                fh.write(line + "\n")
        return entry

    def recent(self, limit: int = 200, *, action: Optional[str] = None) -> list[dict]:
        if not self.path.exists():
            return []
        out: list[dict] = []
        with self._lock:
            lines = self.path.read_text(errors="replace").splitlines()
        for ln in reversed(lines):            # newest first
            try:
                e = json.loads(ln)
            except Exception:
                continue
            if action and e.get("action") != action:
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out


class _Section:
    __slots__ = ("name", "events", "errors", "last_error", "last_ts",
                 "first_ts", "active")

    def __init__(self, name: str) -> None:
        self.name = name
        self.events = 0
        self.errors = 0
        self.last_error: Optional[str] = None
        self.last_ts = 0.0
        self.first_ts = 0.0
        self.active = False        # has this section done real work this session?

    def status(self, now: float, *, job_active: bool) -> str:
        # Errors always matter, running or not.
        if self.errors:
            recent = self.last_ts and now - self.last_ts < _SILENT_AFTER
            return FAILING if (self.errors >= 3 and recent) else DEGRADED
        if not self.active:
            return IDLE
        idle = self.last_ts and now - self.last_ts > _SILENT_AFTER
        # `silent` is only an alarm while a job is RUNNING — a section that should
        # be producing events but stopped. Between jobs, a quiet section is just idle.
        if idle:
            return SILENT if job_active else IDLE
        return HEALTHY

    def snapshot(self, now: float, *, job_active: bool) -> dict:
        return {"section": self.name, "status": self.status(now, job_active=job_active),
                "events": self.events, "errors": self.errors,
                "last_error": self.last_error,
                "idle_s": round(now - self.last_ts, 1) if self.last_ts else None}


class HealthTracker:
    """Live per-section health, fed by the event bus."""

    def __init__(self) -> None:
        self._sections: dict[str, _Section] = {}
        self._agent_section: dict[str, str] = {}   # agent_id → section (kind)
        self._active_jobs: set[str] = set()        # JOB_START seen, no JOB_DONE yet
        self._lock = threading.Lock()

    def feed(self, ev: Event) -> None:
        d = ev.data or {}
        with self._lock:
            # Track whether any job is actively running (so `silent` only alarms
            # mid-run, not between engagements).
            if ev.type == EventType.JOB_START:
                self._active_jobs.add(ev.job_id)
            elif ev.type == EventType.JOB_DONE:
                self._active_jobs.discard(ev.job_id)
            # Learn agent_id → section from spawn events.
            if ev.type == EventType.AGENT_SPAWNED and ev.agent_id:
                self._agent_section[ev.agent_id] = d.get("kind") or d.get("name") \
                    or "agent"
            section = self._section_for(ev)
            s = self._sections.get(section)
            if s is None:
                s = self._sections[section] = _Section(section)
            s.events += 1
            s.last_ts = ev.ts or time.time()
            if not s.first_ts:
                s.first_ts = s.last_ts
            # "active" = did meaningful work (not just spawn/idle chatter)
            if ev.type not in (EventType.AGENT_SPAWNED, EventType.AGENT_DONE):
                s.active = True
            if ev.type == EventType.ERROR or (
                    ev.type == EventType.AGENT_DONE and d.get("failed")):
                s.errors += 1
                s.last_error = (d.get("error") or d.get("text")
                                or f"{ev.type} in {section}")[:300]

    def _section_for(self, ev: Event) -> str:
        d = ev.data or {}
        if ev.type == EventType.ORACLE_VERDICT and d.get("oracle"):
            return f"oracle:{d['oracle']}"
        if ev.type in (EventType.JOB_START, EventType.JOB_DONE):
            return "job"
        if ev.agent_id and ev.agent_id in self._agent_section:
            return self._agent_section[ev.agent_id]
        if ev.type == EventType.ERROR and d.get("name"):
            return d["name"].split(":")[0]
        return ev.agent_id and "agent" or "job"

    def summary(self) -> dict:
        now = time.time()
        with self._lock:
            job_active = bool(self._active_jobs)
            sections = [s.snapshot(now, job_active=job_active)
                        for s in self._sections.values()]
        sections.sort(key=lambda x: (_SEVERITY.get(x["status"], 9), x["section"]))
        counts: dict[str, int] = defaultdict(int)
        for s in sections:
            counts[s["status"]] += 1
        if counts[FAILING]:
            overall = FAILING
        elif counts[DEGRADED]:
            overall = DEGRADED
        elif counts[SILENT]:
            overall = SILENT
        elif counts[HEALTHY]:
            overall = HEALTHY
        else:
            overall = IDLE                 # resting between jobs — calm, not alarming
        return {"overall": overall, "running": job_active,
                "counts": dict(counts), "sections": sections}


# ── process-wide singletons, wired to the bus once ──
_AUDIT: Optional[AuditLog] = None
HEALTH = HealthTracker()
_wired = False


def install(audit_path: Path) -> AuditLog:
    """Wire the audit log + health tracker to the event bus (idempotent)."""
    global _AUDIT, _wired
    _AUDIT = AuditLog(audit_path)
    if not _wired:
        add_event_sink(_on_event)
        _wired = True
    return _AUDIT


def audit() -> Optional[AuditLog]:
    return _AUDIT


def _on_event(ev: Event) -> None:
    HEALTH.feed(ev)
    # Persist the security-relevant milestones (not the high-volume chatter).
    if _AUDIT is not None and ev.type in (
            EventType.JOB_START, EventType.JOB_DONE, EventType.ERROR,
            EventType.VENDOR_PACKET):
        d = ev.data or {}
        _AUDIT.record(f"event:{ev.type}", actor="engine", job_id=ev.job_id,
                      ok=ev.type != EventType.ERROR,
                      detail={k: d[k] for k in list(d)[:8]})

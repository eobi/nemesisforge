"""Finding dedup — many crashes, few bugs.

A fuzzer + a fleet of agents surface the same underlying bug many times (via
different inputs, slightly different stacks). Reporting each as a separate finding
inflates the count and buries the signal — exactly the "AI slop" a vendor
distrusts. This collapses findings to a canonical key (bug class + crash site +
stack hash) and keeps the highest-rung representative of each, so one bug = one
finding at its strongest proof. Pure/deterministic.
"""
from __future__ import annotations

from typing import Any

from .ladder import Finding


def _crash(f: Finding) -> dict:
    ev = f.verdict.evidence or {}
    return ev.get("crash") or {}


def canonical_key(f: Finding) -> str:
    c = f.candidate
    crash = _crash(f)
    frames = crash.get("frames") or []
    if frames:
        top = frames[0]
        sink = f"{top.get('file', '')}:{top.get('func', '')}"
    elif c.location:
        sink = f"{c.location.path}:{c.location.symbol or c.location.line}"
    else:
        sink = c.sink or c.title
    stack_hash = crash.get("stack_hash") or (
        c.crash.get("stack_hash") if isinstance(c.crash, dict) else "") or ""
    return f"{c.bug_class}|{sink}|{stack_hash}"


def dedupe(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Collapse duplicates, keeping the highest-rung finding per canonical key.
    Returns (kept, removed_count)."""
    best: dict[str, Finding] = {}
    for f in findings:
        k = canonical_key(f)
        cur = best.get(k)
        if cur is None or f.rung > cur.rung:
            best[k] = f
    kept = list(best.values())
    return kept, len(findings) - len(kept)

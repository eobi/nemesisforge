"""Novelty classification — proven ≠ new.

A proven bug may be a known n-day (already has a CVE / was seeded from one) or a
genuinely new candidate. Like Nemesis Zero, this is deliberately conservative: it
NEVER auto-labels a finding "zero-day" — promotion to zero-day is a human act
after triage. It only demotes to `n-day` on concrete evidence (a matching seed
CVE or CVE ids on the finding); everything else is `candidate` (worth a human's
attention). Pure/deterministic.
"""
from __future__ import annotations

from typing import Optional, Sequence

from .ladder import Finding

N_DAY = "n-day"
CANDIDATE = "candidate"


def classify(finding: Finding, seed_cves: Optional[Sequence[str]] = None) -> str:
    ev = finding.verdict.evidence or {}
    cve_ids = ev.get("cve_ids") or getattr(finding.candidate, "cve_ids", None) or []
    if seed_cves or cve_ids:
        return N_DAY               # known bug — concrete CVE linkage
    return CANDIDATE               # new-looking; a human decides if it's a 0-day

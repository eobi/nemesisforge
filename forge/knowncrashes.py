"""Known-crash corpus — the "genuine zero-day" gate.

A proven crash is not necessarily a NEW crash: the same bug re-surfaces every run,
and many are already-known n-days. This is a small persistent store, keyed by a
finding's canonical crash signature, that remembers what's been seen (and what
carries a CVE). It lets the engine label each finding:

  - n-day     — matches a signature tagged with a CVE (a known, disclosed bug)
  - known     — seen in a previous run (already surfaced; not new this time)
  - candidate — never seen before → worth a human's eyes for zero-day triage

It is deliberately conservative: it NEVER auto-labels anything "zero-day" (a human
does that after triage); it only demotes on concrete evidence. Pure + file-backed,
so it survives across runs and across the whole fleet.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from . import dedup
from .ladder import Finding

N_DAY = "n-day"
KNOWN = "known"
CANDIDATE = "candidate"


class KnownCrashes:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._db: dict[str, dict] = {}
        if self.path.exists():
            try:
                self._db = json.loads(self.path.read_text())
            except Exception:
                self._db = {}

    @staticmethod
    def signature(finding: Finding) -> str:
        return dedup.canonical_key(finding)

    def lookup(self, key: str) -> Optional[dict]:
        return self._db.get(key)

    def classify(self, finding: Finding, *, record: bool = True) -> str:
        """Label a finding vs the corpus; record novel ones as seen (so the NEXT
        run treats them as 'known', not new)."""
        key = self.signature(finding)
        cve_ids = self._cves(finding)
        prior = self._db.get(key)

        if cve_ids or (prior and prior.get("cve_ids")):
            verdict = N_DAY
        elif prior:
            verdict = KNOWN
        else:
            verdict = CANDIDATE

        if record:
            entry = prior or {"first_run": finding.candidate.agent if
                              finding.candidate else "", "runs": 0}
            entry["runs"] = int(entry.get("runs", 0)) + 1
            entry["bug_type"] = (finding.verdict.evidence or {}).get(
                "crash", {}).get("bug_type", "")
            entry["rung"] = int(finding.rung)
            if cve_ids:
                entry["cve_ids"] = sorted(set(entry.get("cve_ids", []))
                                          | set(cve_ids))
            self._db[key] = entry
        return verdict

    def add_cve(self, key: str, cve: str) -> None:
        entry = self._db.setdefault(key, {"runs": 0})
        entry["cve_ids"] = sorted(set(entry.get("cve_ids", [])) | {cve})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._db, indent=2, sort_keys=True))

    @staticmethod
    def _cves(finding: Finding) -> list[str]:
        ev = finding.verdict.evidence or {}
        return list(ev.get("cve_ids")
                    or getattr(finding.candidate, "cve_ids", None) or [])

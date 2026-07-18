"""Novelty verification — the "is this actually a zero-day?" gate.

Hard lesson (learned the hard way): our engine autonomously found a real heap
overflow in upng's `unfilter_scanline` and the local novelty gate labelled it
`candidate` (new) — but it was already **CVE-2025-11680**. A shallow bug in an
abandoned library is almost always already known; "no CVE in my local corpus" is
NOT "novel".

So this module does NOT decide novelty. It:
  1. runs best-effort PROGRAMMATIC checks (OSV.dev by commit + package guesses),
  2. ALWAYS emits the precise VERIFICATION QUERIES a human/assistant must run
     (library + vulnerable function + bug class) — the search that actually
     catches these,
  3. returns a verdict that is at most `known` (we found a match) or
     `UNVERIFIED` (nobody may claim "zero-day" until a real cross-check clears it).

Never returns "novel". A zero-day claim requires a human confirming the queries
come back empty against NVD/CVE/OSV/the vendor's issues.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Optional

KNOWN = "known"
UNVERIFIED = "unverified"        # the ONLY other state — never "novel"

_OSV = "https://api.osv.dev/v1/query"


def _post(url: str, body: dict, *, timeout: int = 15) -> Optional[dict]:
    try:
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"content-type": "application/json",
                     "User-Agent": "nemesis-forge"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def osv_lookup(*, package: str = "", commit: str = "") -> list[dict]:
    """Best-effort OSV.dev matches. Commit-hash queries are the most reliable;
    package queries need the right ecosystem, so we try a few."""
    hits: list[dict] = []
    seen: set[str] = set()

    def _collect(resp):
        for v in (resp or {}).get("vulns", []) or []:
            vid = v.get("id")
            if vid and vid not in seen:
                seen.add(vid)
                hits.append({"id": vid, "summary": (v.get("summary") or "")[:160],
                             "aliases": v.get("aliases", [])})

    if commit:
        _collect(_post(_OSV, {"commit": commit}))
    if package:
        for eco in ("OSS-Fuzz", "Debian", "Ubuntu", "GitHub Actions", ""):
            body = {"package": {"name": package}}
            if eco:
                body["package"]["ecosystem"] = eco
            _collect(_post(_OSV, body))
    return hits


def verification_queries(*, library: str, function: str, bug_type: str) -> list[str]:
    """The searches that ACTUALLY catch these (a human/assistant runs them)."""
    lib = library or "library"
    fn = function or ""
    bt = bug_type or "heap-buffer-overflow"
    q = [f"{lib} {fn} {bt} CVE".strip(),
         f"{lib} {fn} vulnerability".strip(),
         f'"{fn}" {bt}'.strip() if fn else f"{lib} {bt}",
         f"{lib} CVE advisory", f"{lib} security fuzzing crash"]
    # dedupe, keep order
    out, seen = [], set()
    for s in q:
        s = " ".join(s.split())
        if s and s not in seen:
            seen.add(s); out.append(s)
    return out


def assess(*, library: str, function: str, bug_type: str,
           commit: str = "") -> dict:
    """Cross-check a finding. Returns status (known|unverified) + matches +
    the queries a human MUST run before anyone says 'zero-day'."""
    matches = osv_lookup(package=library, commit=commit)
    queries = verification_queries(library=library, function=function,
                                   bug_type=bug_type)
    status = KNOWN if matches else UNVERIFIED
    note = ("matched a known advisory — NOT novel" if matches else
            "no automated match — novelty UNVERIFIED; run the queries against "
            "NVD/CVE/OSV and the project's issues before claiming a zero-day")
    return {"status": status, "matches": matches, "queries": queries,
            "note": note, "library": library, "function": function,
            "bug_type": bug_type}

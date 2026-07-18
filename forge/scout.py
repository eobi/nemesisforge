"""Target scout — find UNDER-FUZZED, security-relevant code where zero-days still live.

The hardest truth about zero-day hunting: it's mostly target selection. Bugs don't
survive in SQLite/OpenSSL/libpng — Google's OSS-Fuzz has hammered those 24/7 for
years. They survive in the long tail: niche parsers, decoders, serializers, and
protocol/format libraries that NO large fuzzer has ever touched. This scout finds
that long tail:

  1. Search GitHub for C/C++ libraries that parse untrusted input.
  2. Cross-reference the public OSS-Fuzz project list and DROP anything already
     covered — we deliberately hunt what Google does not.
  3. Rank the survivors by security relevance (parses input, real users, a clean
     buildable surface) so the fleet spends its campaign budget where a NEW bug is
     most plausible.

Network- + token-aware and fully degrading: no network / rate-limited → returns
what it can (or nothing) with a clear reason; never throws into the caller.
Coordinated disclosure: the scout PROPOSES; a human authorizes each target.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_GH = "https://api.github.com"
# Queries aimed at the untrusted-input long tail (not the fuzzed-to-death giants).
_QUERIES = [
    "language:C parser stars:30..3000",
    "language:C decoder stars:30..3000",
    "language:C++ parser stars:30..3000",
    "language:C serialization stars:20..2000",
    "language:C protocol stars:20..2000",
    "language:C file format stars:20..2000",
]
_INPUT_HINT = ("parse", "parser", "decode", "decoder", "codec", "deserial",
               "serial", "format", "protocol", "reader", "loader", "unpack",
               "demux", "inflate", "font", "image", "audio", "video", "packet")


@dataclass
class Target:
    name: str
    url: str
    stars: int = 0
    language: str = ""
    description: str = ""
    topics: list = field(default_factory=list)
    size_kb: int = 0
    oss_fuzzed: bool = False
    score: float = 0.0
    why: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "url": self.url, "stars": self.stars,
                "language": self.language, "description": self.description[:200],
                "size_kb": self.size_kb, "oss_fuzzed": self.oss_fuzzed,
                "score": round(self.score, 2), "why": self.why}


def _get(url: str, *, timeout: int = 20) -> Optional[object]:
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "nemesis-forge-scout"}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def oss_fuzz_projects(cache_dir: Optional[Path] = None,
                      ttl_hours: int = 168) -> set[str]:
    """Names of projects already in Google OSS-Fuzz (the 'already fuzzed' set).
    Cached to disk so we don't hammer the API."""
    cache = (Path(cache_dir) / "oss_fuzz_projects.json") if cache_dir else None
    if cache and cache.exists():
        try:
            blob = json.loads(cache.read_text())
            if time.time() - blob.get("ts", 0) < ttl_hours * 3600:
                return set(blob["projects"])
        except Exception:
            pass
    names: set[str] = set()
    page = _get(f"{_GH}/repos/google/oss-fuzz/contents/projects")
    if isinstance(page, list):
        names = {e["name"].lower() for e in page if e.get("type") == "dir"}
    if cache and names:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps({"ts": time.time(),
                                         "projects": sorted(names)}))
        except Exception:
            pass
    return names


def _search(query: str, per_page: int = 30) -> list[dict]:
    url = (f"{_GH}/search/repositories?q={urllib.parse.quote(query)}"
           f"&sort=updated&order=desc&per_page={per_page}")
    data = _get(url)
    return data.get("items", []) if isinstance(data, dict) else []


def score_target(t: Target, oss: set[str]) -> tuple[float, str]:
    """Rank by 'a new memory-safety bug is plausible AND it matters'."""
    text = f"{t.name} {t.description} {' '.join(t.topics)}".lower()
    reasons = []
    s = 0.0
    if t.oss_fuzzed:
        return -1.0, "already in OSS-Fuzz — saturated, skip"
    hints = sum(1 for h in _INPUT_HINT if h in text)
    if hints:
        s += min(hints, 4) * 2.0
        reasons.append(f"{hints} untrusted-input signal(s)")
    if t.language in ("C", "C++"):
        s += 2.0
    # popular enough to matter, not so huge it's already audited to death
    if 50 <= t.stars <= 1500:
        s += 2.0
        reasons.append("real users, not saturated")
    elif t.stars < 50:
        s += 0.5
    s += 1.0                                   # not in OSS-Fuzz → the whole point
    reasons.append("NOT in OSS-Fuzz")
    # Buildability: small repos are usually single/few-file libraries that
    # auto-build (the ones we CAN actually fuzz); huge repos need their own build
    # system and stall the harness. This is the wall, so weight it heavily.
    if 0 < t.size_kb <= 1500:
        s += 3.0
        reasons.append("small → auto-buildable")
    elif t.size_kb > 20000:
        s -= 3.0
        reasons.append("large → hard to auto-build")
    return s, "; ".join(reasons)


def scout(*, limit: int = 15, cache_dir: Optional[Path] = None) -> dict:
    """Return ranked under-fuzzed candidate targets (proposals for human approval)."""
    oss = oss_fuzz_projects(cache_dir)
    seen: dict[str, Target] = {}
    for q in _QUERIES:
        for it in _search(q):
            full = it.get("full_name", "")
            if not full or full in seen:
                continue
            name = (it.get("name") or "").lower()
            t = Target(
                name=it.get("name", ""), url=it.get("html_url", ""),
                stars=int(it.get("stargazers_count", 0)),
                language=it.get("language") or "",
                description=it.get("description") or "",
                topics=it.get("topics") or [],
                size_kb=int(it.get("size", 0)),
                oss_fuzzed=name in oss)
            t.score, t.why = score_target(t, oss)
            seen[full] = t
    ranked = sorted((t for t in seen.values() if t.score > 0),
                    key=lambda t: t.score, reverse=True)[:limit]
    return {"targets": [t.to_dict() for t in ranked],
            "considered": len(seen),
            "oss_fuzz_known": len(oss),
            "note": ("no results — set GITHUB_TOKEN for higher rate limits, or "
                     "supply targets manually") if not ranked else ""}

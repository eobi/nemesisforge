"""API-misuse triage — separate a REAL library vulnerability from a HARNESS ARTIFACT.

A fuzz harness can crash on its OWN mistake, not the library's: it allocates a buffer
and sizes it wrong for the API it calls, passes attacker data as a size/count/filename
(a parameter a real caller controls, not the attacker), calls APIs in an invalid
order/combination, or reuses one buffer across calls with different size needs. Those
crashes are not reportable — shipping one as a "zero-day" gets bounced by the maintainer
and costs reputation. (This is exactly what adpcm-xq turned out to be: a harness that
sized outbuf for one bps then called the 4-bit decoder on it.)

Two signals, combined:
  1. Deterministic: was the overflowed buffer allocated IN THE HARNESS (harness sized
     it → suspect) or IN THE LIBRARY (library over-wrote a buffer it manages → strong
     real-bug signal, like CWPack)?
  2. Adversarial LLM reviewer: given the harness + crash + library source, prompted to
     REFUTE the finding as harness-induced. Writer != reviewer; the verdict ANNOTATES
     and de-rates an artifact — it never deletes a finding, so a human still decides.

Conservative by design: only a confident "artifact" downgrades; anything unsure stays a
candidate (never hide a real bug).
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Optional

from .events import EventType

_HARNESS_FILE = "forge_harness"

_SYSTEM = (
    "You are a skeptical security reviewer. Decide whether a fuzzing crash is a REAL, "
    "reportable library vulnerability or a HARNESS ARTIFACT. Be adversarial: try to "
    "REFUTE it as the harness's fault.\n\n"
    "It is a HARNESS ARTIFACT (NOT reportable) if any hold:\n"
    "- The overflowed/misused buffer was allocated BY THE HARNESS and sized wrong for "
    "the library function actually called (or reused across calls with different size "
    "needs).\n"
    "- The harness passed attacker-controlled fuzz bytes as a NON-INPUT parameter — a "
    "size, length, count, capacity, index, or filename — that a real caller controls, "
    "not the attacker.\n"
    "- The harness called APIs in an invalid order/combination, or left required state "
    "uninitialized.\n\n"
    "It is a REAL vulnerability (reportable) only if reachable by feeding untrusted "
    "INPUT DATA through a documented API with correct setup and buffer management — a "
    "real application using the library the intended way would also crash. A buffer "
    "the LIBRARY itself allocated/manages overflowing is a strong real-bug signal.\n\n"
    'Respond ONLY as JSON: {"verdict":"real"|"artifact","category":"<short>",'
    '"reason":"<specific, cite the harness or library>"}'
)


def _alloc_in_harness(finding) -> Optional[bool]:
    """From the crash evidence: was the overflowed region allocated in the harness?
    Returns True (harness), False (library/elsewhere), or None (unknown)."""
    cr = (getattr(finding.verdict, "evidence", None) or {}).get("crash", {})
    alloc = cr.get("alloc_frames") or cr.get("allocated_by") or []
    if isinstance(alloc, str):
        return _HARNESS_FILE in alloc
    if isinstance(alloc, list) and alloc:
        for fr in alloc:
            f = fr.get("file", "") if isinstance(fr, dict) else str(fr)
            if _HARNESS_FILE in f:
                return True
            if f and f.endswith((".c", ".cc", ".cpp", ".h")):
                return False               # first named non-harness frame = library
    return None


def _lib_snippet(repo, file: str, line: int, span: int = 22) -> str:
    if not repo or not file:
        return ""
    base = Path(file).name
    root = getattr(repo, "root", None)
    if not root:
        return ""
    for p in Path(root).rglob(base):
        try:
            lines = p.read_text(errors="replace").splitlines()
        except Exception:
            continue
        lo, hi = max(0, line - span), min(len(lines), line + span // 2)
        return "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))
    return ""


async def _review_one(finding, repo, llm) -> dict:
    pc = finding.candidate.proposed_check or {}
    harness = pc.get("harness", "")
    cr = (getattr(finding.verdict, "evidence", None) or {}).get("crash", {})
    frames = cr.get("frames") or []
    top = frames[0] if frames else {}
    func, file, line = top.get("func", "?"), top.get("file", "?"), top.get("line", 0)
    alloc = _alloc_in_harness(finding)
    snippet = _lib_snippet(repo, file, int(line or 0))

    prompt = (
        f"CRASH: {cr.get('bug_type','?')} in {func} at {file}:{line}.\n"
        f"Overflowed buffer allocated in: "
        f"{'THE HARNESS' if alloc else ('the library/elsewhere' if alloc is False else 'unknown')}.\n\n"
        f"HARNESS:\n```c\n{harness[:4000]}\n```\n\n"
        f"LIBRARY SOURCE around the crash ({file}:{line}):\n```c\n{snippet[:2500]}\n```\n\n"
        f"Is this a real library vulnerability or a harness artifact?")
    try:
        parsed, _ = await asyncio.to_thread(llm.complete_json, _SYSTEM, prompt)
        if isinstance(parsed, dict) and parsed.get("verdict") in ("real", "artifact"):
            parsed["alloc_in_harness"] = alloc
            return parsed
    except Exception:
        pass
    # fall back to raw completion if the model didn't return clean JSON
    try:
        raw = await asyncio.to_thread(llm.complete, _SYSTEM, prompt, max_tokens=400)
        m = re.search(r'\{.*\}', raw or "", re.S)
        if m:
            parsed = json.loads(m.group(0))
            if parsed.get("verdict") in ("real", "artifact"):
                parsed["alloc_in_harness"] = alloc
                return parsed
    except Exception:
        pass
    return {"verdict": "unreviewed", "reason": "reviewer unavailable",
            "alloc_in_harness": alloc}


async def review(ctx, findings, llm) -> None:
    """Annotate each memory-safety candidate with a real/artifact verdict IN PLACE.
    A confident 'artifact' is de-rated (novelty='artifact') so it never reads as a
    zero-day candidate; everything else is left as-is. Conservative: never hides a
    finding, only annotates + counts."""
    llm = llm or getattr(ctx, "llm", None)      # callers may not thread llm into run_job
    if llm is None or not getattr(llm, "available", False):
        return
    repo = getattr(ctx, "repo", None)
    targets = [f for f in findings
               if getattr(f, "novelty", "") == "candidate"
               and getattr(f.candidate, "bug_class", "") == "memory_safety"]
    if not targets:
        return
    verdicts = await asyncio.gather(*[_review_one(f, repo, llm) for f in targets])
    for f, v in zip(targets, verdicts):
        f.artifacts["misuse_review"] = v
        if v.get("verdict") == "artifact":
            f.novelty = "artifact"           # de-rate: not a zero-day candidate
            ctx.bus.append(EventType.LOG,
                           text=f"misuse-triage: {f.candidate.title} flagged HARNESS "
                                f"ARTIFACT — {v.get('reason','')[:160]}")
        elif v.get("verdict") == "real":
            ctx.bus.append(EventType.LOG,
                           text=f"misuse-triage: {f.candidate.title} confirmed "
                                f"reachable via correct API usage")

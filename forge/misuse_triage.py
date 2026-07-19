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


# Undefined-behavior classes that are REAL but low-severity and usually by-design —
# not memory corruption, not a reportable vulnerability. Fast binary parsers routinely
# do unaligned reads on purpose (CWPack's getDDItem macros); UBSan flags them but they
# are benign on x86/ARM64 and a portability nit at worst. Kept out of the zero-day
# candidate bucket so a "real library behavior" verdict isn't mistaken for "severe".
_BENIGN_UB = re.compile(r"misaligned address|load of misaligned|unaligned|"
                        r"member access within misaligned", re.I)


def _benign_ub(finding) -> str:
    cr = (getattr(finding.verdict, "evidence", None) or {}).get("crash", {})
    bt = (cr.get("bug_type") or "").lower()
    title = getattr(finding.candidate, "title", "") or ""
    if "undefined" in bt and _BENIGN_UB.search(title):
        return ("misaligned-load UB — undefined behavior but NOT memory corruption; "
                "intentional unaligned read in most fast parsers, benign on x86/ARM64")
    return ""


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


# Distinct skeptical LENSES for the multi-vote panel (Refute-or-Promote / OpenAnt):
# independent reviewers each attack the finding from one angle, so a real bug must
# survive all of them and one over-eager skeptic can't sink it alone.
_LENSES = [
    ("buffer-sizing", "Focus ONLY on buffer sizing/allocation: did the HARNESS "
     "allocate or size a buffer wrong for the API it called, or reuse one buffer "
     "across calls with different size needs? If the LIBRARY over-writes a buffer it "
     "manages, that is a REAL bug."),
    ("argument-validity", "Focus ONLY on the arguments the harness passed: did it "
     "pass fuzz bytes as a size/length/count/index/filename, or pass NULL/invalid "
     "values for REQUIRED parameters, or call APIs in an invalid order? Those are "
     "harness artifacts. Valid setup feeding untrusted DATA is a real bug."),
    ("input-reachability", "Focus ONLY on reachability: is the crash reached by "
     "feeding untrusted INPUT DATA through a documented API with correct setup (real "
     "bug), or does it require the harness to mis-drive setup/config the attacker "
     "does not control (artifact)?"),
]


async def _review_one(finding, repo, llm, lens: str = "") -> dict:
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
        + (f"REVIEW LENS — {lens}\n\n" if lens else "")
        + f"HARNESS:\n```c\n{harness[:4000]}\n```\n\n"
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


async def _vote(finding, repo, llm) -> dict:
    """Run the skeptical panel over one finding and return a MAJORITY verdict.
    Conservative: de-rate to 'artifact' only when a majority of reviewers agree, so a
    single over-eager skeptic can never sink a real bug."""
    votes = await asyncio.gather(*[_review_one(finding, repo, llm, lens=desc)
                                   for _, desc in _LENSES])
    art = sum(1 for v in votes if v.get("verdict") == "artifact")
    real = sum(1 for v in votes if v.get("verdict") == "real")
    verdict = ("artifact" if art > real and art >= 2
               else "real" if real >= 2 else "unreviewed")
    reason = next((v.get("reason", "") for v in votes
                   if v.get("verdict") == verdict), "")
    return {"verdict": verdict, "reason": reason,
            "votes": {name: v.get("verdict") for (name, _), v in zip(_LENSES, votes)},
            "alloc_in_harness": votes[0].get("alloc_in_harness") if votes else None}


async def review(ctx, findings, llm) -> None:
    """Annotate each memory-safety candidate with a real/artifact verdict IN PLACE.
    A confident 'artifact' is de-rated (novelty='artifact') so it never reads as a
    zero-day candidate; everything else is left as-is. Conservative: never hides a
    finding, only annotates + counts."""
    llm = llm or getattr(ctx, "llm", None)      # callers may not thread llm into run_job
    if llm is None or not getattr(llm, "available", False):
        return
    repo = getattr(ctx, "repo", None)
    cands = [f for f in findings
             if getattr(f, "novelty", "") == "candidate"
             and getattr(f.candidate, "bug_class", "") == "memory_safety"]
    # De-prioritize benign, by-design undefined behavior (misaligned reads) BEFORE the
    # panel — real library behavior, but low-severity and not a reportable vuln.
    targets = []
    for f in cands:
        why = _benign_ub(f)
        if why:
            f.novelty = "low-severity"
            f.artifacts["severity"] = {"level": "low", "reason": why}
            ctx.bus.append(EventType.LOG,
                           text=f"triage: {f.candidate.title[:60]} → LOW-SEVERITY "
                                f"(by-design UB, not a vuln)")
        else:
            targets.append(f)
    if not targets:
        return
    verdicts = await asyncio.gather(*[_vote(f, repo, llm) for f in targets])
    for f, v in zip(targets, verdicts):
        f.artifacts["misuse_review"] = v
        if v.get("verdict") == "artifact":
            f.novelty = "artifact"           # de-rate: not a zero-day candidate
            ctx.bus.append(EventType.LOG,
                           text=f"misuse-triage: {f.candidate.title} flagged HARNESS "
                                f"ARTIFACT (panel {v.get('votes')}) — "
                                f"{v.get('reason','')[:140]}")
        elif v.get("verdict") == "real":
            ctx.bus.append(EventType.LOG,
                           text=f"misuse-triage: {f.candidate.title} confirmed "
                                f"reachable via correct API usage")

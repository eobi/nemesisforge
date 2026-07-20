"""PoV-gated patch generation (Buttercup / ATLANTIS discipline).

Never emit a patch without re-proving it kills the PoV. The LLM writes a fix for the
crashing library source; the DifferentialOracle then proves the SAME reproducer still
crashes the vulnerable build and is CLEAN on the patched build (REFUTED-on-patch). A
proven patch climbs the finding to PROVEN_EXPLOIT (rung 5) and is attached to the
report; a patch that doesn't re-prove is WITHHELD, not shipped. Cross-validation also
raises discovery precision: if the "patch" doesn't actually stop the crash, the crash
was likely a harness artifact, not a real library bug.

This module only GENERATES the candidate patch; the oracle is the gate.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Optional

_SYSTEM = (
    "You are a security engineer writing a MINIMAL, correct fix for a memory-safety "
    "bug in a C/C++ library. You are given the full source file, the crashing "
    "function, and the sanitizer report. Add the missing bounds/overflow/lifetime "
    "check that stops the crash WITHOUT changing the library's behavior on valid "
    "input. Do not refactor, rename, or touch unrelated code.\n"
    "Return the COMPLETE fixed source file verbatim (all of it), as JSON: "
    '{"patched_source":"<full file text>","explanation":"<one sentence>"}. The '
    "patched_source must be the entire file so it compiles as a drop-in replacement."
)


async def generate_patch(llm, *, source_text: str, function: str, line: int,
                         bug_type: str, sanitizer_output: str = "") -> Optional[str]:
    """One LLM call → the full patched source file (or None). Never trusted: the
    caller must prove it with the DifferentialOracle before using it."""
    if llm is None or not getattr(llm, "available", False) or not source_text:
        return None
    # keep the prompt bounded — center it on the crash site if the file is large
    src = source_text
    if len(src) > 12000 and line:
        lines = source_text.splitlines()
        lo, hi = max(0, line - 120), min(len(lines), line + 120)
        src = "\n".join(lines[lo:hi])
    prompt = (
        f"Crash: {bug_type} in {function}() at line {line}.\n"
        + (f"Sanitizer report:\n```\n{sanitizer_output[-1500:]}\n```\n"
           if sanitizer_output else "")
        + f"Source file to fix:\n```c\n{src[:14000]}\n```\n"
        "Return the complete fixed file.")
    parsed = None
    try:
        parsed, _ = await asyncio.to_thread(llm.complete_json, _SYSTEM, prompt)
    except Exception:
        parsed = None
    if not isinstance(parsed, dict):
        try:
            raw = await asyncio.to_thread(llm.complete, _SYSTEM, prompt, max_tokens=8000)
            m = re.search(r"\{.*\}", raw or "", re.S)
            parsed = json.loads(m.group(0)) if m else None
        except Exception:
            parsed = None
    if not isinstance(parsed, dict):
        return None
    patched = parsed.get("patched_source")
    if isinstance(patched, str) and patched.strip() and patched != source_text:
        return patched
    return None

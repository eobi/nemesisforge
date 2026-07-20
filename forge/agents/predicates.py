"""Directed reachability via LLM progress predicates (Locus, ICSE'26).

Blind coverage-guided mutation almost never constructs the valid-but-pathological
input that reaches a DEEP sink, so correctly-aimed hunts on maintained parsers come
back clean. Locus's fix: have the LLM synthesize ordered "progress predicates" —
intermediate milestones on the path from the entry point to the target sink — and
instrument them as source-level early-exit branches. libFuzzer then gets extra
coverage signal for each milestone reached and prunes executions that can't progress,
giving directed reachability (paper: ~40x faster directed fuzzing).

The honesty discipline is our own applied to fuzzer guidance — writer != validator:
a predicate is UNTRUSTED until it passes BOTH
  (1) the compiler (it must build), and
  (2) symbolic execution proving it is a STRICT RELAXATION of the sink's reaching
      condition — i.e. no input that could reach the sink is ever wrongly pruned.
Because the strict-relaxation proof needs angr, the directed lens runs on Docker/Linux
only; without angr NO predicate is emitted and the fuzzer runs undirected as before.

This module holds the pure, testable pieces (synthesis + source instrumentation);
symbolic validation is `validate()` (angr-gated) and the plumbing lives in the
harness-synth / co-driving agents.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Predicate:
    order: int                 # milestone index along entry -> sink
    function: str              # function whose entry we guard with this predicate
    condition: str             # C boolean expr over the function's params; MUST hold
    rationale: str = ""        # why reaching the sink implies this
    validated: bool = False    # passed compiler AND symbolic strict-relaxation


_SYSTEM = (
    "You are a fuzzing expert doing DIRECTED reachability. Given a C function that is "
    "on the path to a memory-safety sink, you produce ordered 'progress predicates' — "
    "boolean conditions over the function's PARAMETERS that MUST be true for execution "
    "to progress toward the sink. Each predicate is a necessary milestone: if it is "
    "false, the sink is unreachable on this call, so the fuzzer can prune it.\n"
    "STRICT RELAXATION RULE: a predicate must NEVER exclude an input that could reach "
    "the sink. Only assert conditions that are logically NECESSARY to reach it (e.g. a "
    "length field is non-zero, a tag byte selects the vulnerable branch, a pointer is "
    "non-NULL). When unsure, omit — a missing predicate is safe, a wrong one is not.\n"
    "Each condition must be valid C over ONLY the listed parameters (and integer/char "
    "literals), side-effect free, no function calls, no dereferences beyond what the "
    "params allow.\n"
    'Respond ONLY as JSON: {"predicates":[{"condition":"<C expr>","rationale":"<why '
    'necessary>"}, ...]} ordered from earliest milestone to nearest the sink. 0-4 '
    "predicates; fewer is fine."
)

# A predicate condition is only accepted if it references at least one parameter and
# contains no obviously unsafe constructs (calls, statements, dereferences we can't
# verify). Symbolic validation is the real gate; this is a cheap pre-filter.
_UNSAFE = re.compile(r";|\bwhile\b|\bfor\b|\breturn\b|->|\[\s*\w+\s*\]|=[^=]|\w+\s*\(")


async def synthesize(llm, *, function: str, params: list[str], guard_body: str,
                     chain: str = "", sink_text: str = "",
                     max_preds: int = 4) -> list[Predicate]:
    """One LLM call → ordered progress predicates over `function`'s parameters. Gated
    on a live model; returns [] otherwise (fuzzer runs undirected). Pre-filters to
    param-referencing, side-effect-free conditions — symbolic `validate()` is the real
    gate."""
    if llm is None or not getattr(llm, "available", False) or not function:
        return []
    pnames = [p for p in (_param_names(params)) if p]
    if not pnames:
        return []
    prompt = (
        f"Function under directed analysis: {function}({', '.join(params)})\n"
        f"Parameters you may reference: {', '.join(pnames)}\n"
        + (f"Call path entry -> sink: {chain}\n" if chain else "")
        + (f"Target sink line: {sink_text}\n" if sink_text else "")
        + f"Function body:\n```c\n{guard_body[:2600]}\n```\n"
        "Produce the ordered progress predicates.")
    parsed = None
    try:
        parsed, _ = await asyncio.to_thread(llm.complete_json, _SYSTEM, prompt)
    except Exception:
        parsed = None
    if not isinstance(parsed, dict):
        try:
            raw = await asyncio.to_thread(llm.complete, _SYSTEM, prompt, max_tokens=900)
            m = re.search(r"\{.*\}", raw or "", re.S)
            parsed = json.loads(m.group(0)) if m else None
        except Exception:
            parsed = None
    if not isinstance(parsed, dict):
        return []
    out: list[Predicate] = []
    for i, item in enumerate((parsed.get("predicates") or [])[:max_preds]):
        if not isinstance(item, dict):
            continue
        cond = str(item.get("condition", "")).strip()
        if not cond or _UNSAFE.search(cond):
            continue
        if not any(re.search(r"\b" + re.escape(p) + r"\b", cond) for p in pnames):
            continue                       # must constrain an actual parameter
        out.append(Predicate(order=i, function=function, condition=cond,
                             rationale=str(item.get("rationale", ""))[:200]))
    return out


def _param_names(params: list[str]) -> list[str]:
    names = []
    for p in params or []:
        ids = re.findall(r"[A-Za-z_]\w*", p)
        if ids and ids[-1] not in ("void", "const", "unsigned", "int", "char",
                                   "long", "short", "size_t", "uint8_t"):
            names.append(ids[-1])
    return names


# ── 2C. source-to-source instrumentation ────────────────────────────────────
# Weave `if (!(<cond>)) return <stub>;` at the entry of the target function, so
# libFuzzer prunes non-progressing executions and gains a coverage edge per milestone.

_RET_STUB = {"void": "", "bool": "0", "int": "0", "size_t": "0", "unsigned": "0",
             "long": "0", "short": "0", "char": "0", "float": "0", "double": "0"}


def _return_stub(signature: str) -> Optional[str]:
    """Derive a safe early-return for the function's return type from its signature.
    Returns the statement body ('' for void, '0' for scalars, 'NULL' for pointers),
    or None if the type is a struct/unknown we shouldn't fabricate a value for."""
    head = signature.split("(", 1)[0].strip()
    if "*" in head:                        # pointer return (`char *dup`, `T* f`)
        return "NULL"
    toks = re.findall(r"[A-Za-z_]\w*", head)
    toks = [t for t in toks if t not in ("static", "inline", "const", "extern",
                                         "__inline", "MG_INLINE", "DRFLAC_INLINE")]
    if not toks:
        return None
    rettype = toks[0] if len(toks) == 1 else toks[-2] if len(toks) >= 2 else toks[0]
    # `unsigned int foo` / `long long foo` → the type word before the name
    for t in toks[:-1]:
        if t in _RET_STUB:
            rettype = t
            break
    return _RET_STUB.get(rettype)


def instrument_source(source: str, function: str,
                      predicates: list[Predicate]) -> tuple[str, list[Predicate]]:
    """Insert validated predicate early-exits at the entry of `function` in `source`.
    Pure + deterministic. Returns (patched_source, predicates_actually_applied). Only
    predicates with a derivable return stub for this function are applied; the rest are
    skipped (conservative — never emit code that won't compile)."""
    applied = [p for p in predicates if p.validated and p.function == function]
    if not applied:
        return source, []
    # Find the function definition and its opening brace (the same header shape cscan
    # matches). We insert right after the `{`.
    hdr = re.compile(
        r"(?P<sig>(?:[A-Za-z_][\w\*\s\)\(,]*?\s|\*)?" + re.escape(function) +
        r"\s*\((?P<params>[^;{}]*)\))\s*\{")
    m = hdr.search(source)
    if not m:
        return source, []
    stub = _return_stub(m.group("sig"))
    if stub is None:
        return source, []                  # struct/unknown return — don't fabricate
    ret = f"return {stub};" if stub else "return;"
    guard = "".join(
        f"\n    if (!({p.condition})) {ret}  /* forge-predicate {p.order} */"
        for p in sorted(applied, key=lambda x: x.order))
    insert_at = m.end()                     # right after the opening brace
    patched = source[:insert_at] + guard + source[insert_at:]
    return patched, applied


# ── 2B. symbolic strict-relaxation validation (angr-gated; Docker/Linux) ─────
async def validate(predicates: list[Predicate], *, target, harness: str,
                   include_dirs, target_sources=None,
                   sanitizer: str = "address") -> list[Predicate]:
    """Prove each predicate is (1) compilable and (2) a STRICT RELAXATION of the sink's
    reaching condition via symbolic execution. Marks survivors `validated=True`.

    Requires angr (Docker/Linux). Without it, returns [] so the directed lens is a
    no-op and the fuzzer runs undirected — matching the 'full symbolic, Docker-only'
    decision: we never instrument a predicate we couldn't PROVE safe."""
    from .symbolic_hunter import angr_available
    if not angr_available() or not predicates:
        return []
    from . import predicate_symbolic       # heavy import; only under angr
    return await predicate_symbolic.prove_strict_relaxation(
        predicates, target=target, harness=harness, include_dirs=include_dirs,
        target_sources=target_sources, sanitizer=sanitizer)

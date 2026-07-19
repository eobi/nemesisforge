"""LLM format-aware inputs — the structure blind mutation lacks.

For a binary / length-prefixed parser, stock libFuzzer byte-mutation almost never
constructs a valid-but-pathological STRUCTURED input — e.g. a declared length that
exceeds the bytes actually present (the exact CWPack trigger) — so it never reaches
the deep length-handling code where such bugs live. That is why correctly-aimed deep
hunts on mpack/cmp came back clean.

This asks the LLM, which understands the format, for two things a coverage-guided
fuzzer cannot easily build on its own:
  - a libFuzzer DICTIONARY of the format's tokens (type tags, magic, length encodings)
  - a SEED CORPUS of valid + edge-case structured inputs biased to the bug class

Everything is base64 on the wire (no escaping ambiguity) and VALIDATED before use.
The fuzzer still finds the crash and the deterministic oracle still proves it — this
only helps the fuzzer REACH the code. State-of-the-art analogue: ISC4DGF (LLM initial
seed corpus, ~37x speedup), OSS-Fuzz-Gen (+coverage).
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence


@dataclass
class FormatHints:
    dict_tokens: list[bytes] = field(default_factory=list)   # format tokens for -dict
    seeds: list[bytes] = field(default_factory=list)          # structured seed inputs

    def empty(self) -> bool:
        return not self.dict_tokens and not self.seeds


_SYSTEM = (
    "You are a fuzzing expert who understands binary and text file formats. Given a C "
    "parser/decoder, you produce inputs a coverage-guided fuzzer (libFuzzer) cannot "
    "easily construct by random byte mutation, so it can reach deep parsing code.\n"
    "Output TWO things:\n"
    "1. dict_b64: a libFuzzer DICTIONARY as base64-encoded RAW BYTE tokens of the "
    "FORMAT this parser reads — type/tag bytes, magic/signature bytes, length-field "
    "encodings, delimiters, sentinel/reserved values. 20-40 short tokens (1-16 bytes "
    "each).\n"
    "2. seeds_b64: a SEED CORPUS as base64-encoded COMPLETE inputs. About half VALID, "
    "structurally diverse messages (different type tags, nesting, arrays/maps, "
    "strings/bins). About half EDGE CASES aimed at memory-safety bugs: a declared "
    "length/count LARGER than the bytes that follow (truncated), zero-length fields, "
    "deeply nested structures, maximum-value length fields, off-by-one boundaries. "
    "10-16 seeds.\n"
    'Respond ONLY as JSON: {"dict_b64":[...],"seeds_b64":[...]}. Every entry is valid '
    "base64 of raw bytes."
)


def _decode(items, cap: int, *, max_len: int) -> list[bytes]:
    out: list[bytes] = []
    for s in (items or [])[:cap]:
        try:
            b = base64.b64decode(str(s), validate=False)
        except Exception:
            continue
        if b and len(b) <= max_len:
            out.append(b)
    return out


async def generate(llm, *, library: str, header: str = "", entry: str = "",
                   guard: str = "", bug_class: str = "memory_safety",
                   max_seeds: int = 16, max_dict: int = 48) -> FormatHints:
    """One LLM call → (format dictionary tokens, structured seed inputs). Gated on a
    live model; returns empty hints otherwise (the fuzzer just runs as before)."""
    if llm is None or not getattr(llm, "available", False):
        return FormatHints()
    prompt = (
        f"Library: {library}\n"
        f"Public header:\n```c\n{header[:3000]}\n```\n"
        f"Entry function (reads untrusted input):\n```c\n{entry[:2000]}\n```\n"
        + (f"Relevant parsing code:\n```c\n{guard[:2000]}\n```\n" if guard else "")
        + f"Target bug class: {bug_class}.\n"
        "Produce the format dictionary and seed corpus.")
    parsed = None
    try:
        parsed, _ = await asyncio.to_thread(llm.complete_json, _SYSTEM, prompt)
    except Exception:
        parsed = None
    if not isinstance(parsed, dict):
        try:
            raw = await asyncio.to_thread(llm.complete, _SYSTEM, prompt, max_tokens=2200)
            m = re.search(r"\{.*\}", raw or "", re.S)
            parsed = json.loads(m.group(0)) if m else None
        except Exception:
            parsed = None
    if not isinstance(parsed, dict):
        return FormatHints()
    dict_tokens = [t for t in _decode(parsed.get("dict_b64"), max_dict, max_len=64)
                   if 1 <= len(t) <= 64]
    seeds = _decode(parsed.get("seeds_b64"), max_seeds, max_len=65536)
    return FormatHints(dict_tokens=dict_tokens, seeds=seeds)


def _esc(b: bytes) -> str:
    out = []
    for c in b:
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5c:
            out.append("\\\\")
        elif 0x20 <= c < 0x7f:
            out.append(chr(c))
        else:
            out.append(f"\\x{c:02x}")
    return "".join(out)


def write_dict(string_tokens: Optional[Sequence[str]],
               byte_tokens: Optional[Sequence[bytes]],
               path: Path) -> Optional[Path]:
    """Merge cscan's source-literal string tokens with the LLM's binary format tokens
    into ONE libFuzzer dictionary (per-byte hex escaping, correct for binary). Returns
    the path or None if there is nothing to write."""
    toks: list[bytes] = []
    for s in (string_tokens or []):
        if s:
            toks.append(s.encode("utf-8", "replace") if isinstance(s, str) else bytes(s))
    for b in (byte_tokens or []):
        if b:
            toks.append(bytes(b))
    seen: set[bytes] = set()
    uniq: list[bytes] = []
    for t in toks:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    if not uniq:
        return None
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f'kw{i}="{_esc(t)}"' for i, t in enumerate(uniq[:200])))
    return path

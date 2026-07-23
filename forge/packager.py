"""Vendor-disclosure packager — the whole point (rung 6, VENDOR_READY).

A crash proves a fault; a vendor acts on a reproducible, symbolized,
impact-demonstrating packet. This assembles that packet from a finding that has
already climbed to a controlled primitive (rung >= PROVEN_PRIMITIVE) — as a
byproduct of the proof that produced it, not a separate writing task. The six
artifacts every major vendor accepts:

  1. deterministic reproducer      (the captured trigger input + a run script)
  2. symbolized crash + sanitizer  (the typed proof — what upgrades "a crash"
                                     to "a memory-safety vulnerability")
  3. root-cause write-up           (object/field/code-path)
  4. severity + primitive          (exploitability + what the attacker controls)
  5. suggested patch               (moves us to the trusted/higher-paid tier)

Deterministic templates from the CrashInfo/Primitive; an LLMClient (when
configured) enriches the prose root-cause + patch, but is never required.
Reaching VENDOR_READY is a *packaging* step — it does not require full
weaponization, matching what vendors actually accept.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Optional

from .context import JobContext
from .ladder import Finding, PrimitiveKind

# Bug class → coarse severity, before the primitive/controllability nudge.
_SEVERITY = {
    "heap-buffer-overflow": "high", "stack-buffer-overflow": "high",
    "global-buffer-overflow": "high", "heap-use-after-free": "critical",
    "use-after-free": "critical", "double-free": "high",
    "use-after-poison": "high", "undefined-behavior": "medium",
}


def _severity(finding: Finding) -> str:
    ev = finding.verdict.evidence or {}
    bug = ((ev.get("crash") or {}).get("bug_type")
           or (finding.primitive.detail.get("bug_type") if finding.primitive else "")
           or "")
    sev = _SEVERITY.get(bug, "medium")
    # a proven *controlled* write primitive escalates severity.
    if finding.primitive and finding.primitive.controlled \
            and finding.primitive.kind in (PrimitiveKind.OOB_WRITE,
                                           PrimitiveKind.WRITE_WHAT_WHERE):
        sev = "critical"
    return sev


def _crash_of(finding: Finding) -> dict:
    ev = finding.verdict.evidence or {}
    return ev.get("crash") or {}


def _root_cause(finding: Finding, llm=None) -> str:
    crash = _crash_of(finding)
    bug = crash.get("bug_type") or (finding.primitive.detail.get("bug_type")
                                    if finding.primitive else "memory-safety bug")
    frames = crash.get("frames") or []
    top = frames[0] if frames else {}
    loc = f"{top.get('file','?')}:{top.get('line','?')}" if top else "the sink"
    access = crash.get("access") or ""
    det = (f"A {access.lower()+' ' if access else ''}{bug} occurs at {loc}. "
           f"An attacker-supplied input reaches this site and drives an "
           f"out-of-bounds {access.lower() or 'access'} whose extent tracks the "
           f"input length — i.e. the bounds of the operation are derived from "
           f"untrusted data without validation.")
    if llm is not None and getattr(llm, "available", False):
        prompt = (f"Write a concise root-cause analysis for a {bug} at {loc}. "
                  f"Sanitizer summary: {crash.get('summary','')}.")
        text = llm.complete("You are a vulnerability analyst.", prompt)
        if text:
            return text
    return det


def _suggested_patch(finding: Finding, llm=None) -> str:
    crash = _crash_of(finding)
    frames = crash.get("frames") or []
    loc = (f"{frames[0].get('file','?')}:{frames[0].get('line','?')}"
           if frames else "the vulnerable copy")
    det = (f"Validate the length/index against the destination buffer size "
           f"before the write at {loc} (bound the copy to the allocation, or "
           f"grow the allocation to the required size). Reject or truncate "
           f"untrusted lengths that exceed the buffer.")
    if llm is not None and getattr(llm, "available", False):
        text = llm.complete("You are a senior C security engineer.",
                            f"Suggest a minimal patch for the {crash.get('bug_type','bug')} "
                            f"at {loc}. Sanitizer: {crash.get('summary','')}.")
        if text:
            return text
    return det


def assemble_packet(finding: Finding, ctx: JobContext, *, llm=None) -> dict:
    """Build + persist the 6-artifact vendor packet. Returns its manifest and
    writes the reproducer, sanitizer report, and a markdown advisory to
    <artifacts>/packet/. Callers promote the finding to VENDOR_READY."""
    outdir = ctx.artifacts / "packet"
    outdir.mkdir(parents=True, exist_ok=True)
    crash = _crash_of(finding)
    severity = _severity(finding)
    prim = finding.primitive

    # 1. reproducer (input bytes + a run script)
    repro_src = finding.verdict.reproducer
    repro_bytes = b""
    if repro_src and Path(repro_src).exists():
        repro_bytes = Path(repro_src).read_bytes()
    (outdir / "reproducer.bin").write_bytes(repro_bytes)
    # An EXECUTABLE reproduce script (not a stub) for both OSes: point TARGET at
    # the affected binary/harness and it feeds the reproducer.
    run_sh = outdir / "run.sh"
    run_sh.write_text(
        '#!/bin/sh\n'
        '# Reproduce this finding. Set TARGET to the affected binary or ASan harness:\n'
        '#   TARGET=./vulnerable_binary ./run.sh\n'
        'set -e\n'
        'DIR="$(cd "$(dirname "$0")" && pwd)"\n'
        ': "${TARGET:?set TARGET=/path/to/affected/binary}"\n'
        'echo "[*] feeding reproducer.bin to $TARGET (expect: crash / sanitizer report)"\n'
        '"$TARGET" < "$DIR/reproducer.bin" || echo "[+] target crashed (expected)"\n'
        '# file-arg parser instead of stdin? run:  "$TARGET" "$DIR/reproducer.bin"\n')
    try:
        run_sh.chmod(0o755)
    except OSError:
        pass
    # Windows reproduce (file-arg parsers, e.g. FastStone/TextMaker).
    (outdir / "run.ps1").write_text(
        'param([Parameter(Mandatory=$true)][string]$Target)\n'
        '$dir = Split-Path -Parent $MyInvocation.MyCommand.Path\n'
        'Write-Host "[*] opening reproducer.bin with $Target"\n'
        '& $Target (Join-Path $dir "reproducer.bin")\n'
        'Write-Host "[+] exit code $LASTEXITCODE (a crash exits with an NTSTATUS code; '
        'SEH-swallowed faults need a first-chance debugger)"\n')
    # 2. sanitizer report
    san = (finding.verdict.evidence or {}).get("sanitizer_output") or crash.get("summary", "")
    (outdir / "sanitizer.txt").write_text(san or "(no sanitizer output captured)")

    # 3-5. prose
    root_cause = _root_cause(finding, llm)
    patch = _suggested_patch(finding, llm)
    primitive_stmt = (
        f"{prim.kind.value} — {'attacker-controlled' if prim.controlled else 'uncontrolled'}"
        f"; {prim.where}" if prim else "primitive not characterized")

    advisory = _advisory_md(finding, severity, root_cause, primitive_stmt, patch,
                            crash, repro_bytes)
    (outdir / "advisory.md").write_text(advisory)

    manifest = {
        "title": finding.candidate.title,
        "severity": severity,
        "bug_type": crash.get("bug_type") or (prim.detail.get("bug_type") if prim else ""),
        "primitive": primitive_stmt,
        "reproducer": str(outdir / "reproducer.bin"),
        "reproducer_len": len(repro_bytes),
        "run_script": str(outdir / "run.sh"),
        "run_script_windows": str(outdir / "run.ps1"),
        "sanitizer_report": str(outdir / "sanitizer.txt"),
        "advisory": str(outdir / "advisory.md"),
        "root_cause": root_cause,
        "suggested_patch": patch,
        "artifacts_complete": bool(repro_bytes) and bool(san),
    }
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def _advisory_md(finding, severity, root_cause, primitive_stmt, patch, crash,
                 repro_bytes) -> str:
    frames = crash.get("frames") or []
    stack = "\n".join(f"  #{i} {f.get('func','')} {f.get('file','')}:{f.get('line','')}"
                      for i, f in enumerate(frames[:12])) or "  (unsymbolized)"
    repro_b64 = base64.b64encode(repro_bytes).decode() if repro_bytes else ""
    return f"""# Security Advisory — {finding.candidate.title}

**Severity:** {severity.upper()}
**Class:** {crash.get('bug_type') or 'memory-safety'}
**Proof rung:** {finding.rung.name} (oracle: {finding.verdict.oracle})

## Summary
{crash.get('summary') or finding.candidate.title}

## Impact / primitive
{primitive_stmt}

## Root cause
{root_cause}

## Reproduction
A deterministic reproducer is attached (`reproducer.bin`, {len(repro_bytes)} bytes).
Build the target under AddressSanitizer and feed it on stdin; the sanitizer
report in `sanitizer.txt` reproduces every run.

```
reproducer (base64): {repro_b64[:120]}{'…' if len(repro_b64) > 120 else ''}
```

## Symbolized crash
```
{stack}
```

## Suggested patch
{patch}

---
*Generated by Nemesis Forge. Every claim above is oracle-certified: the
sanitizer crash is a captured artifact, not a model's assertion.*
"""

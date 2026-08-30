"""The tool surface, in rings by what a tool is allowed to do.

RING 0  answers questions. Reads no files the operator did not ship with the engine,
        executes nothing. Safe to expose to anything.
RING 1  reads under the operator's target root: findings a previous run wrote, the runs
        that exist. Still executes nothing.
RING 2  RUNS A CAMPAIGN. It compiles the harness it is given and executes it under a
        sanitizer, which is the whole point of the engine and also the reason it is off
        unless the operator turns it on.

The split matters more here than in a linter. Nemesis Forge's job is to run attacker-shaped
input through code until something breaks; a surface that does that by default, on a path a
model chose, is a liability.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import safety

RING0, RING1, RING2 = 0, 1, 2


@dataclass
class Session:
    target_root: Optional[safety.Root] = None
    ring2_enabled: bool = False
    calls: list = field(default_factory=list)

    def record(self, tool: str, ok: bool, note: str = "") -> None:
        self.calls.append({"tool": tool, "ok": ok, "note": note[:200],
                           "t": round(time.time(), 3)})


@dataclass
class Tool:
    name: str
    ring: int
    description: str
    schema: dict
    fn: Callable


# ── ring 0 ────────────────────────────────────────────────────────────────────

def _nf_ladder(_s: Session, **_) -> dict:
    """The ladder is the contract. A model proposes; only an oracle promotes."""
    from forge.ladder import Rung
    rungs = []
    for r in Rung:
        rungs.append({"rung": int(r.value), "name": r.name})
    return {
        "rungs": rungs,
        "rule": ("A model may propose a candidate for any rung and may certify none of "
                 "them. Certification comes from oracles that are deterministic, "
                 "independent of the proposer, and reproducible by a third party."),
        "on_failure": ("A finding an oracle cannot certify is DOWNGRADED to the rung the "
                       "evidence reaches, never dropped. What was not proven is printed "
                       "on every finding."),
    }


def _nf_oracles(_s: Session, **_) -> dict:
    """Every oracle and the rung it can certify."""
    import subprocess
    import sys
    out = subprocess.run([sys.executable, "-m", "forge", "oracles"],
                         capture_output=True, text=True, timeout=60)
    lines = [l.rstrip() for l in out.stdout.splitlines() if l.strip()]
    oracles = []
    for l in lines:
        s = l.strip()
        if s and s[0].isupper() and "Oracle" in s.split()[0]:
            name, _, desc = s.partition("  ")
            oracles.append({"oracle": name.strip(), "certifies": desc.strip()})
    return {"oracles": oracles, "count": len(oracles)}


def _nf_doctor(_s: Session, **_) -> dict:
    """Which lenses this machine has, and what each absence COSTS.

    The cost is the point. A warning with no stated consequence is a warning people learn
    to ignore, and a missing lens silently turns a null result into a completed search.
    """
    import subprocess
    import sys
    out = subprocess.run([sys.executable, "-m", "forge", "doctor"],
                         capture_output=True, text=True, timeout=120)
    present, missing = [], []
    for l in out.stdout.splitlines():
        s = l.strip()
        if s.startswith("yes "):
            present.append(" ".join(s[4:].split()))
        elif s.startswith("NO "):
            missing.append(" ".join(s[3:].split()))
    return {"present": present, "missing": missing,
            "note": ("Missing entries are not errors. The engine runs without them and "
                     "says so in its output rather than reporting a null result as if it "
                     "were a search.")}


def _nf_explain(_s: Session, rung: Optional[int] = None, **_) -> dict:
    """What a rung means, and what evidence promotes to it."""
    table = {
        0: ("UNVERIFIED", "A candidate. Nothing has been proven; a model may have proposed it."),
        1: ("PROVEN_FAULT", "A sanitizer produced a typed report on a concrete input. The "
                            "input is on disk, byte for byte."),
        2: ("PROVEN_REACHABLE", "The fault is reachable from input the real entry point accepts, "
                                "not only from a harness's own scratch state."),
        3: ("PROVEN_SECURITY", "Security-relevant, certified by an oracle INDEPENDENT of the one "
                               "that discovered it."),
        4: ("PROVEN_PRIMITIVE", "The primitive at the faulting instruction is classified and the "
                                "input's control over it is measured."),
        5: ("PROVEN_EXPLOIT", "An exploit primitive is demonstrated, not argued."),
        6: ("VENDOR_READY", "Everything a maintainer needs to reproduce without redoing the work."),
    }
    if rung is None:
        return {"rungs": [{"rung": k, "name": v[0], "means": v[1]} for k, v in table.items()]}
    if rung not in table:
        return {"error": f"no such rung: {rung}", "valid": sorted(table)}
    name, means = table[rung]
    return {"rung": rung, "name": name, "means": means}


def _nf_harness_contract(_s: Session, **_) -> dict:
    """What this engine requires of a harness, so a generator can satisfy it up front.

    Written for Harness Forge, which enforces these as gates before a compiler runs rather
    than asking a model to remember them. The two engines share the rung ladder, so a
    certified harness and a proven finding compose into one chain of evidence.
    """
    return {
        "entry_point": "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)",
        "self_contained": ("`nf_lab` builds ONE translation unit. Either inline the target "
                           "or place the harness beside the sources it includes."),
        "requirements": [
            "Fuzz only the untrusted input bytes. Never pass them as a size, length, "
            "count, index, capacity or filename: those are caller-controlled, and using "
            "them manufactures crashes that are the harness's fault.",
            "Every required parameter gets a valid non-NULL argument. A required pointer "
            "passed as NULL is a HARNESS bug and the crash it produces is not a finding.",
            "Output buffers sized for the one call that uses them, never shared across "
            "calls that need different sizes.",
            "Only functions declared in the public header. Internal helpers do not link "
            "from a separate translation unit and are not the library's attack surface.",
            "One documented entry point per harness, with its setup and teardown.",
        ],
        "checked_here": ("A short probe runs before the campaign and a harness that does "
                         "not reach non-trivial coverage is discarded as dead."),
        "checked_upstream": ("Harness Forge proves these statically (S1-S6) and dynamically "
                             "(D1-D11) and emits a certificate naming what the harness "
                             "CANNOT find. `hforge audit <harness.c>` grades one this "
                             "engine did not write."),
    }


# ── ring 1 ────────────────────────────────────────────────────────────────────

def _nf_runs(s: Session, out: str = "runs", **_) -> dict:
    """Campaigns on disk under the target root."""
    root = safety.need_root(s.target_root)
    d = root.resolve(out)
    if not d.is_dir():
        return {"runs": [], "note": f"no run directory at {d}"}
    runs = []
    for p in sorted(d.iterdir()):
        meta = p / "metadata.json"
        if not meta.is_file():
            continue
        try:
            m = json.loads(meta.read_text())
        except Exception:                                        # noqa: BLE001
            continue
        runs.append({"job_id": m.get("job_id"), "target": m.get("target"),
                     "status": m.get("status"), "findings": m.get("findings"),
                     "top_rung": m.get("top_rung"), "path": str(p)})
    return {"runs": runs, "count": len(runs)}


def _nf_findings(s: Session, run: str = "", **_) -> dict:
    """The findings a campaign wrote, with what each one did NOT establish."""
    root = safety.need_root(s.target_root)
    d = root.resolve(run)
    f = d / "findings.json"
    if not f.is_file():
        return {"error": f"no findings.json under {d}"}
    try:
        data = json.loads(f.read_text())
    except Exception as e:                                       # noqa: BLE001
        return {"error": f"unreadable findings.json: {type(e).__name__}: {e}"}
    return {"run": str(d), "findings": data,
            "reminder": ("A rung is a ceiling on what was PROVEN, not a severity. Nothing "
                         "above the stated rung was certified by any oracle.")}


# ── ring 2 ────────────────────────────────────────────────────────────────────

def _nf_lab(s: Session, harness: str = "", fuzz_time: int = 30, name: str = "lab-target",
            out: str = "runs", sources: Optional[list] = None,
            includes: Optional[list] = None, **_) -> dict:
    """Run a campaign against a harness. COMPILES AND EXECUTES CODE."""
    if not s.ring2_enabled:
        return {"error": ("ring 2 is disabled. This tool compiles the harness it is given "
                          "and executes it under a sanitizer. Start the server with "
                          "--ring2 to allow it.")}
    root = safety.need_root(s.target_root)
    h = root.resolve(harness)
    if not h.is_file():
        return {"error": f"no such harness: {h}"}
    fuzz_time = max(1, min(int(fuzz_time), 3600))
    import subprocess
    import sys
    cmd = [sys.executable, "-m", "forge", "lab", str(h), "--name", name,
           "--fuzz-time", str(fuzz_time), "--out", str(root.resolve(out))]
    # A harness for a real library is not one translation unit. Every path is resolved
    # against the operator's root like the harness itself, so this cannot become a way to
    # compile something from outside it.
    for src in (sources or []):
        cmd += ["--source", str(root.resolve(str(src)))]
    for inc in (includes or []):
        cmd += ["--include", str(root.resolve(str(inc)))]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       timeout=fuzz_time + 600, cwd=str(root.path))
    return {"command": cmd, "exit": r.returncode,
            "stdout": r.stdout[-8000:], "stderr": r.stderr[-4000:],
            "note": ("Findings are on disk in the run directory; read them with "
                     "nf_findings for the structured form.")}


_STR = {"type": "string"}
_INT = {"type": "integer"}

RING0_TOOLS = [
    Tool("nf_ladder", RING0, "the exploitability ladder, and the rule that a model may "
         "propose any rung and certify none", {"type": "object", "properties": {}}, _nf_ladder),
    Tool("nf_oracles", RING0, "every oracle and the rung it certifies",
         {"type": "object", "properties": {}}, _nf_oracles),
    Tool("nf_explain", RING0, "what a rung means and what evidence promotes to it",
         {"type": "object", "properties": {"rung": _INT}}, _nf_explain),
    Tool("nf_doctor", RING0, "which lenses this machine has and what each absence costs",
         {"type": "object", "properties": {}}, _nf_doctor),
    Tool("nf_harness_contract", RING0, "what this engine requires of a harness, for a "
         "generator to satisfy up front", {"type": "object", "properties": {}},
         _nf_harness_contract),
]

RING1_TOOLS = [
    Tool("nf_runs", RING1, "campaigns on disk under the target root",
         {"type": "object", "properties": {"out": _STR}}, _nf_runs),
    Tool("nf_findings", RING1, "the findings a campaign wrote, and what each did NOT prove",
         {"type": "object", "properties": {"run": _STR}, "required": ["run"]}, _nf_findings),
]

RING2_TOOLS = [
    Tool("nf_lab", RING2, "run a campaign against a harness. COMPILES AND EXECUTES CODE",
         {"type": "object", "properties": {
             "harness": _STR, "fuzz_time": _INT, "name": _STR, "out": _STR,
             "sources": {"type": "array", "items": _STR,
                         "description": "library sources compiled with the harness; omit "
                                        "only if the harness is self-contained"},
             "includes": {"type": "array", "items": _STR,
                          "description": "header search directories"}},
          "required": ["harness"]}, _nf_lab),
]

ALL_TOOLS = RING0_TOOLS + RING1_TOOLS + RING2_TOOLS


def tools_for(max_ring: int) -> list:
    return [t for t in ALL_TOOLS if t.ring <= max_ring]


def by_name(name: str) -> Optional[Tool]:
    for t in ALL_TOOLS:
        if t.name == name:
            return t
    return None

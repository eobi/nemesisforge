"""Static-analysis lens — the SOURCE/syntax angle (finds what fuzzing can't reach).

Coverage-guided fuzzing only sees code it can DRIVE into; deep or hard-to-reach
paths stay dark. Static analysis reads the source and reasons over ALL paths at
once. We use the Clang Static Analyzer (built into clang — no CodeQL/Semgrep
install needed): path-sensitive symbolic analysis that flags null-derefs, buffer
issues, use-after-free, uninitialized reads, leaks.

A static warning is a LEAD, not a proof (it can be a false positive) — so, true to
the engine's thesis, these are PROPOSERS: each becomes a high-priority suspect the
dynamic oracle (fuzzer/sanitizer) then tries to CONFIRM. Static finds the needle;
dynamic proves it's sharp. Fusing the two catches bugs neither finds alone.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

# Checkers worth running: memory-safety + security, not style.
_CHECKERS = "core,security,unix,deadcode,nullability"
# clang analyzer text line: path:line:col: warning: message [checker.name]
_WARN = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s+warning:\s+"
                   r"(?P<msg>.*?)(?:\s+\[(?P<checker>[\w.-]+)\])?$")

# Map an analyzer message to our memory-safety bug vocabulary (best-effort).
_KIND = [
    (re.compile(r"buffer overflow|out-of-bound|past the end", re.I), "buffer-overflow"),
    (re.compile(r"use.?after.?free|released memory", re.I), "use-after-free"),
    (re.compile(r"double.?free", re.I), "double-free"),
    (re.compile(r"null pointer|nil|dereference of null", re.I), "null-deref"),
    (re.compile(r"uninitial", re.I), "uninitialized"),
    (re.compile(r"memory leak|leak of", re.I), "memory-leak"),
]


@dataclass
class StaticFinding:
    file: str
    line: int
    col: int
    message: str
    checker: str = ""
    kind: str = "static-warning"

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "col": self.col,
                "message": self.message[:200], "checker": self.checker,
                "kind": self.kind}


def _classify(msg: str) -> str:
    for pat, kind in _KIND:
        if pat.search(msg):
            return kind
    return "static-warning"


def available(compiler: str = "clang") -> bool:
    try:
        r = subprocess.run([compiler, "--analyze", "--help"],
                           capture_output=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False


def analyze(sources: Sequence[Path], *, include_dirs: Optional[Sequence[Path]] = None,
            compiler: str = "clang", timeout: int = 180,
            max_files: int = 60) -> list[StaticFinding]:
    """Run the Clang Static Analyzer over the sources; return parsed warnings."""
    incs = [f"-I{p}" for p in (include_dirs or [])]
    out: list[StaticFinding] = []
    seen: set[tuple] = set()
    for src in list(sources)[:max_files]:
        argv = [compiler, "--analyze", "-Xclang", "-analyzer-output=text",
                "-Xclang", f"-analyzer-checker={_CHECKERS}",
                "-Xclang", "-analyzer-disable-checker=deadcode.DeadStores",
                *incs, str(src)]
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except Exception:
            continue
        for line in (r.stderr or "").splitlines():
            m = _WARN.match(line.strip())
            if not m:
                continue
            key = (m.group("file"), m.group("line"), m.group("msg")[:50])
            if key in seen:
                continue
            seen.add(key)
            out.append(StaticFinding(
                file=m.group("file"), line=int(m.group("line")),
                col=int(m.group("col")), message=m.group("msg"),
                checker=m.group("checker") or "", kind=_classify(m.group("msg"))))
    # memory-safety findings first
    out.sort(key=lambda f: 0 if f.kind != "static-warning" else 1)
    return out

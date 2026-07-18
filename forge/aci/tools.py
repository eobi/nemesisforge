"""The Agent-Computer Interface (ACI, L3) — the uniform toolbelt every agent gets.

Naptime/EnIGMA's lesson: give agents real, named, interactive tools backed by the
target — not one-shot command strings. The ACI is that toolbelt, bound to a job's
target + sandbox, so a deterministic agent and (later) an LLM exploit-synthesizer
use the *same* verbs across source / binary / device targets:

  read_file · grep · list_dir   — navigate the target's source
  build · run                    — compile/execute under a sanitizer (via Target)
  shell                          — run a tool in the sandbox (objdump, ndk-stack…)
  symbolize                      — resolve a stack (target-specific)

File tools are confined to the target's working directory (no path escape), and
`shell` runs in the job's sandbox — never on the host unguarded.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..context import JobContext
from ..sandbox import ExecResult


class ACI:
    def __init__(self, ctx: JobContext) -> None:
        self.ctx = ctx
        self.target = ctx.target
        self.sandbox = getattr(self.target, "sandbox", None)

    # ── workdir-confined source navigation ──
    def _root(self) -> Optional[Path]:
        wd = getattr(self.target, "workdir", None)
        return Path(wd) if wd else None

    def _safe(self, path: str) -> Optional[Path]:
        root = self._root()
        if root is None:
            return None
        p = (root / path).resolve()
        try:
            p.relative_to(root.resolve())
        except ValueError:
            return None                       # path-escape refused
        return p

    def read_file(self, path: str, *, max_bytes: int = 200_000) -> str:
        p = self._safe(path)
        if p is None or not p.is_file():
            return ""
        return p.read_text(errors="replace")[:max_bytes]

    def list_dir(self, path: str = ".") -> list[str]:
        p = self._safe(path)
        if p is None or not p.is_dir():
            return []
        return sorted(x.name for x in p.iterdir())

    def grep(self, pattern: str, *, path: str = ".", max_hits: int = 100) -> list[str]:
        root = self._safe(path)
        if root is None:
            return []
        rx = re.compile(pattern)
        hits: list[str] = []
        files = [root] if root.is_file() else root.rglob("*")
        for f in files:
            if not f.is_file():
                continue
            try:
                for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{f.name}:{n}: {line.strip()[:160]}")
                        if len(hits) >= max_hits:
                            return hits
            except Exception:
                continue
        return hits

    # ── build / run (delegate to the uniform Target contract) ──
    def build(self, harness_source: str = "", **kw):
        return self.target.build(harness_source, **kw)

    def run(self, binary, **kw):
        return self.target.run(binary, **kw)

    # ── sandboxed tool exec (objdump, ndk-stack, …) ──
    def shell(self, argv, *, timeout: float = 30.0) -> ExecResult:
        if self.sandbox is None:
            return ExecResult(rc=127, stdout="", stderr="no sandbox on target")
        return self.sandbox.run(list(argv), timeout=timeout)

    def symbolize(self, stack: str) -> str:
        fn = getattr(self.target, "symbolize", None)
        return fn(stack) if callable(fn) else stack

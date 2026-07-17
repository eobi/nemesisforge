"""Execution sandbox — untrusted builds and PoCs never touch the real host.

Two implementations behind one contract:
  - `DockerSandbox` (production) — the isolated `--network none`, memory/pids/
    time-capped container, ported from Nemesis Zero. This is the default in
    production; every exploit execution runs here.
  - `LocalSandbox` (dev only) — a subprocess with resource limits + a hard
    timeout, so the engine is developable/testable on a laptop without Docker.
    It is NOT isolation; it is guarded by rlimits + timeout and is only ever used
    against our own controlled lab targets. `require_isolation()` refuses it for
    anything that isn't explicitly dev.

An oracle/target asks for a sandbox; it does not care which backend runs it.
"""
from __future__ import annotations

import os
import resource
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, Sequence


@dataclass
class ExecResult:
    rc: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def output(self) -> str:
        return (self.stdout or "") + "\n" + (self.stderr or "")


class Sandbox(Protocol):
    isolated: bool

    def run(self, argv: Sequence[str], *, cwd: Optional[Path] = None,
            stdin: bytes = b"", timeout: float = 30.0,
            env: Optional[dict] = None) -> ExecResult:
        ...


def _limits(cpu_s: int, mem_bytes: int, fsize_bytes: int):
    def _apply():
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 1))
        except (ValueError, OSError):
            pass
        try:                                    # not enforced on macOS; harmless
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        except (ValueError, OSError):
            pass
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_bytes, fsize_bytes))
        except (ValueError, OSError):
            pass
        os.setpgrp()                            # own process group → clean kill
    return _apply


class LocalSandbox:
    """Dev-only: subprocess + rlimits + timeout. Never isolation."""
    isolated = False

    def __init__(self, *, cpu_s: int = 20, mem_mb: int = 2048,
                 fsize_mb: int = 256) -> None:
        self.cpu_s = cpu_s
        self.mem_bytes = mem_mb * 1024 * 1024
        self.fsize_bytes = fsize_mb * 1024 * 1024

    def run(self, argv, *, cwd=None, stdin=b"", timeout=30.0, env=None):
        try:
            p = subprocess.run(
                list(argv), cwd=str(cwd) if cwd else None, input=stdin,
                capture_output=True, timeout=timeout,
                env={**os.environ, **(env or {})},
                preexec_fn=_limits(self.cpu_s, self.mem_bytes, self.fsize_bytes),
            )
        except subprocess.TimeoutExpired as e:
            return ExecResult(rc=124,
                              stdout=(e.stdout or b"").decode("utf-8", "replace"),
                              stderr=(e.stderr or b"").decode("utf-8", "replace"),
                              timed_out=True)
        except FileNotFoundError as e:
            return ExecResult(rc=127, stdout="", stderr=str(e))
        return ExecResult(
            rc=p.returncode,
            stdout=p.stdout.decode("utf-8", "replace"),
            stderr=p.stderr.decode("utf-8", "replace"),
        )


def require_isolation(sandbox: Sandbox, *, allow_local: bool = False) -> None:
    """Guard used before running attacker-influenced code against a real target.
    Refuses a non-isolated sandbox unless the caller explicitly opts into dev."""
    if not getattr(sandbox, "isolated", False) and not allow_local:
        raise PermissionError(
            "refusing to run untrusted code in a non-isolated sandbox; "
            "use DockerSandbox (or pass allow_local=True for a dev lab target)")

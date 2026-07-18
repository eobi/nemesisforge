"""SourceTarget — a buildable source tree, compiled with a sanitizer and run on
an input. The Phase-A concrete Target.

Reuses the Nemesis Zero pattern (build with ASan in a sandbox, run, parse the
sanitizer report), but behind Forge's uniform Target contract so the same
Coordinator/oracles drive it. A discovery/escalation agent supplies a C harness
(the input surface) + optional target sources; the target compiles them with
`-fsanitize=<san>` and runs the harness on the agent's input. A sanitizer crash
is the proof object the ladder climbs on.
"""
from __future__ import annotations

from pathlib import Path
import itertools
import threading
from typing import Optional, Sequence

from .. import triage
from ..sandbox import LocalSandbox, Sandbox
from .base import BuildResult, Observation

_HARNESS = "forge_harness"
# Deterministic, abort-on-report so we always get a parseable crash. Symbolization
# is toggled per-run: discovery only needs "did it crash + what class" (fast,
# symbolize=0), while the oracle wants frames for the rung decision (symbolize=1).
# On macOS symbolization goes through `atos` and costs ~15s per crash, so keeping
# it off for the fuzz loop is a large speedup (Linux/Docker symbolizes fast).
_ASAN_BASE = "detect_leaks=0:abort_on_error=1:halt_on_error=1"


class SourceTarget:
    target_type = "source"

    def __init__(self, workdir: Path | str, *, name: str,
                 languages: Sequence[str] = ("c",),
                 sandbox: Optional[Sandbox] = None,
                 compiler: str = "clang") -> None:
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.name = name
        self.languages = list(languages)
        self.sandbox = sandbox or LocalSandbox()
        self.compiler = compiler
        self._build_seq = itertools.count(1)
        self._lock = threading.Lock()

    def build(self, harness_source: str, *, sanitizer: str = "address",
              target_sources: Optional[Sequence[Path]] = None) -> BuildResult:
        # Each build gets its OWN subdir so parallel builds (the LLM synth squad,
        # concurrent verification) never clobber each other's harness/binary —
        # the source of intermittent "no crash" flakes.
        with self._lock:
            n = next(self._build_seq)
        bdir = self.workdir / f"b{n}"
        bdir.mkdir(parents=True, exist_ok=True)
        src = bdir / f"{_HARNESS}.c"
        src.write_text(harness_source)
        binary = bdir / _HARNESS
        argv = [self.compiler, f"-fsanitize={sanitizer}", "-g", "-O1",
                "-fno-omit-frame-pointer", str(src),
                *[str(p) for p in (target_sources or [])],
                "-o", str(binary)]
        res = self.sandbox.run(argv, cwd=bdir, timeout=180)
        ok = res.rc == 0 and binary.exists()
        return BuildResult(ok=ok, binary=binary if ok else None, log=res.output)

    def run(self, binary: Path, *, stdin: bytes = b"", timeout: float = 60.0,
            symbolize: bool = True) -> Observation:
        opts = f"{_ASAN_BASE}:symbolize={1 if symbolize else 0}"
        res = self.sandbox.run([str(binary)], cwd=self.workdir, stdin=stdin,
                               timeout=timeout, env={"ASAN_OPTIONS": opts})
        crash = triage.parse(res.output)
        return Observation(crashed=crash.crashed, crash=crash, rc=res.rc,
                           output=res.output, timed_out=res.timed_out)

    def harness_path(self) -> Path:
        return self.workdir / f"{_HARNESS}.c"

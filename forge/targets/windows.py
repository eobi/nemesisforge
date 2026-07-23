"""WindowsBinaryTarget — a closed Windows GUI / file-parser, argv/file mode (Phase 2 M0).

A Windows GUI app won't read stdin: it opens a *file* through its UI. So the input
is written to a temp file and the app is launched with that file as an argument
(`App.exe <file>`). A crashing Windows process exits WITH its NTSTATUS exception
code (0xC0000005 access-violation, 0xC0000374 heap-corruption, ...), so a crash is
detected from the exit code alone — no debugger needed for M0. Coverage
(Frida/DynamoRIO) and the fast persistent in-process harness are M1/M2; the
faulting instruction + write/read/DoS grade come from the exploitability oracle.

Runs on a Windows host (the native fuzz agent), via the same `sandbox.run` contract
as everything else, and presents the same `Target` interface as SourceTarget /
BinaryTarget so the fuzzer and every oracle drive it unchanged.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from .. import triage
from ..sandbox import Sandbox, WindowsSandbox
from .base import BuildResult, Observation


class WindowsBinaryTarget:
    target_type = "binary"

    def __init__(self, binary_path: Path | str, *, name: str,
                 sandbox: Optional[Sandbox] = None,
                 argv_template: Optional[Sequence[str]] = None,
                 input_suffix: str = "",
                 arch: str = "x86") -> None:
        self.binary = Path(binary_path)
        self.name = name
        self.languages = ["binary"]
        self.sandbox = sandbox or WindowsSandbox()
        # How the mutated file is delivered on the command line. The literal
        # token "{file}" is replaced with the temp-file path each run; the
        # default is `App.exe <file>` (the app opens the file positionally).
        self.argv_template = list(argv_template or ["{file}"])
        # Some apps dispatch on extension (.tga/.pdf/.tmd) — a per-format harness
        # sets this so the temp file carries the right suffix.
        self.input_suffix = input_suffix
        self.arch = arch
        # Reliable crash detector (a FridaExceptionObserver). When set, run()
        # detects crashes via first-chance exceptions — catching SEH-swallowed AVs
        # that exit 0 — and, crucially, VERIFICATION replays through the same
        # observer, so a real crash is never refuted as an instrumentation
        # artifact. When None, run() falls back to exit-code/NTSTATUS detection
        # (correct for apps that don't swallow the fault).
        self.crash_observer = None

    def build(self, harness_source: Optional[str] = None, *,
              sanitizer: str = "address",
              target_sources: Optional[Sequence[Path]] = None) -> BuildResult:
        ok = self.binary.exists()
        return BuildResult(ok=ok, binary=self.binary if ok else None,
                           log="" if ok else f"binary not found: {self.binary}")

    def run(self, binary: Path, *, stdin: bytes = b"", timeout: float = 30.0,
            symbolize: bool = False) -> Observation:
        # Reliable path: first-chance exception observation (catches SEH-swallowed
        # AVs). Both discovery and verification go through here, so detection and
        # re-verification agree.
        if self.crash_observer is not None:
            return self.crash_observer.observe(binary, stdin=stdin, timeout=timeout)
        return self._run_exitcode(binary, stdin=stdin, timeout=timeout)

    def _run_exitcode(self, binary: Path, *, stdin: bytes = b"",
                      timeout: float = 30.0) -> Observation:
        """Argv/file execution with exit-code (NTSTATUS) crash detection. Correct
        for apps that let the fault crash the process; misses SEH-swallowed faults
        (use crash_observer for those). Kept separate so the observer's own
        fallback can call it without recursing through run()."""
        fd, path = tempfile.mkstemp(suffix=self.input_suffix)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(stdin or b"")
            argv = [str(binary)] + [a.replace("{file}", path)
                                    for a in self.argv_template]
            res = self.sandbox.run(argv, timeout=timeout)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        crash = triage.parse(res.output, win_exit=res.rc)
        return Observation(crashed=crash.crashed, crash=crash, rc=res.rc,
                           output=res.output, timed_out=res.timed_out)

    def harness_path(self) -> Path:
        return self.binary

    def static_info(self) -> dict:
        return {"path": str(self.binary), "arch": self.arch, "os": "windows",
                "argv_template": self.argv_template}

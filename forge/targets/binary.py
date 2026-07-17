"""BinaryTarget — a closed-source binary / firmware, driven concretely.

No source, no build: the adapter runs a prebuilt binary on attacker input in the
sandbox and detects a crash by the fatal signal it dies on (SIGSEGV/SIGBUS =
memory-safety-relevant). That alone makes the whole fleet work on binaries — the
fuzzer and the binary-crash oracle speak the same uniform Target contract as the
source path. When a heavy tool is present (angr for symbolic reachability, an
emulator/QEMU for a foreign arch) the symbolic oracle lights up; when it isn't,
the concrete path still proves crashes and everything degrades gracefully.

`build()` is a no-op that returns the existing binary (so a fuzz agent written
for SourceTarget drives a BinaryTarget unchanged). Static triage
(objdump/nm/strings) provides binary metadata for the report.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional, Sequence

from .. import triage
from ..sandbox import LocalSandbox, Sandbox
from .base import BuildResult, Observation


class BinaryTarget:
    target_type = "binary"

    def __init__(self, binary_path: Path | str, *, name: str,
                 sandbox: Optional[Sandbox] = None,
                 argv: Optional[Sequence[str]] = None,
                 arch: str = "native") -> None:
        self.binary = Path(binary_path)
        self.name = name
        self.languages = ["binary"]
        self.sandbox = sandbox or LocalSandbox()
        self.argv = list(argv or [])      # extra args after the binary
        self.arch = arch

    def build(self, harness_source: Optional[str] = None, *,
              sanitizer: str = "address",
              target_sources: Optional[Sequence[Path]] = None) -> BuildResult:
        ok = self.binary.exists()
        return BuildResult(ok=ok, binary=self.binary if ok else None,
                           log="" if ok else f"binary not found: {self.binary}")

    def run(self, binary: Path, *, stdin: bytes = b"", timeout: float = 30.0,
            symbolize: bool = False) -> Observation:
        res = self.sandbox.run([str(binary), *self.argv], stdin=stdin,
                               timeout=timeout)
        # rc carries the fatal signal for a bare binary (no sanitizer report).
        crash = triage.parse(res.output, rc=res.rc)
        return Observation(crashed=crash.crashed, crash=crash, rc=res.rc,
                           output=res.output, timed_out=res.timed_out)

    def harness_path(self) -> Path:
        # no harness concept for a binary; the oracle's frame check uses this.
        return self.binary

    def static_info(self) -> dict:
        """objdump/nm/strings triage for the report (best-effort)."""
        info: dict = {"path": str(self.binary), "arch": self.arch}
        if shutil.which("objdump"):
            r = self.sandbox.run(["objdump", "-f", str(self.binary)], timeout=20)
            info["format"] = r.stdout[:400]
        if shutil.which("nm"):
            r = self.sandbox.run(["nm", "-D", str(self.binary)], timeout=20)
            info["dynamic_symbols"] = len([l for l in r.stdout.splitlines() if l.strip()])
        return info

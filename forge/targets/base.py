"""The Target contract (L0) — one interface, three adapters (source/binary/device).

The agent fleet and the oracles reason against this uniform contract; each
adapter hides the target-specific mechanics (compile a repo vs. emulate a binary
vs. drive an Android device). That is what makes "prove exploits on ANY target"
real without forking the engine per target type.

Phase A implements `SourceTarget`; `BinaryTarget`/`DeviceTarget` land in Phases
C/D behind the same contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol, Sequence, runtime_checkable

from ..triage import CrashInfo


@dataclass
class BuildResult:
    ok: bool
    binary: Optional[Path] = None
    log: str = ""


@dataclass
class Observation:
    """The result of running the target on one input under a sanitizer."""
    crashed: bool = False
    crash: CrashInfo = field(default_factory=CrashInfo)
    rc: int = 0
    output: str = ""
    timed_out: bool = False


@runtime_checkable
class Target(Protocol):
    name: str
    target_type: str                    # source | binary | device
    languages: Sequence[str]

    def build(self, harness_source: str, *, sanitizer: str = "address",
              target_sources: Optional[Sequence[Path]] = None) -> BuildResult:
        ...

    def run(self, binary: Path, *, stdin: bytes = b"",
            timeout: float = 15.0) -> Observation:
        ...

"""DynamoRIO drcov coverage backend — correct closed-binary coverage.

Fixes the two Frida-Stalker bugs the survey found: drcov records MODULE-RELATIVE
basic blocks (ASLR-invariant, so coverage is comparable across process-per-input
spawns) across ALL threads (so a decoder on a worker thread is covered). It runs
`drrun -t drcov -- <exe> <file>`; drcov dumps a coverage file on process EXIT,
which we parse into a block set.

Honest caveat: drcov flushes on process exit, so a GUI viewer that stays open
(killed on timeout) will not flush — those targets need the persistent in-process
harness (hook the decoder, loop, flush per iteration). For parse-and-exit programs
(CLI tools, most Linux binaries) drcov gives real coverage today.

Crash detection is NOT drcov's job here — it is the target's `crash_observer`
(reliable first-chance exceptions). This backend carries coverage only; the
WindowsFuzzer runs the observer for the crash signal.
"""
from __future__ import annotations

import glob
import os
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .base import Observation
from .binary_cov import CoverageRun


def parse_drcov(data: bytes) -> set:
    """Parse a DynamoRIO drcov file into module-relative basic blocks
    (mod_id << 32 | offset). Handles the binary BB table (drcov's default dump)."""
    blocks: set = set()
    marker = b"BB Table: "
    idx = data.find(marker)
    if idx < 0:
        return blocks
    nl = data.find(b"\n", idx)
    if nl < 0:
        return blocks
    try:
        count = int(data[idx + len(marker):nl].split()[0])
    except (ValueError, IndexError):
        return blocks
    blob = data[nl + 1:]
    for i in range(count):
        o = i * 8
        if o + 8 > len(blob):
            break
        start, _size, mod = struct.unpack_from("<IHH", blob, o)
        blocks.add((mod << 32) | start)
    return blocks


def find_drrun() -> Optional[str]:
    """Locate drrun (DynamoRIO launcher): DYNAMORIO_HOME/bin{64,32} or PATH."""
    import shutil
    cands: list = []
    for env in ("DYNAMORIO_HOME", "DRIO_HOME"):
        base = os.environ.get(env)
        if base:
            cands += [os.path.join(base, "bin64", "drrun.exe"),
                      os.path.join(base, "bin32", "drrun.exe"),
                      os.path.join(base, "bin64", "drrun")]
    w = shutil.which("drrun") or shutil.which("drrun.exe")
    if w:
        cands.append(w)
    for c in cands:
        if c and Path(c).exists():
            return c
    return None


class DrcovCoverage:
    name = "drcov"

    def __init__(self, target, *, drrun: Optional[str] = None) -> None:
        self.target = target
        self.drrun = drrun or find_drrun()

    def available(self) -> bool:
        return bool(self.drrun and Path(self.drrun).exists())

    def _target_run(self, binary, stdin, timeout) -> Observation:
        fn = getattr(self.target, "_run_exitcode", None) or self.target.run
        return fn(binary, stdin=stdin, timeout=timeout)

    def run_with_coverage(self, binary: Path, *, stdin: bytes = b"",
                          timeout: float = 30.0) -> CoverageRun:
        if not self.available():
            return CoverageRun(observation=self._target_run(binary, stdin, timeout),
                               edges=set(), instrumented=False)
        suffix = getattr(self.target, "input_suffix", "")
        tmpl = getattr(self.target, "argv_template", ["{file}"])
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        Path(path).write_bytes(stdin or b"")
        logdir = tempfile.mkdtemp(prefix="drcov-")
        argv = [self.drrun, "-t", "drcov", "-logdir", logdir, "--",
                str(binary)] + [a.replace("{file}", path) for a in tmpl]
        rc = 0
        try:
            rc = subprocess.run(argv, timeout=timeout, capture_output=True).returncode
        except subprocess.TimeoutExpired:
            rc = 124
        except Exception:
            rc = 127
        edges: set = set()
        for lg in glob.glob(os.path.join(logdir, "drcov.*.log")):
            try:
                edges |= parse_drcov(Path(lg).read_bytes())
            except Exception:
                pass
        try:
            os.unlink(path)
        except OSError:
            pass
        from .. import triage
        obs = Observation(crashed=False, crash=triage.CrashInfo(), rc=rc)
        return CoverageRun(observation=obs, edges=edges, instrumented=True)

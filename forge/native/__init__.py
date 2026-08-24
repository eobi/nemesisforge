"""Small native helpers built on demand.

crashcatch: a preload shim that turns a fatal signal into a clean _exit(128+n).

WHY IT EXISTS. On macOS a process that dies by SIGSEGV, SIGBUS, SIGILL or SIGABRT
is handed to the operating system crash reporter, which SUSPENDS it while it
collects a report. One crash is invisible. A fuzzing campaign produces thousands,
the reporter saturates, and processes pile up in an uninterruptible state that
kill -9 cannot clear. Measured on the machine this was written on: over 24 seconds
per native crash with the reporter engaged, 8.7 milliseconds without it.

ASAN_OPTIONS=abort_on_error=0 does NOT cover this. That option tells
AddressSanitizer to _exit() instead of abort(), and a target built without a
sanitizer has no AddressSanitizer in it. Forge fuzzes exactly such targets, so
this is the case where that advice runs out.

WHAT IT COSTS. No crash report and no core file, so a debugger attached after the
fact has nothing to look at. That trade is right for THROUGHPUT, where the only
question is whether an input faults and with which signal. The debugger-backed
oracles build their own targets and are unaffected.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

_CACHE: dict[str, str | None] = {}


def crashcatch_path() -> str | None:
    """Build (once) and return the shim, or None if it cannot be built."""
    if "lib" in _CACHE:
        return _CACHE["lib"]
    _CACHE["lib"] = None
    src = Path(__file__).with_name("crashcatch.c")
    if not src.exists():
        return None
    ext = "dylib" if sys.platform == "darwin" else "so"
    out = Path(tempfile.gettempdir()) / f"forge-crashcatch.{ext}"
    if out.exists():
        _CACHE["lib"] = str(out)
        return _CACHE["lib"]
    cc = os.environ.get("CC") or "cc"
    # Build fat on Apple silicon: an inserted library must match the architecture
    # of the process it lands in, and a single-arch build is silently skipped for
    # arm64e targets with a loader error that looks like the tool is broken.
    arch = ["-arch", "arm64", "-arch", "arm64e"] if sys.platform == "darwin" else []
    flag = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC"]
    try:
        r = subprocess.run([cc, *arch, *flag, "-O1", "-o", str(out), str(src)],
                           capture_output=True, timeout=90)
        if r.returncode == 0 and out.exists():
            _CACHE["lib"] = str(out)
    except (OSError, subprocess.SubprocessError):
        pass
    return _CACHE["lib"]


def preload_env() -> dict:
    """Environment that keeps the OS crash reporter out of the loop."""
    env = {"ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0:allocator_may_return_null=1",
           "UBSAN_OPTIONS": "abort_on_error=0",
           "LSAN_OPTIONS": "detect_leaks=0"}
    lib = crashcatch_path()
    if lib:
        env["DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"] = lib
    return env

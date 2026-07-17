"""Android crash parsing — turn a device tombstone/logcat into typed proof.

The Android scenario that started this: a device crashes, but the vendor needs a
symbolized, typed, reproducible artifact. On Android a native crash produces a
`debuggerd` **tombstone** (in /data/tombstones) — signal + fault address +
per-frame backtrace. Parsing that into `CrashInfo` is the crux: it's what upgrades
"the device crashed" into "a SIGSEGV write fault at libfoo.so!bar" that a vendor
(and the escalation tier) can act on.

Pure parsing — no device required — so the highest-value Android step is testable
without hardware. Live capture (adb/tombstone pull, ndk-stack symbolization) is
the DeviceTarget's job and degrades gracefully when no device is attached.
"""
from __future__ import annotations

import re

from .triage import CrashInfo, Frame, _SIGNAL_BUG, _MEMORY_SIGNALS

# "signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000000"
_SIGNAL = re.compile(
    r"signal\s+(\d+)\s+\((\w+)\).*?fault addr\s+(0x[0-9a-fA-F]+)", re.I)
# "      #00 pc 0000000000012345  /system/lib64/libfoo.so (bar+52)"
_FRAME = re.compile(
    r"#\d+\s+pc\s+[0-9a-fA-F]+\s+(\S+)(?:\s+\(([^)+]+)(?:\+(\d+))?\))?", re.I)
_ABORT_MSG = re.compile(r"Abort message:\s*'([^']*)'", re.I)


def parse_tombstone(text: str) -> CrashInfo:
    """Parse an Android native-crash tombstone into CrashInfo."""
    ci = CrashInfo()
    t = text or ""

    m = _SIGNAL.search(t)
    if not m:
        return ci
    signum = int(m.group(1))
    ci.crashed = True
    ci.bug_type = _SIGNAL_BUG.get(signum, m.group(2).lower())
    fault_addr = m.group(3)
    if signum in _MEMORY_SIGNALS:
        ci.access = "WRITE"     # SEGV_MAPERR/ACCERR — treat as a write fault

    for fm in _FRAME.finditer(t):
        lib = fm.group(1)
        func = fm.group(2) or ""
        off = int(fm.group(3)) if fm.group(3) else 0
        # tombstone frames are lib-relative; symbolization (ndk-stack) fills
        # file:line later. Record lib as the "file" and pc offset as the line.
        ci.frames.append(Frame(func=func.strip(), file=lib, line=off))

    am = _ABORT_MSG.search(t)
    ci.summary = (f"{ci.bug_type} at fault addr {fault_addr}"
                  + (f" — abort: {am.group(1)}" if am else ""))
    # reuse the stack-hash logic
    import hashlib
    basis = f"{ci.bug_type}|" + "|".join(f"{f.func}:{f.file}" for f in ci.frames[:5])
    ci.stack_hash = hashlib.sha1(basis.encode()).hexdigest()[:16]
    return ci

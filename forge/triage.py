"""Sanitizer-report parser — turns a raw crash into a *typed* proof object.

A bare SIGSEGV says "something broke". A sanitizer report says exactly what:
the bug class, whether the bad access was a READ or a WRITE, the faulting stack,
and (for ASan) the allocation/free sites. That typed record is the closest thing
to a cheap proof object that exists — it is what every modern automated system
and every vendor triager trusts, and it is the input contract the escalation
tier consumes to hypothesize a primitive.

Parses AddressSanitizer / HWASan / UBSan / LeakSanitizer text into `CrashInfo`.
Pure string processing.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

# "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x… "
_ASAN_ERR = re.compile(
    r"ERROR:\s*(?:Address|HWAddress|Memory|UndefinedBehavior|Leak)Sanitizer:\s*"
    r"([a-z0-9-]+)", re.I)
# "READ of size 8 at 0x…"  /  "WRITE of size 4 at 0x…"
_ACCESS = re.compile(r"\b(READ|WRITE)\s+of\s+size\s+(\d+)", re.I)
# a symbolized frame:  "#3 0x… in func /path/file.c:42:7"
_FRAME = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+([^\s:]+):(\d+)", re.I)
# UBSan one-liner: "file.c:12:5: runtime error: signed integer overflow…"
_UBSAN = re.compile(r"(\S+):(\d+):\d+:\s*runtime error:\s*(.+)", re.I)

_WRITE_PRIMITIVE_CLASSES = {
    "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
    "heap-use-after-free", "use-after-poison", "stack-use-after-return",
    "stack-use-after-scope", "dynamic-stack-buffer-overflow",
}

# Fatal signals → a bug class, for a bare binary with no sanitizer (Phase C).
# A subprocess killed by signal N returns rc = -N (POSIX); some shells report
# 128+N. SIGSEGV/SIGBUS are the memory-safety-relevant crashes.
_SIGNAL_BUG = {
    11: "segv", 10: "bus-error", 6: "abort", 4: "illegal-instruction",
    8: "floating-point-exception", 5: "trap",
}
_MEMORY_SIGNALS = {11, 10}   # SIGSEGV, SIGBUS — likely memory-safety


@dataclass
class Frame:
    func: str
    file: str
    line: int


@dataclass
class CrashInfo:
    crashed: bool = False
    bug_type: str = ""                 # e.g. heap-buffer-overflow
    access: str = ""                   # READ | WRITE | ""
    access_size: int = 0
    frames: list[Frame] = field(default_factory=list)
    stack_hash: str = ""               # dedup key (top frames)
    summary: str = ""

    @property
    def top(self) -> Optional[Frame]:
        # first non-sanitizer-runtime frame
        for f in self.frames:
            if "sanitizer" not in f.func.lower() and "asan" not in f.func.lower():
                return f
        return self.frames[0] if self.frames else None

    def is_write_primitive(self) -> bool:
        """A controllable WRITE / lifetime bug — the raw material for a
        write-what-where primitive the escalation tier tries to prove."""
        return (self.access.upper() == "WRITE"
                and self.bug_type in _WRITE_PRIMITIVE_CLASSES) \
            or self.bug_type in {"heap-use-after-free"}


def _signal_of(rc: Optional[int]) -> Optional[int]:
    if rc is None:
        return None
    if rc < 0:
        return -rc
    if rc > 128:            # 128 + signal convention
        return rc - 128
    return None


# ── Windows NTSTATUS exceptions (Phase 2 — argv-mode Windows agent) ──
# A crashing Windows process exits WITH its exception code as the exit code, so a
# crash is detectable from the exit code alone, no debugger needed for M0. The
# access type (READ/WRITE) + faulting address come later from the exploitability
# oracle (WinDbg); here we record the class. (name, memory_relevant, security_relevant)
_WINDOWS_EXCEPTIONS = {
    0xC0000005: ("access-violation", True, False),
    0xC0000374: ("heap-corruption", True, True),
    0xC0000409: ("stack-buffer-overrun", True, True),      # /GS cookie tripped
    0xC00000FD: ("stack-overflow", True, False),
    0xC0000006: ("in-page-error", True, False),
    0xC000001D: ("illegal-instruction", False, False),
    0xC0000094: ("integer-divide-by-zero", False, False),
    0xC0000096: ("privileged-instruction", False, False),
    0x80000003: ("breakpoint", False, False),
}
_WINDOWS_MEMORY = {0xC0000005, 0xC0000374, 0xC0000409, 0xC00000FD, 0xC0000006}


def _ntstatus_of(code: Optional[int]) -> Optional[int]:
    """Normalize a process exit code to an unsigned 32-bit NTSTATUS exception code,
    or None if it isn't one. subprocess may surface the code signed (negative), so
    mask to 32-bit; a real exception code has a 0xC (error) or 0x8 (warning) top
    nibble, well outside any POSIX 128+signal exit code."""
    if code is None:
        return None
    u = code & 0xFFFFFFFF
    return u if (u & 0xF0000000) in (0xC0000000, 0x80000000) else None


def parse(output: str, rc: Optional[int] = None,
          win_exit: Optional[int] = None) -> CrashInfo:
    """Parse a run into CrashInfo. A sanitizer report wins; otherwise a fatal
    signal in `rc` (bare Linux binary) or a Windows NTSTATUS exception in
    `win_exit` (Windows agent, argv-mode) is a crash too."""
    text = output or ""
    ci = CrashInfo()

    m = _ASAN_ERR.search(text)
    if m:
        ci.crashed = True
        ci.bug_type = m.group(1).lower()
    else:
        u = _UBSAN.search(text)
        if u:
            ci.crashed = True
            ci.bug_type = "undefined-behavior"
            ci.summary = u.group(3).strip()[:200]
            ci.frames = [Frame("", u.group(1), int(u.group(2)))]

    a = _ACCESS.search(text)
    if a:
        ci.access = a.group(1).upper()
        ci.access_size = int(a.group(2))

    for fm in _FRAME.finditer(text):
        ci.frames.append(Frame(fm.group(1), fm.group(2), int(fm.group(3))))

    # No sanitizer report but the process died on a fatal signal → still a crash
    # (the Phase-C bare-binary path). Memory signals imply a WRITE-ish fault.
    if not ci.crashed:
        sig = _signal_of(rc)
        if sig in _SIGNAL_BUG:
            ci.crashed = True
            ci.bug_type = _SIGNAL_BUG[sig]
            if sig in _MEMORY_SIGNALS:
                ci.access = "WRITE"      # conservative; a SEGV write is common
            ci.summary = f"process crashed with SIG{ci.bug_type.upper()} (signal {sig})"

    # No sanitizer + no POSIX signal → check for a Windows NTSTATUS exception.
    # Additive: only fires when win_exit is supplied (the Windows agent).
    if not ci.crashed and win_exit is not None:
        nt = _ntstatus_of(win_exit)
        if nt is not None:
            ci.crashed = True
            name, mem, _sec = _WINDOWS_EXCEPTIONS.get(
                nt, ("windows-exception", nt in _WINDOWS_MEMORY, False))
            ci.bug_type = name
            if mem:
                ci.access = "WRITE"      # conservative; exploitability oracle refines
            ci.summary = (f"process crashed with {name} "
                          f"(NTSTATUS 0x{nt:08X})")

    if ci.crashed:
        top = ci.top
        basis = f"{ci.bug_type}|{ci.access}|" + "|".join(
            f"{f.func}:{f.file}" for f in ci.frames[:5])
        ci.stack_hash = hashlib.sha1(basis.encode()).hexdigest()[:16]
        if not ci.summary:
            loc = f" at {top.file}:{top.line}" if top else ""
            ci.summary = (f"{ci.bug_type} ({ci.access or 'access'})"
                          f"{loc}").strip()
    return ci

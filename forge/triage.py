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
# ASan section headers that begin an allocation / free stack (heap-overflow/UAF).
_ALLOC_HDR = re.compile(r"(?:previously )?allocated by thread .*here:", re.I)
_FREED_HDR = re.compile(r"freed by thread .*here:", re.I)
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
# SIGNAL NUMBERS ARE NOT PORTABLE, and hardcoding them cost this engine a real bug.
#
# SIGBUS is 10 on macOS and the BSDs, and 7 on Linux. The table below used to say 10
# unconditionally, so on Linux a genuine memory fault delivered as SIGBUS was not in the map
# at all: `crashed` came back False, NativeVerifyOracle refuted the finding, and a real
# overflow was reported as an instrumentation artifact. Worse, 10 on Linux is SIGUSR1, which
# is not a crash -- so the table was simultaneously blind to a fault and primed to invent
# one. The bundled example reproduces it: exit 135 = 128 + 7 on Ubuntu, 139 = 128 + 11 here.
#
# Taken from the `signal` module so the numbers are whatever this platform actually uses.
# KNOWN GAP: an analysis host and a target can differ -- a Linux device examined from a mac
# still resolves the host's numbers. Cross-platform targets need the target's table, not
# ours, and this does not yet plumb that through.
def _signo(name: str, fallback: int) -> int:
    import signal as _signal
    return int(getattr(getattr(_signal, name, None), "value", fallback)
               if hasattr(_signal, name) else fallback)


_SIGNAL_BUG = {
    _signo("SIGSEGV", 11): "segv",
    _signo("SIGBUS", 10): "bus-error",
    _signo("SIGABRT", 6): "abort",
    _signo("SIGILL", 4): "illegal-instruction",
    _signo("SIGFPE", 8): "floating-point-exception",
    _signo("SIGTRAP", 5): "trap",
}
# SIGSEGV/SIGBUS — likely memory-safety
_MEMORY_SIGNALS = {_signo("SIGSEGV", 11), _signo("SIGBUS", 10)}


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
    # Faulting-instruction context — populated by a debugger / the Frida exception
    # observer on Windows (from d.memory + d.context). Feeds the exploitability
    # oracle directly so it need not shell out to gdb/lldb/cdb.
    fault_addr: str = ""               # accessed address (the faulting operand)
    fault_pc: str = ""                 # faulting instruction address
    registers: dict = field(default_factory=dict)
    # ASan allocation/free frames (heap-buffer-overflow / UAF), for misuse-triage's
    # deterministic "allocated in the harness?" signal.
    alloc_frames: list = field(default_factory=list)
    free_frames: list = field(default_factory=list)

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


def _labeled_frames(text: str):
    """Extract ASan allocation + free stack frames — the sections after
    'allocated by thread … here:' and 'freed by thread … here:'. Feeds
    misuse-triage's deterministic 'was it allocated in the harness?' signal."""
    alloc: list = []
    free: list = []
    cur = None
    for line in (text or "").splitlines():
        if _ALLOC_HDR.search(line):
            cur = alloc
            continue
        if _FREED_HDR.search(line):
            cur = free
            continue
        m = _FRAME.search(line)
        if m and cur is not None:
            cur.append(Frame(m.group(1), m.group(2), int(m.group(3))))
        elif cur is not None and not line.strip():
            cur = None                          # blank line ends a section
    return alloc, free


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

    # Allocation / free stacks (for misuse-triage's deterministic signal).
    ci.alloc_frames, ci.free_frames = _labeled_frames(text)

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


def crashinfo_from_frida(exc: dict) -> CrashInfo:
    """Build a CrashInfo from a Frida exception-handler payload — the reliable,
    low-artifact Windows crash signal (catches SEH-swallowed access-violations a
    Delphi/GUI app hides from the exit code). Unlike the `win_exit` path, the
    access type (READ/WRITE) and the faulting address come from `d.memory` /
    `d.context`, not a fabricated 'conservative WRITE', and dedup keys on the
    faulting instruction so distinct AVs stay distinct.

    Expected payload keys (from FRIDA_EXCEPTION_AGENT): kind, op (read|write|
    execute), addr (accessed operand), pc (faulting instruction), regs (dict)."""
    ci = CrashInfo()
    if not exc:
        return ci
    ci.crashed = True
    ci.bug_type = (exc.get("kind") or "access-violation").lower()
    op = (exc.get("op") or "").upper()
    if op in ("READ", "WRITE"):
        ci.access = op
    ci.fault_addr = exc.get("addr") or ""
    ci.fault_pc = exc.get("pc") or ""
    ci.registers = dict(exc.get("regs") or {})
    # Dedup by faulting instruction (module-relative if the caller normalized it),
    # so two different crash sites are two findings, not one.
    basis = f"{ci.bug_type}|{op}|{ci.fault_pc or ci.fault_addr}"
    ci.stack_hash = hashlib.sha1(basis.encode()).hexdigest()[:16]
    loc = ci.fault_addr or ci.fault_pc
    ci.summary = (f"{ci.bug_type} ({op or 'access'})"
                  f"{(' at ' + loc) if loc else ''} (first-chance)")
    return ci

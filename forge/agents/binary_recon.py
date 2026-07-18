"""BinaryReconAgent — the REVERSE-ENGINEERING lens (no source needed).

The other lenses read source; this one attacks a closed binary. Using tools that
are ALWAYS present (nm / objdump / strings — no Ghidra/radare2 install required),
it recovers the binary's imported functions and flags the classic memory-safety and
command-injection sinks it links against (strcpy/gets/sprintf/system/exec…), plus
format-string and shell indicators in its string table. These are LEADS, not proofs
— exactly like the static-source lens: they mark where a bug most likely hides so
the concrete fuzz + crash-oracle path (BinaryTarget) can drive at it, and they
CORROBORATE a dynamic crash landing in the same imported routine.

Deep RE (full disassembly, CFG-reachability) upgrades this when radare2/rizin or
Ghidra headless is available; absent those it degrades to import/string triage,
which still works everywhere.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Optional

from ..events import EventType
from ..ladder import Candidate
from .base import Agent

# Imported libc/system routines that are classic sinks for attacker-controlled data.
_DANGEROUS = {
    # unbounded buffer copies / classic overflow sinks
    "strcpy": "unbounded string copy", "strcat": "unbounded string concat",
    "stpcpy": "unbounded string copy", "gets": "unbounded stdin read (never safe)",
    "sprintf": "unbounded formatted write", "vsprintf": "unbounded formatted write",
    "scanf": "unbounded input parse", "sscanf": "unbounded input parse",
    "wcscpy": "unbounded wide copy", "wcscat": "unbounded wide concat",
    "alloca": "stack alloc from (possibly attacker) size",
    "realpath": "PATH_MAX overflow (legacy)",
    # length-taking copies whose length is often attacker-derived
    "memcpy": "length-controlled copy", "memmove": "length-controlled copy",
    # command / shell execution — command-injection sinks
    "system": "shell command execution", "popen": "shell command execution",
    "execl": "process execution", "execlp": "process execution",
    "execle": "process execution", "execv": "process execution",
    "execvp": "process execution", "execve": "process execution",
    # format strings — dangerous when the format is attacker-controlled
    "printf": "format string (if fmt is tainted)",
    "fprintf": "format string (if fmt is tainted)",
    "syslog": "format string (if fmt is tainted)",
}


class BinaryReconAgent(Agent):
    kind = "binary_recon"

    def __init__(self, ctx, name: str = "binary-recon", parent_id: str = "", *,
                 binary: Optional[Path] = None, max_leads: int = 40) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        # default to the job's binary target if it is one
        self.binary = Path(binary) if binary else Path(
            getattr(getattr(ctx, "target", None), "binary", "") or "")
        self.max_leads = max_leads

    async def run(self) -> list[Candidate]:
        if not self.binary or not self.binary.exists():
            self.log("no binary to recon")
            return []
        if not (shutil.which("nm") or shutil.which("objdump")):
            self.log("no nm/objdump — binary recon idle")
            return []
        self.objective("reverse-engineering lens: recover imports + strings from the "
                       "binary, flag memory-safety / command-injection sinks")
        leads = await asyncio.to_thread(self._recon)
        for lead in leads[:self.max_leads]:
            self.em.emit(EventType.CANDIDATE, title=f"RE: {lead['symbol']}",
                         bug_class="binary_lead", agent=self.name,
                         why=f"{lead['symbol']} — {lead['why']}")
        try:
            (self.ctx.artifacts / "binary_recon.json").write_text(
                json.dumps(leads, indent=2))
        except Exception:
            pass
        self.log(f"binary recon: {len(leads)} sink import(s) flagged — leads, need "
                 f"dynamic confirmation on the binary target")
        return []                            # leads, not oracle-provable candidates

    def _imports(self) -> set[str]:
        """Imported (undefined) symbols — what the binary calls from libc/others."""
        syms: set[str] = set()
        sb = getattr(self.ctx.target, "sandbox", None)
        def _run(argv):
            if sb is not None:
                return sb.run(argv, timeout=25).stdout
            import subprocess
            return subprocess.run(argv, capture_output=True, text=True,
                                  timeout=25).stdout
        if shutil.which("nm"):
            # -u = undefined (imported) symbols; try both plain and dynamic
            for flag in (["-u"], ["-Du"]):
                try:
                    out = _run(["nm", *flag, str(self.binary)])
                except Exception:
                    continue
                for line in out.splitlines():
                    tok = line.strip().split()
                    if tok:
                        syms.add(tok[-1].lstrip("_"))   # strip leading _ (macOS)
        if not syms and shutil.which("objdump"):
            try:
                out = _run(["objdump", "-T", str(self.binary)])
                for line in out.splitlines():
                    if "UND" in line:
                        tok = line.split()
                        if tok:
                            syms.add(tok[-1].lstrip("_"))
            except Exception:
                pass
        return syms

    def _recon(self) -> list[dict]:
        imports = self._imports()
        leads = []
        for sym in sorted(imports):
            base = sym.split("@")[0]          # strip glibc version tags (foo@GLIBC)
            if base.endswith("_chk"):         # fortified libc: __strcpy_chk → strcpy
                base = base[:-4]
            if base in _DANGEROUS:
                leads.append({"symbol": base, "why": _DANGEROUS[base],
                              "class": "command-exec" if base in (
                                  "system", "popen") or base.startswith("exec")
                              else "memory-safety"})
        return leads

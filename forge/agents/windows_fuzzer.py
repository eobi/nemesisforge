"""WindowsFuzzer — mutation-based discovery for a closed Windows file-parser.

Drives a `WindowsBinaryTarget` in argv/file mode: mutate a seed file, open it with
the app, watch for a Windows exception. Coverage-optional:

  - with a `CoverageBackend` (Frida/DynamoRIO, Phase-2 M1): coverage-guided — an
    input that adds block coverage is kept and further mutated, so the fuzzer
    climbs into deep parser code. A crash from an instrumented run is emitted as
    an ``instrumented_crash`` Candidate → the NativeVerifyOracle replays it
    un-instrumented before it is trusted (the anti-artifact discipline).
  - without a backend: dumb argv-mode mutation over the seeds — still finds the
    shallow header/field-overflow bugs typical of image/office parsers (the
    FastStone class). A native crash is emitted as a ``binary_crash`` Candidate.

Deterministic: mutations are driven by a per-iteration seeded PRNG, so a campaign
(and any crash) is reproducible. The finder never certifies its own find — the
oracle chain re-runs to prove it.
"""
from __future__ import annotations

import asyncio
import base64
import random
from typing import Optional, Sequence

from ..ladder import Candidate, CodeLoc
from ..oracles.exploitability import _addr_int
from ..targets.binary_cov import CoverageMap
from .base import Agent

# Distinctive values a parser is most likely to mishandle at a length/size field.
_EXTREMES = (b"\x00", b"\xff", b"\x7f", b"\x80", b"\xff\xff",
             b"\xff\xff\xff\xff", b"\x00\x00\x00\x00")


class WindowsFuzzer(Agent):
    kind = "windows_fuzzer"

    def __init__(self, ctx, name: str = "win-fuzz", parent_id: str = "", *,
                 seeds: Optional[Sequence[bytes]] = None,
                 coverage=None, max_tries: int = 300, max_crashes: int = 5,
                 timeout: float = 20.0) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.seeds = [s for s in (seeds or [b"\x00" * 32]) if s is not None]
        self.coverage = coverage             # a CoverageBackend, or None
        self.max_tries = max_tries
        self.max_crashes = max_crashes
        self.timeout = timeout

    async def run(self) -> list[Candidate]:
        instrumented = bool(self.coverage and self.coverage.available())
        self.objective(
            f"fuzz the Windows target ({'coverage-guided' if instrumented else 'argv-mode'})")
        target = self.ctx.target
        build = await asyncio.to_thread(target.build)
        if not build.ok:
            self.log("target unavailable", log=build.log[-300:])
            return []

        corpus = list(self.seeds)
        cov = CoverageMap()
        seen_crashes: set[str] = set()
        candidates: list[Candidate] = []

        # Run the raw seeds UNMODIFIED first — a seed is often a crashing PoC or
        # high-value corpus that mutation would destroy on iteration 0. Then fuzz.
        raw = list(self.seeds)
        for i in range(len(raw) + self.max_tries):
            if self.ctx.budget.expired():
                self.log("budget expired mid-fuzz")
                break
            inp = raw[i] if i < len(raw) else self._mutate(i - len(raw), corpus)
            obs, edges, instr = await self._exec(target, build.binary, inp)
            if edges and cov.observe(edges) > 0:
                corpus.append(inp)           # coverage-adding → keep + re-mutate
                self.tool_result("coverage", new=len(cov))
            if obs.crashed:
                h = obs.crash.stack_hash or obs.crash.bug_type
                if h in seen_crashes:
                    continue
                seen_crashes.add(h)
                self.log(f"crash: {obs.crash.summary}")
                self.tool_result("run", crashed=True, bug=obs.crash.bug_type)
                # Taint-lite: which input offsets flow to the faulting address?
                # Bounded, crash-only. Populates control_offsets so the
                # exploitability oracle's marker substitution proves write-what-where.
                offsets = await asyncio.to_thread(
                    self._control_offsets, target, build.binary, inp, obs.crash)
                candidates.append(self._candidate(inp, obs.crash, instr, offsets))
                if len(candidates) >= self.max_crashes:
                    break
        if not candidates:
            self.log("no crash within fuzz budget")
        return candidates

    async def _exec(self, target, binary, inp):
        """Run one input; return (Observation, edges, instrumented?). Coverage and
        crash detection can come from different instruments: drcov yields edges but
        no crash; the exception observer yields the reliable crash. Prefer a crash
        the coverage backend itself observed (Frida-Stalker has a first-chance
        handler); otherwise take the crash from the target's observer."""
        edges: set = set()
        instr = False
        obs = None
        if self.coverage and self.coverage.available():
            run = await asyncio.to_thread(
                self.coverage.run_with_coverage, binary, stdin=inp,
                timeout=self.timeout)
            edges, instr = run.edges, run.instrumented
            if run.observation.crashed:
                obs = run.observation
        if obs is None:
            obs = await asyncio.to_thread(target.run, binary, stdin=inp,
                                          timeout=self.timeout)
        return obs, edges, instr

    _MARKER = 0x42424242

    def _control_offsets(self, target, binary, inp: bytes, crash, *,
                         max_offsets: int = 64, width: int = 4) -> list:
        """Which input offsets control the faulting address? Plant a distinctive
        marker at each dword offset, re-run through the crash observer, and keep the
        offsets where the fault address reflects the marker — attacker control of
        the write/read destination. Bounded and crash-only; needs an observer that
        supplies a faulting address (skips otherwise)."""
        base = _addr_int(getattr(crash, "fault_addr", ""))
        if base is None:
            return []                            # no address to taint against
        ctrl: list = []
        mb = self._MARKER.to_bytes(width, "little")
        limit = min(len(inp), max_offsets * width)
        for off in range(0, max(1, limit - width + 1), width):
            planted = bytearray(inp)
            planted[off:off + width] = mb
            try:
                o = target.run(binary, stdin=bytes(planted), timeout=self.timeout)
            except Exception:
                continue
            if o.crashed:
                fa = _addr_int(getattr(o.crash, "fault_addr", ""))
                if fa is not None and (fa & 0xFFFFFFFF) == self._MARKER:
                    ctrl.append(off)
                    if len(ctrl) >= 2:           # enough to prove control
                        break
        return ctrl

    def _candidate(self, inp: bytes, crash, instrumented: bool,
                   control_offsets: Optional[list] = None) -> Candidate:
        top = crash.top
        # An instrumented crash must clear native-verify first; a native crash
        # goes straight to the binary-crash oracle.
        bug_class = "instrumented_crash" if instrumented else "binary_crash"
        pc = {"input_b64": base64.b64encode(inp).decode(),
              "instrumented_bug": crash.bug_type, "native_replays": 5,
              "timeout": self.timeout}
        if control_offsets:
            pc["control_offsets"] = control_offsets
            pc["marker"] = self._MARKER
            pc["marker_width"] = 4
        return Candidate(
            bug_class=bug_class,
            title=crash.summary or f"{crash.bug_type} crash",
            rationale=f"fuzzing found a {len(inp)}-byte input that triggers "
                      f"{crash.bug_type} in {self.ctx.target.name}",
            location=CodeLoc(path=top.file if top else "", line=top.line if top else 0,
                             symbol=top.func if top else ""),
            agent=self.name, proposed_check=pc,
            crash={"bug_type": crash.bug_type, "stack_hash": crash.stack_hash})

    def _mutate(self, i: int, corpus: list) -> bytes:
        """Deterministic mutation of a corpus entry (reproducible by iteration)."""
        rng = random.Random(i * 2654435761)
        buf = bytearray(corpus[rng.randrange(len(corpus))])
        if not buf:
            buf = bytearray(b"\x00" * 16)
        strat = i % 5
        if strat == 0:                       # extreme value at a random offset
            off = rng.randrange(len(buf))
            v = rng.choice(_EXTREMES)
            buf[off:off + len(v)] = v
        elif strat == 1:                     # bit/byte flip
            off = rng.randrange(len(buf))
            buf[off] ^= 1 << rng.randrange(8)
        elif strat == 2:                     # havoc a header field (early bytes)
            off = rng.randrange(min(32, len(buf)))
            buf[off:off + 4] = (0xFFFFFFFF).to_bytes(4, "little")
        elif strat == 3:                     # grow (long run → overflow copies)
            buf += bytes(rng.choice(_EXTREMES)) * rng.randrange(1, 64)
        else:                                # truncate (short read / underflow)
            buf = buf[:max(1, len(buf) // 2)]
        return bytes(buf)

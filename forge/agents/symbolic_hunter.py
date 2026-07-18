"""SymbolicHunterAgent — the PATH angle (reach code the fuzzer stalls on).

Coverage-guided fuzzing gets stuck at hard guards (magic values, checksums, tight
constraints). Symbolic execution *solves* for inputs that satisfy those guards and
drive into deep code — and flags states where control flow or a write becomes
attacker-controlled (angr's unconstrained state). This agent runs angr on the
target's stdin harness, and any input it finds is handed to the SanitizerOracle to
CONFIRM — a symbolic lead is a proposer, the oracle still proves it.

Gated on angr (heavy, optional): without it, the agent no-ops cleanly, so the rest
of the fleet is unaffected. angr path-explosion is real, so it's bounded by a step
+ time budget and is best on small/simple targets.
"""
from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from typing import Optional, Sequence

from ..events import EventType
from ..ladder import Candidate
from .base import Agent


def angr_available() -> bool:
    try:
        import angr  # noqa: F401
        return True
    except Exception:
        return False


class SymbolicHunterAgent(Agent):
    kind = "symbolic_hunter"

    def __init__(self, ctx, name: str = "symbolic", parent_id: str = "", *,
                 harness: str = "", target_sources: Optional[Sequence[Path]] = None,
                 include_dirs: Optional[Sequence[Path]] = None,
                 sanitizer: str = "address", bug_class: str = "memory_safety",
                 max_seconds: int = 90, max_steps: int = 3000,
                 input_len: int = 64) -> None:
        super().__init__(ctx, name=name, parent_id=parent_id)
        self.harness = harness
        self.target_sources = list(target_sources or [])
        self.include_dirs = list(include_dirs or [])
        self.sanitizer = sanitizer
        self.bug_class = bug_class
        self.max_seconds = max_seconds
        self.max_steps = max_steps
        self.input_len = input_len

    async def run(self) -> list[Candidate]:
        if not angr_available():
            self.log("angr not installed — symbolic path lens idle")
            return []
        if not self.harness:
            return []
        self.objective("symbolic-execution lens: solve guards the fuzzer stalls "
                       "on, drive deep, flag attacker-controlled states")
        target = self.ctx.target
        # Build a stdin-driven binary (libFuzzer harness + standalone driver, no
        # fuzzer runtime) so angr can drive symbolic stdin into it.
        build = await asyncio.to_thread(
            target.build, self.harness, sanitizer=self.sanitizer,
            target_sources=self.target_sources or None,
            include_dirs=self.include_dirs or None, libfuzzer_driver=True)
        if not build.ok:
            self.log("symbolic-hunter build failed", log=(build.log or "")[-200:])
            return []
        inputs = await asyncio.to_thread(self._explore, str(build.binary))
        cands = []
        for i, inp in enumerate(inputs):
            self.em.emit(EventType.CANDIDATE, title=f"symbolic reach #{i}",
                         bug_class=self.bug_class, agent=self.name,
                         why="input synthesized by symbolic execution")
            cands.append(Candidate(
                bug_class=self.bug_class,
                title="symbolic-reached input",
                rationale="angr solved for an input reaching deep/attacker-influenced code",
                agent=self.name,
                proposed_check={"harness": self.harness, "libfuzzer": True,
                                "sanitizer": self.sanitizer,
                                "input_b64": base64.b64encode(inp).decode(),
                                "target_sources": [str(p) for p in self.target_sources]
                                or None,
                                "include_dirs": [str(p) for p in self.include_dirs]
                                or None}))
        self.log(f"symbolic lens produced {len(cands)} reaching input(s) "
                 f"for the oracle to confirm")
        return cands

    def _explore(self, binary: str) -> list[bytes]:
        """angr: symbolic stdin → explore for unconstrained (attacker-controlled)
        states, return concretized inputs. Bounded; best-effort."""
        import time
        try:
            import angr
            import claripy
        except Exception:
            return []
        found: list[bytes] = []
        try:
            proj = angr.Project(binary, auto_load_libs=False)
            n = self.input_len
            sym = claripy.BVS("stdin", n * 8)
            state = proj.factory.full_init_state(
                stdin=angr.SimFileStream(name="stdin", content=sym, has_end=True),
                add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                             angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
            simgr = proj.factory.simulation_manager(state, save_unconstrained=True)
            start = time.monotonic()
            steps = 0
            while (simgr.active and steps < self.max_steps
                   and time.monotonic() - start < self.max_seconds):
                simgr.step()
                steps += 1
                for st in list(simgr.unconstrained):
                    try:
                        val = st.solver.eval(sym, cast_to=bytes)
                        if val and val not in found:
                            found.append(val)
                    except Exception:
                        pass
                    simgr.unconstrained.remove(st)
                if len(found) >= 3:
                    break
        except Exception:
            return found
        return found

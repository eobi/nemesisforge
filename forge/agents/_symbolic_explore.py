"""Standalone symbolic-exploration worker — run as an ISOLATED subprocess.

`SymbolicHunterAgent._explore` launches this via `python -m` so an angr/z3 native
crash (SIGSEGV, Z3 assertion) or a hang on a pointer-heavy parser is contained in a
throwaway process instead of taking the whole hunt down (a native SIGSEGV in an
in-process thread is uncatchable). A non-zero exit / timeout just means "no symbolic
inputs" and the co-driving fuzzer runs on undisturbed.

Protocol: reads {"binary": path, "input_len": n, "max_steps": s, "max_seconds": t}
as JSON on stdin; writes a JSON list of base64-encoded concretized inputs to stdout.
"""
from __future__ import annotations

import base64
import json
import sys
import time


def explore(binary: str, input_len: int, max_steps: int, max_seconds: float) -> list:
    try:
        import angr
        import claripy
    except Exception:
        return []
    import logging
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    logging.getLogger("cle").setLevel(logging.CRITICAL)
    found: list[bytes] = []
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        sym = claripy.BVS("stdin", input_len * 8)
        state = proj.factory.full_init_state(
            stdin=angr.SimFileStream(name="stdin", content=sym, has_end=True),
            add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                         angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
        simgr = proj.factory.simulation_manager(state, save_unconstrained=True)
        start, steps = time.monotonic(), 0
        while (simgr.active and steps < max_steps
               and time.monotonic() - start < max_seconds):
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


def main() -> None:
    inputs = []
    try:
        req = json.loads(sys.stdin.read() or "{}")
        if req.get("binary"):
            inputs = explore(req["binary"], int(req.get("input_len", 64)),
                             int(req.get("max_steps", 200)),
                             float(req.get("max_seconds", 120)))
    except Exception:
        inputs = []
    print(json.dumps([base64.b64encode(b).decode() for b in inputs]))


if __name__ == "__main__":
    main()

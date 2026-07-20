"""Standalone predicate strict-relaxation prover — run as an ISOLATED subprocess.

`predicate_symbolic._run_isolated` launches this via `python -m` so that an angr/z3
native crash (SIGSEGV, Z3 assertion) or a hang is contained in a throwaway process:
a non-zero exit / timeout simply means "nothing proven" → the fuzzer runs undirected.
This decoupling (real subprocess, not multiprocessing) is required because the hunt
entry point may itself be a stdin script, which breaks `spawn`/`fork` re-import.

Protocol: reads {"binary": path, "specs": [[idx, function, condition], ...]} as JSON
on stdin; writes a JSON list of validated indices to stdout. Nothing else.
"""
from __future__ import annotations

import json
import sys


def main() -> None:
    validated = []
    try:
        req = json.loads(sys.stdin.read() or "{}")
        binary = req.get("binary")
        specs = req.get("specs") or []
        if not binary or not specs:
            print("[]")
            return
        import logging
        logging.getLogger("angr").setLevel(logging.CRITICAL)
        logging.getLogger("cle").setLevel(logging.CRITICAL)
        import angr
        from forge.agents.predicate_symbolic import _prove_one
        proj = angr.Project(binary, auto_load_libs=False)
        for idx, function, condition in specs:
            try:
                if _prove_one(proj, function, condition):
                    validated.append(idx)
            except Exception:
                continue
    except Exception:
        validated = []
    print(json.dumps(validated))


if __name__ == "__main__":
    main()

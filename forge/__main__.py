"""Nemesis Forge command line.

    python -m forge <command> [options]

Design notes, because they are the reason this file looks the way it does:

  * Every command runs without an API key. The engine's deterministic half, the
    fuzzing loop and the oracles that certify findings, needs no model. A model
    only proposes, so its absence costs you harness synthesis and nothing else.
    `--provider null` is the default for exactly this reason.

  * Every command prints what it could NOT do. A campaign that finds nothing
    because a lens was missing is a different result from a campaign that finds
    nothing because there is nothing there, and the two must not look alike.

  * Nothing here talks to a server. Output is files you can read with cat.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import uuid
from pathlib import Path


def _quiet_third_party() -> None:
    """angr logs a unicorn-loading error at import time on machines without the
    optional native library. It is harmless, it is not ours, and a CLI that
    prints somebody else's stack trace before its own first line looks broken."""
    import logging
    for name in ("angr", "cle", "pyvex", "claripy", "archinfo"):
        logging.getLogger(name).setLevel(logging.CRITICAL)


def _banner(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def cmd_lab(a: argparse.Namespace) -> int:
    """Run a campaign against a harness you supply. No network, no model needed."""
    from .config import load_env
    load_env()
    from .job import lab_job, run_job

    harness = Path(a.harness).read_text()
    if "LLVMFuzzerTestOneInput" not in harness:
        print("error: harness must define LLVMFuzzerTestOneInput", file=sys.stderr)
        return 2

    job = a.job or ("lab-" + uuid.uuid4().hex[:8])
    root = Path(a.out)
    _banner(f"job={job} harness={a.harness} fuzz_time={a.fuzz_time}s "
            f"provider={a.provider or 'null'}")

    ctx, discovery, oracles, escalation, llm = lab_job(
        job, harness, artifacts_root=root, name=a.name,
        fuzz_time=a.fuzz_time, provider=a.provider)
    findings = asyncio.run(run_job(ctx, discovery=discovery, oracles=oracles,
                                   escalation=escalation, llm=llm))
    _banner(f"{len(findings)} finding(s)")
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(vars(f))
        print(json.dumps({k: d.get(k) for k in
                          ("title", "rung", "bug_type", "function")}, default=str))
    print(f"\nartifacts: {root / job}")
    print("read them with:  ls", root / job)
    return 0


def cmd_repo(a: argparse.Namespace) -> int:
    """Point the engine at a git URL. Harness synthesis needs a model."""
    from .config import load_env
    load_env()
    from .job import repo_job, run_job

    if not a.provider or a.provider == "null":
        print("note: no model provider selected, so no harness will be synthesised.\n"
              "      The static lens will still run and report leads. To fuzz, either\n"
              "      pass --provider, or write a harness and use:  python -m forge lab\n",
              file=sys.stderr)

    job = a.job or ("hunt-" + uuid.uuid4().hex[:8])
    root = Path(a.out)
    _banner(f"job={job} url={a.url} targets={a.max_targets} fuzz_time={a.fuzz_time}s")

    ctx, discovery, oracles, escalation, llm = repo_job(
        job, a.url, artifacts_root=root, max_targets=a.max_targets,
        fuzz_time=a.fuzz_time, campaign_minutes=a.minutes,
        sanitizer=a.sanitizer, provider=a.provider, model=a.model)
    findings = asyncio.run(run_job(ctx, discovery=discovery, oracles=oracles,
                                   escalation=escalation))
    _banner(f"{len(findings)} finding(s)")
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(vars(f))
        print(json.dumps({k: d.get(k) for k in
                          ("title", "rung", "bug_type", "function", "novelty")},
                         default=str))
    print(f"\nartifacts: {root / job}")
    return 0


def cmd_oracles(a: argparse.Namespace) -> int:
    """List the oracles and the rung each one can certify."""
    import importlib
    import pkgutil
    from .ladder import Rung
    from . import oracles as _o

    # forge/oracles/__init__.py is empty, so the classes are not attributes of the
    # package. Walk the submodules instead of dir()-ing the package, which silently
    # returned nothing and printed an empty list that looked like "no oracles".
    print("ORACLES, and what each one certifies\n")
    found = []
    for m in pkgutil.iter_modules(_o.__path__):
        mod = importlib.import_module(f"{_o.__name__}.{m.name}")
        for n in dir(mod):
            if not n.endswith("Oracle") or n in ("Oracle", "OracleRouter"):
                continue
            cls = getattr(mod, n)
            if isinstance(cls, type) and cls.__module__ == mod.__name__:
                doc = (cls.__doc__ or "").strip().split("\n")[0]
                found.append((n, doc))
    for n, doc in sorted(set(found)):
        print(f"  {n:<24} {doc[:88]}")
    print(f"\n  {len(set(found))} oracles")
    print("\nRUNGS")
    for r in Rung:
        print(f"  {r.value}  {r.name}")
    print("\nA model may propose a candidate for any rung. Only an oracle may certify one.")
    return 0


def cmd_doctor(a: argparse.Namespace) -> int:
    """Report which lenses are available, and what their absence costs."""
    import shutil
    from . import fuzzengine
    print("ENVIRONMENT\n")
    rows = []
    cc = fuzzengine.find_libfuzzer_clang()
    rows.append(("libFuzzer-capable clang", bool(cc), cc or "",
                 "REQUIRED for coverage-guided discovery"))
    for tool, why in (("clang", "REQUIRED to build targets"),
                      ("git", "needed for repo mode"),
                      ("lldb", "rung-4 operand evidence (macOS)"),
                      ("gdb", "rung-4 operand evidence (Linux)")):
        p = shutil.which(tool)
        rows.append((tool, bool(p), p or "", why))
    for mod, why in (("angr", "symbolic lens; without it, no constraint solving"),
                     ("frida", "closed-binary coverage; without it, source only")):
        try:
            __import__(mod); ok, loc = True, "installed"
        except Exception:
            ok, loc = False, ""
        rows.append((mod, ok, loc, why))
    for name, ok, loc, why in rows:
        mark = "yes" if ok else "NO "
        print(f"  {mark}  {name:<26} {why}")
        if loc and loc != "installed":
            print(f"       {loc}")
    print("\nMissing entries are not errors. The engine runs without them and says so\n"
          "in its output rather than reporting a null result as if it were a search.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m forge",
        description="Nemesis Forge: an LLM fleet proposes, deterministic oracles prove.",
        epilog="Every command runs with no API key. See docs/CLI.md for worked examples.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("lab", help="run a campaign against a harness you supply")
    p.add_argument("harness", help="path to a C file defining LLVMFuzzerTestOneInput")
    p.add_argument("--name", default="lab-target")
    p.add_argument("--fuzz-time", type=int, default=60, dest="fuzz_time",
                   help="seconds per campaign (default 60)")
    p.add_argument("--out", default="runs")
    p.add_argument("--job", default=None)
    p.add_argument("--provider", default=None,
                   help="model provider; omit for the deterministic pipeline")
    p.set_defaults(fn=cmd_lab)

    p = sub.add_parser("repo", help="point the engine at a git URL")
    p.add_argument("url")
    p.add_argument("--minutes", type=int, default=0)
    p.add_argument("--max-targets", type=int, default=3, dest="max_targets")
    p.add_argument("--fuzz-time", type=int, default=45, dest="fuzz_time")
    p.add_argument("--sanitizer", default="address")
    p.add_argument("--out", default="runs")
    p.add_argument("--job", default=None)
    p.add_argument("--provider", default=None)
    p.add_argument("--model", default=None)
    p.set_defaults(fn=cmd_repo)

    p = sub.add_parser("oracles", help="list the oracles and the rungs they certify")
    p.set_defaults(fn=cmd_oracles)

    p = sub.add_parser("doctor", help="report which lenses are available")
    p.set_defaults(fn=cmd_doctor)

    a = ap.parse_args(argv)
    _quiet_third_party()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

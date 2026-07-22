"""forge.windows_hunt — run a Windows desktop-binary zero-day hunt end to end.

On the native Windows fuzz agent (a disposable Windows VM with the target app
installed), point this at a closed file-parser and a few seed files:

    python -m forge.windows_hunt \
        --exe "C:\\Program Files\\FastStone Image Viewer\\FSViewer.exe" \
        --seeds seeds\\a.tga seeds\\b.pcx --suffix .tga \
        --argv-template "{file}" --tries 500

It mutates the seeds, opens each with the app (argv/file mode), catches the
Windows exception, native-verifies the crash un-instrumented, and grades the
faulting-instruction primitive — printing the proof ladder + findings. With Frida
present it goes coverage-guided automatically (``--coverage auto``).

Safety: run only against the operator's OWN installed copy, in a disposable VM
snapshot. Never point it at software you are not authorized to test.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path


def _load_seeds(paths: list[str]) -> list[bytes]:
    seeds: list[bytes] = []
    for p in paths or []:
        fp = Path(p)
        if fp.is_file():
            seeds.append(fp.read_bytes())
        else:
            print(f"[warn] seed not found: {p}", file=sys.stderr)
    return seeds or [b"\x00" * 64]        # a trivial seed so the loop still runs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="forge.windows_hunt",
                                 description="Windows desktop-binary zero-day hunt")
    ap.add_argument("--exe", required=True, help="path to the target .exe")
    ap.add_argument("--seeds", nargs="*", default=[], help="seed input files")
    ap.add_argument("--argv-template", default="{file}",
                    help="how to pass the file, space-separated; {file} is the input")
    ap.add_argument("--suffix", default="", help="temp-file extension, e.g. .tga")
    ap.add_argument("--name", default=None, help="target label (default: exe stem)")
    ap.add_argument("--tries", type=int, default=300)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--coverage", choices=["auto", "frida", "off"], default="auto")
    ap.add_argument("--runs-dir", default="runs")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = ap.parse_args(argv)

    from .job import windows_hunt_job, run_job

    name = args.name or Path(args.exe).stem
    job_id = f"win-{name}-{abs(hash(args.exe)) % 10**8}"
    ctx, discovery, oracles, escalation = windows_hunt_job(
        job_id, args.exe, name=name, seeds=_load_seeds(args.seeds),
        argv_template=args.argv_template.split(), input_suffix=args.suffix,
        coverage=args.coverage, artifacts_root=Path(args.runs_dir),
        max_tries=args.tries, timeout=args.timeout)

    findings = asyncio.run(run_job(ctx, discovery=discovery, oracles=oracles,
                                   escalation=escalation))

    board = ctx.ladder.board()
    if args.json:
        print(json.dumps({"job_id": job_id, "board": board,
                          "findings": len(findings)}, indent=2))
    else:
        print(f"\n=== {name} — proof ladder ===")
        for row in board:
            print(f"  rung {row['rung']} · {row['rung_name']} · {row['candidate']}")
        print(f"\n{len(findings)} finding(s). Artifacts: {ctx.artifacts}")
        if not findings:
            print("  (clean run — the engine reports nothing it cannot prove)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

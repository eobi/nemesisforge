#!/usr/bin/env bash
# Entry point: run an all-lenses Forge campaign on one repo, in Linux where every
# lens actually works (build-system, MSan, angr/ELF, vendored builds).
#
# Usage (inside the container / via docker run):
#   hunt.sh <git-url> [campaign_minutes=20] [max_targets=4] [sanitizer=address]
set -euo pipefail

URL="${1:?usage: hunt.sh <git-url> [campaign_minutes] [max_targets] [sanitizer]}"
MINS="${2:-20}"
TARGETS="${3:-4}"
SAN="${4:-address}"

exec python3 - "$URL" "$MINS" "$TARGETS" "$SAN" <<'PY'
import asyncio, os, sys, uuid, time, json
from pathlib import Path
from forge.config import load_env
load_env()                                   # reads /forge/.env (mounted)
from forge.job import repo_job, run_job

url, mins, targets, san = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]

async def main():
    jid = "hunt-" + uuid.uuid4().hex[:8]
    root = Path("/forge/runs")
    print(f"[{time.strftime('%H:%M:%S')}] LINUX all-lenses campaign: {url} "
          f"(job={jid}, {mins}min, {targets} targets, san={san})", flush=True)
    ctx, discovery, oracles, escalation, llm = repo_job(
        jid, url, artifacts_root=root, max_targets=targets, fuzz_time=120,
        campaign_minutes=mins, sanitizer=os.environ.get("FORGE_SAN", san),
        use_build_system=True, use_symbolic=(os.environ.get("FORGE_SYMBOLIC")=="1"),
        provider=os.environ.get("FORGE_PROVIDER","openai"), model=os.environ.get("FORGE_MODEL","gpt-5.1"))
    bs = ctx.build_system
    print(f"[{time.strftime('%H:%M:%S')}] build_system={bs} "
          f"link={'objects:'+str(len(ctx.target.extra_link_objects)) if ctx.target.extra_link_objects else 'file-by-file'} "
          f"libs={len(ctx.repo.library or [])} seeds={len(ctx.seed_files or [])}", flush=True)
    findings = await run_job(ctx, discovery=discovery, oracles=oracles,
                             escalation=escalation)
    print(f"\n[{time.strftime('%H:%M:%S')}] DONE: {len(findings)} finding(s)", flush=True)
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(vars(f))
        print(json.dumps({k: d.get(k) for k in
              ("title", "rung", "bug_type", "novelty", "function")}, default=str),
              flush=True)
    print("artifacts:", root / jid, flush=True)

asyncio.run(main())
PY

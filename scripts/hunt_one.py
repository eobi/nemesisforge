"""Launch a single deep campaign against one scouted repo, end-to-end.

Usage: python scripts/hunt_one.py <git-url> <campaign_minutes> <max_targets> [fuzz_time]
Loads .env (Anthropic), runs repo_job -> run_job, prints findings + rungs.
"""
import asyncio, os, sys, uuid, json, time
from pathlib import Path

from forge.config import load_env
load_env()

from forge.job import repo_job, run_job


async def main():
    url = sys.argv[1]
    campaign_minutes = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    max_targets = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    fuzz_time = int(sys.argv[4]) if len(sys.argv) > 4 else 45
    job_id = "hunt-" + uuid.uuid4().hex[:8]
    root = Path.cwd() / "runs"

    print(f"[{time.strftime('%H:%M:%S')}] job={job_id} url={url} "
          f"campaign_minutes={campaign_minutes} max_targets={max_targets} "
          f"fuzz_time={fuzz_time}", flush=True)

    ctx, discovery, oracles, escalation, llm = repo_job(
        job_id, url, artifacts_root=root, max_targets=max_targets,
        fuzz_time=fuzz_time, campaign_minutes=campaign_minutes,
        sanitizer=os.environ.get("FORGE_SAN", "address"),
        provider=os.environ.get("FORGE_PROVIDER", "openai"),
        model=os.environ.get("FORGE_MODEL", "gpt-5.1"),
    )
    print(f"[{time.strftime('%H:%M:%S')}] repo cloned: {ctx.repo.root} "
          f"lib_sources={len(ctx.repo.library or [])} "
          f"seed_files={len(ctx.seed_files or [])}", flush=True)

    findings = await run_job(ctx, discovery=discovery, oracles=oracles,
                             escalation=escalation)

    print(f"\n[{time.strftime('%H:%M:%S')}] === DONE: {len(findings)} finding(s) ===",
          flush=True)
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(vars(f))
        print(json.dumps({k: d.get(k) for k in
              ("title", "rung", "bug_type", "function", "novelty",
               "cve", "severity")}, default=str), flush=True)
    # persisted timeline location
    print(f"\nartifacts: {root / job_id}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())

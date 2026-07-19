"""Run one all-lenses Forge campaign on a repo. Usage:
   python scripts/campaign.py <git-url> <campaign_minutes> <max_targets> [sanitizer]
"""
import asyncio, sys, uuid, time, json
from pathlib import Path
from forge.config import load_env
load_env()
from forge.job import repo_job, run_job


async def main():
    url = sys.argv[1]
    mins = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    targets = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    san = sys.argv[4] if len(sys.argv) > 4 else "address"
    # symbolic lens off by default on macOS (angr's Mach-O backend is degraded and
    # just steals cores from the fuzzers); pass "sym" as arg 5 to force it on.
    symbolic = (len(sys.argv) > 5 and sys.argv[5] == "sym")
    jid = "hunt-" + uuid.uuid4().hex[:8]
    root = Path.cwd() / "runs"
    name = url.rstrip("/").split("/")[-1]
    print(f"[{time.strftime('%H:%M:%S')}] {name} all-lenses job={jid} "
          f"({mins}min {targets} targets san={san})", flush=True)
    ctx, discovery, oracles, escalation, llm = repo_job(
        jid, url, artifacts_root=root, max_targets=targets, fuzz_time=120,
        campaign_minutes=mins, sanitizer=san, use_build_system=True,
        use_symbolic=symbolic, provider="anthropic", model="claude-opus-4-8")
    print(f"[{time.strftime('%H:%M:%S')}] {name} link="
          f"{'obj:'+str(len(ctx.target.extra_link_objects)) if ctx.target.extra_link_objects else 'file-by-file'} "
          f"libs={len(ctx.repo.library or [])} seeds={len(ctx.seed_files or [])}", flush=True)
    findings = await run_job(ctx, discovery=discovery, oracles=oracles,
                             escalation=escalation)
    print(f"\n[{time.strftime('%H:%M:%S')}] {name} DONE: {len(findings)} finding(s)",
          flush=True)
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(vars(f))
        print(name, json.dumps({k: d.get(k) for k in
              ("title", "rung", "bug_type", "novelty", "function")}, default=str),
              flush=True)
    print(f"{name} artifacts:", root / jid, flush=True)


if __name__ == "__main__":
    asyncio.run(main())

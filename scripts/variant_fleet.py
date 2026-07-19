"""Variant-hunt FLEET: run a CVE-patch seed across many under-fuzzed targets in
parallel (Big Sleep's method at scale) — many aimed shots at a real twin.

Usage:
  python scripts/variant_fleet.py <minutes> <git-url> [<git-url> ...]
  python scripts/variant_fleet.py <minutes> --scout <N>         # scout N soft targets
  python scripts/variant_fleet.py <minutes> --seed <name> ...   # pick a corpus seed

Default seed is the CWPack unchecked-length pattern (our verified finding). Every
crash still runs the oracle + multi-vote misuse-triage + OSV novelty gate.
"""
import asyncio
import sys
import uuid
from functools import partial
from pathlib import Path

from forge.config import load_env
load_env()

from forge import cve_patches
from forge.fleet import run_fleet
from forge.job import repo_job


def _pick_seed(name: str):
    for s in cve_patches.SEEDS:
        if s.name == name:
            return s
    return cve_patches.CWPACK


def _factory(url: str, seed, minutes: int):
    """A JobFactory for run_fleet: repo_job(seed_patch=...) → first 4 return values."""
    def make():
        jid = "variant-" + uuid.uuid4().hex[:8]
        ctx, discovery, oracles, escalation, _llm = repo_job(
            jid, url, artifacts_root=Path.cwd() / "runs", max_targets=4,
            fuzz_time=120, campaign_minutes=minutes, sanitizer="address,undefined",
            seed_patch=seed.pattern, use_build_system=True, use_symbolic=False,
            provider="anthropic", model="claude-opus-4-8")
        return ctx, discovery, oracles, escalation
    return make


async def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    minutes = int(args[0])
    rest = args[1:]
    seed = cve_patches.CWPACK
    urls: list[str] = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--seed" and i + 1 < len(rest):
            seed = _pick_seed(rest[i + 1])
            i += 2
        elif a == "--scout" and i + 1 < len(rest):
            from forge.scout import scout
            n = int(rest[i + 1])
            r = scout(limit=max(n * 3, 15))
            urls = [t["url"] for t in r["targets"]
                    if t["language"] == "C" and not t.get("oss_fuzzed")][:n]
            i += 2
        else:
            urls.append(a)
            i += 1

    if not urls:
        print("no targets")
        return
    print(f"VARIANT FLEET — seed '{seed.name}' ({seed.origin}) × {len(urls)} target(s), "
          f"{minutes}min each, concurrency 2:")
    for u in urls:
        print("  •", u)

    factories = [_factory(u, seed, minutes) for u in urls]
    results = await run_fleet(factories, concurrency=2)

    print("\n=== FLEET RESULTS ===")
    for url, findings in zip(urls, results):
        real = [f for f in findings if getattr(f, "novelty", "") == "candidate"]
        name = url.rstrip("/").split("/")[-1]
        if real:
            print(f"  {name}: {len(real)} CANDIDATE finding(s) (triage-passed):")
            for f in real:
                print(f"     {f.candidate.title} @ rung {int(f.rung)}")
        else:
            print(f"  {name}: clean ({len(findings)} finding(s), none surviving triage)")


if __name__ == "__main__":
    asyncio.run(main())

"""Fleet — run many targets concurrently, each its own engagement.

The Coordinator already parallelizes sub-agents within one job; the fleet
parallelizes across *targets* (a catalog of repos / binaries / devices), each
with an isolated JobContext + event bus, under a concurrency cap. This is the
"scale" layer: point it at N targets and it fans out, bounded, and returns each
job's findings.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from .ladder import Finding
from .job import run_job

# a factory returns (ctx, discovery, oracles, escalation) for one job
JobFactory = Callable[[], tuple]


async def run_fleet(factories: list[JobFactory], *, concurrency: int = 4
                    ) -> list[list[Finding]]:
    """Run each job (bounded concurrency); return each job's findings in order.
    A job that raises yields [] so one bad target can't sink the fleet."""
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(factory: JobFactory) -> list[Finding]:
        async with sem:
            try:
                ctx, discovery, oracles, escalation = factory()
            except Exception:
                return []
            try:
                return await run_job(ctx, discovery=discovery, oracles=oracles,
                                     escalation=escalation)
            except Exception:
                return []

    return await asyncio.gather(*[_one(f) for f in factories])

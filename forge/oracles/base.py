"""The oracle contract + router.

An oracle is the deterministic, non-LLM verifier that decides a candidate's
rung. Oracles are the load-bearing part of the whole system: the LLM only ever
produces a Candidate; an oracle turns it into a Verdict. Oracles are synchronous
(they may shell out to a sanitizer build, semgrep, angr, a device) — the
Coordinator runs them off the event loop via a worker thread.

The router picks the first oracle whose `handles` set covers a candidate's
`bug_class`. For the escalation tier, an oracle also reads the rung the candidate
is *currently* at (from the ladder) and tries to prove the *next* one.
"""
from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from ..context import JobContext
from ..ladder import Candidate, Verdict


@runtime_checkable
class Oracle(Protocol):
    name: str
    handles: set[str]              # bug_classes this oracle can verify

    def verify(self, ctx: JobContext, candidate: Candidate) -> Verdict:
        ...


class OracleRouter:
    def __init__(self, oracles: list[Oracle]) -> None:
        self.oracles = list(oracles)

    def oracle_for(self, bug_class: str) -> Optional[Oracle]:
        for o in self.oracles:
            if bug_class in o.handles:
                return o
        return None

    def verify(self, ctx: JobContext, candidate: Candidate) -> Optional[Verdict]:
        oracle = self.oracle_for(candidate.bug_class)
        if oracle is None:
            return None
        return oracle.verify(ctx, candidate)

"""The proof ladder — Nemesis Forge's spine.

The whole system is organized around one idea: an LLM *proposes* a candidate; a
deterministic oracle *proves* it; and proof is not a boolean but a **rung** on a
ladder that runs from "raw hypothesis" all the way to "vendor-grade exploit
primitive". A candidate only climbs when a non-LLM oracle certifies the next
rung — never on a model's say-so.

Nemesis Zero's ladder stopped at PROVEN_SECURITY (rung 3: "a meaningful primitive
exists"). Forge adds the weaponization rungs 4–6 that turn a proven fault into
the reproducible, symbolized, impact-demonstrating proof a vendor actually acts
on:

    0 UNVERIFIED        raw LLM hypothesis — never trusted
    1 PROVEN_FAULT      a real fault observed (sanitizer crash / dataflow / OAST)
    2 PROVEN_REACHABLE  reachable from an untrusted entry in a shipping artifact
    3 PROVEN_SECURITY   attacker-influenced + a meaningful primitive exists
    4 PROVEN_PRIMITIVE  controlled crash — attacker picks the faulting addr/value
    5 PROVEN_EXPLOIT    a working PoC demonstrates the primitive (diff-oracle pass)
    6 VENDOR_READY      the 6-artifact disclosure packet is assembled

Pure domain module — dataclasses + enums, no I/O, no LLM. Everything else in the
engine speaks these types.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional


class Rung(enum.IntEnum):
    UNVERIFIED = 0
    PROVEN_FAULT = 1
    PROVEN_REACHABLE = 2
    PROVEN_SECURITY = 3
    PROVEN_PRIMITIVE = 4
    PROVEN_EXPLOIT = 5
    VENDOR_READY = 6


# A finding worth a human's attention (internal report).
REPORTABLE = Rung.PROVEN_SECURITY
# The minimum proof strength worth packaging for a vendor: a *controlled* crash.
# (Vendors accept a proven primitive + root cause; full weaponization is not
# required, so a rung-4 finding is legitimately shippable once packaged to 6.)
VENDOR_MIN = Rung.PROVEN_PRIMITIVE


class Outcome(str, enum.Enum):
    PROVEN = "proven"            # oracle advanced the candidate ≥1 rung
    REFUTED = "refuted"          # oracle actively disproved it — drop it
    INCONCLUSIVE = "inconclusive"  # couldn't decide; an agent may refine + retry


class PrimitiveKind(str, enum.Enum):
    """What an escalated fault actually gives an attacker (rung ≥ 4)."""
    OOB_READ = "oob-read"
    OOB_WRITE = "oob-write"
    WRITE_WHAT_WHERE = "write-what-where"
    USE_AFTER_FREE = "use-after-free"
    PC_CONTROL = "pc-control"
    INFO_LEAK = "info-leak"
    TYPE_CONFUSION = "type-confusion"
    UNKNOWN = "unknown"


@dataclass
class CodeLoc:
    path: str = ""
    line: int = 0
    symbol: str = ""


@dataclass
class Primitive:
    """The exploitation primitive an escalation oracle proved (rung ≥ 4)."""
    kind: PrimitiveKind = PrimitiveKind.UNKNOWN
    controlled: bool = False          # attacker controls the address/value
    where: str = ""                   # what the attacker can influence (addr/offset)
    what: str = ""                    # the data/value they can place
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Candidate:
    """An LLM hypothesis. Untrusted until an oracle certifies it. `proposed_check`
    is the oracle-specific payload (semgrep rule / fuzz harness / crafted input /
    exploit script) the oracle executes to decide."""
    bug_class: str
    title: str
    rationale: str = ""
    location: Optional[CodeLoc] = None
    sink: str = ""
    proposed_check: dict[str, Any] = field(default_factory=dict)
    agent: str = ""                   # which agent authored it
    confidence: float = 0.0           # advisory only — never gates a rung
    # Carried forward as a candidate is escalated up the ladder:
    reproducer: Optional[str] = None  # path/base64 to a minimized trigger
    crash: dict[str, Any] = field(default_factory=dict)  # parsed sanitizer/crash info


@dataclass
class Verdict:
    """An oracle's decision about a candidate."""
    outcome: Outcome
    rung: Rung
    oracle: str
    evidence: dict[str, Any] = field(default_factory=dict)
    feedback: str = ""                # for INCONCLUSIVE: what an agent should fix
    reproducer: Optional[str] = None  # minimized PoC the oracle captured/verified
    primitive: Optional[Primitive] = None

    @property
    def advanced(self) -> bool:
        return self.outcome is Outcome.PROVEN


@dataclass
class Finding:
    """A candidate + the highest verdict it reached. The product's only output;
    only VENDOR_READY findings ship to a vendor."""
    candidate: Candidate
    verdict: Verdict
    rung: Rung
    novelty: str = "candidate"        # zero-day | n-day | already-known | candidate
    severity: str = ""
    primitive: Optional[Primitive] = None
    artifacts: dict[str, Any] = field(default_factory=dict)  # vendor-packet pieces

    @property
    def reportable(self) -> bool:
        return self.rung >= REPORTABLE

    @property
    def vendor_shippable(self) -> bool:
        return self.rung >= Rung.VENDOR_READY


def advances(current: Rung, verdict: Verdict) -> bool:
    """Does this verdict move a candidate strictly UP the ladder? A candidate
    only climbs on a PROVEN verdict whose rung exceeds where it already is."""
    return verdict.outcome is Outcome.PROVEN and verdict.rung > current


class LadderState:
    """Tracks every candidate as a node carrying its current rung + verdict
    history. The Coordinator reads this to decide value-of-information: which
    candidate is cheapest/most-valuable to escalate next."""

    def __init__(self) -> None:
        self._rung: dict[str, Rung] = {}
        self.history: dict[str, list[Verdict]] = {}

    def _key(self, cand: Candidate) -> str:
        loc = cand.location
        where = f"{loc.path}:{loc.line}" if loc else cand.sink or cand.title
        return f"{cand.bug_class}|{where}"

    def rung_of(self, cand: Candidate) -> Rung:
        return self._rung.get(self._key(cand), Rung.UNVERIFIED)

    def apply(self, cand: Candidate, verdict: Verdict) -> bool:
        """Record a verdict. Returns True iff the candidate climbed a rung."""
        key = self._key(cand)
        self.history.setdefault(key, []).append(verdict)
        current = self._rung.get(key, Rung.UNVERIFIED)
        if advances(current, verdict):
            self._rung[key] = verdict.rung
            return True
        return False

    def board(self) -> list[dict[str, Any]]:
        """Snapshot for the proof-ladder UI: every candidate + its current rung."""
        return [
            {"candidate": key, "rung": int(rung), "rung_name": rung.name}
            for key, rung in sorted(self._rung.items(), key=lambda kv: -int(kv[1]))
        ]

"""Per-job shared state handed to every agent in the fleet.

One JobContext per engagement. It carries the identity allocator (so every
sub-agent gets a unique id for the tree), the event bus (visibility), the ladder
state (proof progress), the target under test, the per-job artifact store
(crashes / PoCs / builds shared across agents — the MAPTA "stateful per-job
container" idea), and the budget. Agents never reach for globals; everything they
need is here.
"""
from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .events import Emitter, EventBus, bus_for
from .ladder import LadderState


@dataclass
class Budget:
    """A coarse guard so a runaway fleet can't spin forever. Deterministic
    oracles are cheap; the caps mainly bound LLM agents."""
    deadline_s: float = 1800.0
    max_agents: int = 200
    _started: float = field(default_factory=time.monotonic)
    _agents: int = 0

    def start(self) -> "Budget":
        self._started = time.monotonic()
        return self

    def expired(self) -> bool:
        return (time.monotonic() - self._started) > self.deadline_s

    def charge_agent(self) -> bool:
        """Returns False if spawning another agent would exceed the cap."""
        if self._agents >= self.max_agents:
            return False
        self._agents += 1
        return True


class JobContext:
    def __init__(self, job_id: str, *, target: Any = None,
                 artifacts_root: Optional[Path] = None,
                 budget: Optional[Budget] = None) -> None:
        self.job_id = job_id
        self.bus: EventBus = bus_for(job_id)
        self.ladder = LadderState()
        self.target = target
        self.budget = (budget or Budget()).start()
        root = artifacts_root or (Path.cwd() / "runs")
        self.artifacts: Path = root / job_id
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def new_agent_id(self, name: str) -> str:
        with self._lock:
            n = next(self._ids)
        return f"{name}-{n}"

    def emitter(self, agent_id: str = "", parent_id: str = "") -> Emitter:
        return Emitter(self.bus, agent_id=agent_id, parent_id=parent_id)

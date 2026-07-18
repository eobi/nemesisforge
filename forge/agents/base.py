"""The Agent base — every member of the fleet is one of these.

An Agent owns an identity in the tree (agent_id + parent_id), an Emitter bound to
it, and a lifecycle that automatically brackets its work with AGENT_SPAWNED /
AGENT_DONE (or ERROR) events, so the visibility plane always shows who is running
without the agent remembering to announce itself. Sub-agents are created with
`self.child(...)`, which stamps the parent id — that parentage is what draws the
live agent tree.

Concrete agents (discovery / escalation / validator / reporter) subclass this and
implement `run()`. `run()` returns whatever that agent produces (a discovery
agent returns `list[Candidate]`; a validator returns a `Verdict`); the base only
cares about the lifecycle + activity stream.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable

from ..context import JobContext
from ..events import EventType


class Agent(ABC):
    kind: str = "agent"

    def __init__(self, ctx: JobContext, name: str | None = None,
                 parent_id: str = "") -> None:
        self.ctx = ctx
        self.name = name or self.kind
        self.agent_id = ctx.new_agent_id(self.name)
        self.parent_id = parent_id
        self.em = ctx.emitter(self.agent_id, parent_id)

    @abstractmethod
    async def run(self) -> Any:
        """The agent's actual work. Return its product."""

    async def execute(self) -> Any:
        """Lifecycle wrapper: budget-gate, bracket with spawned/done events."""
        if not self.ctx.budget.charge_agent():
            self.em.emit(EventType.ERROR, name=self.name,
                         error="agent budget exceeded")
            return None
        self.em.emit(EventType.AGENT_SPAWNED, kind=self.kind, name=self.name)
        try:
            result = await self.run()
        except Exception as e:  # an agent must never take the fleet down
            self.em.emit(EventType.ERROR, name=self.name,
                         error=f"{type(e).__name__}: {e}")
            self.em.emit(EventType.AGENT_DONE, name=self.name, failed=True)
            return None
        self.em.emit(EventType.AGENT_DONE, name=self.name)
        return result

    @property
    def aci(self):
        """The agent-computer interface (L3): read_file/grep/build/run/shell/
        symbolize, backed by this job's target + sandbox."""
        if not hasattr(self, "_aci"):
            from ..aci.tools import ACI
            self._aci = ACI(self.ctx)
        return self._aci

    # ── spawning (builds the tree) ──
    def child(self, factory: Callable[..., "Agent"], *args: Any, **kwargs: Any) -> "Agent":
        """Construct a sub-agent parented to this one. `factory` is an Agent
        subclass or a callable taking (ctx, ..., parent_id=...)."""
        return factory(self.ctx, *args, parent_id=self.agent_id, **kwargs)

    # ── activity helpers (thin wrappers over the emitter) ──
    def objective(self, text: str, **d: Any) -> None:
        self.em.emit(EventType.OBJECTIVE, text=text, **d)

    def think(self, step: int, text: str, **d: Any) -> None:
        self.em.emit(EventType.THINK, step=step, text=text, **d)

    def tool(self, name: str, **d: Any) -> None:
        self.em.emit(EventType.TOOL_CALL, tool=name, **d)

    def tool_result(self, name: str, **d: Any) -> None:
        self.em.emit(EventType.TOOL_RESULT, tool=name, **d)

    def log(self, text: str, **d: Any) -> None:
        self.em.emit(EventType.LOG, text=text, **d)

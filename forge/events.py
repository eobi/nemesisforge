"""The activity event bus — the visibility plane's backbone.

The user's hard requirement: *every* activity is visible. So every agent in the
fleet emits structured events that carry its place in the tree (agent_id +
parent_id), and the web layer streams them over SSE to a live agent-tree UI and a
proof-ladder board. No agent does hidden work — if it thought it, ran a tool, or
got an oracle verdict, there is an event for it.

Design: an append-only per-job log with pub/sub. `append` assigns a monotonic
`seq` and fans the event out to live subscribers; `since` replays history (so a
late-joining UI, or a reload, sees the whole run). In-memory for now; the shape
is deliberately serialisable so a durable (SQLite) store can back it later
without touching callers.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass, field
from typing import Any, AsyncIterator, Optional


class EventType:
    """The vocabulary of the activity feed. Kept as flat strings so new agent
    kinds can emit without a schema migration."""
    JOB_START = "job_start"
    JOB_DONE = "job_done"
    AGENT_SPAWNED = "agent_spawned"   # a sub-agent joined the tree
    AGENT_DONE = "agent_done"
    OBJECTIVE = "objective"           # an agent stated what it's trying to do
    THINK = "think"                   # a ReAct reasoning step
    TOOL_CALL = "tool_call"           # an ACI tool was invoked
    TOOL_RESULT = "tool_result"
    CANDIDATE = "candidate"           # a hypothesis was produced
    ORACLE_VERDICT = "oracle_verdict"  # a deterministic oracle decided
    RUNG_UP = "rung_up"               # a candidate climbed the ladder
    POC_WRITTEN = "poc_written"       # an escalation agent authored an exploit
    VALIDATED = "validated"           # an independent validator confirmed a PoC
    REFUTED = "refuted"
    VENDOR_PACKET = "vendor_packet"   # a VENDOR_READY disclosure packet assembled
    LADDER = "ladder"                 # a proof-ladder board snapshot
    LOG = "log"
    ERROR = "error"


@dataclass
class Event:
    type: str
    job_id: str
    agent_id: str = ""                # "" = the job/coordinator root
    parent_id: str = ""               # the spawning agent (builds the tree)
    data: dict[str, Any] = field(default_factory=dict)
    seq: int = -1                     # assigned by the bus
    ts: float = 0.0                   # assigned by the bus

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventBus:
    """Append-only log + async pub/sub for a single job."""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        self._events: list[Event] = []
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._done = False

    def append(self, type: str, *, agent_id: str = "", parent_id: str = "",
               **data: Any) -> Event:
        ev = Event(type=type, job_id=self.job_id, agent_id=agent_id,
                   parent_id=parent_id, data=dict(data),
                   seq=len(self._events), ts=time.time())
        self._events.append(ev)
        for q in list(self._subscribers):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:  # slow consumer — drop it, it can replay via since()
                self._subscribers.discard(q)
        if type in (EventType.JOB_DONE, EventType.ERROR):
            self._done = True
        return ev

    def since(self, after_seq: int) -> list[Event]:
        return [e for e in self._events if e.seq > after_seq]

    def all(self) -> list[Event]:
        return list(self._events)

    @property
    def done(self) -> bool:
        return self._done

    async def stream(self, *, replay: bool = True) -> AsyncIterator[Event]:
        """Yield every event: history first (if replay), then live ones as they
        arrive, until the job finishes. Used by the SSE endpoint."""
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=1000)
        # Snapshot history BEFORE subscribing so we neither miss nor double-emit.
        history = self.all() if replay else []
        self._subscribers.add(q)
        try:
            last_seq = -1
            for ev in history:
                last_seq = ev.seq
                yield ev
            if self._done and q.empty():
                return
            while True:
                ev = await q.get()
                if ev.seq <= last_seq:
                    continue  # already replayed from history
                last_seq = ev.seq
                yield ev
                if ev.type in (EventType.JOB_DONE, EventType.ERROR) and q.empty():
                    return
        finally:
            self._subscribers.discard(q)


class Emitter:
    """A thin handle bound to one agent's identity, so an agent just calls
    `emit(EventType.THINK, step=n, text=...)` without repeating its ids."""

    def __init__(self, bus: EventBus, agent_id: str = "", parent_id: str = "") -> None:
        self.bus = bus
        self.agent_id = agent_id
        self.parent_id = parent_id

    def emit(self, type: str, **data: Any) -> Event:
        return self.bus.append(type, agent_id=self.agent_id,
                               parent_id=self.parent_id, **data)

    def child(self, agent_id: str) -> "Emitter":
        """Derive an emitter for a spawned sub-agent (parent = this agent)."""
        return Emitter(self.bus, agent_id=agent_id, parent_id=self.agent_id)


# ── per-job bus registry (the web layer looks a bus up by job id) ──
_BUSES: dict[str, EventBus] = {}


def bus_for(job_id: str) -> EventBus:
    bus = _BUSES.get(job_id)
    if bus is None:
        bus = EventBus(job_id)
        _BUSES[job_id] = bus
    return bus


def drop_bus(job_id: str) -> None:
    _BUSES.pop(job_id, None)

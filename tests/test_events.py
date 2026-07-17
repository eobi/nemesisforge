"""The activity event bus — the visibility plane's backbone."""
import asyncio

from forge.events import EventBus, EventType, Emitter, bus_for, drop_bus


def test_append_assigns_monotonic_seq_and_ids():
    bus = EventBus("job1")
    a = bus.append(EventType.OBJECTIVE, agent_id="coord", text="map surface")
    b = bus.append(EventType.THINK, agent_id="coord", step=1)
    assert a.seq == 0 and b.seq == 1
    assert a.ts > 0
    assert a.data["text"] == "map surface"
    assert bus.since(0) == [b]           # strictly-after
    assert len(bus.all()) == 2


def test_emitter_builds_the_agent_tree():
    bus = EventBus("job2")
    coord = Emitter(bus, agent_id="coord")
    coord.emit(EventType.OBJECTIVE, text="root")
    child = coord.child("solver-1")     # a spawned sub-agent
    ev = child.emit(EventType.THINK, step=0, text="grep for memcpy")
    assert ev.agent_id == "solver-1"
    assert ev.parent_id == "coord"      # parentage → the tree edges


def test_done_flag_on_job_done():
    bus = EventBus("job3")
    assert bus.done is False
    bus.append(EventType.JOB_DONE, findings=0)
    assert bus.done is True


def test_registry_returns_same_bus():
    b1 = bus_for("jobX")
    b2 = bus_for("jobX")
    assert b1 is b2
    drop_bus("jobX")
    assert bus_for("jobX") is not b1


def test_stream_replays_history_then_live():
    async def run():
        bus = EventBus("job4")
        bus.append(EventType.JOB_START)
        bus.append(EventType.OBJECTIVE, text="hi")
        seen = []

        async def consume():
            async for ev in bus.stream():
                seen.append(ev.type)
                if ev.type == EventType.JOB_DONE:
                    break

        task = asyncio.create_task(consume())
        await asyncio.sleep(0.02)        # let it drain history + subscribe
        bus.append(EventType.RUNG_UP, rung=1)   # a live event
        bus.append(EventType.JOB_DONE)
        await asyncio.wait_for(task, timeout=2)
        return seen

    seen = asyncio.run(run())
    # history (job_start, objective) then live (rung_up, job_done), no dupes
    assert seen == [EventType.JOB_START, EventType.OBJECTIVE,
                    EventType.RUNG_UP, EventType.JOB_DONE]

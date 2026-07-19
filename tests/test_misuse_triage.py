"""API-misuse triage: a proven crash that is the harness's fault gets de-rated so it
never reads as a zero-day candidate; a real bug is left untouched. Uses a mock LLM
(deterministic) — the live-model discrimination is validated separately."""
import asyncio
from types import SimpleNamespace

from forge import misuse_triage
from forge.events import EventType


class _MockLLM:
    available = True

    def __init__(self, verdict):
        self._v = verdict

    def complete_json(self, system, prompt):
        return ({"verdict": self._v, "category": "test", "reason": "mock"}, {})


class _SeqLLM:
    """Returns a scripted sequence of verdicts across the panel's lens calls."""
    available = True

    def __init__(self, verdicts):
        self._q = list(verdicts)

    def complete_json(self, system, prompt):
        v = self._q.pop(0) if self._q else "real"
        return ({"verdict": v, "category": "test", "reason": "mock"}, {})


def _finding(alloc_file):
    return SimpleNamespace(
        novelty="candidate",
        artifacts={},
        candidate=SimpleNamespace(
            proposed_check={"harness": "int LLVMFuzzerTestOneInput(){return 0;}"},
            bug_class="memory_safety", title="heap-buffer-overflow"),
        verdict=SimpleNamespace(evidence={"crash": {
            "bug_type": "heap-buffer-overflow",
            "frames": [{"func": "f", "file": "lib.c", "line": 10}],
            "alloc_frames": [{"func": "g", "file": alloc_file, "line": 3}]}}))


def _ctx():
    events = []
    bus = SimpleNamespace(append=lambda t, **k: events.append((t, k)))
    return SimpleNamespace(repo=None, bus=bus, _events=events), events


def test_artifact_is_derated():
    ctx, events = _ctx()
    f = _finding("forge_harness.c")
    asyncio.run(misuse_triage.review(ctx, [f], _MockLLM("artifact")))
    assert f.novelty == "artifact"                    # no longer a candidate
    assert f.artifacts["misuse_review"]["verdict"] == "artifact"
    assert any("ARTIFACT" in k.get("text", "") for _, k in events)


def test_real_is_kept():
    ctx, _ = _ctx()
    f = _finding("lib.c")
    asyncio.run(misuse_triage.review(ctx, [f], _MockLLM("real")))
    assert f.novelty == "candidate"                   # untouched
    assert f.artifacts["misuse_review"]["verdict"] == "real"


def test_single_dissent_cannot_flip_real():
    # panel votes real/real/artifact → majority real → NOT de-rated
    ctx, _ = _ctx()
    f = _finding("lib.c")
    asyncio.run(misuse_triage.review(ctx, [f], _SeqLLM(["real", "real", "artifact"])))
    assert f.novelty == "candidate"                   # one skeptic can't sink it
    assert f.artifacts["misuse_review"]["verdict"] == "real"


def test_benign_ub_marked_low_severity():
    # a misaligned-load UBSan finding is real library behavior but low-severity/by-design
    ctx, _ = _ctx()
    f = SimpleNamespace(
        novelty="candidate", artifacts={},
        candidate=SimpleNamespace(
            proposed_check={"harness": "x"}, bug_class="memory_safety",
            title="load of misaligned address 0x61 for type 'uint16_t'"),
        verdict=SimpleNamespace(evidence={"crash": {
            "bug_type": "undefined-behavior",
            "frames": [{"func": "cw_unpack_next", "file": "cwpack.c", "line": 516}]}}))
    # even a mock LLM that would say 'real' shouldn't be consulted — filtered first
    asyncio.run(misuse_triage.review(ctx, [f], _MockLLM("real")))
    assert f.novelty == "low-severity"
    assert f.artifacts["severity"]["level"] == "low"
    assert "misuse_review" not in f.artifacts        # panel was skipped


def test_majority_artifact_derates():
    # panel votes artifact/artifact/real → majority artifact → de-rated
    ctx, _ = _ctx()
    f = _finding("forge_harness.c")
    asyncio.run(misuse_triage.review(ctx, [f], _SeqLLM(["artifact", "artifact", "real"])))
    assert f.novelty == "artifact"


def test_alloc_in_harness_signal():
    assert misuse_triage._alloc_in_harness(_finding("forge_harness.c")) is True
    assert misuse_triage._alloc_in_harness(_finding("cwpack.c")) is False


def test_noop_without_llm():
    ctx, _ = _ctx()
    f = _finding("forge_harness.c")
    asyncio.run(misuse_triage.review(ctx, [f], None))  # no model → no change
    assert f.novelty == "candidate"
    assert "misuse_review" not in f.artifacts

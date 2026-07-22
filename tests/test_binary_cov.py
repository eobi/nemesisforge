"""Closed-binary coverage backend — the coverage-novelty core + the discipline
that a crash found under instrumentation becomes an `instrumented_crash`
Candidate the NativeVerifyOracle must clear."""
from pathlib import Path

from forge.targets.binary_cov import (
    CoverageMap, CoverageRun, FridaStalkerCoverage, select_corpus,
    to_instrumented_candidate,
)
from forge.targets.base import Observation
from forge.triage import CrashInfo


# ── CoverageMap: the engine of coverage-guided fuzzing ──
def test_coverage_map_counts_new_edges():
    cov = CoverageMap()
    assert cov.observe([1, 2, 3]) == 3
    assert cov.observe([2, 3]) == 0          # nothing new
    assert cov.observe([3, 4]) == 1          # only 4 is new
    assert len(cov) == 4


def test_coverage_map_is_new():
    cov = CoverageMap()
    cov.observe([1, 2])
    assert cov.is_new([3]) is True
    assert cov.is_new([1, 2]) is False


# ── select_corpus: keep only inputs that add coverage ──
class _FakeBackend:
    """A backend whose coverage is scripted per-input, so the selection logic is
    testable without any real target."""
    name = "fake"

    def __init__(self, edges_by_input):
        self._edges = edges_by_input

    def available(self):
        return True

    def run_with_coverage(self, binary, *, stdin=b"", timeout=30.0):
        return CoverageRun(observation=Observation(), edges=set(self._edges.get(stdin, ())))


def test_select_corpus_drops_redundant_inputs():
    seeds = [b"a", b"b", b"c"]
    backend = _FakeBackend({b"a": {1, 2}, b"b": {1, 2}, b"c": {3}})
    kept = select_corpus(Path("x"), seeds, backend)
    assert b"a" in kept and b"c" in kept      # a opens {1,2}, c adds {3}
    assert b"b" not in kept                    # b is fully redundant with a


def test_select_corpus_never_returns_empty():
    kept = select_corpus(Path("x"), [b"only"], _FakeBackend({b"only": set()}))
    assert kept == [b"only"]


# ── the discipline: instrumented crash → native-verify Candidate ──
def test_instrumented_crash_becomes_native_verify_candidate():
    obs = Observation(crashed=True,
                      crash=CrashInfo(crashed=True, bug_type="segv", summary="boom"))
    run = CoverageRun(observation=obs, edges={1, 2}, instrumented=True)
    cand = to_instrumented_candidate(b"payload", run)
    assert cand.bug_class == "instrumented_crash"    # routes to native-verify
    assert cand.proposed_check["instrumented_bug"] == "segv"
    assert cand.proposed_check["native_replays"] == 5
    import base64
    assert base64.b64decode(cand.proposed_check["input_b64"]) == b"payload"


# ── graceful degradation when Frida is absent ──
def test_frida_backend_degrades_without_frida():
    class _T:
        def run(self, binary, *, stdin=b"", timeout=30.0):
            return Observation(crashed=False)
    backend = FridaStalkerCoverage(_T())
    run = backend.run_with_coverage(Path("x"), stdin=b"in")
    # no frida → concrete run, truthfully marked non-instrumented, empty edges
    assert run.instrumented is False and run.edges == set()

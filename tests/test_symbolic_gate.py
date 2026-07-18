"""Phase K — the angr symbolic oracle. The load-bearing invariant is honesty: it
NEVER returns a proof unless angr actually shows an unconstrained state. Here we
assert the safe degradation (no angr / no binary → INCONCLUSIVE, never PROVEN)."""
from types import SimpleNamespace

from forge.context import JobContext
from forge.ladder import Candidate, Outcome, Rung
from forge.oracles.symbolic import SymbolicOracle


def _ctx(tmp_path, target=None):
    return JobContext("job-sym", target=target, artifacts_root=tmp_path)


def test_no_angr_is_inconclusive_never_proven(tmp_path):
    o = SymbolicOracle()
    o.available = False                      # force the no-angr path
    ctx = _ctx(tmp_path, target=SimpleNamespace(binary="/bin/ls"))
    cand = Candidate(bug_class="binary_crash", title="segv",
                     proposed_check={"input_b64": ""})
    v = o.verify(ctx, cand)
    assert v.outcome is Outcome.INCONCLUSIVE
    assert v.rung == Rung.UNVERIFIED
    assert "angr not installed" in v.feedback


def test_available_but_no_binary_is_inconclusive(tmp_path):
    o = SymbolicOracle()
    o.available = True                       # pretend angr is present
    ctx = _ctx(tmp_path, target=SimpleNamespace(binary=None))
    cand = Candidate(bug_class="binary_crash", title="segv",
                     proposed_check={"input_b64": ""})
    v = o.verify(ctx, cand)
    assert v.outcome is Outcome.INCONCLUSIVE   # no fake proof without a real binary

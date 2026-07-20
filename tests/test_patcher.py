"""PoV-gated patch generation: the LLM writes a fix, but nothing ships unless the
DifferentialOracle re-proves it kills the PoV. Here we test the generator + the
oracle's pure decision (the gate is exercised end-to-end under a live/Docker run)."""
import asyncio

from forge import patcher
from forge.oracles.differential import decide
from forge.ladder import Outcome, Rung


class _LLM:
    available = True

    def __init__(self, out):
        self._out = out

    def complete_json(self, system, prompt):
        return (self._out, {})


def test_generate_patch_returns_full_file():
    src = "int f(char*b,int n){ return b[n]; }\n"
    fixed = "int f(char*b,int n){ if(n<0) return 0; return b[n]; }\n"
    out = asyncio.run(patcher.generate_patch(
        _LLM({"patched_source": fixed, "explanation": "bounds check"}),
        source_text=src, function="f", line=1, bug_type="heap-buffer-overflow"))
    assert out == fixed


def test_generate_patch_rejects_noop_and_empty():
    src = "int f(){return 0;}\n"
    # identical source → no patch
    assert asyncio.run(patcher.generate_patch(
        _LLM({"patched_source": src}), source_text=src, function="f", line=1,
        bug_type="x")) is None
    # empty → no patch
    assert asyncio.run(patcher.generate_patch(
        _LLM({"patched_source": "   "}), source_text=src, function="f", line=1,
        bug_type="x")) is None


def test_generate_patch_no_model_is_noop():
    assert asyncio.run(patcher.generate_patch(
        None, source_text="x", function="f", line=1, bug_type="x")) is None


def test_differential_gate_semantics():
    # the gate the patcher relies on: PoV must crash vuln AND be clean on patched
    assert decide(True, "heap-buffer-overflow", False)[:2] == (
        Outcome.PROVEN, Rung.PROVEN_EXPLOIT)          # fix proven → ship
    assert decide(True, "heap-buffer-overflow", True)[0] == Outcome.REFUTED  # bad fix
    assert decide(False, "x", False)[0] == Outcome.INCONCLUSIVE  # PoV didn't repro

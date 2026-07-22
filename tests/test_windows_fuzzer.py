"""Phase 2 M0/M1 — the WindowsFuzzer loop + windows_hunt_job assembler, driven by
a fake target/coverage backend so the mutation + candidate-emission logic is
testable without a Windows host."""
import asyncio
from pathlib import Path

from forge import triage
from forge.context import JobContext
from forge.targets.base import BuildResult, Observation
from forge.targets.binary_cov import CoverageRun
from forge.agents.windows_fuzzer import WindowsFuzzer


class _FakeTarget:
    """Crashes (access-violation) whenever the input contains a 0xFF byte — the
    mutator emits 0xFF within its budget, so the fuzzer reliably finds it."""
    name = "fake-app"
    target_type = "binary"

    def build(self, *a, **k):
        return BuildResult(ok=True, binary=Path("app.exe"))

    def run(self, binary, *, stdin=b"", timeout=20.0, symbolize=False):
        if b"\xff" in stdin:
            ci = triage.parse("", win_exit=0xC0000005)
            return Observation(crashed=True, crash=ci, rc=0xC0000005)
        return Observation(crashed=False, crash=triage.parse(""), rc=0)


class _FakeCoverage:
    """Coverage backend that grows coverage per-input and crashes on 0xFF."""
    def __init__(self, target):
        self.target = target

    def available(self):
        return True

    def run_with_coverage(self, binary, *, stdin=b"", timeout=20.0):
        obs = self.target.run(binary, stdin=stdin, timeout=timeout)
        edges = {hash(bytes(stdin[:4])) & 0xFFFF}      # some coverage per distinct prefix
        return CoverageRun(observation=obs, edges=edges, instrumented=True)


def _ctx(tmp_path):
    return JobContext(f"job-{tmp_path.name}", target=_FakeTarget(),
                      artifacts_root=tmp_path)


def test_argv_mode_fuzzer_finds_and_emits_binary_crash(tmp_path):
    ctx = _ctx(tmp_path)
    agent = WindowsFuzzer(ctx, seeds=[b"\x00" * 16], coverage=None, max_tries=200)
    cands = asyncio.run(agent.run())
    assert cands, "fuzzer should find the 0xFF crash within budget"
    c = cands[0]
    assert c.bug_class == "binary_crash"           # native run → binary-crash oracle
    assert c.crash["bug_type"] == "access-violation"
    assert c.proposed_check.get("input_b64")


def test_coverage_guided_fuzzer_emits_instrumented_crash(tmp_path):
    ctx = _ctx(tmp_path)
    backend = _FakeCoverage(ctx.target)
    agent = WindowsFuzzer(ctx, seeds=[b"\x00" * 16], coverage=backend, max_tries=200)
    cands = asyncio.run(agent.run())
    assert cands
    # a crash from an instrumented run must clear native-verify first
    assert cands[0].bug_class == "instrumented_crash"
    assert cands[0].proposed_check.get("native_replays") == 5


def test_clean_target_reports_nothing(tmp_path):
    class _Clean(_FakeTarget):
        def run(self, binary, *, stdin=b"", timeout=20.0, symbolize=False):
            return Observation(crashed=False, crash=triage.parse(""), rc=0)
    ctx = JobContext(f"job-{tmp_path.name}", target=_Clean(), artifacts_root=tmp_path)
    agent = WindowsFuzzer(ctx, seeds=[b"\x00" * 8], coverage=None, max_tries=50)
    assert asyncio.run(agent.run()) == []


def test_windows_hunt_job_assembles(tmp_path):
    from forge.job import windows_hunt_job
    exe = tmp_path / "FSViewer.exe"
    exe.write_bytes(b"MZ")
    ctx, discovery, oracles, escalation = windows_hunt_job(
        f"win-{tmp_path.name}", str(exe), name="fsviewer",
        seeds=[b"\x00" * 8], input_suffix=".tga", coverage="off",
        artifacts_root=tmp_path, max_tries=10)
    assert ctx.target.name == "fsviewer"
    assert ctx.target.input_suffix == ".tga"
    oracle_names = {o.name for o in oracles} | {o.name for o in escalation}
    assert {"binary-crash", "native-verify", "exploitability"} <= oracle_names

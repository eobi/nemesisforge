"""Phase 2 M0 — Windows argv-mode: NTSTATUS-exception crash parsing + the
WindowsBinaryTarget, driven by a fake Windows sandbox (cross-platform testable)."""
from pathlib import Path

from forge import triage
from forge.sandbox import ExecResult
from forge.targets.windows import WindowsBinaryTarget


# ── Windows NTSTATUS exception parsing (pure) ──
def test_access_violation_unsigned():
    ci = triage.parse("", win_exit=0xC0000005)
    assert ci.crashed and ci.bug_type == "access-violation"
    assert ci.access == "WRITE"                 # conservative until the oracle refines
    assert "0xC0000005" in ci.summary


def test_access_violation_signed_form_normalizes():
    # subprocess often surfaces the code signed (0xC0000005 → -1073741819).
    ci = triage.parse("", win_exit=-1073741819)
    assert ci.crashed and ci.bug_type == "access-violation"


def test_heap_corruption_is_security_relevant_class():
    ci = triage.parse("", win_exit=0xC0000374)
    assert ci.crashed and ci.bug_type == "heap-corruption"


def test_non_memory_exception_has_no_write_access():
    ci = triage.parse("", win_exit=0xC000001D)   # illegal instruction
    assert ci.crashed and ci.bug_type == "illegal-instruction"
    assert ci.access == ""


def test_unmapped_ntstatus_still_a_crash():
    ci = triage.parse("", win_exit=0xC0000008)   # invalid handle, unmapped
    assert ci.crashed and ci.bug_type == "windows-exception"


def test_clean_exit_is_not_a_crash():
    assert triage.parse("", win_exit=0).crashed is False
    assert triage.parse("", win_exit=1).crashed is False   # normal error exit


# ── WindowsBinaryTarget via a fake Windows sandbox ──
class _FakeWinSandbox:
    """Records the argv it was invoked with and returns a scripted exit code —
    stands in for a real Windows agent so the argv/file plumbing is testable
    anywhere."""
    isolated = False

    def __init__(self, rc=0, output=""):
        self.rc = rc
        self.output = output
        self.calls = []

    def run(self, argv, *, cwd=None, stdin=b"", timeout=30.0, env=None):
        self.calls.append(list(argv))
        return ExecResult(rc=self.rc, stdout=self.output, stderr="")


def _target(tmp_path, rc, **kw):
    exe = tmp_path / "App.exe"
    exe.write_bytes(b"MZ")                       # just needs to exist for build()
    sb = _FakeWinSandbox(rc=rc)
    t = WindowsBinaryTarget(exe, name="app", sandbox=sb, **kw)
    return t, sb, exe


def test_argv_mode_passes_input_as_a_file_argument(tmp_path):
    t, sb, exe = _target(tmp_path, rc=0, input_suffix=".tga")
    build = t.build()
    assert build.ok
    t.run(build.binary, stdin=b"\x00\x00\x02fuzz")
    argv = sb.calls[0]
    assert argv[0] == str(exe)                   # exe first
    assert len(argv) == 2                         # exe + a file path (default template)
    assert argv[1].endswith(".tga")               # suffix honored (extension dispatch)


def test_custom_argv_template_substitutes_file(tmp_path):
    t, sb, exe = _target(tmp_path, rc=0, argv_template=["/print", "{file}"])
    t.run(t.build().binary, stdin=b"x")
    argv = sb.calls[0]
    assert argv[1] == "/print" and argv[2].endswith("")   # {file} replaced in slot 2


def test_crash_detected_from_ntstatus_exit_code(tmp_path):
    t, sb, exe = _target(tmp_path, rc=0xC0000005)
    obs = t.run(t.build().binary, stdin=b"A" * 64)
    assert obs.crashed is True
    assert obs.crash.bug_type == "access-violation"


def test_clean_run_is_not_a_crash(tmp_path):
    t, sb, exe = _target(tmp_path, rc=0)
    obs = t.run(t.build().binary, stdin=b"A" * 64)
    assert obs.crashed is False


# ── the oracle chain drives a Windows target unchanged ──
def test_native_verify_oracle_proves_a_windows_crash(tmp_path):
    from forge.context import JobContext
    from forge.ladder import Candidate, Outcome, Rung
    from forge.oracles.native_verify import NativeVerifyOracle

    t, sb, exe = _target(tmp_path, rc=0xC0000005)   # replays crash every run
    ctx = JobContext(f"job-{tmp_path.name}", target=t, artifacts_root=tmp_path)
    cand = Candidate(bug_class="instrumented_crash", title="win crash",
                     proposed_check={"input": "A" * 64, "native_replays": 3})
    v = NativeVerifyOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN
    assert v.rung >= Rung.PROVEN_FAULT              # a native-confirmed Windows crash

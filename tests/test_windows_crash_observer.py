"""P1 correctness: crash-observation decoupling (A1), real READ/WRITE + address
(A5), and register-context write-what-where (C1). The headline test is that an
SEH-swallowed crash now SURVIVES native-verify instead of being refuted as an
'instrumentation artifact'. All tested with fakes — no frida/Windows needed."""
import base64
import struct
from pathlib import Path

from forge import triage
from forge.context import JobContext
from forge.ladder import Candidate, Outcome, PrimitiveKind, Rung
from forge.targets.base import Observation
from forge.targets.windows import WindowsBinaryTarget
from forge.oracles.native_verify import NativeVerifyOracle
from forge.oracles.exploitability import ExploitabilityOracle


# ── A5: crashinfo_from_frida — real access type + address, dedup by faulting PC ──
def test_frida_crash_write_from_memory_operation():
    ci = triage.crashinfo_from_frida({"kind": "access-violation", "op": "write",
                                      "addr": "0x42424242", "pc": "0x578e63"})
    assert ci.crashed and ci.bug_type == "access-violation"
    assert ci.access == "WRITE"                 # from d.memory.operation, not fabricated
    assert ci.fault_addr == "0x42424242" and ci.fault_pc == "0x578e63"


def test_frida_crash_read_not_mislabeled_write():
    ci = triage.crashinfo_from_frida({"kind": "access-violation", "op": "read",
                                      "addr": "0x10", "pc": "0xabc"})
    assert ci.access == "READ"


def test_frida_crash_dedup_keys_on_pc():
    a = triage.crashinfo_from_frida({"kind": "access-violation", "op": "write", "pc": "0x111"})
    b = triage.crashinfo_from_frida({"kind": "access-violation", "op": "write", "pc": "0x222"})
    assert a.stack_hash != b.stack_hash         # distinct crash sites → distinct findings


# ── A1: the SEH-swallowed crash survives verification ──
class _SehObserver:
    """A crash the exit code hides (SEH-swallowed) but the exception observer
    catches on every run — reliable, so verification agrees with discovery."""
    def __init__(self, target):
        self.target = target

    def available(self):
        return True

    def observe(self, binary, *, stdin=b"", timeout=15.0):
        if b"\xff" in stdin:
            return Observation(crashed=True, rc=0, crash=triage.crashinfo_from_frida(
                {"kind": "access-violation", "op": "write",
                 "addr": "0x42424242", "pc": "0x578e63"}))
        return Observation(crashed=False, crash=triage.CrashInfo(), rc=0)


def _win_target(tmp_path):
    exe = tmp_path / "App.exe"
    exe.write_bytes(b"MZ")
    t = WindowsBinaryTarget(exe, name="app", input_suffix=".tga")
    t.crash_observer = _SehObserver(t)
    return t


def test_run_delegates_to_crash_observer(tmp_path):
    t = _win_target(tmp_path)
    o = t.run(t.build().binary, stdin=b"\xff\xff")
    assert o.crashed and o.crash.access == "WRITE" and o.crash.fault_addr == "0x42424242"
    # benign input → no crash (no exit-code false positive)
    assert t.run(t.build().binary, stdin=b"\x00\x00").crashed is False


def test_seh_crash_survives_native_verify(tmp_path):
    # THE headline fix: native-verify replays via the SAME observer → PROVEN,
    # not refuted as an 'instrumentation artifact' (the pre-fix behaviour).
    t = _win_target(tmp_path)
    ctx = JobContext(f"job-{tmp_path.name}", target=t, artifacts_root=tmp_path)
    cand = Candidate(bug_class="instrumented_crash", title="seh av",
                     proposed_check={"input_b64": base64.b64encode(b"\xff" * 64).decode(),
                                     "native_replays": 3})
    v = NativeVerifyOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN
    assert v.evidence["native_reproductions"] == 3


# ── C1 + A2: register-context write-what-where via marker substitution ──
class _ControlledWriteObserver:
    """Faulting WRITE address == the dword at input offset 0 → attacker controls it."""
    def __init__(self, target):
        self.target = target

    def available(self):
        return True

    def observe(self, binary, *, stdin=b"", timeout=15.0):
        addr = struct.unpack_from("<I", (bytes(stdin) + b"\0\0\0\0"))[0]
        return Observation(crashed=True, rc=0, crash=triage.crashinfo_from_frida(
            {"kind": "access-violation", "op": "write", "addr": hex(addr), "pc": "0x578e63"}))


def test_exploitability_proves_write_what_where_from_observer(tmp_path):
    exe = tmp_path / "App.exe"
    exe.write_bytes(b"MZ")
    t = WindowsBinaryTarget(exe, name="app")
    t.crash_observer = _ControlledWriteObserver(t)
    ctx = JobContext(f"job-{tmp_path.name}", target=t, artifacts_root=tmp_path)
    inp = b"\x00\x00\x00\x00padding"           # base dword = 0 (null-ish)
    cand = Candidate(bug_class="binary_crash", title="controlled write",
                     proposed_check={"input_b64": base64.b64encode(inp).decode(),
                                     "control_offsets": [0], "marker": 0x42424242,
                                     "marker_width": 4})
    v = ExploitabilityOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN and v.rung is Rung.PROVEN_PRIMITIVE
    assert v.primitive.kind is PrimitiveKind.WRITE_WHAT_WHERE
    assert v.primitive.controlled


def test_taint_derives_the_controlling_offset(tmp_path):
    # A2: the write address is the dword at input offset 4 → the taint pass must
    # find offset 4 (and only it) as controlling the faulting address.
    from forge.agents.windows_fuzzer import WindowsFuzzer

    class _T:
        name = "app"
        def run(self, binary, *, stdin=b"", timeout=20.0, symbolize=False):
            addr = struct.unpack_from("<I", (bytes(stdin) + b"\0" * 8), 4)[0]
            return Observation(crashed=True, rc=0, crash=triage.crashinfo_from_frida(
                {"kind": "access-violation", "op": "write", "addr": hex(addr), "pc": "0x100"}))

    tgt = _T()
    ctx = JobContext(f"job-{tmp_path.name}", target=tgt, artifacts_root=tmp_path)
    f = WindowsFuzzer(ctx, seeds=[b"\x00" * 16])
    inp = b"\x00" * 16
    base = tgt.run(None, stdin=inp).crash
    assert f._control_offsets(tgt, Path("x"), inp, base) == [4]

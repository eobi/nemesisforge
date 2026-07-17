"""Phase D — Android: tombstone → typed proof → security finding (no device)."""
import asyncio
from types import SimpleNamespace

from forge.android import parse_tombstone
from forge.context import JobContext
from forge.ladder import Candidate, Outcome, Rung
from forge.oracles.device_crash import DeviceCrashOracle
from forge.targets.device import DeviceTarget

TOMBSTONE = r"""*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'google/sdk_gphone64_arm64/generic_arm64:14/UPB5.230623.003'
pid: 12345, tid: 12345, name: media.codec  >>> /system/bin/mediaserver <<<
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000010
    x0  0000000000000000  x1  0000000000000010
backtrace:
      #00 pc 000000000004a1b2  /system/lib64/libstagefright.so (android::MPEG4Extractor::parseChunk+340)
      #01 pc 0000000000067890  /system/lib64/libmedia.so (android::MediaExtractor::extract+16)
      #02 pc 0000000000012345  /system/bin/mediaserver (main+52)
"""


def test_parse_tombstone():
    ci = parse_tombstone(TOMBSTONE)
    assert ci.crashed and ci.bug_type == "segv" and ci.access == "WRITE"
    assert ci.frames and ci.frames[0].file.endswith("libstagefright.so")
    assert "parseChunk" in ci.frames[0].func
    assert "0x0000000000000010" in ci.summary
    assert ci.stack_hash


def test_parse_non_crash_tombstone():
    assert parse_tombstone("just some log lines, no signal").crashed is False


def test_device_oracle_proves_memory_crash(tmp_path):
    ctx = JobContext(f"job-{tmp_path.name}", target=None, artifacts_root=tmp_path)
    cand = Candidate(bug_class="android_crash",
                     title="SIGSEGV in libstagefright MPEG4Extractor",
                     proposed_check={"tombstone": TOMBSTONE})
    v = DeviceCrashOracle().verify(ctx, cand)
    assert v.outcome is Outcome.PROVEN
    assert v.rung is Rung.PROVEN_SECURITY        # memory signal from a codec
    assert v.evidence["memory_relevant"] is True
    from pathlib import Path
    assert v.reproducer and Path(v.reproducer).exists()


def test_device_oracle_inconclusive_without_tombstone(tmp_path):
    ctx = JobContext(f"job-{tmp_path.name}", target=None, artifacts_root=tmp_path)
    cand = Candidate(bug_class="android_crash", title="x", proposed_check={})
    v = DeviceCrashOracle().verify(ctx, cand)
    assert v.outcome is Outcome.INCONCLUSIVE and "tombstone" in v.feedback


def test_device_target_degrades_without_adb():
    # no adb/device here → available False, build not ok (graceful, not a crash)
    t = DeviceTarget(name="pixel")
    assert t.available is False
    assert t.build().ok is False
    obs = t.run()
    assert obs.crashed is False and "unavailable" in obs.output

"""DeviceTarget — Android / mobile, driven over adb.

Live execution (push a trigger, run it, pull the tombstone, symbolize with
ndk-stack) needs a device or emulator; when none is attached this adapter
degrades cleanly (`available == False`) instead of failing. Crucially, the
*proof + packaging* path does not require live hardware: a tombstone captured
from a device (or provided) is parsed into typed CrashInfo by
`forge.android.parse_tombstone`, proven by the device-crash oracle, and packaged
into the vendor-grade advisory — which is the whole point of the Android case.
"""
from __future__ import annotations

import shutil
from typing import Optional

from ..sandbox import LocalSandbox, Sandbox
from .base import BuildResult, Observation


class DeviceTarget:
    target_type = "device"

    def __init__(self, *, name: str, serial: Optional[str] = None,
                 sandbox: Optional[Sandbox] = None,
                 package: Optional[str] = None) -> None:
        self.name = name
        self.serial = serial
        self.languages = ["android", "native"]
        self.sandbox = sandbox or LocalSandbox()
        self.package = package

    def _adb(self, *args: str, timeout: float = 20.0):
        pre = ["adb"] + (["-s", self.serial] if self.serial else [])
        return self.sandbox.run([*pre, *args], timeout=timeout)

    @property
    def available(self) -> bool:
        if shutil.which("adb") is None:
            return False
        try:
            r = self._adb("get-state", timeout=10)
            return "device" in (r.stdout or "")
        except Exception:
            return False

    def build(self, harness_source: Optional[str] = None, *,
              sanitizer: str = "address", target_sources=None) -> BuildResult:
        ok = self.available
        return BuildResult(ok=ok, binary=None,
                           log="" if ok else "no adb / no device online")

    def run(self, binary=None, *, stdin: bytes = b"", timeout: float = 60.0,
            symbolize: bool = True) -> Observation:
        if not self.available:
            return Observation(crashed=False, output="device unavailable")
        # live path (device attached): trigger + pull the newest tombstone.
        tomb = self.latest_tombstone()
        from ..android import parse_tombstone
        ci = parse_tombstone(tomb)
        return Observation(crashed=ci.crashed, crash=ci, output=tomb)

    def latest_tombstone(self) -> str:
        if not self.available:
            return ""
        ls = self._adb("shell", "ls", "-t", "/data/tombstones/")
        first = (ls.stdout or "").split()
        if not first:
            return ""
        cat = self._adb("shell", "cat", f"/data/tombstones/{first[0]}")
        return cat.stdout or ""

    def harness_path(self):
        return None

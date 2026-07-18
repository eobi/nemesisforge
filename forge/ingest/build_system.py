"""Build-system integration — reach the HARD-to-build (and therefore under-fuzzed)
targets.

Single-file libraries build trivially — and are exactly the ones everyone already
fuzzed and CVE'd. The genuinely under-explored code lives in libraries that need
their OWN build system (make/cmake/autotools) with specific defines, generated
files, and flags. Compiling those file-by-file fails (missing symbols/config), so
we could never fuzz them — until now.

This drives the repo's real build with our instrumentation injected
(`CC=<libFuzzer clang>`, `CFLAGS=-fsanitize=fuzzer-no-link,address,...`), then
collects the produced INSTRUMENTED objects / static archive to link harnesses
against — the same approach OSS-Fuzz uses. `fuzzer-no-link` gives coverage + ASan
without a libFuzzer main; the harness (built `-fsanitize=fuzzer,...`) provides main.

Best-effort + time-boxed: a build that needs external deps or an exotic system just
fails cleanly and the caller falls back to the file-by-file path.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence


@dataclass
class BuildProduct:
    system: str = "none"
    archives: list[Path] = field(default_factory=list)   # .a static libs (preferred)
    objects: list[Path] = field(default_factory=list)     # instrumented .o (filtered)
    ok: bool = False
    log: str = ""

    def link_inputs(self) -> list[str]:
        """What to hand the harness link: prefer a static archive, else objects."""
        if self.archives:
            return [str(p) for p in self.archives]
        return [str(p) for p in self.objects]


def _as_cxx(cc: str) -> str:
    return cc + "++" if cc.endswith("clang") else cc


def _has_main(obj: Path) -> bool:
    try:
        r = subprocess.run(["nm", str(obj)], capture_output=True, text=True,
                           timeout=15)
        return any(l.split()[-1] in ("_main", "main") and " T " in l
                   for l in r.stdout.splitlines() if l.strip())
    except Exception:
        return False


def _collect(build_dir: Path, root: Path, extra_link: Sequence[str]) -> BuildProduct:
    from .repo import _SKIP_DIRS
    archives = [p for p in build_dir.rglob("*.a")
                if not any(x.lower() in _SKIP_DIRS
                           for x in p.relative_to(build_dir).parts[:-1])]
    objects = []
    if not archives:                          # only fall back to loose objects
        for p in build_dir.rglob("*.o"):
            parts = {x.lower() for x in p.relative_to(build_dir).parts[:-1]}
            if parts & _SKIP_DIRS:
                continue
            if _has_main(p):                  # would clash with libFuzzer's main
                continue
            objects.append(p)
    return BuildProduct(archives=archives, objects=objects,
                        ok=bool(archives or objects))


def build_library(root: Path, *, compiler: str, sanitizer: str = "address",
                  extra_link: Optional[Sequence[str]] = None,
                  timeout: int = 900) -> BuildProduct:
    """Build the repo with its own build system + our instrumentation. Returns the
    instrumented archives/objects to link the harness against (ok=False on failure)."""
    from .repo import detect_build_system
    root = Path(root)
    system = detect_build_system(root)
    extra_link = list(extra_link or [])
    cflags = (f"-fsanitize=fuzzer-no-link,{sanitizer} -g -O1 "
              f"-fno-omit-frame-pointer")
    env = {**os.environ, "CC": compiler, "CXX": _as_cxx(compiler),
           "CFLAGS": cflags, "CXXFLAGS": cflags,
           "LDFLAGS": " ".join(extra_link)}
    logs: list[str] = []

    def _run(argv, cwd, extra_env=None):
        try:
            r = subprocess.run(argv, cwd=str(cwd), env={**env, **(extra_env or {})},
                               capture_output=True, text=True, timeout=timeout)
            logs.append(f"$ {' '.join(argv)}\n{(r.stdout or '')[-500:]}"
                        f"{(r.stderr or '')[-800:]}")
            return r.returncode == 0
        except Exception as e:
            logs.append(f"$ {' '.join(argv)} -> {type(e).__name__}: {e}")
            return False

    if system == "cmake":
        bdir = root / "_forge_build"
        bdir.mkdir(exist_ok=True)
        # STATIC_LIBRARY try-compile + COMPILER_WORKS: skip cmake's compiler-probe
        # test BINARIES — each instrumented exe takes ~15s to start under ASan on
        # macOS, so dozens of probes would stall configure for many minutes.
        ok = _run(["cmake", "-S", str(root), "-B", str(bdir),
                   f"-DCMAKE_C_COMPILER={compiler}",
                   f"-DCMAKE_CXX_COMPILER={_as_cxx(compiler)}",
                   f"-DCMAKE_C_FLAGS={cflags}", f"-DCMAKE_CXX_FLAGS={cflags}",
                   "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
                   "-DCMAKE_C_COMPILER_WORKS=1", "-DCMAKE_CXX_COMPILER_WORKS=1",
                   "-DCMAKE_BUILD_TYPE=Debug", "-DBUILD_SHARED_LIBS=OFF"], root)
        if ok:
            _run(["cmake", "--build", str(bdir), "-j", "4"], root)
        prod = _collect(bdir, root, extra_link)
    elif system in ("make", "autotools"):
        if system == "autotools" and (root / "configure").exists():
            _run(["./configure"], root)
        _run(["make", "-j", "4"], root)
        prod = _collect(root, root, extra_link)
    else:
        prod = BuildProduct(system=system, ok=False)

    prod.system = system
    prod.log = "\n".join(logs)[-3000:]
    return prod

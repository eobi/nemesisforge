"""libFuzzer engine plumbing — the real coverage-guided muscle.

Discovery used to be a length-sweep (`A`, `AA`, `AAAA`…). This module gives Forge
an actual coverage-guided fuzzer: compile a `LLVMFuzzerTestOneInput` harness with
`-fsanitize=fuzzer,address` and let libFuzzer explore the input space with
coverage feedback, a corpus, and a dictionary — the same engine OSS-Fuzz runs.

Two toolchain facts this handles:
  - Apple's `/usr/bin/clang` does NOT ship the libFuzzer runtime
    (`libclang_rt.fuzzer_osx.a` is missing), so on macOS we must reach for a
    Homebrew-LLVM clang. On Linux/Docker plain `clang` ships it. `find_libfuzzer_clang()`
    resolves the right one (cached) and returns None when none is available, so
    the caller degrades to the legacy fuzzer instead of crashing.
  - The oracle re-verifies a crash by feeding one input over stdin. A libFuzzer
    binary ignores stdin, so `LF_DRIVER` is a tiny standalone `main()` that reads
    stdin (or a file arg) and calls `LLVMFuzzerTestOneInput` — letting the SAME
    harness be built WITHOUT the fuzzer runtime (default compiler) for replay.
"""
from __future__ import annotations

import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Standalone driver: turns an LLVMFuzzerTestOneInput harness into a stdin/file
# program so the oracle can replay one input under plain ASan (no fuzzer runtime).
LF_DRIVER = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(int argc, char **argv) {
  size_t cap = 1 << 16, n = 0;
  unsigned char *tmp = (unsigned char *)malloc(cap);
  FILE *f = stdin;
  if (argc > 1) { f = fopen(argv[1], "rb"); if (!f) return 0; }
  size_t r;
  while ((r = fread(tmp + n, 1, cap - n, f)) > 0) {
    n += r;
    if (n == cap) { cap *= 2; tmp = (unsigned char *)realloc(tmp, cap); }
  }
  /* Hand LLVMFuzzerTestOneInput a buffer sized EXACTLY to the input, so an
     out-of-bounds READ past the input faults under ASan exactly as it does
     under libFuzzer (which tightly sizes `data`, redzone immediately after).
     A slack read buffer would silently absorb OOB reads that only trip when
     the allocation ends at `size` — the false-negative that made the oracle
     refute real libFuzzer crashes. */
  unsigned char *data = (unsigned char *)malloc(n ? n : 1);
  if (n) memcpy(data, tmp, n);
  free(tmp);
  LLVMFuzzerTestOneInput(data, n);
  free(data);
  return 0;
}
"""

_PROBE = (b"#include <stdint.h>\n#include <stddef.h>\n"
          b"int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;}\n")

_cache: Optional[str] = None


def find_libfuzzer_clang() -> Optional[str]:
    """Return the path to a clang that can link `-fsanitize=fuzzer`, or None.

    Cached per process (the probe compiles a tiny harness once). Prefers a
    Homebrew-LLVM clang on macOS, then whatever `clang` is on PATH."""
    global _cache
    if _cache is not None:
        return _cache or None

    candidates: list[str] = []
    if platform.system() == "Darwin":
        candidates += ["/opt/homebrew/opt/llvm/bin/clang",
                       "/usr/local/opt/llvm/bin/clang"]
    onpath = shutil.which("clang")
    if onpath:
        candidates.append(onpath)

    for c in candidates:
        if _links_fuzzer(c):
            _cache = c
            return c
    _cache = ""
    return None


_ubsan_cache: dict[str, Optional[list]] = {}
_UB_PROBE = (b"#include <stdint.h>\n#include <stddef.h>\n"
             b"int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){"
             b"if(n){int x=2147483647;x+=d[0];volatile int z=x;(void)z;}return 0;}\n")


def ubsan_fuzzer_flags(clang: str) -> Optional[list]:
    """Extra link flags to make `-fsanitize=fuzzer,address,undefined` LINK with
    `clang`, or None if UBSan+fuzzer can't be built at all. Probed once + cached.

    On macOS the Apple system linker rejects Homebrew-clang UBSan objects, so we
    need `-fuse-ld=lld`; on Linux the system linker is fine. Rather than guess the
    linker's filename, we compile a tiny UB harness and see what actually works."""
    if clang in _ubsan_cache:
        return _ubsan_cache[clang]
    result: Optional[list] = None
    for extra in (["-fuse-ld=lld"], []):
        if _builds_ubsan(clang, extra):
            result = extra
            break
    _ubsan_cache[clang] = result
    return result


_msan_cache: dict[str, Optional[list]] = {}


def msan_fuzzer_flags(clang: str) -> Optional[list]:
    """Extra link flags to build `-fsanitize=fuzzer,memory` (MemorySanitizer, finds
    uninitialized-memory reads), or None if unsupported here. MSan is mutually
    exclusive with ASan and needs instrumented deps, so it typically works only on
    Linux for self-contained targets; on macOS this returns None and the caller
    degrades to ASan. Probed once + cached."""
    if clang in _msan_cache:
        return _msan_cache[clang]
    result: Optional[list] = None
    for extra in (["-fuse-ld=lld"], []):
        if _builds_san(clang, "fuzzer,memory", extra):
            result = extra
            break
    _msan_cache[clang] = result
    return result


def _builds_san(clang: str, fsan: str, extra: list) -> bool:
    try:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "u.c"
            src.write_bytes(_PROBE)
            out = Path(d) / "u"
            r = subprocess.run([clang, f"-fsanitize={fsan}", *extra, "-O0",
                                str(src), "-o", str(out)],
                               capture_output=True, timeout=90)
            return r.returncode == 0 and out.exists()
    except Exception:
        return False


def _builds_ubsan(clang: str, extra: list) -> bool:
    try:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "u.c"
            src.write_bytes(_UB_PROBE)
            out = Path(d) / "u"
            r = subprocess.run(
                [clang, "-fsanitize=fuzzer,address,undefined",
                 "-fno-sanitize-recover=undefined", *extra, "-O0",
                 str(src), "-o", str(out)],
                capture_output=True, timeout=90)
            return r.returncode == 0 and out.exists()
    except Exception:
        return False


def _links_fuzzer(clang: str) -> bool:
    if not (clang and (Path(clang).exists() or shutil.which(clang))):
        return False
    try:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "p.c"
            src.write_bytes(_PROBE)
            out = Path(d) / "p"
            r = subprocess.run(
                [clang, "-fsanitize=fuzzer,address", "-O0", str(src), "-o", str(out)],
                capture_output=True, timeout=60)
            return r.returncode == 0 and out.exists()
    except Exception:
        return False


@dataclass
class FuzzResult:
    crashed: bool = False
    crash_input: Optional[bytes] = None
    coverage: int = 0          # libFuzzer `cov:` (edges hit)
    features: int = 0          # libFuzzer `ft:` (features)
    execs: int = 0             # total executed units
    exec_per_s: int = 0
    corpus: int = 0            # corpus entries at end
    output: str = ""
    rc: int = 0
    timed_out: bool = False


_COV = re.compile(r"cov:\s*(\d+)\s+ft:\s*(\d+)")
_CORP = re.compile(r"corp:\s*(\d+)")
_EXECS = re.compile(r"stat::number_of_executed_units:\s*(\d+)")
_EPS = re.compile(r"stat::average_exec_per_sec:\s*(\d+)")


def parse_stats(output: str) -> tuple[int, int, int, int, int]:
    """Pull (cov, ft, execs, exec/s, corpus) from libFuzzer stderr."""
    cov = ft = corp = execs = eps = 0
    for m in _COV.finditer(output):
        cov, ft = int(m.group(1)), int(m.group(2))   # last wins
    cm = list(_CORP.finditer(output))
    if cm:
        corp = int(cm[-1].group(1))
    em = _EXECS.search(output)
    if em:
        execs = int(em.group(1))
    pm = _EPS.search(output)
    if pm:
        eps = int(pm.group(1))
    return cov, ft, execs, eps, corp

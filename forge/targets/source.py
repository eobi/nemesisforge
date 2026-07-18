"""SourceTarget — a buildable source tree, compiled with a sanitizer and run on
an input. The Phase-A concrete Target.

Reuses the Nemesis Zero pattern (build with ASan in a sandbox, run, parse the
sanitizer report), but behind Forge's uniform Target contract so the same
Coordinator/oracles drive it. A discovery/escalation agent supplies a C harness
(the input surface) + optional target sources; the target compiles them with
`-fsanitize=<san>` and runs the harness on the agent's input. A sanitizer crash
is the proof object the ladder climbs on.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import itertools
import threading
from typing import Optional, Sequence

from .. import triage
from .. import fuzzengine
from ..sandbox import LocalSandbox, Sandbox
from .base import BuildResult, Observation

_HARNESS = "forge_harness"
_DRIVER = "forge_lf_driver"

# Tokens that appear in C++ but never in valid C — so detection never mis-flags a
# C harness (which would otherwise fail to link against the C target sources).
_CPP_MARKERS = ('extern "C"', "nullptr", "reinterpret_cast", "static_cast",
                "::", "template<", "template <", "std::")


def _looks_cpp(src: str) -> bool:
    return any(m in src for m in _CPP_MARKERS)


def _as_cxx(compiler: str) -> str:
    """Map a C clang path to its C++ driver (clang → clang++)."""
    if compiler.endswith("clang"):
        return compiler + "++"
    if compiler.endswith("gcc"):
        return compiler[:-3] + "g++"
    return compiler + "++"
# Deterministic, abort-on-report so we always get a parseable crash. Symbolization
# is toggled per-run: discovery only needs "did it crash + what class" (fast,
# symbolize=0), while the oracle wants frames for the rung decision (symbolize=1).
# On macOS symbolization goes through `atos` and costs ~15s per crash, so keeping
# it off for the fuzz loop is a large speedup (Linux/Docker symbolizes fast).
_ASAN_BASE = "detect_leaks=0:abort_on_error=1:halt_on_error=1"


class SourceTarget:
    target_type = "source"

    def __init__(self, workdir: Path | str, *, name: str,
                 languages: Sequence[str] = ("c",),
                 sandbox: Optional[Sandbox] = None,
                 compiler: str = "clang") -> None:
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.name = name
        self.languages = list(languages)
        self.sandbox = sandbox or LocalSandbox()
        self.compiler = compiler
        self._build_seq = itertools.count(1)
        self._lock = threading.Lock()
        self._obj_lock = threading.Lock()      # serialize library object compiles
        # Phase N: an instrumented static archive built by the repo's OWN build
        # system (make/cmake/autotools) plus its generated-header dirs. When set,
        # EVERY build() links against it instead of compiling library sources
        # file-by-file — the only way to reach hard, multi-file targets. Set once
        # by repo_job; picked up transparently by discovery, co-driving, AND the
        # oracle's replay (they all build through this shared target).
        self.extra_link_objects: list[str] = []
        self.extra_include_dirs: list[Path] = []

    def _newdir(self) -> Path:
        # Each build gets its OWN subdir so parallel builds (the LLM synth squad,
        # concurrent verification) never clobber each other's harness/binary —
        # the source of intermittent "no crash" flakes.
        with self._lock:
            n = next(self._build_seq)
        bdir = self.workdir / f"b{n}"
        bdir.mkdir(parents=True, exist_ok=True)
        return bdir

    def _lib_objects(self, sources, compiler: str, common: list):
        """Compile each library source to a CACHED .o (keyed by path+mtime+flags),
        so repeated harness builds link against prebuilt objects instead of
        recompiling the whole library every time. Serialized so parallel harness
        builds compile the library exactly once."""
        cache = self.workdir / "_objcache"
        objs: list[str] = []
        logs: list[str] = []
        with self._obj_lock:                 # compile-once across parallel builds
            cache.mkdir(parents=True, exist_ok=True)
            keyf = hashlib.sha1(("|".join(common) + "|" + compiler).encode()
                                ).hexdigest()[:10]
            for s in sources:
                s = Path(s)
                try:
                    mt = int(s.stat().st_mtime)
                except Exception:
                    mt = 0
                obj = cache / (hashlib.sha1(f"{s}|{mt}|{keyf}".encode()
                                            ).hexdigest()[:16] + ".o")
                if not obj.exists():
                    r = self.sandbox.run([compiler, *common, "-c", str(s),
                                          "-o", str(obj)], timeout=400)
                    if r.rc != 0 or not obj.exists():
                        logs.append(f"[lib skip {s.name}: {r.output[-160:]}]")
                        continue
                objs.append(str(obj))
        return objs, "\n".join(logs)

    def build(self, harness_source: str, *, sanitizer: str = "address",
              target_sources: Optional[Sequence[Path]] = None,
              include_dirs: Optional[Sequence[Path]] = None,
              extra_objects: Optional[Sequence[str]] = None,
              fuzzer: bool = False, libfuzzer_driver: bool = False) -> BuildResult:
        """Compile a harness under a sanitizer.

        Three modes (additive — the default main()/stdin path is unchanged):
          - default: a self-contained main() harness (the legacy presets).
          - fuzzer=True: an `LLVMFuzzerTestOneInput` harness linked with the
            libFuzzer runtime (`-fsanitize=fuzzer,<san>`) → a coverage-guided
            fuzzing binary. Needs a libFuzzer-capable clang (resolved for us).
          - libfuzzer_driver=True: the SAME `LLVMFuzzerTestOneInput` harness, but
            linked with a tiny stdin/file driver instead of the fuzzer runtime, so
            the oracle can replay one input on the DEFAULT compiler.
        """
        bdir = self._newdir()
        # A synthesized harness may be C++ (OSS-Fuzz harnesses often are, and LLMs
        # drift to nullptr/reinterpret_cast/lambdas). Detect it and compile the
        # harness as C++ with the C++ driver so it links — the target C sources
        # still compile as C by extension.
        cpp = _looks_cpp(harness_source)
        src = bdir / (f"{_HARNESS}.cc" if cpp else f"{_HARNESS}.c")
        src.write_text(harness_source)
        binary = bdir / _HARNESS
        driver = None
        compiler = self.compiler

        extra: list[str] = []
        if fuzzer:
            compiler = fuzzengine.find_libfuzzer_clang() or self.compiler
            sans = [s for s in sanitizer.split(",") if s]
            if "memory" in sans:
                # MSan is mutually exclusive with ASan and needs instrumented deps.
                flags = fuzzengine.msan_fuzzer_flags(compiler)
                if flags is None:                # unsupported (e.g. macOS) → degrade
                    sans = [s for s in sans if s != "memory"] or ["address"]
                else:
                    sans = ["memory"] + [s for s in sans
                                         if s in ("undefined",)]  # no address
                    extra.extend(flags)
            if "undefined" in sans:
                flags = fuzzengine.ubsan_fuzzer_flags(compiler)
                if flags is not None:
                    extra.extend(flags)              # e.g. -fuse-ld=lld on macOS
                else:
                    sans = [s for s in sans if s != "undefined"]   # unsupported → degrade
            fsan = "fuzzer," + ",".join(sans) if sans else "fuzzer,address"
        elif libfuzzer_driver:
            driver = bdir / f"{_DRIVER}.c"
            driver.write_text(fuzzengine.LF_DRIVER)
            fsan = sanitizer
        else:
            fsan = sanitizer

        if cpp:                              # use the C++ driver so libc++ links
            compiler = _as_cxx(compiler)
        incs = [f"-I{p}" for p in
                list(include_dirs or []) + self.extra_include_dirs]
        # UBSan only warns by default; make it a hard, parseable crash so the
        # oracle can prove integer/UB bugs the same way it proves ASan crashes.
        recover = ["-fno-sanitize-recover=undefined"] if "undefined" in fsan else []
        common = [f"-fsanitize={fsan}", "-g", "-O1", "-fno-omit-frame-pointer",
                  *recover, *extra, *incs]

        # Lift the sandbox CPU cap for the trusted compile step (a big target like
        # the SQLite amalgamation, or a whole library, needs minutes).
        sb = self.sandbox
        prev_cpu = getattr(sb, "cpu_s", None)
        if prev_cpu is not None:
            sb.cpu_s = max(prev_cpu, 300)
        try:
            # Compile the LIBRARY sources to CACHED objects ONCE — otherwise a
            # multi-file library is recompiled on every harness attempt/repair and
            # the campaign drowns in builds instead of fuzzing. Only the harness
            # (+driver) recompiles per attempt; the link is cheap.
            # Phase N: if the target carries an instrumented archive from the repo's
            # OWN build system, link THAT (it has every symbol) and SKIP compiling
            # library sources file-by-file — which fails on hard multi-file libs and
            # would duplicate symbols the archive already provides.
            archive = list(self.extra_link_objects)
            lib = [] if archive else list(target_sources or [])
            objs, objlog = (self._lib_objects(lib, compiler, common)
                            if lib else ([], ""))
            # Pre-built objects/archives from the repo's OWN build system (Phase N)
            # are linked directly — no recompile.
            prebuilt = archive + [str(o) for o in (extra_objects or [])]
            front = [str(src)] + ([str(driver)] if driver else [])
            argv = [compiler, *common, *front, *objs, *prebuilt, "-o", str(binary)]
            res = sb.run(argv, cwd=bdir, timeout=600)
            # Safety net: if the build-system archive didn't satisfy the harness
            # (e.g. cmake built only a partial lib), fall back to the proven
            # file-by-file compile so an archive can never REGRESS a target that
            # already worked. Never breaks the non-archive path.
            if archive and (res.rc != 0 or not binary.exists()) and target_sources:
                lib = list(target_sources)
                objs, objlog = self._lib_objects(lib, compiler, common)
                if objs:
                    argv = [compiler, *common, *front, *objs,
                            *[str(o) for o in (extra_objects or [])],
                            "-o", str(binary)]
                    res = sb.run(argv, cwd=bdir, timeout=600)
        finally:
            if prev_cpu is not None:
                sb.cpu_s = prev_cpu
        ok = res.rc == 0 and binary.exists()
        if lib and objlog:
            res = res.__class__(rc=res.rc, stdout=res.stdout,
                                stderr=objlog + "\n" + res.stderr,
                                timed_out=res.timed_out)
        return BuildResult(ok=ok, binary=binary if ok else None, log=res.output)

    def fuzz(self, binary: Path, *, corpus_dir: Optional[Path] = None,
             dict_path: Optional[Path] = None, max_total_time: int = 20,
             max_len: int = 4096, timeout: Optional[float] = None,
             focus_function: str = "", seeds: Optional[Sequence[bytes]] = None
             ) -> fuzzengine.FuzzResult:
        """Run a libFuzzer binary with coverage feedback + corpus + dictionary.

        Phase-J directed fuzzing: `focus_function` steers libFuzzer's energy toward
        inputs that reach a specific function (the sink the reasoning tier
        nominated), and `seeds` injects LLM-crafted guard-passing inputs into the
        corpus so the fuzzer mutates onward from them.

        Returns the first crashing input (if any) plus coverage stats. The crashing
        input is emitted as a Candidate whose crash the SanitizerOracle then
        independently rebuilds + replays (writer ≠ validator)."""
        art = binary.parent
        if corpus_dir:
            corpus_dir = Path(corpus_dir)
            corpus_dir.mkdir(parents=True, exist_ok=True)
            for i, s in enumerate(seeds or []):
                # a deterministic name so re-injecting the same seed is idempotent
                (corpus_dir / f"seed_{len(s)}_{abs(hash(bytes(s))) & 0xffffff:06x}"
                 ).write_bytes(bytes(s))
        argv = [str(binary), f"-max_total_time={int(max_total_time)}",
                f"-max_len={int(max_len)}", f"-artifact_prefix={art}/",
                "-print_final_stats=1"]
        if focus_function:
            argv.append(f"-focus_function={focus_function}")
        if dict_path and Path(dict_path).exists():
            argv.append(f"-dict={dict_path}")
        if corpus_dir:
            argv.append(str(corpus_dir))
        # libFuzzer needs headroom over max_total_time; also lift the sandbox CPU
        # cap for the duration of the fuzz so a long budget isn't SIGXCPU-killed.
        wall = timeout or (max_total_time + 30)
        sb = self.sandbox
        prev_cpu = getattr(sb, "cpu_s", None)
        if prev_cpu is not None:
            sb.cpu_s = int(wall) + 30
        try:
            res = sb.run(argv, cwd=art, timeout=wall,
                         env={"ASAN_OPTIONS": _ASAN_BASE + ":symbolize=0"})
        finally:
            if prev_cpu is not None:
                sb.cpu_s = prev_cpu

        crash_input = None
        for pat in ("crash-*", "oom-*", "timeout-*", "leak-*"):
            hits = sorted(art.glob(pat))
            if hits:
                crash_input = hits[0].read_bytes()
                break
        cov, ft, execs, eps, corp = fuzzengine.parse_stats(res.output)
        # A real crash always writes an artifact; key off that, plus explicit
        # sanitizer/deadly-signal signatures. (Do NOT treat any "ERROR:" as a
        # crash — libFuzzer prints benign ERRORs like a failed focus-function.)
        crashed = crash_input is not None or any(
            sig in res.output for sig in
            ("ERROR: AddressSanitizer", "ERROR: libFuzzer: deadly signal",
             "UndefinedBehaviorSanitizer:", "runtime error:"))
        return fuzzengine.FuzzResult(
            crashed=crashed, crash_input=crash_input, coverage=cov, features=ft,
            execs=execs, exec_per_s=eps, corpus=corp, output=res.output,
            rc=res.rc, timed_out=res.timed_out)

    def run(self, binary: Path, *, stdin: bytes = b"", timeout: float = 60.0,
            symbolize: bool = True) -> Observation:
        opts = f"{_ASAN_BASE}:symbolize={1 if symbolize else 0}"
        res = self.sandbox.run([str(binary)], cwd=self.workdir, stdin=stdin,
                               timeout=timeout, env={"ASAN_OPTIONS": opts})
        crash = triage.parse(res.output)
        return Observation(crashed=crash.crashed, crash=crash, rc=res.rc,
                           output=res.output, timed_out=res.timed_out)

    def harness_path(self) -> Path:
        return self.workdir / f"{_HARNESS}.c"

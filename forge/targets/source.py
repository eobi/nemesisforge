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
import itertools
import threading
from typing import Optional, Sequence

from .. import triage
from .. import fuzzengine
from ..sandbox import LocalSandbox, Sandbox
from .base import BuildResult, Observation

_HARNESS = "forge_harness"
_DRIVER = "forge_lf_driver"
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

    def _newdir(self) -> Path:
        # Each build gets its OWN subdir so parallel builds (the LLM synth squad,
        # concurrent verification) never clobber each other's harness/binary —
        # the source of intermittent "no crash" flakes.
        with self._lock:
            n = next(self._build_seq)
        bdir = self.workdir / f"b{n}"
        bdir.mkdir(parents=True, exist_ok=True)
        return bdir

    def build(self, harness_source: str, *, sanitizer: str = "address",
              target_sources: Optional[Sequence[Path]] = None,
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
        src = bdir / f"{_HARNESS}.c"
        src.write_text(harness_source)
        binary = bdir / _HARNESS
        sources = [str(src), *[str(p) for p in (target_sources or [])]]
        compiler = self.compiler

        if fuzzer:
            compiler = fuzzengine.find_libfuzzer_clang() or self.compiler
            fsan = f"fuzzer,{sanitizer}"
        elif libfuzzer_driver:
            driver = bdir / f"{_DRIVER}.c"
            driver.write_text(fuzzengine.LF_DRIVER)
            sources.append(str(driver))
            fsan = sanitizer
        else:
            fsan = sanitizer

        argv = [compiler, f"-fsanitize={fsan}", "-g", "-O1",
                "-fno-omit-frame-pointer", *sources, "-o", str(binary)]
        res = self.sandbox.run(argv, cwd=bdir, timeout=180)
        ok = res.rc == 0 and binary.exists()
        return BuildResult(ok=ok, binary=binary if ok else None, log=res.output)

    def fuzz(self, binary: Path, *, corpus_dir: Optional[Path] = None,
             dict_path: Optional[Path] = None, max_total_time: int = 20,
             max_len: int = 4096, timeout: Optional[float] = None
             ) -> fuzzengine.FuzzResult:
        """Run a libFuzzer binary with coverage feedback + corpus + dictionary.

        Returns the first crashing input (if any) plus coverage stats. The
        crashing input is emitted as a Candidate whose crash the SanitizerOracle
        then independently rebuilds + replays (writer ≠ validator)."""
        art = binary.parent
        argv = [str(binary), f"-max_total_time={int(max_total_time)}",
                f"-max_len={int(max_len)}", f"-artifact_prefix={art}/",
                "-print_final_stats=1"]
        if dict_path and Path(dict_path).exists():
            argv.append(f"-dict={dict_path}")
        if corpus_dir:
            Path(corpus_dir).mkdir(parents=True, exist_ok=True)
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
        crashed = crash_input is not None or "ERROR: " in res.output
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

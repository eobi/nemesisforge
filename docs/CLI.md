# Command line, with real output

Every transcript below was captured from a run on macOS arm64. Nothing is typed by
hand. Where a number would differ on your machine, it is a measurement, not a promise.

---

## `doctor` — what is available, and what its absence costs

```
$ python -m forge doctor

ENVIRONMENT

  yes  libFuzzer-capable clang    REQUIRED for coverage-guided discovery
       /opt/homebrew/opt/llvm/bin/clang
  yes  clang                      REQUIRED to build targets
  yes  git                        needed for repo mode
  yes  lldb                       rung-4 operand evidence (macOS)
  NO   gdb                        rung-4 operand evidence (Linux)
  yes  angr                       symbolic lens; without it, no constraint solving
  NO   frida                      closed-binary coverage; without it, source only

Missing entries are not errors. The engine runs without them and says so
in its output rather than reporting a null result as if it were a search.
```

Run this first. A campaign that finds nothing because a lens was missing is a
different result from a campaign that finds nothing because there is nothing there.

---

## `lab` — a campaign against a harness you supply

No API key. The half of the engine that certifies a finding never needed a model.

```
$ python -m forge lab examples/harness_trunc.c --fuzz-time 30

[10:12:12] job=lab-54735991 harness=examples/harness_trunc.c fuzz_time=30s provider=null
[10:12:15] 1 finding(s)

  rung 1   heap-buffer-overflow (WRITE)
  class      memory_safety
  evidence   coverage-guided fuzzing reached cov=5 in 130 execs and found a
             4-byte input triggering heap-buffer-overflow
  NOT shown  anything above rung 1: no oracle certified it

artifacts: /tmp/fd2/lab-54735991
```

Read the last line before the others. The engine found a real heap overflow in three
seconds and then told you the honest limit of what it proved. Rung 1 means a fault was
observed. It does **not** mean reachable from real input, security-relevant, or
controllable, because no oracle certified those.

Artifacts:

```
$ ls /tmp/fd2/lab-54735991
corpus  findings.json  metadata.json  repro-40b8c8495f598517.bin  work
```

`findings.json` carries the sanitizer output verbatim, the base64 of the crashing
input, the coverage reached, and the exact build command.

---

## `oracles` — the machinery, and what each part certifies

```
$ python -m forge oracles

ORACLES, and what each one certifies

  BinaryCrashOracle        Proves a crash in a closed-source binary by concrete execution.
  ControllabilityOracle    Measures how much of the faulting write the input controls.
  DeviceCrashOracle        Proves an Android native crash from a tombstone.
  DifferentialOracle       The universal reward: faults on the vulnerable build,
                           clean on the patched one.
  ExploitabilityOracle     Classifies the primitive at the faulting instruction, and
                           refuses to dress a null dereference up as exploitable.
  NativeVerifyOracle       The anti-false-positive gate: replays natively, so
                           instrumentation artifacts do not survive.
  SanitizerOracle          The first deterministic prover: a typed sanitizer report.
  SymbolicOracle           angr-backed reachability and primitive proof.

  8 oracles

RUNGS
  0  UNVERIFIED      3  PROVEN_SECURITY   6  VENDOR_READY
  1  PROVEN_FAULT    4  PROVEN_PRIMITIVE
  2  PROVEN_REACHABLE 5 PROVEN_EXPLOIT

A model may propose a candidate for any rung. Only an oracle may certify one.
```

---

## `repo` — point it at a git URL

Harness synthesis is the model's job, so this path wants a provider.

```
$ python -m forge repo https://github.com/example/lib --provider openai --minutes 5
```

Without a provider it says so and runs the static lens only:

```
note: no model provider selected, so no harness will be synthesised.
      The static lens will still run and report leads. To fuzz, either
      pass --provider, or write a harness and use:  python -m forge lab
```

That message exists because the alternative, a silent zero-finding run, is
indistinguishable from a search that genuinely found nothing.

---

## Note for macOS users

The engine injects a small preload shim so that a fatal signal does not wake the
operating system crash reporter. Without it a native crash takes **over 24 seconds**
on this machine and a campaign deadlocks against its own backlog; with it, **0.03
seconds**. `ASAN_OPTIONS=abort_on_error=0` does not cover this case, because a target
built without a sanitizer has no sanitizer in it to obey the option. See
`forge/native/__init__.py`.

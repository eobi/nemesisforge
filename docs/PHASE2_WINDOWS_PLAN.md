# Phase 2 — Windows desktop-binary hunting (make FastStone / TextMaker / Power PDF / Acrobat real)

Goal, in one sentence: point the zero-day scanner at a closed **Windows GUI file-parser**
(FastStone, TextMaker, Power PDF, Acrobat), and it coverage-fuzzes the parser, native-verifies each
crash, grades exploitability at the faulting instruction, and reports only proven, novel bugs with a
reproducing file — the same proof-ladder discipline the Linux/source path already has.

This is not a rebuild. Every new piece plugs into an existing Forge seam. What is genuinely new is a
**Windows execution surface** and a **coverage engine + harness model that fits a GUI app**.

---

## Why it is not already possible (the three real gaps)

1. **Execution surface is Linux.** `forge/sandbox.py` is a Linux subprocess/container (POSIX
   `setrlimit`, `--network none`). It cannot run a Windows `.exe`. So a Docker container is the wrong
   place to fuzz a Windows app; the tight fuzz loop must run **on Windows**, next to the target.
2. **The binary model is stdin + POSIX signal.** `forge/targets/binary.py` feeds input on stdin and
   detects a crash by SIGSEGV/SIGBUS. A GUI app takes a **file** through its UI and faults with a
   **Windows exception** (`0xC0000005`), not a POSIX signal.
3. **Coverage on a closed binary is a skeleton.** `forge/targets/binary_cov.py` (`FridaStalkerCoverage`)
   degrades to a concrete run (`instrumented=False`); the real spawn/attach/coverage plumbing is this
   phase.

---

## Architecture decision: a native Windows fuzz agent, orchestrator coordinates

The tight loop (mutate → run-with-coverage → keep-if-new → repeat), especially in **persistent mode**
(thousands of exec/s in one process), must be **local to the target on Windows**. Cross-host RPC per
input would kill throughput. So:

- **Windows fuzz agent** (native): runs the whole coverage-guided loop on the Windows host/VM, drives
  the target, collects coverage + crashes, does native-verify locally. Ships as a signed portable
  exe / service (reuse the Nemesis Blue Windows signing story: Authenticode EV).
- **Orchestrator** (the existing Python engine, in Docker or on the same Windows box): assigns
  campaigns, holds the corpus/ladder/report, runs the LLM tiers (harness synthesis, escalation,
  misuse-triage), and receives proven findings. Talks to the agent over a control channel (gRPC/HTTP
  over localhost or WinRM), NOT per-input.

Net: the Docker product stays; Windows-binary hunting adds a Windows agent. (An all-native Windows
install of the engine is also viable and is the simpler v1 — one box, no cross-host channel.)

---

## The five components (each maps to an existing seam)

### 1. `WindowsBinaryTarget` — the Target adapter (extends `forge/targets/base.py`)
Implements the same `Target` contract (`build()` no-op returns the exe; `run(input) -> Observation`)
so the fuzzer + oracles drive it unchanged. `run()` delegates to the Windows agent: deliver the input
file, execute the target (argv or persistent harness), return an `Observation` whose `crash` is parsed
from the **Windows exception** (new `triage` path: exception code + faulting address → `CrashInfo`,
mirroring the existing sanitizer/signal parsers).

### 2. Windows coverage backend — realize `forge/targets/binary_cov.py`
`binary_cov.py` already defines the `CoverageBackend` protocol, `CoverageMap`, `select_corpus`,
`to_instrumented_candidate`, and the `FRIDA_STALKER_AGENT` JS. Make it real, with pluggable engines
(pick per target; `native-verify` covers instrumentation artifacts regardless):
- **DynamoRIO / WinAFL-style (recommended primary):** mature Windows coverage, persistent-mode,
  `drcov` blocks. Best throughput on big apps (Acrobat).
- **TinyInst (Jackalope-style):** lightweight dynamic instrumentation, good for macOS+Windows parity.
- **Frida-Stalker (already prototyped, fallback):** cross-platform, scriptable, arms Stalker around
  the parse call on the real target thread; slower + artifact-prone, which is exactly why the
  **native-verify oracle exists**.
- **Intel PT (optional, fastest):** hardware trace, no instrumentation artifacts; needs supported CPUs.

Coverage feeds the existing `CoverageMap` novelty gate; a crash becomes an `instrumented_crash`
Candidate via `to_instrumented_candidate` → routed to native-verify.

### 3. Per-format harness synthesis (the GUI problem, solved two ways)
A GUI app will not read stdin. Two harness modes, chosen per target:
- **argv/file mode (v1, simple):** launch `App.exe <mutated_file>`, watch for the exception, kill,
  repeat. Works for all four (they accept a file path). Slow (GUI startup per input) but proves the
  pipeline and needs zero RE.
- **persistent in-process mode (v2, fast):** hook the **decoder entry** and call it in a loop with new
  inputs without restarting the app (libFuzzer-persistent equivalent, WinAFL persistent). 100–1000×
  faster. Needs the parse-function address per app — which the manual RE already produced:
  - **FastStone 8.3 (image):** TGA/PCX/BMP decoders (the exact functions from the arbitrary-write PoV).
  - **TextMaker 2024 (office):** the document-parse path from the controlled-write repro.
  - **Power PDF 2025.3 / Acrobat DC (PDF):** the PDF object/stream parser module (scope coverage to the
    parser, not the whole app).
  This is `harness_synth` for a closed binary: `binary_recon` (imports/strings/CFG) + the LLM proposes
  the decoder entry + input-delivery; a coverage probe confirms the harness reaches parser code.
  Reachability directing (`forge/ingest/reachability.py`) scopes which decoder by the file format fed.

### 4. Windows crash + exploitability oracle (reuse what's built)
- **native-verify** (`forge/oracles/native_verify.py`, built): replay the crashing file in a fresh
  **un-instrumented** Windows process K times; only native-confirmed crashes climb. Port the "crash?"
  check from POSIX signal to Windows exit-code/exception. This kills DynamoRIO/Frida artifacts — the
  Little-CMS lesson, on Windows.
- **exploitability** (`forge/oracles/exploitability.py`, built): grade the faulting instruction —
  write-what-where / controlled OOB-read / null-deref DoS — via marker substitution. Feed it the
  Windows crash context from **WinDbg/cdb** (`!analyze`-class: exception code `0xC0000005`, faulting
  address, registers, disassembly), replacing the gdb/lldb backtrace path. This is the FastStone
  arbitrary-write proof, automated.
- Proof ladder, `misuse_triage` (N-skeptic), `cve_check` OSV novelty gate, `packager` disclosure —
  reused verbatim.

### 5. Orchestration, packaging, safety
- **Campaign queue + budget:** reuse `forge/fleet.py` + `context.Budget`; a Windows campaign is a
  background job, results stream to the proof ladder + report.
- **Windows agent packaging:** signed portable exe / service (Authenticode EV, matching Nemesis Blue).
- **Safety:** fuzz only the operator's own installed copy of the app, in a disposable Windows VM
  snapshot; never touch a live asset. Coordinated disclosure for any third-party 0-day (the CWPack
  workflow).

---

## Milestones (each proven by a concrete target)

- **M0 — Windows agent + argv-mode crash pipeline.** `WindowsBinaryTarget` + agent + Windows-exception
  `CrashInfo`. Prove: feed a known-bad TGA to **FastStone**, the agent catches the `0xC0000005`,
  native-verify confirms it un-instrumented, exploitability grades it. (Rediscover a *known* crash end
  to end — no new bug required.)
- **M1 — DynamoRIO coverage + coverage-guided loop.** Realize the coverage backend; the fuzzer keeps
  coverage-adding inputs. Prove: coverage grows on **FastStone**'s image decoders from a seed corpus.
- **M2 — persistent in-process harness (image).** Hook FastStone's TGA/PCX decoder, run persistent.
  Prove: ≥100× throughput vs argv; rediscover the arbitrary-write path and let exploitability prove
  `WRITE_WHAT_WHERE`.
- **M3 — format harnesses for PDF + office.** Add PDF (Power PDF, then Acrobat — parser-scoped
  coverage) and office (**TextMaker**). Prove: coverage on each parser; native-verified crashes.
- **M4 — verifier-gated reporting + disclosure.** Every reported bug: native-reproduced file + faulting
  instruction + exploitability grade + OSV-novelty + fix/detection. Coordinated-disclosure packet.

---

## Already done vs new (honest accounting)

- **Done (this session):** the two oracles (`native_verify`, `exploitability`), the `binary_cov`
  contract + `CoverageMap` + Frida agent JS, the proof ladder, and the **manual PoVs on these exact
  apps** (FastStone arbitrary write proven; TextMaker controlled-write repro) — proof the techniques
  land on the real targets.
- **New (this phase):** the Windows agent + execution surface, a production Windows coverage engine
  (DynamoRIO/TinyInst/Frida), Windows-exception crash parsing, WinDbg-fed exploitability, and the
  persistent per-format harnesses.

## Risks / honest caveats
- **Acrobat is huge.** Whole-app coverage is heavy; scope to the PDF parser module or it will crawl.
- **GUI dialogs / anti-debug.** Some apps pop modal dialogs or resist instrumentation; the agent needs
  a dialog-dismiss + a non-invasive attach path.
- **Persistent-mode state bleed.** Re-entering a parser without resetting global state can cause false
  crashes; native-verify is the backstop, but harness reset matters.
- **Licensing.** Fuzz only the operator's own licensed install; ship no app binaries.
- **Effort:** M0–M2 (FastStone, image) is the fast win and reuses the most RE; PDF/office (M3) is where
  the real engineering is.

## Verification (definition of done)
Point the scanner at a locally-installed **FastStone Image Viewer 8.3**, give it a small TGA seed, and
within a campaign it: grows coverage on the decoder, produces a native-verified crash, grades it
`WRITE_WHAT_WHERE` at the faulting instruction, checks OSV for novelty, and emits a disclosure packet
with the reproducing `.tga` — with zero instrumentation-only or unreachable findings reported.

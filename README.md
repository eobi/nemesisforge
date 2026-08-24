# Nemesis Forge

**An LLM fleet proposes. Deterministic oracles prove.**

Nemesis Forge is an autonomous vulnerability discovery engine with one rule wired
through its architecture: *a model may propose a candidate for any rung of the
exploitability ladder, and may certify none of them.* Certification comes from
oracles that are deterministic, independent of the proposer, and reproducible by
a third party.

That constraint is the whole design. It is also, on the evidence, the part the
field most needs.

---

## Why this rather than another agent

Discovery already scales. In the largest published effort to date, Claude Mythos
identified **23,019** vulnerability candidates; **126** were published as CVEs, and
**one** is attributed to the project itself. Of 1,061 publicly attributed AI-assisted
discoveries, **14 (1.3%)** were confirmed exploited in the wild, which is
[almost identical to the rate across all vulnerabilities](https://www.vulncheck.com/blog/anthropic-glasswing-cves).

Meanwhile maintainers are closing their doors. curl
[ended its bug bounty](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/)
in February 2026: roughly 20% of reports were AI-generated and only 5% of reported
vulnerabilities were real. libxml2 dropped embargoed reports entirely. Node.js
raised its signal floor.

AI raised the volume. It did not raise the value. The scarce thing is not a finding,
it is **a finding somebody can trust without redoing your work**, and that is what
this engine is built to produce.

| Most agents | Nemesis Forge |
|---|---|
| the **agent** is at the centre, tools serve it | the **oracle** is at the centre, the model serves it |
| a finding is accepted or rejected | a finding is placed at the rung its evidence reaches |
| rejection discards | **downgrade, never drop** |
| reports what it found | also reports what it **could not establish** |

---

## Install

```bash
git clone https://github.com/eobi/nemesisforge.git
cd nemesisforge
python -m forge doctor
```

There is nothing to install. **The engine core is standard library only.** No server,
no database, no API key. `doctor` reports which optional lenses are present and what
their absence costs, so a null result is never mistaken for a completed search.

Optional lenses: a libFuzzer-capable clang (coverage-guided discovery), lldb or gdb
(rung-4 operand evidence), `angr` (symbolic reachability), `frida` (closed-binary
coverage).

---

## Get started in five commands

Each of these runs on a clean clone, needs no API key, and returns in seconds.

```bash
# 1. What is available on this machine, and what its absence would cost you
python -m forge doctor

# 2. The machinery: eight oracles, and the rung each one can certify
python -m forge oracles

# 3. Your first finding. A real heap overflow, found in about three seconds.
python -m forge lab examples/harness_trunc.c --fuzz-time 30
```

That third command prints:

```
  rung 1   heap-buffer-overflow (WRITE)
  class      memory_safety
  evidence   coverage-guided fuzzing reached cov=5 in 130 execs and found a
             4-byte input triggering heap-buffer-overflow
  NOT shown  anything above rung 1: no oracle certified it
```

Read the last line first. The engine found a real bug and then told you the honest
limit of what it proved.

```bash
# 4. Read the evidence it kept. Nothing is hidden behind a server.
ls runs/*/ && cat runs/*/findings.json | python -m json.tool | head -40

# 5. Give it longer and watch the corpus grow
python -m forge lab examples/harness_trunc.c --fuzz-time 120 --out runs/longer
```

### Point it at your own code

Write a harness that defines `LLVMFuzzerTestOneInput`, then:

```bash
python -m forge lab path/to/your_harness.c --fuzz-time 300 --name my-target
```

Use `examples/harness_trunc.c` as the template. The only contract is that entry point.

### Useful flags

```bash
--fuzz-time N     seconds per campaign (default 60). Start at 30, go to 300+.
--out DIR         where artifacts land (default runs/)
--name NAME       what to call the target in the report
--job ID          fix the job id, so repeated runs are comparable
--provider P      attach a model; omit for the deterministic pipeline
```

---

## Using a model

The engine has two halves. **The half that certifies a finding never needs a model**,
which is why every command above works without one. A model is the *proposer*: it
writes harnesses, which is the step that decides whether there is anything to fuzz
at all.

### Which providers work

| Provider | Set this | Default model |
|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-opus-4-8` |
| `openai` | `OPENAI_API_KEY` | `gpt-5.1` |
| `gemini` | `GEMINI_API_KEY` | `gemini-2.5-pro` |
| `openrouter` | `OPENROUTER_API_KEY` | `anthropic/claude-opus-4-8` |
| `ollama` | nothing, runs locally | `qwen2.5-coder:7b` |
| `local` | nothing, any OpenAI-compatible server on `127.0.0.1:9920` | `default` |

### Set one up

```bash
# A hosted model
export ANTHROPIC_API_KEY=sk-...
python -m forge repo https://github.com/DaveGamble/cJSON --provider anthropic --minutes 5

# Or a different one, and pin the model explicitly
export OPENAI_API_KEY=sk-...
python -m forge repo https://github.com/DaveGamble/cJSON     --provider openai --model gpt-5.1 --minutes 5 --max-targets 2
```

### No key, no cloud: run the model locally

`ollama` needs no key and sends nothing off your machine. For a private codebase this
is usually the right choice.

```bash
ollama pull qwen2.5-coder:7b
python -m forge repo https://github.com/DaveGamble/cJSON --provider ollama --minutes 10
```

Point it elsewhere with `OLLAMA_HOST`, or use `--provider local` for any
OpenAI-compatible server you are already running.

### What a model changes, and what it does not

Try it without a provider first. It clones, runs the static lens, and says plainly
what it did not do (about 14 seconds):

```bash
python -m forge repo https://github.com/DaveGamble/cJSON --max-targets 1
```

```
note: no model provider selected, so no harness will be synthesised.
      The static lens will still run and report leads. To fuzz, either
      pass --provider, or write a harness and use:  python -m forge lab
```

That message exists because a silent zero-finding run is indistinguishable from a
search that genuinely found nothing.

A better model writes better harnesses, and a harness is the difference between
reaching the parser and never getting past the front door. It does **not** change what
gets certified. The oracles do not consult it, cannot be persuaded by it, and will
refuse a rung it claims but cannot evidence.

---

## The ladder

A finding is reported at the rung its evidence reaches, and no higher.

| Rung | Name | What it takes |
|---|---|---|
| 0 | UNVERIFIED | a candidate, nothing proven |
| 1 | PROVEN_FAULT | a typed sanitizer report, or a signal death |
| 2 | PROVEN_REACHABLE | the fault is reached from untrusted input |
| 3 | PROVEN_SECURITY | the fault is a memory-safety violation, not a graceful abort |
| 4 | PROVEN_PRIMITIVE | both operands of the corrupting write traced to bytes you control |
| 5 | PROVEN_EXPLOIT | a working proof of concept |
| 6 | VENDOR_READY | reproducible by the vendor, with a report they can act on |

Missing evidence lowers the rung. It never discards the finding.

---

## The oracles

Eight, each deterministic, each certifying one thing.

| Oracle | Certifies |
|---|---|
| `SanitizerOracle` | a typed sanitizer report is the evidence |
| `DifferentialOracle` | faults on the vulnerable build, clean on the patched one |
| `NativeVerifyOracle` | replays natively, so instrumentation artifacts do not survive |
| `BinaryCrashOracle` | a crash in a closed-source binary, by concrete execution |
| `DeviceCrashOracle` | an Android native crash, from a tombstone |
| `ControllabilityOracle` | how much of the faulting write the input controls |
| `ExploitabilityOracle` | the primitive at the faulting instruction |
| `SymbolicOracle` | reachability and primitive proof, via angr |

`ExploitabilityOracle` refuses to dress a null dereference up as exploitable. Anything
faulting below the first page is denial of service, by construction, not opinion.

---

## A finding this engine withdrew

`findings/` contains the CWPack heap out-of-bounds report, and it also contains a
result that did **not** survive. That is deliberate. An engine that only ever confirms
is not an engine, it is a generator with good manners. The retraction is kept with its
reason so the failure mode is visible.

Disclosure follows a 90-day window. Materials for a finding are published when the
window closes or a fix ships, whichever is first.

---

## Author

**Obi Ebuka David**
Department of Computer Science, University of Dayton

Built alongside research on triage and proof for memory-safety findings. The
measurements this engine produces are more useful with a second pair of eyes on
them, so if you use it, please get in touch.

## Citing this work

GitHub renders a **Cite this repository** button from [`CITATION.cff`](CITATION.cff).
For a bibliography:

```bibtex
@software{david_nemesisforge_2026,
  author  = {David, Obi Ebuka},
  title   = {{Nemesis Forge}: an {LLM} fleet proposes, deterministic oracles prove},
  year    = {2026},
  version = {1.0.0},
  url     = {https://github.com/eobi/nemesisforge},
  license = {MIT},
  note    = {Department of Computer Science, University of Dayton}
}
```

Plain text:

> David, Obi Ebuka (2026). *Nemesis Forge: an LLM fleet proposes, deterministic
> oracles prove* (version 1.0.0) [Computer software]. Department of Computer
> Science, University of Dayton. https://github.com/eobi/nemesisforge

**Cite the commit, not the branch.** This engine produces measurements, and a
measurement is only reproducible against a fixed version of the thing that produced
it. Include the short SHA of the commit you ran:

```bibtex
  note = {Commit 83454ef}
```

If you need a DOI for a journal that requires one, enable the Zenodo integration for
this repository and cut a release; Zenodo mints a DOI per release and reads the
metadata from `CITATION.cff` directly.

## Licence

MIT. See [LICENSE](LICENSE).

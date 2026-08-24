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

## Use it

**Run a campaign against a harness you supply.** No model required, because the half
of the engine that certifies a finding never needed one.

```bash
python -m forge lab examples/harness_trunc.c --fuzz-time 60
```

**Point it at a repository.** Harness synthesis is the model's job, so this path wants
a provider. Without one the static lens still runs and reports leads.

```bash
python -m forge repo https://github.com/example/lib --provider openai --minutes 5
```

**Inspect the machinery.**

```bash
python -m forge oracles     # the eight oracles and the rung each certifies
python -m forge doctor      # what is available, and what its absence costs
```

Worked examples with real captured output: [`docs/CLI.md`](docs/CLI.md).

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
MSc Computer Science, Department of Computer Science, University of Dayton

Built alongside research on triage and proof for memory-safety findings. If you use
this engine in academic work, please cite the repository and get in touch: the
measurements it produces are more useful with a second pair of eyes on them.

## Licence

MIT. See [LICENSE](LICENSE).

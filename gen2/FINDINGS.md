# Second-corpus experiment: findings

Generated with Nemesis Forge against staged pre-fix versions of open-source C
libraries. Purpose: test whether the Ladder paper's triage signal generalises beyond
FastStone, without waiting on a second corpus from Fraunhofer.

## Result: the signal does not transfer

| Measurement | macro-F1 | Trustworthy |
|---|---|---|
| Within FastStone, format-specific features (39) | 0.845 | yes |
| Within FastStone, container-agnostic features (24) | **0.676** | yes |
| FastStone -> Forge transfer, absolute features | 0.147 | yes, and it is a failure |
| FastStone -> Forge transfer, scale-free features | 0.162 | yes, and it is a failure |
| Forge -> FastStone transfer | 0.037 | equals majority; no transfer |
| Majority baseline on Forge | 0.133 | - |
| Size-only, FastStone -> Forge | 0.241 | beats our method |
| Within Forge | 0.992 | **NO - artefact, see below** |

Two conclusions, one positive and one negative.

**Positive.** Dropping every format-specific field costs 0.845 -> 0.676 on FastStone,
still far above the 0.370 deployed-label baseline. The principle is not about image
geometry; it is about a declared size being inconsistent with the bytes present.

**Negative.** Trained on FastStone, the method does not transfer to an independently
generated corpus. It scores below a file-size heuristic (0.241) and barely above the
constant predictor (0.133). In the reverse direction it equals the constant predictor
exactly. Until shown otherwise the method should be read as target-specific.

## Why the within-Forge 0.992 must not be quoted as a success

In this corpus class is perfectly determined by library, and library by container:
cJSON = JSON text = READ, nanosvg = SVG = WRITE, frozen = large bracket files = DoS.
A model scoring 0.992 has learned which format it is looking at, which fixes the class
by construction. It is a measurement of the confound, not of the principle.

## Rescue hypotheses tested and rejected

1. *The training corpus is class-imbalanced (FastStone is 5.9% READ), so the model
   never learned READ.* Balancing to 63 per class made transfer worse: 0.352 -> 0.214,
   and WRITE accuracy collapsed from 0.775 to 0.050.
2. *The features are scale-dependent; a threshold learned on 52-byte binary TGAs cannot
   apply to 20 KB JSON.* Restricting to ratios, fractions, flags and per-byte counts
   moved transfer from 0.147 to 0.162. Not a rescue.

## What the differential oracle did, and it worked

Of 639 fuzzer-found crashes replayed against both builds, **331 were rejected because
the patched build also faults**, i.e. they are not the bug the target was staged for.
For nanosvg it isolated exactly the 8 genuine CVE-2019-1000032 crashes out of 39. This
is the paper's central mechanism, validated on a corpus it had never seen. Without it,
half of this corpus would have been mislabelled.

## Why fuzzing could not build a class-diverse corpus

libFuzzer rewards small crashing inputs. Once it finds the easiest bug in a target it
minimises away the structure the other bugs need, and every directed run collapsed back
to heap-buffer-overflow READ:

- `frozen`, seeded for recursion depth: 150/150 crashes were heap over-reads, and the
  patched build faults too, because the fuzzer found the unfixed `json_get_escape_len`
  bug rather than the recursion bug.
- `nanosvg`, seeded with long scanset runs: 31/39 were heap over-reads; only 8 were the
  stack write the seeds targeted.
- Default `max_len` is 4096; the recursion bug needs roughly 20,000 nesting levels.

The WRITE and DoS classes therefore had to be **constructed and individually verified
against the sanitizer**, not discovered. This is weaker evidence than fuzzer-found data
and any write-up must say so.

## Corpus as built

600 crashes, 3 libraries: READ 300 (fuzzer-found, clean differential),
WRITE 150 (constructed, clean differential), DoS 150 (constructed; the patched build
also faults because the frozen recursion bug is unfixed upstream, recorded per row).

## What would actually test generality

Targets where the wanted class is the *easiest* bug in that target, or harnesses gated
to a single code path so the fuzzer cannot escape to an easier one. Several libraries
must contribute each class, otherwise class and target stay confounded and no
held-out-target protocol is valid.

## Files

`gen_classes.py` construct+verify, `label.py` sanitizer labelling, `features2.py`
container-agnostic features, `eval_cross.py` transfer with --balance and --scale-free
controls, `eval2.py` leave-one-target-out, `labels_final.csv`, `features_final.csv`,
`logs/cross_final.txt`.

## A within-library test that must NOT be reported as a result

To check whether the within-Forge 0.992 was purely container identification, we built a
within-library test: frozen only, READ vs DoS, both classes constructed by the same
pipeline, and the READ inputs padded so the two size distributions match (READ median
88,994 bytes vs DoS 76,760, near-identical ranges). Size-only scores 0.388 against a
0.333 majority, confirming the size confound was removed.

The full feature set then scores 0.997. That number is meaningless. The tree uses a
single feature, `unclosed_quote`: every constructed READ carries an unterminated string,
because the frozen over-read is reached through a dangling escape inside one, and every
constructed DoS is bracket nesting with no quotes at all. We built the classes with
structurally different markers and then measured a feature that detects those markers.

This is not repairable by better construction. For this pair of bugs the triggering
structures genuinely are different kinds of object, so any feature set separates them
trivially, and the experiment cannot distinguish "the method works" from "the constructs
differ". The pair should not be used for a discrimination claim.

It is the third circularity failure in this line of work (the original TriageBench
generator, the calibration of its replacement, and this). That is the argument for the
scorer's circularity guard being a permanent fixture rather than a one-off fix.

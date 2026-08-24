# W1 result: the generality question, settled

Run 2026-08-19/20 on Docker with amd64 emulation on an arm64 host.

## What was built

| | |
|---|---|
| ARVO records read | 4,993 |
| Projects meeting >=2 classes and >=3 bugs | 126 |
| Projects selected | 12 |
| Bugs attempted | 279 |
| Reproduced with PoC | **274** (5 images absent upstream) |
| Labelled from the sanitizer report | **210** |
| Differential holds (fixed build clean) | **210 / 210** |
| Projects with >=2 classes | **11 / 11** |

The Forge second corpus could not answer the generality question because each staged
target contained exactly one bug, so class was perfectly determined by target. ARVO
removes that by construction: every class is present in training no matter which
project is held out.

## A parser bug caught before it produced a fake corpus

The first labelling run reported 74 bugs, **all DoS**, and 0/10 projects with two or
more classes. The cause was in `03-label.py`:

```python
RE_KIND = re.compile(r"(?:AddressSanitizer|ERROR):\s*([a-zA-Z\-]+)")
```

The report line is `==7==ERROR: AddressSanitizer: heap-buffer-overflow`. `ERROR:`
matches first, so group(1) captured the string `AddressSanitizer` itself. Every
buffer-overflow report was therefore classified `unclassifiable`, and only reports
containing the literal `SEGV` survived, all of which are DoS.

136 reports carried an explicit `READ of size` or `WRITE of size` line and produced
zero READ or WRITE labels. Row counts alone would not have revealed this; only reading
the reports against the parser did.

## The result

Leave-one-project-out, 24 container-agnostic features, 11 folds, none skipped:

| | macro-F1 |
|---|---|
| majority-class predictor | **0.202** |
| size-only heuristic | **0.214** |
| ours | **0.202** |

Size-weighted over all 210 bugs: majority 0.209, size-only 0.278, ours 0.250.
Restricted to the five folds with n>=15 (179 bugs), the non-degenerate read:
majority 0.215, size-only 0.284, ours **0.249**, and ours beats size-only in
**1 of 5** large folds.

**The method does not transfer across projects.** On an unconfounded corpus it equals
a constant predictor and loses to file size, which is the same shape as the FastStone
to Forge cross-corpus result (0.147 against 0.241 for size) and now without the
confound that made that result contestable.

## What this does and does not license

**Does.** The transfer failure is now established on 11 independent projects with a
valid held-out protocol, 210 differentially-confirmed bugs, and every class present in
training for every fold. The earlier hedge, that the second corpus confounded class
with library, no longer applies.

**Does not.** These are the 24 container-agnostic features, not the 39 FastStone
features, which cannot apply to mruby or njs. So this measures whether the *principle*
transfers, not whether that specific model does. It is also OSS-Fuzz Linux/ASan rather
than Windows/page-heap, and 6 of 11 folds are small enough that macro-F1 on them is
noisy.

**The claim it supports:** ship the procedure and a few labels, not a pretrained model.
That is what the label-efficiency table already argued from the other direction, and
this is the strongest available evidence for it.

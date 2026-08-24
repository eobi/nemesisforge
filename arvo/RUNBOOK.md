# W1: the generality corpus, via ARVO

## Why this and not more hand-staging

The Forge attempt failed for a structural reason, not a tooling one. Each hand-staged
target contained exactly one bug, so the bug class was perfectly determined by the
target, and holding out a target removed the only source of its class. No valid
held-out-target protocol existed.

ARVO removes that by construction: 6,100+ reproducible OSS-Fuzz vulnerabilities across
311 projects, with many projects appearing repeatedly under different crash types, and
a vulnerable/fixed image pair per bug. Selection here optimises for exactly that
property rather than for interesting bugs.

Source: https://github.com/n132/ARVO  (paper: arXiv 2408.02153)
Metadata: https://github.com/n132/ARVO-Meta

## Requirements

x86_64 Linux. This is the hard constraint and the reason none of it runs on the Mac:
ARVO images are x86-only. Ubuntu 22.04/24.04, Docker, 150-200 GB disk, 8+ vCPU.

## Steps

```bash
./00-provision.sh                      # docker + tools; refuses to run on non-x86_64

git clone --depth 1 https://github.com/n132/ARVO-Meta
python3 01-select-targets.py ARVO-Meta/meta -o selected.json
#   keeps only projects with >= 2 distinct classes and >= 3 bugs.
#   Read its crash-type table before continuing: it prints how each raw OSS-Fuzz
#   crash string was mapped to WRITE / READ / DoS, and a bad mapping poisons everything.

./02-reproduce.sh selected.json corpus 0
#   pulls n132/arvo:<id>-vul and -fix, runs both, keeps the two sanitizer reports and
#   the PoC, then deletes the images (they are large). Start with a small max, e.g.
#   ./02-reproduce.sh selected.json corpus 20, and confirm PoCs are actually extracted
#   before committing to the full run.

python3 03-label.py corpus -o labels_arvo.csv --selected selected.json
#   class from the vulnerable report, differential from the fixed one. Prints the
#   per-project class table: that table decides whether the experiment is valid.

python3 features2.py labels_arvo.csv -o features_arvo.csv
python3 04-evaluate.py features_arvo.csv
#   leave-one-project-out. Skips folds whose held-out classes are absent from training
#   rather than averaging over degenerate ones.
```

## What counts as success

Not a high score. Success is a corpus where `03-label.py` reports most projects
carrying two or more classes, so that `04-evaluate.py` has valid folds. If it reports
mostly single-class projects, the corpus is the wrong shape and no number from it means
anything, exactly as in the Forge attempt.

## Known uncertainty

`02-reproduce.sh` discovers the PoC path inside each image rather than assuming one,
because that path is not documented anywhere I could verify. If extraction fails on the
first small batch, inspect an image directly:

```bash
docker run --rm --entrypoint /bin/sh n132/arvo:<id>-vul -c 'ls -la /tmp /; cat /bin/arvo'
```

and fix the candidate list at the top of the extraction block.

Field names in ARVO-Meta are also read defensively (`localId`/`local_id`/`id`,
`crash_type`/`crashType`). If `01-select-targets.py` reports zero usable records, print
one record and adjust `field()`.

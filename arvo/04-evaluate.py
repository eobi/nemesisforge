#!/usr/bin/env python3
"""
The generality test, run properly for the first time.

Leave-one-project-out: train on every project except P, predict on P, with no crash
from P ever seen. This is only meaningful when the held-out project's classes are all
present in the training data, so the script checks that per fold and reports folds it
had to skip rather than quietly averaging over degenerate ones. That check is the whole
reason the earlier Forge attempt was invalid.

Baselines: the majority class of the training set, and file size alone. Size matters
because on FastStone a size heuristic reached most of the score and we could not tell
whether it was the vulnerability or the harness. A corpus drawn from 300+ upstream
projects, fuzzed by OSS-Fuzz rather than by us, is the instrument that settles it.

Usage: python3 04-evaluate.py features_arvo.csv
"""
import argparse, collections, csv, random, statistics, sys

CLASSES = ("WRITE", "READ", "DoS")
META = ("target", "filename", "cls")


def build_tree(Xtr, ytr, depth, min_leaf):
    import wo_eval as W
    if len(set(ytr)) < 2:
        return None, collections.Counter(ytr).most_common(1)[0][0]
    return W.build(Xtr, ytr, list(range(len(Xtr))), 0, depth, min_leaf), None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("features", nargs="?", default="features_arvo.csv")
    ap.add_argument("--ladder", default=None,
                    help="path to the ladder-dont-label dir (for wo_eval/robustness)")
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--min-leaf", type=int, default=10)
    a = ap.parse_args()
    if a.ladder:
        sys.path.insert(0, a.ladder)
    import wo_eval as W

    rows = list(csv.DictReader(open(a.features)))
    names = [k for k in rows[0] if k not in META]
    X = [[float(r[k]) for k in names] for r in rows]
    y = [r["cls"] for r in rows]
    tg = [r["target"] for r in rows]
    projects = sorted(set(tg))
    size_i = names.index("size") if "size" in names else 0

    print(f"corpus: {len(y)} bugs, {len(projects)} projects, {len(names)} features")
    print("class distribution:", dict(collections.Counter(y)), "\n")

    def mf(pred, gold):
        present = [c for c in CLASSES if c in set(gold)]
        return statistics.mean(W.prf(pred, gold, c)[2] for c in present)

    print(f"  {'held-out project':<26}{'n':>5}{'majority':>10}{'size':>8}{'ours':>8}"
          f"{'acc':>8}  note")
    agg, skipped = [], 0
    for p in projects:
        tr = [i for i in range(len(y)) if tg[i] != p]
        te = [i for i in range(len(y)) if tg[i] == p]
        if not tr or not te:
            continue
        trcls, tecls = set(y[i] for i in tr), set(y[i] for i in te)
        missing = tecls - trcls
        if missing:
            print(f"  {p:<26}{len(te):>5}{'':>10}{'':>8}{'':>8}{'':>8}  "
                  f"SKIPPED: training set lacks {','.join(sorted(missing))}")
            skipped += 1
            continue
        Xtr = [X[i] for i in tr]; ytr = [y[i] for i in tr]
        Xte = [X[i] for i in te]; yte = [y[i] for i in te]
        maj = collections.Counter(ytr).most_common(1)[0][0]
        m_maj = mf([maj] * len(yte), yte)
        t_s, const = build_tree([[r[size_i]] for r in Xtr], ytr, a.depth, a.min_leaf)
        p_size = ([const] * len(Xte) if t_s is None
                  else [W.predict(t_s, [r[size_i]]) for r in Xte])
        t_o, const = build_tree(Xtr, ytr, a.depth, a.min_leaf)
        p_ours = ([const] * len(Xte) if t_o is None
                  else [W.predict(t_o, r) for r in Xte])
        m_size, m_ours = mf(p_size, yte), mf(p_ours, yte)
        acc = sum(1 for q, g in zip(p_ours, yte) if q == g) / len(yte)
        print(f"  {p:<26}{len(te):>5}{m_maj:>10.3f}{m_size:>8.3f}{m_ours:>8.3f}{acc:>8.3f}")
        agg.append((m_maj, m_size, m_ours, acc))

    if agg:
        cols = list(zip(*agg))
        print(f"\n  {'MEAN over ' + str(len(agg)) + ' valid folds':<26}{'':>5}"
              f"{statistics.mean(cols[0]):>10.3f}{statistics.mean(cols[1]):>8.3f}"
              f"{statistics.mean(cols[2]):>8.3f}{statistics.mean(cols[3]):>8.3f}")
        print(f"  folds skipped as degenerate: {skipped}")
        print(f"\n  headline: leave-one-project-out macro-F1 "
              f"{statistics.mean(cols[2]):.3f} against {statistics.mean(cols[0]):.3f} "
              f"majority and {statistics.mean(cols[1]):.3f} size-only.")
    else:
        print("\n  no valid folds. The corpus still does not support the test.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

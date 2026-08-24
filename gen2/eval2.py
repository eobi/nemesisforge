#!/usr/bin/env python3
"""
The generality experiment: does the signal transfer to a target the model has never
seen?

Within-target cross-validation answers a weak question, because a model can learn one
program's quirks. The question Steven asked, and the one the FastStone paper cannot
answer, is whether a method trained on some targets predicts on a different one. So the
headline protocol here is leave-one-target-out: train on every target except T, test on
T, and never let a single crash from T inform the model.

Reported for each held-out target:
  majority     the trivial predictor, for scale
  size-only    file size and nothing else, because on the FastStone corpus a size
               heuristic alone reached most of the score and we could not tell whether
               that was the bug or the harness. A second corpus built by a different
               fuzzer with different seeds is exactly the instrument that settles it.
  ours         the container-agnostic features of features2.py

A caveat this script prints rather than hides: if a held-out target contains only one
class, leave-one-target-out on it is close to degenerate, and its numbers should be
read as "did the model get the class right at all", not as a discrimination score.

Usage: python3 eval2.py features2.csv
"""
import argparse, collections, csv, os, random, statistics, sys

LADDER = os.path.expanduser(
    "~/Desktop/Research/Ladder-Dont-Label/ladder-dont-label")
sys.path.insert(0, LADDER)
import wo_eval as W          # the same CART and metrics the paper uses
import robustness as R

CLASSES = ("WRITE", "READ", "DoS")
META = ("target", "filename", "cls")

# Two fuzz runs against the same library are NOT two targets. Holding out one while
# training on the other would leak the same code across the split, which is exactly
# the mistake this experiment exists to avoid. Normalise to the library.
LIBRARY = {
    "cjson_minify": "cJSON", "cjson_parsestr": "cJSON",
    "nanosvg_color": "nanosvg", "nanosvg_write": "nanosvg",
    "frozen_dos": "frozen", "faststone": "faststone",
}
def lib(t): return LIBRARY.get(t, t)



def load(path):
    rows = list(csv.DictReader(open(path)))
    names = [k for k in rows[0] if k not in META]
    X = [[float(r[k]) for k in names] for r in rows]
    y = [r["cls"] for r in rows]
    t = [lib(r["target"]) for r in rows]
    return X, y, t, names


def fit_predict(Xtr, ytr, Xte, depth=5, min_leaf=10):
    if len(set(ytr)) < 2:
        return [collections.Counter(ytr).most_common(1)[0][0]] * len(Xte)
    tree = W.build(Xtr, ytr, list(range(len(Xtr))), 0, depth, min_leaf)
    return [W.predict(tree, x) for x in Xte]


def scores(pred, gold):
    present = [c for c in CLASSES if c in set(gold)]
    return (statistics.mean(W.prf(pred, gold, c)[2] for c in present),
            sum(1 for p, g in zip(pred, gold) if p == g) / len(gold))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("features", nargs="?", default="features2.csv")
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--min-leaf", type=int, default=10)
    a = ap.parse_args()

    X, y, tg, names = load(a.features)
    targets = sorted(set(tg))
    print(f"corpus: {len(y)} crashes, {len(targets)} targets, {len(names)} features "
          f"(no format-specific fields)\n")
    print(f"  {'target':<18}{'n':>6}  class distribution")
    for t in targets:
        d = collections.Counter(y[i] for i in range(len(y)) if tg[i] == t)
        print(f"  {t:<18}{sum(d.values()):>6}  " +
              ", ".join(f"{k}={v}" for k, v in d.most_common()))
    print(f"  {'ALL':<18}{len(y):>6}  " +
          ", ".join(f"{k}={v}" for k, v in collections.Counter(y).most_common()))

    size_i = names.index("size") if "size" in names else 0

    print("\n" + "=" * 70)
    print("A. WITHIN-TARGET (grouped by identical feature vector)")
    print("=" * 70)
    print(f"  {'target':<18}{'macro-F1':>11}{'acc':>9}")
    for t in targets:
        idx = [i for i in range(len(y)) if tg[i] == t]
        Xs = [X[i] for i in idx]; ys = [y[i] for i in idx]
        if len(set(ys)) < 2:
            print(f"  {t:<18}{'single-class':>11}{'':>9}")
            continue
        g = R.feature_groups(Xs)
        rng = random.Random(1000)
        oof = R.cv(Xs, ys, R.grouped_folds(g, ys, 5, rng), a.depth, a.min_leaf)
        keep = [i for i in range(len(ys)) if oof[i] is not None]
        m, acc = scores([oof[i] for i in keep], [ys[i] for i in keep])
        print(f"  {t:<18}{m:>11.3f}{acc:>9.3f}")

    print("\n" + "=" * 70)
    print("B. LEAVE-ONE-TARGET-OUT  (the generality test)")
    print("=" * 70)
    print(f"  {'held-out target':<18}{'majority':>10}{'size-only':>11}{'ours':>9}"
          f"{'ours acc':>10}  note")
    agg = []
    for t in targets:
        tr = [i for i in range(len(y)) if tg[i] != t]
        te = [i for i in range(len(y)) if tg[i] == t]
        if not tr or not te:
            continue
        Xtr = [X[i] for i in tr]; ytr = [y[i] for i in tr]
        Xte = [X[i] for i in te]; yte = [y[i] for i in te]

        maj = collections.Counter(ytr).most_common(1)[0][0]
        m_maj, _ = scores([maj] * len(yte), yte)
        p_size = fit_predict([[r[size_i]] for r in Xtr], ytr,
                             [[r[size_i]] for r in Xte], a.depth, a.min_leaf)
        m_size, _ = scores(p_size, yte)
        p_ours = fit_predict(Xtr, ytr, Xte, a.depth, a.min_leaf)
        m_ours, acc = scores(p_ours, yte)
        note = "single-class target" if len(set(yte)) < 2 else ""
        print(f"  {t:<18}{m_maj:>10.3f}{m_size:>11.3f}{m_ours:>9.3f}{acc:>10.3f}  {note}")
        agg.append((m_maj, m_size, m_ours, acc))

    if agg:
        print(f"  {'MEAN':<18}" + "".join(
            f"{statistics.mean(c):>10.3f}" if i == 0 else
            f"{statistics.mean(c):>11.3f}" if i == 1 else
            f"{statistics.mean(c):>9.3f}" if i == 2 else
            f"{statistics.mean(c):>10.3f}"
            for i, c in enumerate(zip(*agg))))

    print("\n" + "=" * 70)
    print("C. THE FILE-SIZE CONFOUND, ON A DIFFERENT HARNESS")
    print("=" * 70)
    byc = collections.defaultdict(list)
    for i in range(len(y)):
        byc[y[i]].append(X[i][size_i])
    for c in CLASSES:
        if not byc[c]:
            continue
        v = sorted(byc[c])
        print(f"  {c:<6} n={len(v):5d}  median={statistics.median(v):9.1f}  "
              f"mean={statistics.mean(v):9.1f}")
    print("  On the FastStone corpus, size alone reached 0.684 macro-F1 and we could")
    print("  not tell whether that was the vulnerability or the fuzzer's seeds. Compare")
    print("  the size-only column above: if it does NOT transfer here, the FastStone")
    print("  size signal was an artefact of how that corpus was generated.")


if __name__ == "__main__":
    main()

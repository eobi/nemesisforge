#!/usr/bin/env python3
"""
Real-corpus evaluation: can the exploitability class of a crash be predicted from the
input's decoder-relevant header arithmetic alone?

Protocol
--------
  target      : RCA exploitability class in {WRITE, READ, DoS}, from the provider's
                independent per-crash root-cause analysis (ground-truth.csv).
  features    : structural, input-derived only (features.py). No filename fields, no
                crash site, no fault label, no execution. The crash site and the fuzzer
                fault label are used ONLY as baselines, never as inputs to the model.
  split       : stratified k-fold cross-validation, repeated over several seeds.
                Every number below is out-of-fold: nothing is scored on data it trained on.
  model       : a depth-limited CART (gini) implemented here in the standard library,
                so the artifact has no dependencies and is byte-reproducible.

Baselines
---------
  majority     : always predict the most common class.
  symptom      : the fuzzer's own fault label (the conventional pipeline).
  crash-site   : predict from the faulting module (in-module vs page-heap-relocated).

Usage: python3 wo_eval.py [--folds 5] [--seeds 10] [--depth 5]
"""
import csv, os, re, sys, math, random, argparse, collections, statistics

HERE = os.path.dirname(os.path.abspath(__file__))
WRITE_RC = {"Crash 01", "Crash 04", "Crash 05", "Crash 07"}
READ_RC = {"Crash 03", "Crash 08"}
CLASSES = ("WRITE", "READ", "DoS")
FNAME = re.compile(r"^fsviewer-([A-Z_]+)_c0000005__([a-z0-9_]+)\+([0-9a-f]+)__", re.I)

DROP = {"filename", "container"}  # container is one-hot'd separately


# ---------------------------------------------------------------- data

def load(features_csv, gt_csv):
    gt = {r["filename"]: (r["root_cause"], r["problem_class"])
          for r in csv.DictReader(open(gt_csv))}
    feats = list(csv.DictReader(open(features_csv)))
    X, y, base = [], [], []
    names = None
    for r in feats:
        fn = r["filename"]
        if fn not in gt:
            continue
        rc, pclass = gt[fn]
        cls = "WRITE" if rc in WRITE_RC else "READ" if rc in READ_RC else "DoS"
        vec, nm = [], []
        for k, v in r.items():
            if k in DROP:
                continue
            vec.append(float(v)); nm.append(k)
        for c in ("TGA", "PCX", "OTHER"):          # one-hot the container
            vec.append(1.0 if r["container"] == c else 0.0); nm.append(f"container={c}")
        if names is None:
            names = nm
        X.append(vec); y.append(cls)
        m = FNAME.match(fn)
        base.append({"fault": (m.group(1).upper() if m else "?"),
                     "module": (m.group(2).lower() if m else "?"),
                     # Application Verifier's own exploitability classification, as
                     # recorded in the RCA. This is a DIFFERENT labeller from the
                     # fuzzer bucket above, and it is the one the paper's headline is
                     # about: AVRF calls these NULL_POINTER_WRITE, i.e. "null-deref DoS".
                     "avrf": pclass})
    return X, y, base, names


# ---------------------------------------------------------------- metrics

def prf(pred, gold, cls):
    tp = sum(1 for p, g in zip(pred, gold) if p == cls and g == cls)
    fp = sum(1 for p, g in zip(pred, gold) if p == cls and g != cls)
    fn = sum(1 for p, g in zip(pred, gold) if p != cls and g == cls)
    P = tp / (tp + fp) if tp + fp else 0.0
    R = tp / (tp + fn) if tp + fn else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    return P, R, F


def macro_f1(pred, gold):
    return statistics.mean(prf(pred, gold, c)[2] for c in CLASSES)


# ---------------------------------------------------------------- CART

class Node:
    __slots__ = ("feat", "thr", "left", "right", "label")

    def __init__(self, label=None):
        self.feat = self.thr = self.left = self.right = None
        self.label = label


def gini(counts, n):
    return 1.0 - sum((c / n) ** 2 for c in counts.values()) if n else 0.0


def build(X, y, idx, depth, max_depth, min_leaf):
    counts = collections.Counter(y[i] for i in idx)
    node = Node(counts.most_common(1)[0][0])
    if depth >= max_depth or len(idx) < 2 * min_leaf or len(counts) == 1:
        return node

    n = len(idx)
    parent = gini(counts, n)
    best = (0.0, None, None)  # (gain, feature, threshold)

    for f in range(len(X[0])):
        vals = sorted({X[i][f] for i in idx})
        if len(vals) < 2:
            continue
        # candidate thresholds at midpoints; cap the count so wide integer ranges
        # (e.g. row_bytes) do not blow up the search
        cands = [(vals[k] + vals[k + 1]) / 2 for k in range(len(vals) - 1)]
        if len(cands) > 64:
            step = len(cands) / 64.0
            cands = [cands[int(k * step)] for k in range(64)]
        for t in cands:
            lc, rc = collections.Counter(), collections.Counter()
            for i in idx:
                (lc if X[i][f] <= t else rc)[y[i]] += 1
            ln, rn = sum(lc.values()), sum(rc.values())
            if ln < min_leaf or rn < min_leaf:
                continue
            gain = parent - (ln / n) * gini(lc, ln) - (rn / n) * gini(rc, rn)
            if gain > best[0]:
                best = (gain, f, t)

    if best[1] is None or best[0] <= 1e-12:
        return node
    _, f, t = best
    left = [i for i in idx if X[i][f] <= t]
    right = [i for i in idx if X[i][f] > t]
    node.feat, node.thr = f, t
    node.left = build(X, y, left, depth + 1, max_depth, min_leaf)
    node.right = build(X, y, right, depth + 1, max_depth, min_leaf)
    return node


def predict(node, x):
    while node.feat is not None:
        node = node.left if x[node.feat] <= node.thr else node.right
    return node.label


# ---------------------------------------------------------------- protocol

def stratified_folds(y, k, rng):
    by = collections.defaultdict(list)
    for i, c in enumerate(y):
        by[c].append(i)
    folds = [[] for _ in range(k)]
    for c, idxs in by.items():
        rng.shuffle(idxs)
        for j, i in enumerate(idxs):
            folds[j % k].append(i)
    return folds


def run(folds_k, seeds, max_depth, min_leaf, quiet=False):
    X, y, base, names = load(os.path.join(HERE, "features.csv"),
                             os.path.join(HERE, "ground-truth.csv"))
    n = len(y)
    dist = collections.Counter(y)
    if not quiet:
        print(f"mapped inputs: {n}   class distribution: "
              + ", ".join(f"{c}={dist[c]} ({100*dist[c]/n:.1f}%)" for c in CLASSES))
        print(f"features: {len(names)}   protocol: {folds_k}-fold stratified CV "
              f"x {seeds} seeds   model: CART depth<={max_depth}, min_leaf={min_leaf}\n")

    # ---- baselines (deterministic, no training, scored on the whole corpus)
    maj = dist.most_common(1)[0][0]
    b_major = [maj] * n
    b_symptom = ["WRITE" if "WRITE" in b["fault"] else "READ" if "READ" in b["fault"]
                 else "DoS" for b in base]
    b_site = ["WRITE" if b["module"] == "unknown" else "DoS" for b in base]

    # ---- ours: out-of-fold predictions, repeated over seeds
    per_seed = []
    for s in range(seeds):
        rng = random.Random(1000 + s)
        folds = stratified_folds(y, folds_k, rng)
        oof = [None] * n
        for k in range(folds_k):
            test = folds[k]
            train = [i for j, f in enumerate(folds) if j != k for i in f]
            tree = build(X, y, train, 0, max_depth, min_leaf)
            for i in test:
                oof[i] = predict(tree, X[i])
        per_seed.append(oof)

    def agg(cls):
        rows = [prf(oof, y, cls) for oof in per_seed]
        return tuple(statistics.mean(r[j] for r in rows) for j in range(3)), \
               tuple((statistics.stdev(r[j] for r in rows) if len(rows) > 1 else 0.0)
                     for j in range(3))

    if not quiet:
        print(f"{'method':<34}{'WRITE P':>9}{'R':>8}{'F1':>8}{'macro-F1':>11}")
        for nm, p in (("majority class", b_major),
                      ("fuzzer symptom label", b_symptom),
                      ("crash site (module)", b_site)):
            P, R, F = prf(p, y, "WRITE")
            print(f"{nm:<34}{P:>9.3f}{R:>8.3f}{F:>8.3f}{macro_f1(p, y):>11.3f}")
        (P, R, F), (sP, sR, sF) = agg("WRITE")
        mf = statistics.mean(macro_f1(o, y) for o in per_seed)
        sm = statistics.stdev(macro_f1(o, y) for o in per_seed) if seeds > 1 else 0.0
        print(f"{'input-structure CART (ours)':<34}{P:>9.3f}{R:>8.3f}{F:>8.3f}{mf:>11.3f}")
        print(f"{'  +/- sd over seeds':<34}{sP:>9.3f}{sR:>8.3f}{sF:>8.3f}{sm:>11.3f}")

        print("\nper-class, out-of-fold (mean over seeds):")
        for c in CLASSES:
            (P, R, F), _ = agg(c)
            print(f"  {c:<6} P={P:.3f}  R={R:.3f}  F1={F:.3f}   (support {dist[c]})")

        # what the model actually keys on, from a tree fit on everything
        full = build(X, y, list(range(n)), 0, max_depth, min_leaf)
        used = []

        def walk(nd, d=0):
            if nd.feat is None:
                return
            used.append((d, names[nd.feat], nd.thr))
            walk(nd.left, d + 1); walk(nd.right, d + 1)
        walk(full)
        print("\nsplits chosen by a tree fit on the full corpus (depth, feature, threshold):")
        for d, nm, t in used[:12]:
            print(f"  {'  '*d}d{d}  {nm} <= {t:g}")

        # the paper's headline, recomputed, with the labeller named correctly
        nullw = [i for i, b in enumerate(base)
                 if b["avrf"].startswith("NULL_POINTER_WRITE")]
        ex = sum(1 for i in nullw if y[i] == "WRITE")
        print(f"\nApplication Verifier labels {len(nullw)} crashes NULL_POINTER_WRITE "
              f"('null-deref DoS');\n  their true class is WRITE in {ex}/{len(nullw)} "
              f"cases ({100*ex/len(nullw):.1f}%).")
        # and how our predictor does on exactly that AVRF-dismissed subset
        rec = []
        for oof in per_seed:
            tp = sum(1 for i in nullw if y[i] == "WRITE" and oof[i] == "WRITE")
            rec.append(tp / ex if ex else 0.0)
        print(f"  of those {ex} AVRF-dismissed exploitable writes, ours recovers "
              f"{statistics.mean(rec)*100:.1f}% (sd {statistics.stdev(rec)*100:.1f}) "
              f"out-of-fold.")

    return per_seed, y


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--min-leaf", type=int, default=10)
    a = ap.parse_args()
    run(a.folds, a.seeds, a.depth, a.min_leaf)

#!/usr/bin/env python3
"""
Robustness suite for the real-corpus result.

A fuzzer corpus is full of siblings: inputs mutated from the same seed that differ in
bytes but not in any field a decoder reads. If those siblings straddle a train/test
split, a model can score well by memorising a feature vector rather than by learning
the decoder arithmetic. Everything here exists to find out whether that is what
happened, and to keep the comparison against conventional triage honest.

  1. duplicate census      - exact byte duplicates, identical feature vectors, and
                             identical decoder-visible header prefixes.
  2. grouped CV            - four protocols of increasing strictness. Note that
                             grouping by header prefix does NOT contain grouping by
                             feature vector: the two relations cross-cut, so neither
                             alone is strictest. The honest control is the JOIN of
                             both, and that is what we report as the headline.
  3. fair baseline         - the identical learner given only what a conventional
                             pipeline has (the crash symptom and the crash site).
                             Comparing our model against a hand-coded rule instead
                             would flatter it, because the fuzzer's four buckets are
                             all read/write fault types and cannot express a third
                             class at all.
  4. learning curve        - out-of-fold score against training-set size.
  5. feature ablation      - drop each feature family and re-measure.
  6. capacity sweep        - depth AND minimum leaf size. Sweeping depth alone proves
                             nothing here, because min_leaf binds first on 1,070 rows.
  7. confusion matrix      - where the errors actually are.
  8. size confound         - the distribution of file size per class, because file
                             size alone is a large part of the signal and may be a
                             property of how the corpus was generated.

Usage: python3 robustness.py [--seeds 10] [--folds 5]
"""
import argparse, collections, csv, hashlib, os, random, statistics
import wo_eval as W

CORPUS = os.path.expanduser("~/Desktop/Arts Demands/fsviewer/fsviewer-crashes")
CLASSES = W.CLASSES


# ------------------------------------------------------------------ grouping

def feature_groups(X):
    """Group index -> ids of records sharing an identical feature vector."""
    g, out = {}, []
    for x in X:
        k = tuple(x)
        if k not in g:
            g[k] = len(g)
        out.append(g[k])
    return out


def header_groups(filenames, nbytes=24):
    """Group by the leading header bytes the decoder actually parses."""
    g, out = {}, []
    for fn in filenames:
        p = os.path.join(CORPUS, fn)
        try:
            h = hashlib.sha256(open(p, "rb").read()[:nbytes]).hexdigest()
        except OSError:
            h = fn
        if h not in g:
            g[h] = len(g)
        out.append(g[h])
    return out


def joined_groups(*groupings):
    """
    Connected components of "shares a feature vector OR shares a header prefix".

    This is the control that actually holds: neither relation contains the other, so
    grouping by either one alone still lets some sibling pairs straddle a fold.
    """
    n = len(groupings[0])
    parent = list(range(n))

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for grouping in groupings:
        first = {}
        for i, g in enumerate(grouping):
            if g in first:
                union(i, first[g])
            else:
                first[g] = i
    return [find(i) for i in range(n)]


def grouped_folds(groups, y, k, rng):
    """Assign whole groups to folds, largest first, always to the lightest fold."""
    members = collections.defaultdict(list)
    for i, gid in enumerate(groups):
        members[gid].append(i)
    order = sorted(members.values(), key=len, reverse=True)
    rng.shuffle(order)
    order.sort(key=len, reverse=True)
    folds = [[] for _ in range(k)]
    for grp in order:
        j = min(range(k), key=lambda t: len(folds[t]))
        folds[j].extend(grp)
    return folds


def cv(X, y, folds_list, depth, min_leaf):
    oof = [None] * len(y)
    for k in range(len(folds_list)):
        test = folds_list[k]
        train = [i for j, f in enumerate(folds_list) if j != k for i in f]
        if not train or not test:
            continue
        t = W.build(X, y, train, 0, depth, min_leaf)
        for i in test:
            oof[i] = W.predict(t, X[i])
    return oof


def repeated(X, y, k, seeds, depth, min_leaf, groups=None):
    """Return (mean, sd) of macro-F1 and of WRITE P/R over seeds."""
    mf, wp, wr = [], [], []
    for s in range(seeds):
        rng = random.Random(1000 + s)
        fl = (grouped_folds(groups, y, k, rng) if groups is not None
              else W.stratified_folds(y, k, rng))
        oof = cv(X, y, fl, depth, min_leaf)
        keep = [i for i in range(len(y)) if oof[i] is not None]
        p = [oof[i] for i in keep]
        g = [y[i] for i in keep]
        mf.append(W.macro_f1(p, g))
        P, R, _ = W.prf(p, g, "WRITE")
        wp.append(P); wr.append(R)
    ms = lambda v: (statistics.mean(v), statistics.stdev(v) if len(v) > 1 else 0.0)
    return ms(mf), ms(wp), ms(wr)


def fmt(t):
    return f"{t[0]:.3f} (sd {t[1]:.3f})"


# ------------------------------------------------------------------ main

def main(seeds, folds, depth, min_leaf):
    X, y, base, names = W.load("features.csv", "ground-truth.csv")
    gtset = {r["filename"] for r in csv.DictReader(open("ground-truth.csv"))}
    fns = [r["filename"] for r in csv.DictReader(open("features.csv")) if r["filename"] in gtset]
    n = len(y)

    print("=" * 74)
    print("1. DUPLICATE CENSUS")
    print("=" * 74)
    blobs = {}
    for f in fns:
        try:
            blobs[f] = open(os.path.join(CORPUS, f), "rb").read()
        except OSError:
            pass
    bh = collections.defaultdict(list)
    for f, b in blobs.items():
        bh[hashlib.sha256(b).hexdigest()].append(f)
    exact = {k: v for k, v in bh.items() if len(v) > 1}
    fg = feature_groups(X)
    hg = header_groups(fns)
    jg = joined_groups(fg, hg)
    fcount = collections.Counter(fg); fdup = {k: v for k, v in fcount.items() if v > 1}
    hcount = collections.Counter(hg); hdup = {k: v for k, v in hcount.items() if v > 1}
    print(f"  records                            : {n}")
    print(f"  exact byte-duplicate groups        : {len(exact)} "
          f"({sum(len(v) for v in exact.values())} files)")
    print(f"  identical feature-vector groups    : {len(fdup)} "
          f"({sum(fdup.values())} files, largest {max(fdup.values()) if fdup else 0})")
    print(f"  identical header-prefix groups     : {len(hdup)} "
          f"({sum(hdup.values())} files, largest {max(hdup.values()) if hdup else 0})")
    print(f"  distinct feature vectors           : {len(set(fg))}")
    print(f"  distinct header prefixes           : {len(set(hg))}")
    # the two relations cross-cut; quantify it, because it decides which is strictest
    a = collections.defaultdict(set)
    for i in range(n):
        a[fg[i]].add(hg[i])
    b = collections.defaultdict(set)
    for i in range(n):
        b[hg[i]].add(fg[i])
    print(f"  feature-vector groups spanning >1 header prefix : "
          f"{sum(1 for v in a.values() if len(v) > 1)}")
    print(f"  header-prefix groups spanning >1 feature vector : "
          f"{sum(1 for v in b.values() if len(v) > 1)}")
    print(f"  => neither relation contains the other, so neither alone is strictest.")
    print(f"  JOINED components (feature vector OR header prefix): {len(set(jg))}")

    print()
    print("=" * 74)
    print("2. LEAKAGE-CONTROLLED CROSS-VALIDATION")
    print("=" * 74)
    print(f"  {folds}-fold, {seeds} seeds, CART depth<={depth}, min_leaf={min_leaf}\n")
    print(f"  {'protocol':<46}{'macro-F1':>17}{'WRITE P':>17}{'WRITE R':>17}")
    for label, grp in (("stratified (siblings may straddle folds)", None),
                       ("grouped by identical feature vector", fg),
                       ("grouped by header prefix", hg),
                       ("JOINED grouping (headline)", jg)):
        mf, wp, wr = repeated(X, y, folds, seeds, depth, min_leaf, grp)
        print(f"  {label:<46}{fmt(mf):>17}{fmt(wp):>17}{fmt(wr):>17}")

    print()
    print("=" * 74)
    print("3. FAIR BASELINE: THE SAME LEARNER ON CONVENTIONAL FEATURES")
    print("=" * 74)
    FAULTS = sorted({b["fault"] for b in base})
    MODS = sorted({b["module"] for b in base})
    Xc = [[1.0 * (b["fault"] == f) for f in FAULTS] + [1.0 * (b["module"] == m) for m in MODS]
          for b in base]
    mfc, wpc, wrc = repeated(Xc, y, folds, seeds, depth, min_leaf, jg)
    mfo, wpo, wro = repeated(X, y, folds, seeds, depth, min_leaf, jg)
    print(f"  {'feature set (identical learner, JOINED grouping)':<46}"
          f"{'macro-F1':>17}{'WRITE P':>17}{'WRITE R':>17}")
    print(f"  {'crash symptom + crash site (conventional)':<46}"
          f"{fmt(mfc):>17}{fmt(wpc):>17}{fmt(wrc):>17}")
    print(f"  {'input header arithmetic (ours)':<46}"
          f"{fmt(mfo):>17}{fmt(wpo):>17}{fmt(wro):>17}")
    print(f"  => like-for-like gap: {mfo[0]-mfc[0]:+.3f} macro-F1.")
    print()
    print("  For contrast, the hand-coded rules a pipeline actually ships. These are")
    print("  NOT the fair comparison: the fuzzer's four buckets are all read/write")
    print("  fault types, so such a rule cannot express a third class at all and one")
    print("  third of its macro-F1 is zero by construction.")
    maj = collections.Counter(y).most_common(1)[0][0]
    b_sym = ["WRITE" if "WRITE" in q["fault"] else "READ" if "READ" in q["fault"] else "DoS"
             for q in base]
    b_site = ["WRITE" if q["module"] == "unknown" else "DoS" for q in base]
    for nm, p in (("majority class", [maj] * n), ("crash site rule", b_site),
                  ("fuzzer symptom rule", b_sym)):
        print(f"    {nm:<26} macro-F1 {W.macro_f1(p, y):.3f}   per class: " +
              "  ".join(f"{c} F1={W.prf(p, y, c)[2]:.3f} (n_pred={p.count(c)})"
                        for c in CLASSES))

    print()
    print("=" * 74)
    print("4. LEARNING CURVE (JOINED grouping)")
    print("=" * 74)
    print(f"  {'train fraction':>16}{'macro-F1':>20}")
    for frac in (0.1, 0.2, 0.4, 0.6, 0.8, 1.0):
        sc = []
        for s in range(max(3, seeds // 3)):
            rng = random.Random(4000 + s)
            fl = grouped_folds(jg, y, folds, rng)
            oof = [None] * n
            for k in range(folds):
                test = fl[k]
                train = [i for j, f in enumerate(fl) if j != k for i in f]
                rng.shuffle(train)
                train = train[:max(20, int(len(train) * frac))]
                if len(set(y[i] for i in train)) < 2:
                    continue
                t = W.build(X, y, train, 0, depth, min_leaf)
                for i in test:
                    oof[i] = W.predict(t, X[i])
            keep = [i for i in range(n) if oof[i] is not None]
            sc.append(W.macro_f1([oof[i] for i in keep], [y[i] for i in keep]))
        m = statistics.mean(sc)
        sd = statistics.stdev(sc) if len(sc) > 1 else 0.0
        print(f"  {frac:>15.0%}{m:>15.3f} (sd {sd:.3f})")

    print()
    print("=" * 74)
    print("5. FEATURE-FAMILY ABLATION (JOINED grouping)")
    print("=" * 74)
    FAMS = {
        "all features": lambda nm: True,
        "  minus TGA row/payload arithmetic":
            lambda nm: not nm.startswith(("tga_row", "tga_declared", "tga_payload")),
        "  minus PCX scanline arithmetic":
            lambda nm: not nm.startswith(("pcx_bpl", "pcx_scanline", "pcx_plane",
                                          "pcx_width_underflow", "pcx_height_underflow")),
        "  minus raw geometry (w/h/bpp)":
            lambda nm: not nm.startswith(("tga_width", "tga_height", "tga_bpp",
                                          "pcx_width", "pcx_height", "pcx_bpp")),
        "  minus filesize":
            lambda nm: nm != "filesize",
        "  ONLY filesize + container":
            lambda nm: nm == "filesize" or nm.startswith("container="),
        "  ONLY derived overflow flags":
            lambda nm: nm in ("tga_row_overflows_16b", "tga_row_trunc_to_zero",
                              "tga_payload_deficit", "tga_header_past_eof",
                              "pcx_width_underflow", "pcx_bpl_short",
                              "pcx_plane_row_mismatch"),
    }
    print(f"  {'feature set':<40}{'macro-F1':>18}{'delta':>10}")
    baseline_mf = None
    for label, keep_fn in FAMS.items():
        cols = [j for j, nm in enumerate(names) if keep_fn(nm)]
        if not cols:
            continue
        Xs = [[row[j] for j in cols] for row in X]
        mf, _, _ = repeated(Xs, y, folds, max(3, seeds // 2), depth, min_leaf, jg)
        if baseline_mf is None:
            baseline_mf = mf[0]
            print(f"  {label:<40}{fmt(mf):>18}{'':>10}")
        else:
            print(f"  {label:<40}{fmt(mf):>18}{mf[0]-baseline_mf:>+10.3f}")

    print()
    print("=" * 74)
    print("6. CAPACITY SWEEP (JOINED grouping)")
    print("=" * 74)
    print("  Sweeping depth alone proves little: min_leaf binds first on 1,070 rows.")
    print("  So we sweep both.\n")
    print(f"  {'max depth':>12}{'macro-F1':>20}")
    for d in (2, 3, 4, 5, 6, 8, 12):
        mf, _, _ = repeated(X, y, folds, max(3, seeds // 2), d, min_leaf, jg)
        print(f"  {d:>12}{fmt(mf):>20}")
    print(f"\n  {'min leaf':>12}{'macro-F1':>20}   (depth fixed at {depth})")
    for ml in (1, 2, 5, 10, 20, 50, 100):
        mf, _, _ = repeated(X, y, folds, max(3, seeds // 2), depth, ml, jg)
        print(f"  {ml:>12}{fmt(mf):>20}")

    print()
    print("=" * 74)
    print("7. CONFUSION MATRIX (JOINED grouping, seed 1000)")
    print("=" * 74)
    rng = random.Random(1000)
    oof = cv(X, y, grouped_folds(jg, y, folds, rng), depth, min_leaf)
    cm = collections.Counter(zip(y, oof))
    print(f"  {'true \\ pred':<12}" + "".join(f"{c:>10}" for c in CLASSES) + f"{'total':>10}")
    for t in CLASSES:
        row = [cm[(t, p)] for p in CLASSES]
        print(f"  {t:<12}" + "".join(f"{v:>10}" for v in row) + f"{sum(row):>10}")

    print()
    print("=" * 74)
    print("8. THE FILE-SIZE CONFOUND")
    print("=" * 74)
    fs = {r["filename"]: float(r["filesize"]) for r in csv.DictReader(open("features.csv"))}
    byc = collections.defaultdict(list)
    for i, fn in enumerate(fns):
        byc[y[i]].append(fs[fn])
    print(f"  {'class':<8}{'n':>6}{'median':>10}{'mean':>10}{'p10':>8}{'p90':>10}")
    for c in CLASSES:
        v = sorted(byc[c])
        print(f"  {c:<8}{len(v):>6}{statistics.median(v):>10.1f}{statistics.mean(v):>10.1f}"
              f"{v[len(v)//10]:>8.1f}{v[9*len(v)//10]:>10.1f}")
    print("  File size alone (with container) reaches a large fraction of the full")
    print("  score. There is a benign reading, that a file too short to decode is")
    print("  rejected and an over-read needs bytes to over-read into. There is also a")
    print("  malign one, that this reflects the fuzzer's seeds and per-path mutation")
    print("  budget, i.e. how the corpus was built rather than what the bugs are.")
    print("  Nothing in this corpus distinguishes them. A second corpus, generated by")
    print("  a different harness, would.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--min-leaf", type=int, default=10)
    a = ap.parse_args()
    main(a.seeds, a.folds, a.depth, a.min_leaf)

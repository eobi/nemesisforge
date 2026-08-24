#!/usr/bin/env python3
"""
Cross-corpus transfer: train on FastStone, predict on the Forge corpus.

Why this and not leave-one-target-out. In the Forge corpus each staged target contains
exactly one bug, so the bug class is perfectly confounded with the target: cJSON yields
only over-reads, the directed nanosvg run only stack writes, frozen only recursion
denial-of-service. Holding out a target therefore removes the only source of its class
from training, and the model could never predict it. That protocol would report a
number, and the number would be meaningless.

Training on one corpus and testing on the other has none of that problem, and it is a
harder test than the one we were asked for. The two corpora share nothing:

    FastStone                        Forge
    closed-source Windows app        open-source C libraries
    TGA and PCX images               JSON, SVG
    Zabel's GUI-termination harness  libFuzzer
    page-heap / Application Verifier AddressSanitizer
    labelled by a human analyst      labelled mechanically from the sanitizer
    x86 Windows                      arm64 macOS

The only thing in common is the hypothesis: that the destination of a corrupting write
is computed from a size the input declares, and that the computation is visible in the
input. Features are the container-agnostic ones from features2.py, which know nothing
about any of these formats.

Both directions are reported. Training on Forge and testing on FastStone is the more
useful direction in practice, because the Forge corpus is releasable and the FastStone
one is not.

Usage: python3 eval_cross.py [--faststone-features PATH] [--forge-features features2.csv]
"""
import argparse, collections, csv, os, statistics, sys

LADDER = os.path.expanduser("~/Desktop/Research/Ladder-Dont-Label/ladder-dont-label")
sys.path.insert(0, LADDER)
import wo_eval as W

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



# Features whose value has the same meaning regardless of how big the input is.
# The failure of the first cross-corpus run was diagnosed as scale dependence: a
# threshold like "size <= 197" or "declared > 65535", learned on 52-byte binary TGAs,
# is meaningless on 20 KB JSON. Ratios and fractions do not have that problem.
SCALE_FREE = {"decl_over_size", "printable", "digits", "high_bytes", "entropy",
              "unclosed_quote", "dangling_escape", "open_comment",
              "ends_in_escape", "ends_in_quote"}
# Counts that become scale-free once divided by the input size.
PER_BYTE = {"decl_exceeds", "decl_gt16", "decl_gt31", "decl_trunc16_zero",
            "quote_count", "escape_count", "unbalanced_abs", "max_depth",
            "max_run", "max_token", "nulls"}


def to_scale_free(X, names):
    """Rebuild the matrix using only quantities that do not depend on input size."""
    si = names.index("size") if "size" in names else None
    keep = [(n, i) for i, n in enumerate(names) if n in SCALE_FREE]
    rate = [(n, i) for i, n in enumerate(names) if n in PER_BYTE]
    out_names = [n for n, _ in keep] + [f"{n}_per_byte" for n, _ in rate]
    out = []
    for r in X:
        sz = max(1.0, r[si]) if si is not None else 1.0
        out.append([r[i] for _, i in keep] + [r[i] / sz for _, i in rate])
    return out, out_names


def load_generic(path):
    rows = list(csv.DictReader(open(path)))
    names = [k for k in rows[0] if k not in META]
    X = [[float(r[k]) for k in names] for r in rows]
    y = [r["cls"] for r in rows]
    t = [lib(r.get("target", "?")) for r in rows]
    return X, y, t, names


def align(nA, nB):
    """Keep only features present in both corpora, in a stable order."""
    common = [n for n in nA if n in set(nB)]
    return common, [nA.index(n) for n in common], [nB.index(n) for n in common]


def fit_predict(Xtr, ytr, Xte, depth, min_leaf):
    if len(set(ytr)) < 2:
        return [collections.Counter(ytr).most_common(1)[0][0]] * len(Xte)
    tree = W.build(Xtr, ytr, list(range(len(Xtr))), 0, depth, min_leaf)
    return [W.predict(tree, x) for x in Xte]


def report(name, pred, gold, extra=""):
    present = [c for c in CLASSES if c in set(gold)]
    mf = statistics.mean(W.prf(pred, gold, c)[2] for c in present)
    acc = sum(1 for p, g in zip(pred, gold) if p == g) / len(gold)
    print(f"  {name:<34}macro-F1 {mf:.3f}   acc {acc:.3f}   {extra}")
    return mf, acc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--faststone-features", default="faststone_generic.csv")
    ap.add_argument("--forge-features", default="features2.csv")
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--min-leaf", type=int, default=10)
    ap.add_argument("--scale-free", action="store_true",
                    help="use only size-independent features (ratios, fractions, "
                         "flags, and counts divided by input size). Tests whether the "
                         "cross-corpus failure was scale dependence rather than the "
                         "principle not holding.")
    ap.add_argument("--balance", action="store_true",
                    help="downsample the training corpus to equal class sizes. "
                         "FastStone is 63.8%% WRITE and only 5.9%% READ, so a model "
                         "trained on it barely learns READ; this separates 'the "
                         "principle does not transfer' from 'we never taught it that "
                         "class'.")
    a = ap.parse_args()

    XA, yA, tA, nA = load_generic(a.faststone_features)   # FastStone
    XB, yB, tB, nB = load_generic(a.forge_features)       # Forge
    if a.balance:
        import random as _r
        rng = _r.Random(0)
        by = collections.defaultdict(list)
        for i, c in enumerate(yA):
            by[c].append(i)
        k = min(len(v) for v in by.values())
        keep = sorted(i for v in by.values() for i in rng.sample(v, k))
        XA = [XA[i] for i in keep]; yA = [yA[i] for i in keep]; tA = [tA[i] for i in keep]
        print(f"[--balance] FastStone downsampled to {k} per class ({len(yA)} total)\n")

    common, iA, iB = align(nA, nB)
    XA = [[r[i] for i in iA] for r in XA]
    XB = [[r[i] for i in iB] for r in XB]
    if a.scale_free:
        XA, nsf = to_scale_free(XA, common)
        XB, _ = to_scale_free(XB, common)
        common = nsf
        print(f"[--scale-free] {len(common)} size-independent features: "
              f"{', '.join(common)}\n")

    print(f"FastStone : {len(yA):5d} crashes  " +
          ", ".join(f"{k}={v}" for k, v in collections.Counter(yA).most_common()))
    print(f"Forge     : {len(yB):5d} crashes  " +
          ", ".join(f"{k}={v}" for k, v in collections.Counter(yB).most_common()))
    print(f"            {len(tB and set(tB))} Forge targets: {sorted(set(tB))}")
    print(f"shared features: {len(common)} (container-agnostic only)\n")

    size_i = common.index("size") if "size" in common else 0

    print("=" * 74)
    print("TRAIN FastStone  ->  TEST Forge")
    print("=" * 74)
    majA = collections.Counter(yA).most_common(1)[0][0]
    report("majority of training corpus", [majA] * len(yB), yB)
    report("size only", fit_predict([[r[size_i]] for r in XA], yA,
                                    [[r[size_i]] for r in XB], a.depth, a.min_leaf), yB)
    p = fit_predict(XA, yA, XB, a.depth, a.min_leaf)
    report("ours (generic features)", p, yB)
    cm = collections.Counter(zip(yB, p))
    print(f"\n  {'true/pred':<10}" + "".join(f"{c:>9}" for c in CLASSES))
    for t in CLASSES:
        if not any(g == t for g in yB):
            continue
        print(f"  {t:<10}" + "".join(f"{cm[(t,c)]:>9}" for c in CLASSES))
    print("\n  per Forge target:")
    for tt in sorted(set(tB)):
        idx = [i for i in range(len(yB)) if tB[i] == tt]
        acc = sum(1 for i in idx if p[i] == yB[i]) / len(idx)
        truth = collections.Counter(yB[i] for i in idx).most_common(1)[0][0]
        got = collections.Counter(p[i] for i in idx).most_common(2)
        print(f"    {tt:<18} n={len(idx):4d}  true={truth:<6} acc={acc:.3f}  "
              f"predicted={dict(got)}")

    print()
    print("=" * 74)
    print("TRAIN Forge  ->  TEST FastStone   (the releasable direction)")
    print("=" * 74)
    majB = collections.Counter(yB).most_common(1)[0][0]
    report("majority of training corpus", [majB] * len(yA), yA)
    report("size only", fit_predict([[r[size_i]] for r in XB], yB,
                                    [[r[size_i]] for r in XA], a.depth, a.min_leaf), yA)
    q = fit_predict(XB, yB, XA, a.depth, a.min_leaf)
    report("ours (generic features)", q, yA)

    print()
    print("=" * 74)
    print("READ THIS BEFORE QUOTING ANY NUMBER ABOVE")
    print("=" * 74)
    print("  Every Forge target contains exactly one bug, so its class is constant per")
    print("  target. A transfer score is therefore driven as much by the class balance")
    print("  of the Forge corpus as by the model. The per-target accuracy table is the")
    print("  honest view: it says, for each held-out library, whether the FastStone")
    print("  model put that library's crashes in the right class at all.")
    print("  A high score here is evidence the signal survives a change of format,")
    print("  fuzzer, allocator, labeller and architecture. It is NOT evidence of")
    print("  fine-grained discrimination within a target, which this corpus cannot test.")


if __name__ == "__main__":
    main()

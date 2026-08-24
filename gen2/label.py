#!/usr/bin/env python3
"""
Label a Forge-generated crash corpus from the sanitizer, not from a human.

This is the part that makes the second corpus stronger than the FastStone one. There,
the exploitability class came from one analyst's root-cause analysis, a single
labelling with no second annotator, and its denial-of-service class was constructed
rather than observed. Here every label is read out of an AddressSanitizer report:

    heap-buffer-overflow  ... WRITE of size N   ->  WRITE
    stack-buffer-overflow ... WRITE of size N   ->  WRITE
    global-buffer-overflow... WRITE of size N   ->  WRITE
    ...any of the above   ... READ of size N    ->  READ
    SEGV on unknown address 0x000000000000      ->  DoS   (null dereference)
    stack-overflow                              ->  DoS   (uncontrolled recursion)
    allocation-size-too-big / OOM               ->  DoS

Mechanical, objective, and reproducible by anyone with the same build. It also gives a
CONFIRMED denial-of-service class, which the FastStone corpus does not have.

Each crash is replayed against the VULNERABLE build to obtain the report, and against
the PATCHED build to record whether the fix closes it. That second column is the
differential oracle: a crash that still faults on the patched side is not evidence of
the bug under study and is flagged.

Usage: python3 label.py [--targets a,b,c] [-o labels.csv]
"""
import argparse, csv, os, re, subprocess, sys, collections

W = os.path.dirname(os.path.abspath(__file__))
STAGED = os.path.expanduser("~/Documents/NemesisForge/handhunt/_cve/_staged")

# target -> staged case supplying the vulnerable/patched standalone drivers
CASES = {
    "cjson_minify":   "cve_cjson_minify",
    "cjson_parsestr": "cve_cjson_parsestr",
    "nanosvg_color":  "cve_nanosvg_color",
    "nanosvg_write":  "cve_nanosvg_color",
    "frozen_dos":     "cve_frozen_recursion",
}

ASAN_ENV = dict(os.environ, ASAN_OPTIONS=(
    "abort_on_error=0:detect_leaks=0:allocator_may_return_null=1:"
    "max_allocation_size_mb=512:symbolize=0"))

RE_KIND = re.compile(r"AddressSanitizer:\s+([a-z\-]+)")
RE_ACCESS = re.compile(r"\b(READ|WRITE) of size (\d+)")
RE_SEGVADDR = re.compile(r"SEGV on unknown address (0x[0-9a-f]+)")
RE_FRAME0 = re.compile(r"#0\s+0x[0-9a-f]+\s+in\s+(\S+)")


def classify(report):
    """Map a sanitizer report to (class, kind, access, faulting_function)."""
    kind = (RE_KIND.search(report) or [None, ""])[1] if RE_KIND.search(report) else ""
    acc = RE_ACCESS.search(report)
    access = acc.group(1) if acc else ""
    fn = (RE_FRAME0.search(report).group(1) if RE_FRAME0.search(report) else "")

    if kind in ("heap-buffer-overflow", "stack-buffer-overflow",
                "global-buffer-overflow", "dynamic-stack-buffer-overflow",
                "heap-use-after-free", "container-overflow"):
        if access == "WRITE":
            return "WRITE", kind, access, fn
        if access == "READ":
            return "READ", kind, access, fn
        return "DoS", kind, access, fn          # overflow with no access line
    if kind in ("stack-overflow", "allocation-size-too-big", "out-of-memory"):
        return "DoS", kind, access, fn
    if kind == "SEGV":
        m = RE_SEGVADDR.search(report)
        addr = int(m.group(1), 16) if m else -1
        # a fault near zero is an uncontrolled null dereference; a wild address is not
        if 0 <= addr < 0x10000:
            return "DoS", "SEGV-null", access, fn
        return ("WRITE" if access == "WRITE" else "READ" if access == "READ"
                else "DoS"), "SEGV-wild", access, fn
    return "", kind, access, fn                 # no crash / unrecognised


def run(binary, path):
    try:
        with open(path, "rb") as f:
            p = subprocess.run([binary], stdin=f, capture_output=True,
                               env=ASAN_ENV, timeout=3)
        return (p.stdout + p.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        # some patched builds loop forever on malformed input; that is not a crash,
        # and for the differential it counts as "does not fault"
        return "TIMEOUT"
    except OSError as e:
        return f"OSERROR {e}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default=",".join(CASES))
    ap.add_argument("-o", default="labels.csv")
    ap.add_argument("--cap", type=int, default=0,
                    help="max crashes to label per target; 0 = all. Caps keep one "
                         "prolific target from dominating the corpus.")
    a = ap.parse_args()

    rows, stats = [], collections.Counter()
    for t in a.targets.split(","):
        t = t.strip()
        case = CASES.get(t)
        vb = os.path.join(STAGED, case, "vbin") if case else None
        pb = os.path.join(STAGED, case, "pbin") if case else None
        cdir = os.path.join(W, "crashes", t)
        if not (vb and os.path.exists(vb) and os.path.isdir(cdir)):
            print(f"  {t}: no vulnerable driver or no crashes, skipped")
            continue
        files = sorted(os.listdir(cdir))
        if a.cap and len(files) > a.cap:
            step = len(files) / a.cap                 # deterministic even spread
            files = [files[int(i * step)] for i in range(a.cap)]
        print(f"  {t}: replaying {len(files)} crashes...", flush=True)
        for fn in files:
            path = os.path.join(cdir, fn)
            if not os.path.isfile(path):
                continue
            rep_v = run(vb, path)
            cls, kind, access, fn0 = classify(rep_v)
            if not cls:
                stats[f"{t}: no crash on vulnerable build"] += 1
                continue
            rep_p = run(pb, path) if os.path.exists(pb) else ""
            cls_p, kind_p, _, _ = classify(rep_p)
            rows.append({
                "target": t, "filename": fn, "path": path,
                "cls": cls, "asan_kind": kind, "access": access, "fault_fn": fn0,
                "patched_still_faults": int(bool(cls_p)),
                "size": os.path.getsize(path),
            })
            stats[f"{t}: {cls} ({kind})"] += 1
            if cls_p:
                stats[f"{t}: PATCHED ALSO FAULTS -> excluded from oracle"] += 1

    if not rows:
        print("no labelled crashes"); return 1
    with open(os.path.join(W, a.o), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)

    print(f"\nwrote {a.o}: {len(rows)} labelled crashes\n")
    for k, v in sorted(stats.items()):
        print(f"  {v:5d}  {k}")
    print("\nclass totals:", dict(collections.Counter(r["cls"] for r in rows)))
    print("per target   :", dict(collections.Counter(r["target"] for r in rows)))
    clean = sum(1 for r in rows if not r["patched_still_faults"])
    print(f"differential holds (patched clean) for {clean}/{len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

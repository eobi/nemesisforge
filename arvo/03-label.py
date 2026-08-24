#!/usr/bin/env python3
"""
Label the ARVO corpus from the sanitizer reports, and apply the differential oracle.

Same discipline as the Forge experiment: the class comes from the vulnerable build's
report, never from a human; the fixed build's report says whether the patch closes it.
A bug whose fixed build still faults is not evidence about that bug and is flagged.

Usage: python3 03-label.py corpus -o labels_arvo.csv --selected selected.json
"""
import argparse, collections, csv, json, os, re, sys

RE_KIND = re.compile(r"(?:AddressSanitizer|UndefinedBehaviorSanitizer|"
                     r"MemorySanitizer|ThreadSanitizer|LeakSanitizer):\s*([a-zA-Z\-]+)")
RE_ACCESS = re.compile(r"\b(READ|WRITE) of size (\d+)")
RE_SEGV = re.compile(r"SEGV on unknown address (0x[0-9a-f]+)")


def classify(report):
    kind = ""
    m = RE_KIND.search(report or "")
    if m:
        kind = m.group(1).lower()
    acc = RE_ACCESS.search(report or "")
    access = acc.group(1) if acc else ""
    if kind in ("heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
                "dynamic-stack-buffer-overflow", "heap-use-after-free",
                "container-overflow", "use-after-poison"):
        return (access or "DoS"), kind
    if kind in ("stack-overflow", "out-of-memory", "allocation-size-too-big",
                "negative-size-param", "requested-allocation-size-exceeds-maximum-supported-size",
                "bus", "ill", "fpe", "abrt"):
        return "DoS", kind
    if kind == "unknown-crash":
        # ASan could not name the region; the direction line is still authoritative
        return (access or "DoS"), kind
    if kind == "segv" or "SEGV" in (report or ""):
        m = RE_SEGV.search(report or "")
        addr = int(m.group(1), 16) if m else -1
        if 0 <= addr < 0x10000:
            return "DoS", "SEGV-null"
        return (access or "DoS"), "SEGV"
    return "", kind


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--selected", default="selected.json")
    ap.add_argument("-o", default="labels_arvo.csv")
    a = ap.parse_args()

    proj = {}
    if os.path.exists(a.selected):
        for r in json.load(open(a.selected)):
            proj[str(r["id"])] = r["project"]

    rows, stats = [], collections.Counter()
    pocdir = os.path.join(a.corpus, "poc")
    for fn in sorted(os.listdir(pocdir)):
        path = os.path.join(pocdir, fn)
        if not os.path.isfile(path):
            continue
        vr = open(os.path.join(a.corpus, "reports", f"{fn}.vul.txt"),
                  errors="replace").read() if os.path.exists(
                  os.path.join(a.corpus, "reports", f"{fn}.vul.txt")) else ""
        fr_path = os.path.join(a.corpus, "reports", f"{fn}.fix.txt")
        fr = open(fr_path, errors="replace").read() if os.path.exists(fr_path) else ""
        cls, kind = classify(vr)
        if not cls:
            stats[f"unclassifiable ({kind or 'no crash'})"] += 1
            continue
        fcls, _ = classify(fr)
        rows.append({"target": proj.get(fn, "unknown"), "filename": fn, "path": path,
                     "cls": cls, "asan_kind": kind,
                     "patched_still_faults": int(bool(fcls)),
                     "provenance": "arvo-oss-fuzz",
                     "size": os.path.getsize(path)})
        stats[f"{cls} ({kind})"] += 1
        if fcls:
            stats["patched also faults"] += 1

    if not rows:
        print("nothing labelled", file=sys.stderr)
        return 1
    with open(a.o, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)

    print(f"wrote {a.o}: {len(rows)} labelled bugs\n")
    for k, v in stats.most_common():
        print(f"  {v:5d}  {k}")
    byproj = collections.defaultdict(collections.Counter)
    for r in rows:
        byproj[r["target"]][r["cls"]] += 1
    print("\nper project (this is what decides whether leave-one-project-out is valid):")
    multi = 0
    for p, d in sorted(byproj.items(), key=lambda kv: -sum(kv[1].values())):
        flag = ""
        if len(d) >= 2:
            multi += 1
        else:
            flag = "  <-- single class, contributes nothing to the held-out test"
        print(f"  {p:<28} " + ", ".join(f"{k}={v}" for k, v in d.most_common()) + flag)
    print(f"\nprojects with >= 2 classes: {multi}/{len(byproj)}")
    clean = sum(1 for r in rows if not r["patched_still_faults"])
    print(f"differential holds (fixed build clean) for {clean}/{len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Choose ARVO vulnerabilities that can actually answer the generality question.

The Forge experiment failed because each hand-staged target contained exactly one bug,
so the bug class was perfectly determined by the target and no held-out-target protocol
was valid. ARVO fixes that structurally: 6,100+ vulnerabilities across 311 projects,
many projects appearing repeatedly with different crash types.

So the selection criterion is not "interesting bugs". It is:

    keep a project only if it contributes at least MIN_CLASSES distinct crash classes
    and at least MIN_BUGS distinct bugs

That is what makes leave-one-project-out meaningful: every class is present in the
training set no matter which project is held out.

Usage:
    git clone --depth 1 https://github.com/n132/ARVO-Meta
    python3 01-select-targets.py ARVO-Meta/meta -o selected.json
"""
import argparse, collections, glob, json, os, re, sys

MIN_CLASSES = 2      # a project must show at least this many distinct classes
MIN_BUGS = 3         # and at least this many bugs, so it is not a fluke
TARGET_PROJECTS = 12 # how many projects to keep

# Map an ARVO/OSS-Fuzz crash description onto the paper's three classes.
def to_class(crash_type: str) -> str:
    c = (crash_type or "").lower()
    if not c:
        return ""
    if "write" in c:
        return "WRITE"
    if "read" in c:
        return "READ"
    # Sanitizer classes with no access direction in the string
    if any(k in c for k in ("stack-overflow", "out-of-memory", "timeout",
                            "null", "undefined", "divide", "assert",
                            "unknown", "leak", "float")):
        return "DoS"
    if any(k in c for k in ("overflow", "use-after-free", "double-free", "uaf")):
        return ""   # a memory bug whose direction we cannot determine: drop it
    return ""


def field(rec, *names):
    for n in names:
        if n in rec and rec[n]:
            return rec[n]
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("metadir")
    ap.add_argument("-o", default="selected.json")
    a = ap.parse_args()

    files = sorted(glob.glob(os.path.join(a.metadir, "*.json")))
    if not files:
        print(f"no metadata under {a.metadir}", file=sys.stderr)
        return 1
    print(f"reading {len(files)} ARVO records")

    byproj = collections.defaultdict(list)
    seen_types = collections.Counter()
    for f in files:
        try:
            rec = json.load(open(f))
        except Exception:
            continue
        lid = field(rec, "localId", "local_id", "id") or os.path.splitext(os.path.basename(f))[0]
        proj = field(rec, "project", "project_name")
        ctype = field(rec, "crash_type", "crashType", "crash", "sanitizer_crash_type")
        cls = to_class(ctype)
        seen_types[ctype] += 1
        if not (proj and cls):
            continue
        byproj[proj].append({"id": str(lid), "project": proj,
                             "crash_type": ctype, "cls": cls})

    print(f"projects with usable records: {len(byproj)}")
    print("\nmost common raw crash types (sanity-check the mapping):")
    for t, n in seen_types.most_common(12):
        print(f"  {n:6d}  {t or '(empty)'}  -> {to_class(t) or 'DROPPED'}")

    # rank projects by class diversity first, then by how balanced they are
    ranked = []
    for proj, recs in byproj.items():
        d = collections.Counter(r["cls"] for r in recs)
        if len(d) < MIN_CLASSES or sum(d.values()) < MIN_BUGS:
            continue
        balance = min(d.values()) / max(d.values())
        ranked.append((len(d), balance, sum(d.values()), proj, d, recs))
    ranked.sort(key=lambda t: (-t[0], -t[1], -t[2]))

    print(f"\nprojects meeting >= {MIN_CLASSES} classes and >= {MIN_BUGS} bugs: {len(ranked)}")
    keep = ranked[:TARGET_PROJECTS]
    out = []
    print(f"\nselected {len(keep)}:")
    for ncls, bal, tot, proj, d, recs in keep:
        print(f"  {proj:<28} {tot:4d} bugs  " +
              ", ".join(f"{k}={v}" for k, v in d.most_common()))
        out.extend(recs)

    agg = collections.Counter(r["cls"] for r in out)
    print(f"\ntotal selected bugs: {len(out)}  classes: {dict(agg)}")
    if len(agg) < 3:
        print("WARNING: fewer than three classes overall; leave-one-project-out will be "
              "degenerate for the missing class")
    json.dump(out, open(a.o, "w"), indent=1)
    print(f"wrote {a.o}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

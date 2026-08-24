#!/usr/bin/env python3
"""
Container-agnostic feature extraction.

The FastStone extractor reads TGA and PCX headers. That is fine for one target family
and useless for a generality claim, because the moment the second corpus contains JSON,
SVG and glTF, there are no image headers to parse.

So this restates the paper's principle without reference to any format. The claim was
never "image geometry predicts exploitability." It was:

    the destination of a heap-corrupting write is computed from a size the input
    declares, and that computation is visible in the input.

A declared size can be a TGA row stride, a MessagePack length prefix, a glTF chunk
length, or the implied length of an unterminated JSON string. All of them share the
same observable signature: something in the input asserts a size, and that size is
inconsistent with the bytes actually present.

Three families, none of them format-specific:

  A. size-vs-capacity   every 2- and 4-byte field in the leading bytes is read as a
                        candidate declared length, in both endiannesses, and compared
                        against the bytes actually available. Also the largest integer
                        literal appearing in text, for textual formats.
  B. termination        does the input stop in the middle of a construct? unbalanced
                        brackets, an unclosed quote, a dangling escape, an unterminated
                        comment. These are the textual analogue of a truncated payload.
  C. shape              depth, longest token, longest byte run, printable fraction,
                        digit fraction. Cheap descriptors that let a learner tell the
                        container families apart without being told.

Usage: python3 features2.py labels.csv -o features2.csv
"""
import argparse, csv, math, os, re, collections

U16LE = lambda b, i: b[i] | (b[i+1] << 8)
U16BE = lambda b, i: (b[i] << 8) | b[i+1]
U32LE = lambda b, i: int.from_bytes(b[i:i+4], "little")
U32BE = lambda b, i: int.from_bytes(b[i:i+4], "big")

INT_RE = re.compile(rb"\d{1,19}")
OPEN, CLOSE = b"{[(", b"}])"


def size_vs_capacity(b):
    """
    Family A. Read the first 64 bytes as candidate length fields and ask how far each
    would overrun the file. This is the format-independent version of "the declared
    payload exceeds the bytes present".
    """
    n = len(b)
    cands = []
    lim = min(len(b) - 4, 64)
    for i in range(0, max(0, lim)):
        for f in (U16LE, U16BE):
            cands.append(f(b, i))
        for f in (U32LE, U32BE):
            cands.append(f(b, i))
    # textual formats declare sizes as digits, not binary fields
    for m in INT_RE.findall(b[:4096]):
        try:
            cands.append(int(m))
        except ValueError:
            pass
    cands = [c for c in cands if c > 0]
    if not cands:
        return dict(decl_max=0, decl_over_size=0.0, decl_exceeds=0, decl_gt16=0,
                    decl_gt31=0, decl_trunc16_zero=0)
    mx = max(cands)
    return dict(
        decl_max=min(mx, 1 << 40),
        decl_over_size=min(mx / max(1, n), 1e6),
        decl_exceeds=sum(1 for c in cands if c > n),
        # a declared size that does not fit in 16 or 32 bits is the truncation
        # precondition the paper certifies on FastStone
        decl_gt16=sum(1 for c in cands if c > 0xFFFF),
        decl_gt31=sum(1 for c in cands if c > 0x7FFFFFFF),
        decl_trunc16_zero=sum(1 for c in cands if c > 0 and (c & 0xFFFF) == 0),
    )


def termination(b):
    """Family B. Does the input stop mid-construct?"""
    depth = maxdepth = 0
    inq = False
    esc = False
    quotes = 0
    escapes = 0
    for ch in b:
        c = bytes([ch])
        if esc:
            esc = False
            continue
        if c == b"\\":
            esc = True
            escapes += 1
            continue
        if c == b'"':
            inq = not inq
            quotes += 1
            continue
        if inq:
            continue
        if c in OPEN:
            depth += 1
            maxdepth = max(maxdepth, depth)
        elif c in CLOSE:
            depth -= 1
    return dict(
        unbalanced=depth,
        unbalanced_abs=abs(depth),
        max_depth=maxdepth,
        unclosed_quote=int(inq),
        dangling_escape=int(esc),
        quote_count=quotes,
        escape_count=escapes,
        open_comment=int(b.count(b"/*") > b.count(b"*/")),
        ends_in_escape=int(b.endswith(b"\\")),
        ends_in_quote=int(b.endswith(b'"')),
    )


def shape(b):
    """Family C. Cheap descriptors, no format knowledge."""
    n = len(b)
    if n == 0:
        return dict(size=0, printable=0.0, digits=0.0, nulls=0, max_run=0,
                    max_token=0, entropy=0.0, high_bytes=0.0)
    cnt = collections.Counter(b)
    ent = -sum((v / n) * math.log2(v / n) for v in cnt.values())
    run = best = 1
    for i in range(1, n):
        run = run + 1 if b[i] == b[i-1] else 1
        best = max(best, run)
    toks = re.split(rb"[\s,;:{}\[\]()<>\"']+", b)
    return dict(
        size=n,
        printable=sum(1 for c in b if 32 <= c < 127) / n,
        digits=sum(1 for c in b if 48 <= c <= 57) / n,
        nulls=cnt.get(0, 0),
        max_run=best,
        max_token=max((len(t) for t in toks), default=0),
        entropy=ent,
        high_bytes=sum(1 for c in b if c >= 128) / n,
    )


def extract(path):
    b = open(path, "rb").read()
    f = {}
    f.update(size_vs_capacity(b))
    f.update(termination(b))
    f.update(shape(b))
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("labels")
    ap.add_argument("-o", default="features2.csv")
    a = ap.parse_args()

    rows = []
    for r in csv.DictReader(open(a.labels)):
        if not os.path.exists(r["path"]):
            continue
        rows.append({"target": r["target"], "filename": r["filename"],
                     "cls": r["cls"], **extract(r["path"])})
    if not rows:
        print("nothing to extract"); return
    with open(a.o, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)
    nfeat = len(rows[0]) - 3
    print(f"wrote {a.o}: {len(rows)} rows, {nfeat} features, "
          f"no format-specific fields")
    print("per target:", dict(collections.Counter(r["target"] for r in rows)))
    print("per class :", dict(collections.Counter(r["cls"] for r in rows)))


if __name__ == "__main__":
    main()

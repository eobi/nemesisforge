"""cscan — a pragmatic, dependency-free C/C++ code-intelligence pass.

Not a full parser (no tree-sitter/CodeQL needed): it strips comments/strings,
brace-matches to recover function bodies, builds a name-based call graph, finds
memory-safety-relevant sinks, and computes which sinks are REACHABLE from an
untrusted-input entry point. Good enough to rank "where a novel bug most likely
hides" far better than a flat grep — which is exactly what the reasoning agent
needs to aim discovery. Heuristic by design; it informs the LLM + the fuzzer, it
never asserts a bug (the oracle still proves everything).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# Sink kind → danger weight. Higher = more classically exploitable.
_SINKS: dict[str, tuple[re.Pattern, float]] = {
    "gets":     (re.compile(r"\bgets\s*\("), 6.0),
    "strcpy":   (re.compile(r"\b(strcpy|strcat|stpcpy)\s*\("), 4.5),
    "sprintf":  (re.compile(r"\b(sprintf|vsprintf)\s*\("), 4.5),
    "alloca":   (re.compile(r"\balloca\s*\("), 4.0),
    "memcpy":   (re.compile(r"\b(memcpy|memmove|bcopy)\s*\("), 3.5),
    "strncpy":  (re.compile(r"\b(strncpy|strncat|snprintf)\s*\("), 2.0),
    "malloc":   (re.compile(r"\b(malloc|calloc|realloc)\s*\("), 1.5),
    "index":    (re.compile(r"\w+\s*\[[^\]]*\b\w+\b[^\]]*\]\s*="), 1.5),  # arr[i]=
    "ptrarith": (re.compile(r"\*\s*\(\s*\w+\s*\+"), 1.0),                  # *(p+..)
    # Temporal-memory-safety loci (use-after-free / double-free). Detecting the bug
    # is the fuzzer/oracle's job; the sink marks the manual-lifetime code worth the
    # DEEPER (symbolic + LLM) budget — K-REPRO's difficulty gradient: spatial OOB is
    # cheap for plain fuzzing, temporal UAF/double-free is where it needs help.
    "free":     (re.compile(r"\b(free|kfree|g_free|xfree)\s*\("), 2.5),
    "realloc_t":(re.compile(r"\brealloc\s*\("), 2.0),                     # frees on move
}

# Sink kinds whose bugs (UAF/double-free) plain coverage-guided fuzzing under-finds,
# so the reasoning/symbolic budget is biased toward them.
_TEMPORAL = frozenset({"free", "realloc_t"})

# Function-name signals for an untrusted-input entry point.
_ENTRY = re.compile(
    r"(parse|decode|load|read|scan|unpack|deserialize|from_|_open|import|"
    r"inflate|decompress|demux|process|handle|next_|get_)", re.I)

_ID = r"[A-Za-z_]\w*"
# A function definition header: ... name(params) {   at brace depth 0.
_FUNC_HDR = re.compile(
    r"(?P<sig>(?:[A-Za-z_][\w\*\s\)\(,]*?\s|\*)?(?P<name>" + _ID + r")\s*"
    r"\((?P<params>[^;{}]*)\))\s*\{")


@dataclass
class Func:
    name: str
    file: str
    start: int                    # 1-based line of the signature
    end: int
    params: list[str] = field(default_factory=list)
    calls: set[str] = field(default_factory=set)
    body: str = ""


@dataclass
class Sink:
    kind: str
    func: str
    file: str
    line: int
    text: str
    input_influenced: bool = False
    reachable: bool = False
    score: float = 0.0


def _strip(code: str) -> str:
    """Blank out comments + string/char literals (keep newlines) so structural
    scanning isn't fooled by braces/keywords inside them."""
    out, i, n = [], 0, len(code)
    while i < n:
        c = code[i]
        two = code[i:i + 2]
        if two == "//":
            j = code.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif two == "/*":
            j = code.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", code[i:j])); i = j
        elif c in "\"'":
            j = i + 1
            while j < n and code[j] != c:
                j += 2 if code[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(re.sub(r"[^\n]", " ", code[i:j])); i = j
        else:
            out.append(c); i += 1
    return "".join(out)


def scan_text(code: str, *, file: str = "<mem>") -> tuple[list[Func], list[Sink]]:
    stripped = _strip(code)
    lines_start = [0]
    for m in re.finditer(r"\n", stripped):
        lines_start.append(m.end())

    def line_of(pos: int) -> int:
        lo, hi = 0, len(lines_start) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if lines_start[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    funcs: list[Func] = []
    for m in _FUNC_HDR.finditer(stripped):
        # keyword false positives (if/for/while/switch/sizeof/return ...)
        if m.group("name") in {"if", "for", "while", "switch", "sizeof",
                               "return", "else", "do"}:
            continue
        brace = stripped.find("{", m.start())
        depth, j, n = 0, brace, len(stripped)
        while j < n:
            if stripped[j] == "{":
                depth += 1
            elif stripped[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        start_line, end_line = line_of(m.start()), line_of(j)
        params = [p.strip() for p in m.group("params").split(",") if p.strip()
                  and p.strip() != "void"]
        funcs.append(Func(name=m.group("name"), file=file, start=start_line,
                          end=end_line, params=params,
                          body=code[m.start():j + 1]))

    names = {f.name for f in funcs}
    sinks: list[Sink] = []
    for f in funcs:
        pnames = {re.findall(_ID, p)[-1] for p in f.params if re.findall(_ID, p)}
        body_stripped = _strip(f.body)
        # call graph (names that appear as `name(` and are known functions)
        for cm in re.finditer(_ID + r"\s*\(", body_stripped):
            nm = cm.group().split("(")[0].strip()
            if nm in names and nm != f.name:
                f.calls.add(nm)
        # sinks
        base = f.start - 1
        for kind, (pat, _w) in _SINKS.items():
            for sm in pat.finditer(body_stripped):
                ln = base + body_stripped[:sm.start()].count("\n") + 1
                text = _line_text(code, ln)
                influenced = any(re.search(r"\b" + re.escape(p) + r"\b", text)
                                 for p in pnames)
                sinks.append(Sink(kind=kind, func=f.name, file=file, line=ln,
                                  text=text.strip()[:200],
                                  input_influenced=influenced))
    return funcs, sinks


def _line_text(code: str, line: int) -> str:
    lines = code.splitlines()
    return lines[line - 1] if 0 < line <= len(lines) else ""


@dataclass
class CodeIntel:
    funcs: dict[str, Func] = field(default_factory=dict)
    callers: dict[str, set] = field(default_factory=dict)   # name → callers
    sinks: list[Sink] = field(default_factory=list)

    def entry_points(self) -> list[Func]:
        eps = []
        for f in self.funcs.values():
            takes_buf = any(("*" in p or "[" in p) for p in f.params)
            if _ENTRY.search(f.name) and (takes_buf or len(f.params) >= 1):
                eps.append(f)
        return eps or [f for f in self.funcs.values()
                       if any("*" in p for p in f.params) and f.name not in self.callers]

    def reachable(self) -> set[str]:
        seen: set[str] = set()
        stack = [f.name for f in self.entry_points()]
        while stack:
            nm = stack.pop()
            if nm in seen:
                continue
            seen.add(nm)
            fn = self.funcs.get(nm)
            if fn:
                stack.extend(fn.calls - seen)
        return seen

    def ranked_sinks(self, *, limit: int = 25) -> list[Sink]:
        reach = self.reachable()
        for s in self.sinks:
            s.reachable = s.func in reach
            base = _SINKS.get(s.kind, (None, 1.0))[1]
            s.score = base + (2.5 if s.input_influenced else 0) + \
                (1.5 if s.reachable else 0) + \
                (2.0 if s.kind in _TEMPORAL else 0)   # K-REPRO: aim budget at temporal
        return sorted(self.sinks, key=lambda s: s.score, reverse=True)[:limit]

    def has_temporal_sink(self, func: str) -> bool:
        """True if `func` contains a UAF/double-free-class sink — used to bias the
        symbolic lens toward the targets plain fuzzing under-finds."""
        return any(s.func == func and s.kind in _TEMPORAL for s in self.sinks)


def scan_repo(sources: Iterable[Path]) -> CodeIntel:
    ci = CodeIntel()
    for src in sources:
        try:
            code = Path(src).read_text(errors="replace")
        except Exception:
            continue
        funcs, sinks = scan_text(code, file=str(src))
        for f in funcs:
            ci.funcs[f.name] = f          # last definition wins (good enough)
        ci.sinks.extend(sinks)
    for f in ci.funcs.values():
        for callee in f.calls:
            ci.callers.setdefault(callee, set()).add(f.name)
    return ci


def guard_tokens(text: str, *, limit: int = 48) -> list[str]:
    """Literal tokens in code that look like input guards — string/char literals
    and hex magic numbers — for a targeted libFuzzer dictionary that helps the
    fuzzer clear the guards on the way to a sink."""
    toks: set[str] = set()
    toks |= set(re.findall(r'"([ -~]{2,32})"', text))
    toks |= set(re.findall(r"'([ -~]{1,8})'", text))
    for m in re.findall(r"\b0x[0-9A-Fa-f]{2,8}\b", text):
        toks.add(m)
    return sorted(t for t in toks if t)[:limit]


def write_dict(tokens: list[str], path: Path) -> Optional[Path]:
    """Write a libFuzzer dictionary from tokens; returns the path or None."""
    toks = [t for t in tokens if t]
    if not toks:
        return None
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    esc = [t.replace("\\", "\\\\").replace('"', '\\"') for t in toks]
    path.write_text("\n".join(f'kw{i}="{t}"' for i, t in enumerate(esc)))
    return path


def func_body(ci: "CodeIntel", name: str, *, max_chars: int = 2000) -> str:
    """The source of a function (the sink's guard context for the LLM)."""
    fn = ci.funcs.get(name)
    return (fn.body[:max_chars] if fn else "")


def summarize_sinks(sinks: list[Sink], *, limit: int = 20) -> str:
    """Compact, ranked view for an LLM prompt — the reasoning context."""
    out = []
    for s in sinks[:limit]:
        flags = []
        if s.input_influenced:
            flags.append("input-influenced")
        if s.reachable:
            flags.append("reachable")
        tag = f" [{', '.join(flags)}]" if flags else ""
        out.append(f"{Path(s.file).name}:{s.line} in {s.func}() "
                   f"· {s.kind}{tag}\n    {s.text}")
    return "\n".join(out)

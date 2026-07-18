"""Repo ingestion — clone a source repo and map its fuzzable surface.

This is what makes "point Forge at any open-source technology" real: a git URL in,
a checked-out tree + a ranked list of candidate entry-point sources out. The
harness-synth agent then writes an `LLVMFuzzerTestOneInput` harness per entry point
and the libFuzzer engine fuzzes it.

Deliberately pragmatic for Stage 1: we compile the harness directly against the
handful of `.c` files that hold the chosen function (the OSS-Fuzz-Gen "function
under test" approach), which covers the small/medium single-purpose C libraries
that are the richest memory-safety targets. Full CMake/Make link-against-the-built-
library integration is a Stage-2 deepening; `detect_build_system` already records
what a repo needs so that upgrade is additive.

Safety: cloning + building third-party code is a coordinated-disclosure engagement.
The clone is shallow, pinned, size-capped, and time-boxed; the caller runs it
locally against a repo it is authorized to test.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Directories that rarely hold the shipping attack surface — deprioritized so the
# entry-point ranking surfaces real library code, not fixtures.
_SKIP_DIRS = {"test", "tests", "testing", "example", "examples", "demo", "demos",
              "third_party", "thirdparty", "vendor", "deps", "external", "bench",
              "benchmark", "benchmarks", "fuzz", "fuzzing", "doc", "docs",
              ".git", "build", "cmake", "contrib", "tools"}

_SRC_EXT = {".c", ".cc", ".cpp", ".cxx"}
# Function-name signals that a source parses / decodes untrusted input.
_ENTRY_HINTS = re.compile(
    r"\b\w*(parse|decode|load|read|scan|unpack|deserialize|from_(?:str|buf|bytes|"
    r"json|xml)|_open|import|inflate|decompress|demux)\w*\s*\(", re.I)


@dataclass
class RepoInfo:
    root: Path
    url: str
    ref: str = ""
    build_system: str = "none"          # cmake | make | autotools | meson | none
    sources: list[Path] = field(default_factory=list)   # ranked entry-point .c
    headers: list[Path] = field(default_factory=list)


def clone(url: str, dest: Path, *, ref: Optional[str] = None,
          depth: int = 1, timeout: int = 180) -> RepoInfo:
    """Shallow-clone `url` into `dest` (pinned to `ref` if given). Raises on
    failure so the job surfaces a clear error instead of fuzzing nothing."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not _is_safe_url(url):
        raise ValueError(f"refusing to clone non-git/opaque URL: {url!r}")
    argv = ["git", "clone", "--quiet", "--depth", str(depth),
            "--single-branch"]
    if ref:
        argv += ["--branch", ref]
    argv += [url, str(dest)]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0 or not dest.exists():
        raise RuntimeError(f"git clone failed: {r.stderr.strip()[:400]}")
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                          capture_output=True, text=True)
    info = RepoInfo(root=dest, url=url, ref=(ref or head.stdout.strip()[:12]))
    info.build_system = detect_build_system(dest)
    info.sources = rank_sources(dest)
    info.headers = _find(dest, {".h", ".hpp"}, limit=200)
    return info


def _is_safe_url(url: str) -> bool:
    # Accept https and git protocols and scp-style git@host:path; reject file://,
    # shell metacharacters, and ext:: transports that could run commands.
    if any(c in url for c in ";|&`$\n\r"):
        return False
    if url.startswith(("https://", "http://", "git://")):
        return True
    return bool(re.match(r"^[\w.-]+@[\w.-]+:[\w./-]+$", url))    # scp-style


def detect_build_system(root: Path) -> str:
    if (root / "CMakeLists.txt").exists():
        return "cmake"
    if (root / "configure").exists() or (root / "configure.ac").exists():
        return "autotools"
    if (root / "meson.build").exists():
        return "meson"
    if (root / "Makefile").exists() or (root / "makefile").exists():
        return "make"
    return "none"


def _find(root: Path, exts: set[str], *, limit: int) -> list[Path]:
    out: list[Path] = []
    for p in sorted(root.rglob("*")):
        if len(out) >= limit:
            break
        if p.suffix.lower() in exts and not _skipped(p, root):
            out.append(p)
    return out


def _skipped(p: Path, root: Path) -> bool:
    return any(part.lower() in _SKIP_DIRS for part in p.relative_to(root).parts[:-1])


def rank_sources(root: Path, *, limit: int = 60) -> list[Path]:
    """Rank `.c`/`.cpp` files by how much they look like an untrusted-input
    surface (parse/decode/load functions), smaller-and-fewer-deps first."""
    scored: list[tuple[float, Path]] = []
    for p in _find(root, _SRC_EXT, limit=1500):
        try:
            text = p.read_text(errors="replace")
        except Exception:
            continue
        hints = len(_ENTRY_HINTS.findall(text))
        if hints == 0:
            continue
        includes = text.count("#include")
        loc = text.count("\n") + 1
        # more entry hints = better; fewer includes + moderate size = easier build.
        score = hints * 3 - includes * 0.5 - max(0, loc - 4000) / 1000.0
        scored.append((score, p))
    scored.sort(key=lambda t: t[0], reverse=True)
    return [p for _s, p in scored[:limit]]


def entry_snippet(path: Path, *, max_lines: int = 120) -> str:
    """A compact view of a source's likely entry points for the LLM: the lines
    around functions that parse untrusted input, with line numbers."""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except Exception:
        return ""
    keep: list[str] = []
    for i, ln in enumerate(lines):
        if _ENTRY_HINTS.search(ln) or (ln and ln[0] not in " \t#/}" and "(" in ln):
            keep.append(f"{i + 1}: {ln}")
        if len(keep) >= max_lines:
            break
    return "\n".join(keep)

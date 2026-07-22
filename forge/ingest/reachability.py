"""Reachability directing — asset exposure → the code the hunt should target.

The single biggest *new* speedup this integration adds: don't fuzz a whole
library blind, fuzz only the code the live asset actually exposes. If Red saw the
asset accept PNG uploads, the reachable surface is the PNG decoder — so the hunt
directs the fuzzer at `png_*` / `*decode*` functions and skips the rest. That
prunes the search space *before* fuzzing starts.

`reachable_hints(exposure)` maps the asset's observed input surface (file formats
it accepts, protocols it speaks) to function-name substrings that mark the
entry code. The variant-hunter / harness-synth agents intersect these with a
repo's ranked entry points (`repo.rank_sources`) to focus the campaign; the Locus
predicate lens then directs the fuzzer the rest of the way to the sink.

Pure + conservative: an empty/unknown exposure returns an empty set, which the
caller treats as "no directing signal — hunt the full ranked surface" (so the
filter never *removes* reachable code, it only *prioritizes* when it has signal).
"""
from __future__ import annotations

import re

# Format / surface token → decoder-function-name substrings that parse it. Kept
# lowercase; matching is substring-insensitive. Generic parse verbs are always
# added so a format we don't have a specific entry for still directs at parsers.
_FORMAT_HINTS: dict[str, set[str]] = {
    "png":   {"png", "inflate", "zlib"},
    "jpeg":  {"jpeg", "jpg", "huff", "idct"},
    "jpg":   {"jpeg", "jpg", "huff", "idct"},
    "gif":   {"gif", "lzw"},
    "webp":  {"webp", "vp8", "lossless"},
    "tga":   {"tga", "targa", "rle"},
    "pcx":   {"pcx", "rle"},
    "tiff":  {"tiff", "tif", "ifd"},
    "bmp":   {"bmp", "dib"},
    "pdf":   {"pdf", "xref", "stream", "cos"},
    "xml":   {"xml", "sax", "dom", "entity"},
    "json":  {"json", "parse", "token"},
    "zip":   {"zip", "inflate", "deflate"},
    "gzip":  {"gz", "inflate", "deflate"},
    "tar":   {"tar", "ustar"},
    "http":  {"http", "header", "request", "uri", "chunk"},
    "tls":   {"tls", "ssl", "handshake", "asn1", "x509"},
    "dns":   {"dns", "resolv", "rr", "label"},
    "font":  {"ttf", "otf", "glyph", "sfnt", "cmap"},
}
_GENERIC_VERBS = {"parse", "decode", "load", "read", "scan", "unpack",
                  "deserialize", "import", "demux", "inflate", "decompress"}

_TOKEN = re.compile(r"[a-z0-9]+")


def _canon(item: str) -> list[str]:
    """Break an exposure item ('image/png', '.PNG', 'upload:jpeg') into tokens."""
    return _TOKEN.findall((item or "").lower())


def reachable_hints(exposure) -> set[str]:
    """Map an asset's exposure (a list/set of format or protocol tokens) to the
    function-name substrings a directed hunt should target. Empty → no signal."""
    if not exposure:
        return set()
    if isinstance(exposure, str):
        exposure = [exposure]
    hints: set[str] = set()
    matched = False
    for item in exposure:
        for tok in _canon(item):
            if tok in _FORMAT_HINTS:
                hints |= _FORMAT_HINTS[tok]
                matched = True
    if matched:
        hints |= _GENERIC_VERBS       # add generic parse verbs alongside specifics
    return hints


def focus_sources(ranked, hints, root=None):
    """Given repo.rank_sources output (paths) and reachability hints, return the
    subset whose path/name matches a hint, preserving rank order. Empty hints or
    no matches → the full ranked list unchanged (never prune to nothing)."""
    if not hints:
        return list(ranked)
    focused = []
    for p in ranked:
        name = str(getattr(p, "name", p)).lower()
        rel = str(p).lower()
        if any(h in name or h in rel for h in hints):
            focused.append(p)
    return focused or list(ranked)

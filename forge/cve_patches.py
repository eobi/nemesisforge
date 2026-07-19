"""CVE-patch corpus for variant hunting (Big Sleep's method, at scale).

The variant hunter already turns ONE bug-fix diff into a hunt for un-patched twins
(`variant_hunter.py` seed_patch). This module holds a small, curated corpus of
memory-safety PATTERNS to hunt with — starting with our own verified CWPack finding —
plus `from_commit`, which loads a REAL CVE fix-diff off a fixing commit so the corpus
can grow with actual advisories.

Honesty: the generic entries are described as *patterns* (reasoning seeds), not tied to
any fabricated CVE id. Real CVE patches enter via `from_commit(repo, <fixing-commit>)`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PatchSeed:
    name: str                              # short pattern name
    pattern: str                           # the seed_patch text (diff or description)
    origin: str = ""                       # provenance: CVE id / repo@commit / "ours"
    domains: tuple = field(default_factory=tuple)   # target hints for scouting


# Our own verified finding — a real, recent, unchecked-length memory-safety bug.
CWPACK = PatchSeed(
    name="unchecked-stream-length",
    origin="CWPack (our finding, CVE pending)",
    domains=("messagepack", "cbor", "tlv", "length-prefixed", "streaming-parser"),
    pattern=r"""--- a/goodies/basic-contexts/basic_contexts.c
+++ b/goodies/basic-contexts/basic_contexts.c
@@ handle_stream_unpack_underflow: refill the unpack buffer @@
     unsigned long l = fread(uc->end, 1, suc->buffer_length - remains, suc->file);
-    if (!l)                       /* BUG: only a ZERO read is treated as short */
+    uc->end += l;
+    /* A SHORT read (0 < l < more) was wrongly treated as success, so the parser
+       advanced `current` past `end`; the next refill computed remains = end -
+       current as a huge unsigned value and called memmove with it (heap OOB).
+       PATTERN: a length/count from untrusted input drives a buffer op WITHOUT
+       checking it against the bytes actually available. */
+    if ((unsigned long)(uc->end - uc->current) < more)
     {
         if (feof(suc->file)) return CWP_RC_END_OF_INPUT;
         suc->uc.err_no = ferror(suc->file);
         return CWP_RC_ERROR_IN_HANDLER;
     }
-    uc->end += l;
     return CWP_RC_OK;
""")

# Generic memory-safety patterns (reasoning seeds, not a specific CVE).
DECLARED_LEN = PatchSeed(
    name="declared-length-vs-available",
    origin="generic pattern",
    domains=("parser", "decoder", "length-prefixed", "binary-format"),
    pattern=(
        "PATTERN (memory safety): a parser reads a LENGTH or COUNT field from "
        "untrusted input (a str/bin/array/map size, a chunk length, a TLV length) "
        "and then reads/copies/allocates using that value WITHOUT validating it "
        "against the number of bytes actually remaining in the input. FIX: bound the "
        "declared length by the remaining input before using it. Hunt functions that "
        "read a length from input then index/copy/advance by it."))

INT_OVERFLOW_ALLOC = PatchSeed(
    name="integer-overflow-in-size",
    origin="generic pattern",
    domains=("parser", "decoder", "image", "codec"),
    pattern=(
        "PATTERN (memory safety): an allocation or copy size is computed by "
        "multiplying/adding untrusted values (width*height*bpp, count*elem_size, "
        "len+header) that can OVERFLOW to a small value, so a small buffer is "
        "allocated but a large amount is then written (heap overflow). FIX: check for "
        "overflow before the multiply/add. Hunt size arithmetic on input-derived "
        "values feeding malloc/memcpy."))

OFF_BY_ONE = PatchSeed(
    name="loop-bound-off-by-one",
    origin="generic pattern",
    domains=("parser", "decoder", "string"),
    pattern=(
        "PATTERN (memory safety): a loop or index uses `<=` where it should use `<`, "
        "or writes outbuf[i] where i can equal the buffer length, driven by an "
        "input-controlled count — a one-element out-of-bounds write/read. Hunt loops "
        "bounded by an input-derived count that write to a fixed or just-sized "
        "buffer."))

# The corpus. Add real CVE patches with from_commit().
SEEDS: list[PatchSeed] = [CWPACK, DECLARED_LEN, INT_OVERFLOW_ALLOC, OFF_BY_ONE]


def from_commit(repo_root: Path, commit: str, *, name: str = "",
                origin: str = "") -> Optional[PatchSeed]:
    """Load a REAL bug-fix diff from a fixing commit as a variant-hunt seed.
    `repo_root` is a local clone; `commit` any ref (hash/tag/HEAD~1)."""
    from .ingest import repo as _repo
    diff = _repo.patch_diff(Path(repo_root), commit)
    if not diff:
        return None
    return PatchSeed(name=name or f"patch@{commit[:10]}",
                     pattern=diff, origin=origin or f"{repo_root}@{commit}")

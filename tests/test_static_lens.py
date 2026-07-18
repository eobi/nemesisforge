"""Phase M2 — the static-analysis lens (source/syntax angle). The Clang Static
Analyzer must flag a memory-safety bug from the SOURCE (no fuzzing). Needs clang."""
import shutil

import pytest

from forge.analysis import clang_static

pytestmark = pytest.mark.skipif(shutil.which("clang") is None,
                                reason="clang not available")

# A null-deref reachable only on one path — a static analyzer catches it by
# reasoning over paths; a fuzzer would have to drive exactly into it.
BUGGY = r"""
#include <stdlib.h>
int deref(int flag) {
    int *p = NULL;
    if (flag == 42) {
        p = (int*)malloc(sizeof(int));
        if (!p) return 0;
    }
    return *p;          /* NULL deref when flag != 42 */
}
"""


def test_static_analyzer_flags_a_source_bug(tmp_path):
    assert clang_static.available()
    src = tmp_path / "bug.c"
    src.write_text(BUGGY)
    findings = clang_static.analyze([src])
    assert findings, "static analyzer should flag the null-deref"
    assert any(f.kind in ("null-deref", "static-warning") for f in findings)
    assert any("bug.c" in f.file for f in findings)


def test_classify_maps_messages_to_bug_vocab():
    assert clang_static._classify("Dereference of null pointer") == "null-deref"
    assert clang_static._classify("Use-after-free of released memory") == "use-after-free"
    assert clang_static._classify("stack buffer overflow past the end") == "buffer-overflow"
    assert clang_static._classify("some unrelated note") == "static-warning"

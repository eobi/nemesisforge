"""Sanitizer-report parser → typed CrashInfo."""
from forge.triage import parse

_ASAN = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000051
WRITE of size 4 at 0x602000000051 thread T0
    #0 0x4a1b2c in __asan_memcpy /llvm/compiler-rt/asan.c:1
    #1 0x108abc in parse_header /src/proj/parser.c:88:5
    #2 0x109def in main /src/proj/harness.c:12:3
0x602000000051 is located 1 bytes to the right of 16-byte region
allocated by thread T0 here:
    #0 0x4a0000 in malloc
    #1 0x108000 in parse_header /src/proj/parser.c:80:10
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""

_UBSAN = "/src/proj/math.c:12:5: runtime error: signed integer overflow: 2147483647 + 1"


def test_parse_asan_heap_overflow():
    ci = parse(_ASAN)
    assert ci.crashed
    assert ci.bug_type == "heap-buffer-overflow"
    assert ci.access == "WRITE" and ci.access_size == 4
    # top non-runtime frame is parse_header, not the __asan_memcpy interceptor
    assert ci.top.func == "parse_header" and ci.top.line == 88
    assert ci.stack_hash and len(ci.stack_hash) == 16
    assert ci.is_write_primitive() is True   # WRITE + overflow class


def test_parse_ubsan():
    ci = parse(_UBSAN)
    assert ci.crashed and ci.bug_type == "undefined-behavior"
    assert "signed integer overflow" in ci.summary
    assert ci.is_write_primitive() is False


def test_parse_no_crash():
    ci = parse("all good, exit 0")
    assert ci.crashed is False and ci.bug_type == ""


def test_read_is_not_write_primitive():
    ci = parse(_ASAN.replace("WRITE of size 4", "READ of size 8"))
    assert ci.access == "READ"
    assert ci.is_write_primitive() is False


def test_parse_captures_alloc_and_free_frames():
    from forge import triage
    txt = (
        "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60\n"
        "READ of size 4 at 0x60 thread T0\n"
        "    #0 0x1 in use /src/lib.c:10\n"
        "freed by thread T0 here:\n"
        "    #0 0x2 in free\n"
        "    #1 0x3 in do_free /src/lib.c:20\n"
        "\n"
        "previously allocated by thread T0 here:\n"
        "    #0 0x4 in malloc\n"
        "    #1 0x5 in do_alloc /src/lib.c:30\n")
    ci = triage.parse(txt)
    assert ci.crashed
    assert any("lib.c" in f.file for f in ci.free_frames)
    assert any("lib.c" in f.file for f in ci.alloc_frames)

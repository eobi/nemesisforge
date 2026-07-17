"""Phase C — BinaryTarget: fuzz a prebuilt binary, prove the crash by signal."""
import asyncio
import shutil
import subprocess

import pytest

from forge.job import binary_lab_job, run_job
from forge.ladder import Outcome, Rung
from forge.triage import parse


# ── signal-based crash parsing (no toolchain) ──
def test_parse_segv_from_signal():
    ci = parse("", rc=-11)              # SIGSEGV
    assert ci.crashed and ci.bug_type == "segv" and ci.access == "WRITE"
    ci2 = parse("", rc=139)            # 128 + 11
    assert ci2.crashed and ci2.bug_type == "segv"


def test_parse_abort_is_crash_not_memory():
    ci = parse("", rc=-6)              # SIGABRT
    assert ci.crashed and ci.bug_type == "abort" and ci.access == ""


def test_parse_clean_exit_no_crash():
    assert parse("ok", rc=0).crashed is False
    assert parse("ok", rc=1).crashed is False   # normal non-zero exit


def test_sanitizer_report_wins_over_signal():
    # if an ASan report is present, use it even though rc is a fatal signal
    ci = parse("ERROR: AddressSanitizer: heap-buffer-overflow\nWRITE of size 4 at 0x1",
               rc=-6)
    assert ci.bug_type == "heap-buffer-overflow"


# ── real binary fuzz (needs clang to produce a binary; no ASan) ──
VULN_SRC = r"""
#include <unistd.h>
int main(void){ char in[64]; long n=read(0,in,sizeof(in));
 if(n>8){ volatile int *p=0; return *p; }   /* null-deref → SIGSEGV on big input */
 return 0; }
"""


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not available")
def test_binary_job_proves_signal_crash(tmp_path):
    # compile a bare binary (no sanitizer) and treat it as a closed-source target
    src = tmp_path / "v.c"
    src.write_text(VULN_SRC)
    binpath = tmp_path / "v"
    subprocess.run(["clang", "-O0", str(src), "-o", str(binpath)], check=True)

    ctx, discovery, oracles, escalation = binary_lab_job(
        f"job-{tmp_path.name}", str(binpath), artifacts_root=tmp_path, max_tries=6)
    findings = asyncio.run(run_job(ctx, discovery=discovery, oracles=oracles,
                                   escalation=escalation))
    assert len(findings) == 1
    f = findings[0]
    # a SIGSEGV reached from untrusted stdin = security-relevant memory fault
    assert f.rung == Rung.PROVEN_SECURITY
    assert f.verdict.oracle == "binary-crash"
    assert f.verdict.evidence["memory_relevant"] is True

"""Phase-A end-to-end: a job fuzzes a lab harness, the oracle proves the crash,
a finding lands, and the whole run is streamed. No LLM, real clang+ASan."""
import asyncio
import shutil

import pytest

from forge.events import EventType
from forge.job import lab_job, run_job
from forge.ladder import Rung

pytestmark = pytest.mark.skipif(shutil.which("clang") is None,
                                reason="clang not available")

# malloc(1) so the fuzzer overflows on its 2-byte input (crash at try 1) — keeps
# the macOS ASan-slow run count to a minimum.
VULN = r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    char *buf = malloc(1);
    char in[256];
    long n = read(0, in, sizeof(in));
    if (n < 0) n = 0;
    memcpy(buf, in, (unsigned long)n);   /* heap-buffer-overflow once n > 1 */
    int r = buf[0]; free(buf); return r;
}
"""


def test_lab_job_end_to_end(tmp_path):
    ctx, discovery, oracles = lab_job(f"job-{tmp_path.name}", VULN,
                                      artifacts_root=tmp_path, max_tries=4)
    findings = asyncio.run(run_job(ctx, discovery=discovery, oracles=oracles))

    assert len(findings) == 1
    assert findings[0].rung == Rung.PROVEN_FAULT
    assert "heap-buffer-overflow" in findings[0].verdict.evidence["crash"]["bug_type"]

    types = [e.type for e in ctx.bus.all()]
    assert types[0] == EventType.JOB_START
    assert types[-1] == EventType.JOB_DONE
    # the fleet + the climb were all streamed
    spawns = {e.data.get("name") for e in ctx.bus.all()
              if e.type == EventType.AGENT_SPAWNED}
    assert {"coordinator", "fuzz"} <= spawns
    assert EventType.RUNG_UP in types
    assert EventType.CANDIDATE in types

    # findings persisted for the report/packager tier
    assert (ctx.artifacts / "findings.json").exists()

    # JOB_DONE carries the summary the UI shows
    done = ctx.bus.all()[-1]
    assert done.data["findings"] == 1 and "board" in done.data


def test_clean_harness_finds_nothing(tmp_path):
    safe = r"""
#include <unistd.h>
int main(void){ char in[16]; long n=read(0,in,sizeof(in)); return (int)(n>0?in[0]:0); }
"""
    ctx, discovery, oracles = lab_job(f"job-{tmp_path.name}", safe,
                                      artifacts_root=tmp_path, max_tries=3)
    findings = asyncio.run(run_job(ctx, discovery=discovery, oracles=oracles))
    assert findings == []
    assert ctx.bus.all()[-1].type == EventType.JOB_DONE

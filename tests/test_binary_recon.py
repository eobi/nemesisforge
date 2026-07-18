"""The reverse-engineering lens flags sink imports in a closed binary (no source),
and emits them as LEADS (not proven candidates)."""
import asyncio
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from forge.context import JobContext
from forge.events import EventType
from forge.targets.binary import BinaryTarget
from forge.agents.binary_recon import BinaryReconAgent


@pytest.mark.skipif(not shutil.which("clang") and not shutil.which("cc"),
                    reason="no C compiler")
@pytest.mark.skipif(not shutil.which("nm") and not shutil.which("objdump"),
                    reason="no nm/objdump")
def test_re_lens_flags_sink_imports(tmp_path):
    cc = shutil.which("clang") or shutil.which("cc")
    src = tmp_path / "v.c"
    src.write_text(
        "#include <string.h>\n#include <stdlib.h>\n#include <stdio.h>\n"
        "int main(int c, char**v){ char b[16]; if(c>1){ strcpy(b, v[1]); "
        "system(b);} printf(\"%s\", b); return 0; }\n")
    binp = tmp_path / "v"
    subprocess.run([cc, "-O0", "-g", str(src), "-o", str(binp)], check=True)

    tgt = BinaryTarget(binp, name="v")
    ctx = JobContext("re", target=tgt, artifacts_root=tmp_path)
    agent = BinaryReconAgent(ctx, binary=binp)
    cands = asyncio.run(agent.run())

    # leads, not oracle-provable candidates
    assert cands == []
    leads = {c.data.get("title") for c in ctx.bus.all()
             if c.type == EventType.CANDIDATE}
    # at minimum the command-exec sink is caught (system)
    assert any("system" in (t or "") for t in leads), leads
    persisted = (ctx.artifacts / "binary_recon.json")
    assert persisted.exists()


def test_re_lens_noops_without_binary(tmp_path):
    class _T:  # target with no binary
        sandbox = None
        binary = tmp_path / "does-not-exist"
    ctx = JobContext("re0", target=_T(), artifacts_root=tmp_path)
    agent = BinaryReconAgent(ctx, binary=tmp_path / "nope")
    assert asyncio.run(agent.run()) == []

"""Agentic reproduce: the ACI debug verb captures a real backtrace, and the
ReproduceAgent decodes its reproducer + no-ops cleanly when it can't build."""
import base64
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from forge.aci.tools import ACI
from forge.agents.reproduce import ReproduceAgent


def _aci():
    target = SimpleNamespace(workdir=None, sandbox=None, run=lambda *a, **k: None)
    return ACI(SimpleNamespace(target=target))


@pytest.mark.skipif(not (shutil.which("gdb") or shutil.which("lldb")),
                    reason="no gdb/lldb")
def test_debug_captures_backtrace_on_real_crash():
    cc = shutil.which("clang") or shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler")
    d = Path(tempfile.mkdtemp())
    src, binf = d / "crash.c", d / "crash"
    src.write_text("int main(){ volatile int *p=0; return *p; }\n")
    r = subprocess.run([cc, "-g", "-O0", str(src), "-o", str(binf)],
                       capture_output=True)
    if r.returncode != 0:
        pytest.skip("compile failed")
    out = _aci().debug(binf, stdin=b"", timeout=30)
    assert isinstance(out, str) and out            # produced debugger output
    # a batch debugger on a null-deref prints a stop/fault or a frame
    assert any(k in out.lower() for k in ("frame", "signal", "sigsegv", "#0",
                                          "stop reason", "main"))


def test_debug_never_raises_on_missing_binary():
    out = _aci().debug("/nonexistent/binary/xyz", stdin=b"abc", timeout=5)
    assert isinstance(out, str)                    # graceful, no exception


def test_reproduce_input_decodes_b64():
    pc = {"input_b64": base64.b64encode(b"hello").decode()}
    assert ReproduceAgent._input(pc) == b"hello"
    assert ReproduceAgent._input({"input": "raw"}) == b"raw"
    assert ReproduceAgent._input({}) == b""

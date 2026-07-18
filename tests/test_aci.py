"""ACI toolbelt (L3) — workdir-confined tools on every agent."""
from types import SimpleNamespace
from forge.aci.tools import ACI
from forge.context import JobContext
from forge.sandbox import LocalSandbox


def test_aci_read_grep_confined(tmp_path):
    (tmp_path / "a.c").write_text("int main(){ memcpy(x,y,n); return 0; }")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.c").write_text("void f(){ strcpy(a,b); }")
    target = SimpleNamespace(workdir=tmp_path, sandbox=LocalSandbox())
    aci = ACI(JobContext("j", target=target, artifacts_root=tmp_path))
    assert "int main" in aci.read_file("a.c")
    hits = aci.grep("memcpy|strcpy")
    assert any("a.c" in h for h in hits) and any("b.c" in h for h in hits)
    # path escape refused
    assert aci.read_file("../../../etc/passwd") == ""
    assert "a.c" in aci.list_dir(".")


def test_aci_on_agent(tmp_path):
    from forge.agents.base import Agent

    class A(Agent):
        async def run(self):
            return None
    target = SimpleNamespace(workdir=tmp_path, sandbox=LocalSandbox())
    a = A(JobContext("j", target=target, artifacts_root=tmp_path))
    assert a.aci is a.aci               # cached
    assert hasattr(a.aci, "build") and hasattr(a.aci, "shell")

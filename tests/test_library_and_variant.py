"""Phase L fixes: whole-library source collection (so multi-file libs LINK) and
L3 patch-seeded variant reasoning. Fast — no clang."""
import asyncio
import json
from types import SimpleNamespace

from forge.ingest import repo as R
from forge.agents.variant_hunter import VariantHunterAgent
from forge.context import JobContext
from forge.ingest.repo import RepoInfo


def test_library_sources_excludes_main_and_gathers_all(tmp_path):
    root = tmp_path / "lib"
    (root / "src").mkdir(parents=True)
    (root / "test").mkdir()
    (root / "src" / "reader.c").write_text("int read_it(void){return 0;}")
    (root / "src" / "writer.c").write_text("int write_it(void){return 1;}")
    (root / "src" / "cli.c").write_text("int main(int c,char**v){return 0;}")  # has main
    (root / "test" / "t.c").write_text("int main(){return 0;}")                # test dir
    libs = {p.name for p in R.library_sources(root)}
    assert libs == {"reader.c", "writer.c"}      # both lib files, no main(), no test


def test_patch_seeded_variant_reasoning_uses_the_diff():
    # With a seed patch, the reasoning tier must run variant analysis (find the
    # un-patched twin) — assert it feeds the diff to the model and returns noms.
    captured = {}

    class MockLLM:
        name, model, available = "mock", "m", True
        def complete_json(self, system, user, *, max_tokens=4096):
            captured["system"] = system; captured["user"] = user
            return [{"file": "b.c", "function": "copy2", "why": "same memcpy twin"}], {}
        def complete(self, *a, **k): return ""

    ctx = JobContext("j", target=SimpleNamespace(), artifacts_root=None)
    info = RepoInfo(root=None, url="x", sources=[SimpleNamespace()])
    ag = VariantHunterAgent(ctx, repo=info, llm=MockLLM(),
                            seed_patch="--- a/a.c\n+++ b/a.c\n- memcpy(d,s,n);\n+ if(n<=8) memcpy(d,s,n);")
    from forge.analysis import cscan
    sinks = [cscan.Sink(kind="memcpy", func="copy2", file="b.c", line=3,
                        text="memcpy(d,s,n)", input_influenced=True, reachable=True)]
    noms = asyncio.run(ag._reason(sinks))
    assert noms and noms[0]["function"] == "copy2"
    assert "variant analysis" in captured["system"].lower()
    assert "memcpy" in captured["user"]           # the patch diff reached the model

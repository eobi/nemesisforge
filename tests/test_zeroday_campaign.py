"""zeroday_repo_job — the asset-pointed campaign assembler. Confirms it dispatches
by artifact kind and applies reachability directing end-to-end (offline, via a
local source dir, which repo.clone accepts)."""
import pytest

from forge.ingest.resolve import Component, ResolvedArtifact
from forge.job import zeroday_repo_job


def test_rejects_non_source_artifact():
    art = ResolvedArtifact(Component(product="x"), kind="binary", locator="/bin/x")
    with pytest.raises(ValueError, match="SOURCE artifact"):
        zeroday_repo_job("job-x", art)
    unresolved = ResolvedArtifact(Component(product="x"), kind="unresolved", locator="")
    with pytest.raises(ValueError):
        zeroday_repo_job("job-x", unresolved)


# Two ranked entry-point sources; reachability hint {png} should focus to one.
_PNG_C = r"""
#include <stddef.h>
int png_read_image(const unsigned char *buf, size_t n){
  int x=0; for(size_t i=0;i<n;i++) x^=buf[i]; return x;   /* parse-ish */
}
int parse_png_header(const unsigned char *b){ return b?b[0]:0; }
"""
_OTHER_C = r"""
#include <stddef.h>
int parse_config(const char *s){ return s?(int)s[0]:0; }
int decode_widget(const char *s){ return s?1:0; }
"""


def test_source_artifact_applies_reachability_focus(tmp_path):
    repo = tmp_path / "mylib"
    repo.mkdir()
    (repo / "png.c").write_text(_PNG_C)
    (repo / "other.c").write_text(_OTHER_C)

    art = ResolvedArtifact(Component(product="mylib", version="1.0.0"),
                           kind="source", locator=str(repo), ref="")
    # use_build_system defaults on but is best-effort; no clang → graceful fallback.
    ctx, discovery, oracles, escalation, llm = zeroday_repo_job(
        "job-zd", art, reach_hints={"png"})

    # the pipeline is assembled (discovery agents + sanitizer/escalation oracles)
    assert discovery and oracles and escalation
    # reachability directing kept the png source and dropped the unrelated one
    focused = {p.name for p in ctx.repo.sources}
    assert "png.c" in focused
    assert "other.c" not in focused


def test_no_hints_keeps_full_surface(tmp_path):
    repo = tmp_path / "mylib2"
    repo.mkdir()
    (repo / "png.c").write_text(_PNG_C)
    (repo / "other.c").write_text(_OTHER_C)
    art = ResolvedArtifact(Component(product="mylib2", version="1.0.0"),
                           kind="source", locator=str(repo), ref="")
    ctx, *_ = zeroday_repo_job("job-zd2", art)      # no reach_hints
    names = {p.name for p in ctx.repo.sources}
    assert {"png.c", "other.c"} <= names            # nothing pruned

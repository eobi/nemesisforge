"""Phase K — continuous mode. `changed_functions` must map a git commit's diff to
the C functions it touched, so variant-hunting can focus on the just-changed code
(catch the regression the day it lands). Needs git."""
import shutil
import subprocess

import pytest

from forge.ingest import repo as _repo

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git missing")


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True,
                   capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                        "PATH": subprocess.os.environ.get("PATH", "")})


V1 = """\
#include <string.h>
int untouched(int a){ return a + 1; }
int parse_header(const char *in, unsigned n){
    char b[8];
    memcpy(b, in, 4);
    return b[0];
}
"""
# same file, parse_header's memcpy length changed (the "regression")
V2 = """\
#include <string.h>
int untouched(int a){ return a + 1; }
int parse_header(const char *in, unsigned n){
    char b[8];
    memcpy(b, in, n);          /* now trusts n — the introduced bug */
    return b[0];
}
"""


def test_changed_functions_isolates_the_edited_function(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "p.c").write_text(V1)
    _git(root, "add", "p.c")
    _git(root, "commit", "-q", "-m", "v1")
    base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()

    (root / "p.c").write_text(V2)
    _git(root, "commit", "-q", "-am", "v2: regression in parse_header")

    changed = _repo.changed_functions(root, base)
    assert "parse_header" in changed         # the edited function is in scope
    assert "untouched" not in changed        # the untouched one is not

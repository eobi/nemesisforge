"""Phase L1 — deep-campaign muscle: seed harvest, campaign budget, persistent
corpus seeding, MSan degrade. Fast (no clang except the cached MSan probe)."""
from pathlib import Path
from types import SimpleNamespace

from forge import fuzzengine
from forge.agents.codrive import CoDrivingFuzzAgent
from forge.agents.variant_hunter import _slug
from forge.context import JobContext
from forge.ingest import repo as R


def test_harvest_seeds_collects_test_inputs_not_source(tmp_path):
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "tests" / "input1.json").write_bytes(b'{"a":1}')
    (root / "tests" / "sample.bin").write_bytes(b"\x00\x01\x02\x03")
    (root / "tests" / ".gitignore").write_text("*.o")        # dotfile → skipped
    (root / "tests" / "helper.c").write_text("int x;")        # source → skipped
    (root / "src" / "lib.c").write_text("int y;")             # not seed dir
    (root / "tests" / "huge.dat").write_bytes(b"A" * (200 * 1024))  # too big

    seeds = {p.name for p in R.harvest_seeds(root)}
    assert seeds == {"input1.json", "sample.bin"}


def test_campaign_budget_spreads_over_long_rounds():
    ctx = JobContext("j", target=SimpleNamespace(), artifacts_root=Path("/tmp"))
    a = CoDrivingFuzzAgent(ctx, harness="x", campaign_minutes=60)
    assert a.rounds >= 8 and a.round_time >= 30
    assert abs(a.rounds * a.round_time - 3600) < a.round_time    # ~60 min total
    b = CoDrivingFuzzAgent(ctx, harness="x")                     # default unchanged
    assert b.rounds == 4 and b.round_time == 15


def test_slug_is_stable_and_safe():
    assert _slug("sqlite3StrAccumEnlarge") == "fn_sqlite3StrAccumEnlarge_"
    assert _slug("a/b c!") == "fn_a_b_c__"       # fs-safe
    assert _slug("x") == _slug("x")              # stable → persistent corpus key


def test_seed_corpus_copies_repo_inputs_idempotently(tmp_path):
    seedsrc = tmp_path / "s"
    seedsrc.mkdir()
    f1 = seedsrc / "a.bin"; f1.write_bytes(b"hello")
    f2 = seedsrc / "b.bin"; f2.write_bytes(b"world")
    ctx = JobContext("j", target=SimpleNamespace(), artifacts_root=tmp_path)
    ctx.seed_files = [f1, f2]
    corpus = tmp_path / "corpus"
    ag = CoDrivingFuzzAgent(ctx, harness="x", corpus_dir=corpus)
    assert ag._seed_corpus() == 2
    assert len(list(corpus.glob("seed_*"))) == 2
    assert ag._seed_corpus() == 0                # content-hashed → idempotent resume
    assert len(list(corpus.glob("seed_*"))) == 2


def test_msan_degrades_gracefully_when_unsupported():
    # On macOS MSan isn't supported → probe returns None (the build then degrades to
    # ASan). This just asserts the probe never raises and is cached.
    clang = fuzzengine.find_libfuzzer_clang()
    if clang is None:
        return
    r1 = fuzzengine.msan_fuzzer_flags(clang)
    r2 = fuzzengine.msan_fuzzer_flags(clang)
    assert r1 == r2                              # cached, deterministic
    assert r1 is None or isinstance(r1, list)

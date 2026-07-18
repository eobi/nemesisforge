"""Phase K — the genuine-zero-day gate. A crash is 'candidate' the first time,
'known' when it re-surfaces in a later run, and 'n-day' when it carries a CVE.
Pure + file-backed; fast."""
from forge.knowncrashes import KnownCrashes, N_DAY, KNOWN, CANDIDATE
from forge.ladder import Candidate, CodeLoc, Finding, Outcome, Rung, Verdict


def _finding(sink="parser.c:parse", stack="abc123", bug="heap-buffer-overflow",
             cve=None):
    ev = {"crash": {"bug_type": bug, "stack_hash": stack}}
    if cve:
        ev["cve_ids"] = [cve]
    cand = Candidate(bug_class="memory_safety", title="overflow",
                     location=CodeLoc(path=sink.split(":")[0], line=1,
                                      symbol=sink.split(":")[1]),
                     crash={"bug_type": bug, "stack_hash": stack})
    v = Verdict(Outcome.PROVEN, Rung.PROVEN_SECURITY, "sanitizer", evidence=ev)
    return Finding(candidate=cand, verdict=v, rung=Rung.PROVEN_SECURITY)


def test_new_then_known_then_persists(tmp_path):
    path = tmp_path / "known.json"
    kc = KnownCrashes(path)
    assert kc.classify(_finding()) == CANDIDATE      # first sighting → new
    assert kc.classify(_finding()) == KNOWN          # same bug again → not new
    kc.save()

    kc2 = KnownCrashes(path)                          # reload from disk
    assert kc2.classify(_finding()) == KNOWN         # persisted across runs
    # a genuinely different bug is still a candidate
    assert kc2.classify(_finding(sink="img.c:decode", stack="deadbeef")) == CANDIDATE


def test_cve_tagged_is_n_day(tmp_path):
    kc = KnownCrashes(tmp_path / "known.json")
    assert kc.classify(_finding(cve="CVE-2024-9999")) == N_DAY


def test_add_cve_demotes_a_prior_candidate(tmp_path):
    kc = KnownCrashes(tmp_path / "known.json")
    f = _finding(sink="x.c:y", stack="ff00")
    assert kc.classify(f) == CANDIDATE
    kc.add_cve(KnownCrashes.signature(f), "CVE-2025-1")
    assert kc.classify(f) == N_DAY                    # now known-disclosed

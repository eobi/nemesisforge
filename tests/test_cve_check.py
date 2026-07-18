"""Phase M1 — novelty verification. The load-bearing rule: NEVER claim 'novel'.
A finding is at most 'known' (matched an advisory) or 'unverified' (a human must
cross-check before anyone says zero-day). Learned from mislabeling CVE-2025-11680
as a candidate. No network in the asserted paths."""
from forge import cve_check


def test_never_returns_novel_only_known_or_unverified():
    assert cve_check.KNOWN == "known"
    assert cve_check.UNVERIFIED == "unverified"
    assert not hasattr(cve_check, "NOVEL")


def test_verification_queries_target_the_vulnerable_function():
    qs = cve_check.verification_queries(
        library="upng", function="unfilter_scanline",
        bug_type="heap-buffer-overflow")
    # the query that actually catches CVE-2025-11680 must be generated
    assert any("unfilter_scanline" in q and "CVE" in q for q in qs)
    assert any("upng" in q for q in qs)


def test_assess_defaults_to_unverified_without_a_match(monkeypatch):
    # no network → osv_lookup returns [] → status must be UNVERIFIED, never novel,
    # and it must still hand back queries for a human to run.
    monkeypatch.setattr(cve_check, "osv_lookup", lambda **k: [])
    r = cve_check.assess(library="upng", function="unfilter_scanline",
                         bug_type="heap-buffer-overflow")
    assert r["status"] == cve_check.UNVERIFIED
    assert r["queries"] and "UNVERIFIED" in r["note"]


def test_assess_reports_known_when_advisory_matches(monkeypatch):
    monkeypatch.setattr(cve_check, "osv_lookup",
                        lambda **k: [{"id": "CVE-2025-11680", "summary": "OOB write"}])
    r = cve_check.assess(library="libwebsockets", function="unfilter_scanline",
                         bug_type="heap-buffer-overflow")
    assert r["status"] == cve_check.KNOWN
    assert r["matches"][0]["id"] == "CVE-2025-11680"

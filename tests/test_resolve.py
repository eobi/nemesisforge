"""Artifact Resolver — the pure component→artifact bridge, plus the SBOM and
reachability directing that feed it. All offline/deterministic."""
from forge.ingest.resolve import (
    Component, normalize_version, resolve,
)
from forge.ingest.sbom import components_from_facts
from forge.ingest.reachability import focus_sources, reachable_hints


# ── normalize_version: pull a clean pin out of a noisy banner ──
def test_normalize_version_from_banner():
    assert normalize_version("1.2.14 (from bundled PNG lib)") == "1.2.14"
    assert normalize_version("v1.3.1") == "1.3.1"
    assert normalize_version("nginx/1.24.0") == "1.24.0"
    assert normalize_version("unknown") == "unknown"


# ── resolve: known upstream, ecosystems, unresolved ──
def test_resolve_known_upstream_pins_tag():
    a = resolve(Component(product="zlib", version="1.2.3"))
    assert a.kind == "source"
    assert a.locator == "https://github.com/madler/zlib"
    assert a.ref == "v1.2.3"


def test_resolve_underscore_tag_convention():
    a = resolve(Component(product="curl", version="8.10.1"))
    assert a.ref == "curl-8_10_1"


def test_resolve_dash_tag_convention():
    a = resolve(Component(product="freetype", version="2.13.3"))
    assert a.ref == "VER-2-13-3"


def test_resolve_pypi_exact_version_sdist():
    a = resolve(Component(product="pillow", version="10.0.0", ecosystem="pypi"))
    assert a.kind == "sdist"
    assert "pypi.org/pypi/pillow/10.0.0/json" in a.locator
    assert a.ref == "10.0.0"


def test_resolve_npm_exact_version_tarball():
    a = resolve(Component(product="lodash", version="4.17.20", ecosystem="npm"))
    assert a.kind == "npm-tarball"
    assert a.locator.endswith("lodash-4.17.20.tgz")


def test_resolve_explicit_repo_url_wins():
    a = resolve(Component(product="mylib", version="2.0.0",
                          repo_url="https://github.com/acme/mylib"))
    assert a.kind == "source"
    assert a.locator == "https://github.com/acme/mylib"
    assert a.ref == "v2.0.0"


def test_resolve_unknown_is_unresolved_with_reason():
    a = resolve(Component(product="totally-unknown-thing", version="1.0"))
    assert not a.resolved
    assert "no resolver" in a.reason


def test_resolve_pypi_without_version_unresolved():
    a = resolve(Component(product="pillow", ecosystem="pypi"))
    assert not a.resolved


# ── SBOM: Red facts → components ──
def test_components_from_facts_picks_product_from_banner():
    facts = {"tech_versions": [
        {"port": 443, "product": "http", "version": "nginx 1.24.0"},
        {"port": 22, "product": "ssh", "version": "OpenSSH 9.6"},
    ]}
    comps = components_from_facts(facts)
    prods = {c.product for c in comps}
    assert "nginx" in prods
    ngx = next(c for c in comps if c.product == "nginx")
    assert ngx.version == "1.24.0" and ngx.port == 443


def test_components_from_facts_dedupes_and_handles_unknown():
    facts = {"tech_versions": [
        {"port": 80, "product": "http", "version": "unknown"},
        {"port": 8080, "product": "http", "version": "unknown"},
    ]}
    comps = components_from_facts(facts)
    assert len(comps) == 1                     # deduped on (product, version)
    assert comps[0].version == ""              # 'unknown' banner → no pin


def test_components_from_empty_facts():
    assert components_from_facts({}) == []


# ── reachability: exposure → directing hints ──
def test_reachable_hints_png_directs_at_decoder():
    hints = reachable_hints(["image/png"])
    assert "png" in hints and "decode" in hints


def test_reachable_hints_empty_when_no_signal():
    assert reachable_hints([]) == set()
    assert reachable_hints(None) == set()


def test_focus_sources_prioritizes_matching_and_never_prunes_to_nothing():
    from pathlib import Path
    ranked = [Path("src/pngread.c"), Path("src/util.c"), Path("src/jpeg.c")]
    focused = focus_sources(ranked, reachable_hints(["png"]))
    assert Path("src/pngread.c") in focused
    # with no hints, the full list passes through unchanged
    assert focus_sources(ranked, set()) == ranked

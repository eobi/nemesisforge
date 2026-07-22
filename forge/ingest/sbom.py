"""Per-asset SBOM — turn Red's recon facts into a list of resolvable Components.

Nemesis Red's fingerprint/nmap engines drop `facts["tech_versions"]` — a list of
`{"port", "product", "version"}` rows (the nmap service name + its free-text
version banner) — and `facts["open_ports"]`. This module distills those into the
`Component` rows the resolver consumes, extracting a clean product + pinned
version out of the noisy banner text.

Pure string processing: no I/O, fully unit-testable. It is the first half of the
bridge (facts → components); `resolve.resolve` is the second (component → artifact).
"""
from __future__ import annotations

from .resolve import KNOWN_UPSTREAMS, Component, normalize_version

# Banner substrings → the canonical product name we know how to resolve. The nmap
# `product` column is a service name ("http"), so the real component is usually
# named in the free-text `version` banner ("... nginx 1.24.0"). We scan the banner
# for a product we have an upstream mapping for.
_BANNER_PRODUCTS = tuple(KNOWN_UPSTREAMS.keys()) + (
    "nginx", "apache", "openssh", "node.js", "express", "php", "python",
)


def _pick_product(service: str, banner: str) -> str:
    """Best product name: a known product named in the banner beats the bare
    nmap service name."""
    low = (banner or "").lower()
    for name in _BANNER_PRODUCTS:
        if name in low:
            return name
    return (service or "").strip() or "unknown"


def components_from_facts(facts: dict) -> list[Component]:
    """Distill `facts` into resolvable Components. Deduplicates on (product,
    version); rows with no usable version still surface (unpinned) so the caller
    can decide."""
    rows = (facts or {}).get("tech_versions") or []
    out: list[Component] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        # Accept both fact shapes: Red/nmap uses {"product","version"} (product =
        # service name, version = banner text); Pentagon fingerprint uses
        # {"name","version"} (name = product, version = clean version).
        service = str(row.get("product") or row.get("name") or "")
        banner = str(row.get("version") or "")
        if banner.lower() in ("", "unknown"):
            banner = ""
        product = _pick_product(service, banner)
        version = normalize_version(banner)
        key = (product.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Component(
            product=product, version=version, ecosystem="auto",
            port=int(row.get("port") or 0),
            evidence=(banner or service or "").strip()))
    return out

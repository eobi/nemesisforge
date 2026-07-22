"""Artifact Resolver — the bridge from a *live component* to an *analyzable artifact*.

This is the linchpin that turns "point at a deployed asset" into "hunt a zero-day".
Nemesis Red's recon yields a component per asset — `(product, version, port)` plus
exposure hints. Nemesis Forge hunts *artifacts* — a source tree, an sdist, a
binary. Neither can cross that gap alone; this module does, deterministically.

`resolve(component)` is a **pure** function: it computes *where* the analyzable
artifact lives (a git URL + the exact version tag, an sdist download URL, a
package tarball, an image ref, a binary path) without doing any I/O. That
coordinate computation is the novel part and is fully unit-testable offline.
`acquire(artifact, dest)` then does the network/disk work, reusing
`forge.ingest.repo.clone` for the source path so the resolved artifact feeds
`repo_job` unchanged.

Version pinning is the whole game: resolving the *exact* running version is what
makes the downstream patch-seeding "version-exact" (the specific missing security
patches become directed targets) rather than a generic corpus.

Safety: resolving is recon-only bookkeeping; acquiring pulls third-party code the
caller is authorized to test, into the sandbox — never the live asset.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Component:
    """One identified component of a live asset (a row of the per-asset SBOM)."""
    product: str
    version: str = ""
    ecosystem: str = "auto"        # git | pypi | npm | oci | binary | auto
    repo_url: str = ""             # upstream git URL if already known
    port: int = 0
    evidence: str = ""             # how Red identified it (banner, header, …)
    exposure: list[str] = field(default_factory=list)  # formats/endpoints it accepts


@dataclass
class ResolvedArtifact:
    """Where an analyzable artifact for a component lives + how to fetch it."""
    component: Component
    kind: str                      # source | sdist | npm-tarball | image | binary | unresolved
    locator: str                   # git URL | download URL | image ref | file path
    ref: str = ""                  # git tag / version pin
    reason: str = ""               # why unresolved, or a note

    @property
    def resolved(self) -> bool:
        return self.kind != "unresolved"


# Curated product → (upstream git URL, tag template). Extensible; the archetypes
# are the outdated bundled libraries the FastStone work surfaced (libpng/zlib) plus
# the common memory-safety-rich parsers. Tag conventions differ per project, hence
# the template placeholders resolved by `_format_tag`.
KNOWN_UPSTREAMS: dict[str, tuple[str, str]] = {
    "zlib":          ("https://github.com/madler/zlib", "v{version}"),
    "libpng":        ("https://github.com/pnggroup/libpng", "v{version}"),
    "libjpeg-turbo": ("https://github.com/libjpeg-turbo/libjpeg-turbo", "{version}"),
    "libwebp":       ("https://github.com/webmproject/libwebp", "v{version}"),
    "openssl":       ("https://github.com/openssl/openssl", "openssl-{version}"),
    "curl":          ("https://github.com/curl/curl", "curl-{version_underscore}"),
    "expat":         ("https://github.com/libexpat/libexpat", "R_{version_underscore}"),
    "libexpat":      ("https://github.com/libexpat/libexpat", "R_{version_underscore}"),
    "freetype":      ("https://github.com/freetype/freetype", "VER-{version_dash}"),
    "libxml2":       ("https://github.com/GNOME/libxml2", "v{version}"),
    "pcre2":         ("https://github.com/PCRE2Project/pcre2", "pcre2-{version}"),
    "sqlite":        ("https://github.com/sqlite/sqlite", "version-{version}"),
}

_SEMVER = re.compile(r"\d+(?:\.\d+){1,3}[a-z]?")


def normalize_version(raw: str) -> str:
    """Extract a clean version string from a banner/version field.
    '1.2.14 (from PNG lib)' → '1.2.14'; 'v1.3.1' → '1.3.1'."""
    if not raw:
        return ""
    m = _SEMVER.search(raw.strip().lstrip("vV"))
    return m.group(0) if m else raw.strip()


def _format_tag(template: str, version: str) -> str:
    v = normalize_version(version)
    return (template
            .replace("{version_underscore}", v.replace(".", "_"))
            .replace("{version_dash}", v.replace(".", "-"))
            .replace("{version}", v))


def resolve(component: Component) -> ResolvedArtifact:
    """Pure: compute the artifact coordinates for a component. No I/O."""
    product = (component.product or "").strip()
    version = normalize_version(component.version)
    eco = (component.ecosystem or "auto").lower()

    # An explicit upstream repo URL always wins — pin to the version tag if we have one.
    if component.repo_url and (eco in ("auto", "git")):
        ref = _format_tag("v{version}", version) if version else ""
        return ResolvedArtifact(component, "source", component.repo_url, ref=ref,
                                reason="explicit upstream repo")

    if eco == "pypi":
        if not version:
            return ResolvedArtifact(component, "unresolved", "",
                                    reason="pypi component with no version to pin")
        # The PyPI JSON API row for the EXACT version; acquire() picks the sdist.
        return ResolvedArtifact(
            component, "sdist",
            f"https://pypi.org/pypi/{product}/{version}/json", ref=version,
            reason="pypi exact-version sdist")

    if eco == "npm":
        if not version:
            return ResolvedArtifact(component, "unresolved", "",
                                    reason="npm component with no version to pin")
        return ResolvedArtifact(
            component, "npm-tarball",
            f"https://registry.npmjs.org/{product}/-/{product}-{version}.tgz",
            ref=version, reason="npm exact-version tarball")

    if eco == "oci":
        # product is the image ref (repo[:tag] / digest); pulled + extracted later.
        return ResolvedArtifact(component, "image", product,
                                ref=version, reason="container image")

    if eco == "binary":
        return ResolvedArtifact(component, "binary", product,
                                reason="raw binary on a reachable host")

    # auto / unknown ecosystem: try the curated OSS upstream registry by product.
    key = product.lower()
    if key in KNOWN_UPSTREAMS:
        url, tmpl = KNOWN_UPSTREAMS[key]
        ref = _format_tag(tmpl, version) if version else ""
        return ResolvedArtifact(component, "source", url, ref=ref,
                                reason=f"known upstream for {product}")

    return ResolvedArtifact(
        component, "unresolved", "",
        reason=f"no resolver for product={product!r} ecosystem={eco!r} — add an "
               f"upstream mapping or pass repo_url/ecosystem")


def acquire(artifact: ResolvedArtifact, dest: Path, *, ref: Optional[str] = None):
    """Fetch a resolved artifact into `dest` (I/O). Returns a `RepoInfo` for the
    source path (reusing repo.clone, so it feeds repo_job unchanged); for other
    kinds returns the local path the caller hands to a BinaryTarget/build step.
    Only the source/binary kinds are wired in Phase 0; the rest raise a clear
    NotImplementedError naming the phase that lands them."""
    from . import repo as _repo
    if artifact.kind == "source":
        if not artifact.locator:
            raise ValueError("source artifact has no git URL to clone")
        return _repo.clone(artifact.locator, Path(dest),
                           ref=ref or artifact.ref or None)
    if artifact.kind == "binary":
        p = Path(artifact.locator)
        if not p.exists():
            raise FileNotFoundError(f"binary artifact not found: {p}")
        return p
    raise NotImplementedError(
        f"acquire() for kind={artifact.kind!r} lands in a later phase "
        f"(sdist/npm → Phase 1 fetch, image → Phase 2, firmware → Phase 3)")

"""Where the server is allowed to read and write.

The engine runs campaigns, which means it compiles and executes code the operator pointed
it at. A tool surface that will do that anywhere on the filesystem is not a tool surface,
it is a remote shell. Every path a tool accepts is resolved and checked against a root the
operator names at startup; symlinks are resolved BEFORE the check, because a relative path
that escapes through one is the oldest trick there is.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional


class RootError(Exception):
    """A path left the operator's root, or no root was set."""


class Root:
    def __init__(self, path: Path) -> None:
        self.path = path

    @classmethod
    def of(cls, raw: str) -> "Root":
        p = Path(raw).expanduser().resolve()
        if not p.is_dir():
            raise RootError(f"target root is not a directory: {p}")
        return cls(p)

    def resolve(self, raw: str) -> Path:
        """A path inside the root, or RootError. Resolves symlinks first."""
        if not raw:
            raise RootError("empty path")
        p = Path(raw).expanduser()
        p = (self.path / p) if not p.is_absolute() else p
        p = p.resolve()
        if p != self.path and self.path not in p.parents:
            raise RootError(f"path escapes the target root: {p} not under {self.path}")
        return p


def need_root(root: Optional[Root]) -> Root:
    if root is None:
        raise RootError(
            "no target root. Start the server with --target-root <dir>; tools that touch "
            "the filesystem are refused without one rather than defaulting to cwd.")
    return root

"""Portal auth — a small, dependency-free session layer that gates the engine.

Credentials are configured out-of-band (never in code): `FORGE_USERS` as
`user:<sha256hex>,user2:<sha256hex>` and/or `FORGE_PASSWORD` (for user `admin`).
If none are set, a random admin password is generated once at startup and printed
to the server log — so the portal is never accidentally left open with a known
default. Sessions are stateless HMAC-signed tokens (secret from `FORGE_SECRET`, else
a per-process random), carried in an httponly cookie. Set `FORGE_AUTH=off` to
disable auth for trusted-local / test use.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Optional

COOKIE = "forge_session"
_RUNTIME_SECRET = secrets.token_bytes(32)
_GENERATED: Optional[str] = None


def enabled() -> bool:
    return os.environ.get("FORGE_AUTH", "on").lower() not in ("off", "0", "false")


def _secret() -> bytes:
    s = os.environ.get("FORGE_SECRET")
    return s.encode() if s else _RUNTIME_SECRET


def _sha(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()


def _configured_users() -> dict[str, str]:
    users: dict[str, str] = {}
    for pair in os.environ.get("FORGE_USERS", "").split(","):
        if ":" in pair:
            u, h = pair.split(":", 1)
            users[u.strip()] = h.strip().lower()
    pw = os.environ.get("FORGE_PASSWORD")
    if pw:
        users.setdefault("admin", _sha(pw))
    return users


def ensure_default_password() -> Optional[str]:
    """If no users are configured, mint a random admin password once and return it
    (to be logged). Returns None when real credentials exist."""
    global _GENERATED
    if _configured_users():
        return None
    if _GENERATED is None:
        _GENERATED = secrets.token_urlsafe(9)
    return _GENERATED


def _effective_users() -> dict[str, str]:
    users = _configured_users()
    if users:
        return users
    return {"admin": _sha(ensure_default_password() or "")}


def verify_credentials(username: str, password: str) -> bool:
    h = _effective_users().get(username or "")
    return bool(h) and hmac.compare_digest(h, _sha(password or ""))


def make_token(username: str, *, ttl: int = 86400) -> str:
    payload = f"{username}:{int(time.time()) + ttl}"
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()


def verify_token(token: str) -> Optional[str]:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, exp, sig = raw.rsplit(":", 2)
        good = hmac.new(_secret(), f"{username}:{exp}".encode(),
                        hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good, sig) or int(exp) < time.time():
            return None
        return username
    except Exception:
        return None

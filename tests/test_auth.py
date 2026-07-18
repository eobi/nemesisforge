"""Portal auth — credential check, signed-token round-trip, tamper rejection."""
import importlib

import forge.auth as auth


def test_credentials_and_token_roundtrip(monkeypatch):
    monkeypatch.setenv("FORGE_PASSWORD", "hunter2")
    monkeypatch.setenv("FORGE_SECRET", "test-secret")
    importlib.reload(auth)               # pick up env
    assert auth.verify_credentials("admin", "hunter2")
    assert not auth.verify_credentials("admin", "nope")
    assert not auth.verify_credentials("ghost", "hunter2")
    tok = auth.make_token("admin")
    assert auth.verify_token(tok) == "admin"
    assert auth.verify_token(tok + "x") is None      # tampered signature
    assert auth.verify_token("not-a-token") is None


def test_expired_token_is_rejected(monkeypatch):
    monkeypatch.setenv("FORGE_SECRET", "s")
    importlib.reload(auth)
    assert auth.verify_token(auth.make_token("u", ttl=-1)) is None


def test_generated_default_when_unconfigured(monkeypatch):
    monkeypatch.delenv("FORGE_PASSWORD", raising=False)
    monkeypatch.delenv("FORGE_USERS", raising=False)
    importlib.reload(auth)
    pw = auth.ensure_default_password()
    assert pw and auth.verify_credentials("admin", pw)   # portal never left open


def test_auth_can_be_disabled(monkeypatch):
    monkeypatch.setenv("FORGE_AUTH", "off")
    importlib.reload(auth)
    assert auth.enabled() is False
    monkeypatch.delenv("FORGE_AUTH")
    importlib.reload(auth)
    assert auth.enabled() is True         # on by default

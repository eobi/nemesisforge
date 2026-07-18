"""Load the INI-style .env into provider env vars.

The project .env uses configparser sections ([anthropic]/[openai]/[gemini]/
[ollama]) rather than KEY=VALUE. This maps those into the ANTHROPIC_API_KEY /
OPENAI_API_KEY / … env vars the provider registry reads. Never logs values.
Idempotent; existing env vars win.
"""
from __future__ import annotations

import configparser
import os
from pathlib import Path

_MAP = {
    ("anthropic", "api_key"): "ANTHROPIC_API_KEY",
    ("openai", "api_key"): "OPENAI_API_KEY",
    ("gemini", "api_key"): "GEMINI_API_KEY",
    ("openrouter", "api_key"): "OPENROUTER_API_KEY",
    ("xai", "api_key"): "XAI_API_KEY",
}
_loaded = False


def load_env(path: str | Path | None = None) -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    p = Path(path or (Path(__file__).resolve().parent.parent / ".env"))
    if not p.exists():
        return
    cfg = configparser.ConfigParser()
    try:
        cfg.read(p)
    except Exception:
        return
    for (sec, key), env in _MAP.items():
        if cfg.has_option(sec, key):
            val = cfg.get(sec, key).strip()
            if val and not os.environ.get(env):
                os.environ[env] = val
    if cfg.has_option("ollama", "host"):
        host = cfg.get("ollama", "host").strip()
        if host:
            os.environ.setdefault("OLLAMA_HOST", host)

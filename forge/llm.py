"""LLM layer — the brain. Multi-provider, user-selected from the portal.

The deterministic core (fuzzing + oracles) proves things with no model. The LLM
is the *intuition* on top: it hypothesizes where bugs hide, writes custom exploit
PoCs to reach primitives fuzzing can't, and narrates root cause + patches — while
every claim it makes is still handed to a deterministic oracle to prove. The
model proposes; the oracle disposes.

Providers are pluggable and chosen per-run from the portal:
  - anthropic         (Anthropic Messages API; ANTHROPIC_API_KEY)
  - openai            (OpenAI /v1/chat/completions; OPENAI_API_KEY)
  - openrouter        (OpenAI-compatible; OPENROUTER_API_KEY)
  - ollama / local    (OpenAI-compatible local server; no key — e.g. :11434, :9920)
  - null              (no model — the deterministic core still runs fully)

Uses stdlib urllib so there's no hard SDK dependency; any OpenAI-compatible
endpoint works by pointing `base_url` at it.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class LLMClient(Protocol):
    name: str
    model: str
    available: bool

    def complete(self, system: str, user: str, *, max_tokens: int = 2048) -> str: ...
    def complete_json(self, system: str, user: str, *,
                      max_tokens: int = 4096) -> tuple[Optional[Any], dict]: ...


# ── provider registry (drives the portal dropdown) ──
PROVIDERS: dict[str, dict] = {
    "anthropic": {
        "label": "Anthropic (Claude)", "env": "ANTHROPIC_API_KEY",
        "models": ["claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5"],
        "kind": "anthropic", "base": "https://api.anthropic.com"},
    "openai": {
        "label": "OpenAI (GPT)", "env": "OPENAI_API_KEY",
        "models": ["gpt-5.1", "gpt-5.1-codex", "o4"],
        "kind": "openai", "base": "https://api.openai.com"},
    "openrouter": {
        "label": "OpenRouter (multi-model)", "env": "OPENROUTER_API_KEY",
        "models": ["anthropic/claude-opus-4-8", "openai/gpt-5.1",
                   "deepseek/deepseek-r1", "meta-llama/llama-3.3-70b-instruct"],
        "kind": "openai", "base": "https://openrouter.ai/api"},
    "ollama": {
        "label": "Ollama (local)", "env": None,
        "models": ["qwen2.5-coder:7b", "llama3.1:8b", "deepseek-r1:8b"],
        "kind": "openai", "base": "http://localhost:11434"},
    "local": {
        "label": "Local server (OpenAI-compatible)", "env": None,
        "models": ["default"], "kind": "openai", "base": "http://127.0.0.1:9920"},
}


def list_providers() -> list[dict]:
    """For the portal: providers + models + whether a key is present."""
    out = []
    for pid, p in PROVIDERS.items():
        configured = p["env"] is None or bool(os.environ.get(p["env"]))
        out.append({"id": pid, "label": p["label"], "models": p["models"],
                    "needs_key": p["env"] is not None, "configured": configured})
    return out


def _post_json(url: str, headers: dict, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


class NullLLM:
    name = "null"
    model = "-"
    available = False

    def complete(self, system, user, *, max_tokens=2048) -> str:
        return ""

    def complete_json(self, system, user, *, max_tokens=4096):
        return None, {"error": "no LLM configured", "cost_usd": 0.0}


class AnthropicClient:
    name = "anthropic"

    def __init__(self, model: str, api_key: str, base: str, timeout: float = 120):
        self.model, self.api_key, self.base, self.timeout = model, api_key, base, timeout
        self.available = bool(api_key)

    def complete(self, system, user, *, max_tokens=2048) -> str:
        if not self.available:
            return ""
        try:
            d = _post_json(
                f"{self.base}/v1/messages",
                {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                {"model": self.model, "max_tokens": max_tokens, "system": system,
                 "messages": [{"role": "user", "content": user}]}, self.timeout)
            parts = d.get("content") or []
            return "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        except Exception:
            return ""

    def complete_json(self, system, user, *, max_tokens=4096):
        text = self.complete(system + "\nReturn ONLY valid JSON.", user,
                             max_tokens=max_tokens)
        return _extract_json(text), {"cost_usd": 0.0}


class OpenAICompatClient:
    """OpenAI /v1/chat/completions — covers OpenAI, OpenRouter, Ollama, and any
    local server (llama.cpp, vLLM, LM Studio, the :9920 endpoint)."""
    name = "openai"

    def __init__(self, model: str, api_key: Optional[str], base: str,
                 timeout: float = 120):
        self.model, self.api_key, self.base, self.timeout = model, api_key, base, timeout
        # local servers need no key; hosted ones do
        self.available = True

    def complete(self, system, user, *, max_tokens=2048) -> str:
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            d = _post_json(
                f"{self.base}/v1/chat/completions", headers,
                {"model": self.model, "max_tokens": max_tokens,
                 "messages": [{"role": "system", "content": system},
                              {"role": "user", "content": user}]}, self.timeout)
            return d["choices"][0]["message"]["content"] or ""
        except Exception:
            return ""

    def complete_json(self, system, user, *, max_tokens=4096):
        text = self.complete(system + "\nReturn ONLY valid JSON.", user,
                             max_tokens=max_tokens)
        return _extract_json(text), {"cost_usd": 0.0}


def _extract_json(text: str) -> Optional[Any]:
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = t.split("```", 2)[1].lstrip("json").strip() if "```" in t[3:] else t
    for a, b in (("[", "]"), ("{", "}")):
        i, j = t.find(a), t.rfind(b)
        if i != -1 and j > i:
            try:
                return json.loads(t[i:j + 1])
            except Exception:
                pass
    return None


def make_client(provider: Optional[str] = None, model: Optional[str] = None,
                api_key: Optional[str] = None,
                base_url: Optional[str] = None) -> LLMClient:
    """Resolve the user's portal selection to a working client (NullLLM if the
    provider is unknown or a required key is absent)."""
    if not provider or provider == "null":
        return NullLLM()
    spec = PROVIDERS.get(provider)
    if spec is None:
        return NullLLM()
    key = api_key or (os.environ.get(spec["env"]) if spec["env"] else None)
    if spec["env"] and not key:
        return NullLLM()            # hosted provider without a key → no model
    base = base_url or spec["base"]
    mdl = model or spec["models"][0]
    if spec["kind"] == "anthropic":
        return AnthropicClient(mdl, key, base)
    return OpenAICompatClient(mdl, key, base)

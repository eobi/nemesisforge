"""LLM seam — the one place a model plugs into the fleet.

Everything deterministic (fuzzing, sanitizer/differential/controllability
oracles) runs with NO model. The LLM's job is the parts that genuinely need
reasoning: writing a *custom* exploit PoC to reach a primitive the fuzzer can't,
hypothesizing a root cause, drafting the vendor write-up. Those agents take an
`LLMClient`; with `NullLLM` they no-op (and say so), so the system is fully
functional and testable without a provider, and a provider is a drop-in.

Keeping this a thin protocol (not a concrete SDK) is deliberate: the provider
choice (Anthropic / subscription CLI / local / multi-model voting) is a decision
to make explicitly, and this is where it lands. `make_client` is the factory to
extend when that decision is made.
"""
from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class LLMClient(Protocol):
    name: str
    available: bool

    def complete(self, system: str, user: str, *, max_tokens: int = 2048) -> str:
        """Return the model's text completion."""
        ...

    def complete_json(self, system: str, user: str, *,
                      max_tokens: int = 4096) -> tuple[Optional[Any], dict]:
        """Return (parsed_json | None, meta) where meta carries cost/error."""
        ...


class NullLLM:
    """The default: no model. Agents that require one degrade gracefully and
    emit a 'no LLM configured' signal instead of silently doing nothing."""
    name = "null"
    available = False

    def complete(self, system: str, user: str, *, max_tokens: int = 2048) -> str:
        return ""

    def complete_json(self, system: str, user: str, *,
                      max_tokens: int = 4096) -> tuple[Optional[Any], dict]:
        return None, {"error": "no LLM configured", "cost_usd": 0.0}


def make_client(provider: Optional[str] = None,
                model: Optional[str] = None) -> LLMClient:
    """Resolve an LLMClient. Today only NullLLM — real providers (Anthropic API /
    subscription CLI / local / a multi-model voting jury) plug in here once the
    provider decision is made. Multi-provider voting is the recommended shape:
    one model writes the exploit, a *different* one adjudicates it (writer ≠
    validator at the model level too)."""
    # TODO(provider): wire Anthropic / OpenAI-compatible / subscription-CLI here.
    return NullLLM()

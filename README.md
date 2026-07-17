# Nemesis Forge

**Zero-day discovery → proven-exploit engine.** An LLM fleet *proposes*;
deterministic oracles *prove*; a fault is escalated up a ladder to a
**vendor-grade exploit primitive** — with every step certified by a non-LLM
oracle and every activity visible.

The thesis: proof is a **captured artifact, not a model's claim**. The universal
reward is the **differential sanitizer oracle** — a PoC passes iff it triggers
the same typed sanitizer crash on the vulnerable build and *not* on the patched
build (how OSS-Fuzz / syzbot / CyberGym define success, and what a vendor checks).

## The proof ladder
```
0 UNVERIFIED  1 PROVEN_FAULT  2 PROVEN_REACHABLE  3 PROVEN_SECURITY
4 PROVEN_PRIMITIVE  5 PROVEN_EXPLOIT  6 VENDOR_READY
```
Rungs 4–6 (weaponization → vendor packet) are what Nemesis Zero never did.
Only VENDOR_READY ships to a vendor. Scope: source → binary → device.
Proof model: coordinated vendor disclosure. See the design doc for the full
seven-layer architecture.

## Status — Phase A (spine)
- `forge/ladder.py` — the extended proof ladder + LadderState.
- `forge/events.py` — the activity event bus (visibility plane backbone).

## Dev
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

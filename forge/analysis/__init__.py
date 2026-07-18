"""Code intelligence (L-analysis) — the reasoning tier's eyes.

Dependency-free static analysis of C/C++: functions, a call graph, dangerous
sinks, and reachability from untrusted-input entry points. This is what lets the
LLM reason over *ranked, reachable* sinks with real context instead of 25 blind
grep lines — the Phase-I upgrade that makes variant analysis (Big Sleep's method)
possible.
"""
from .cscan import CodeIntel, Func, Sink, scan_repo, scan_text  # noqa: F401

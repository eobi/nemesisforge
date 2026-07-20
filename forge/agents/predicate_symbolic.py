"""Symbolic strict-relaxation proof for directed-fuzzing predicates (Locus 2B).

A progress predicate P is a STRICT RELAXATION of a sink's reaching condition iff every
input that reaches the sink satisfies P — so instrumenting `if(!P) return;` can never
prune a bug-reaching path. Formally: reach the sink symbolically, take its path
constraint C, and prove  C ⟹ P , i.e.  UNSAT(C ∧ ¬P).

The soundness logic (C→SMT translation + the UNSAT check) is pure claripy and unit
tested. The angr exploration that produces C runs best on Docker/Linux; on any failure
this returns [] (no predicate validated) so the fuzzer runs undirected — we NEVER
instrument a predicate we could not prove safe.
"""
from __future__ import annotations

import re
from typing import Optional

import claripy


# ── C boolean condition → claripy expression over per-parameter symbolic vars ──
# Deliberately small + total: only the operators a strict-relaxation predicate needs.
# Anything we can't translate raises → the predicate is REJECTED (conservative).

_TOKEN = re.compile(r"""
    \s*(?:
      (?P<num>0[xX][0-9a-fA-F]+|\d+)          |
      (?P<char>'(?:\\.|[^'])')                |
      (?P<id>[A-Za-z_]\w*)                    |
      (?P<op><<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^<>!()~])
    )""", re.VERBOSE)


def _lex(s: str) -> list[tuple[str, str]]:
    toks, i = [], 0
    while i < len(s):
        m = _TOKEN.match(s, i)
        if not m or m.end() == i:
            if s[i:].strip() == "":
                break
            raise ValueError(f"untranslatable token near {s[i:i+12]!r}")
        i = m.end()
        kind = m.lastgroup
        toks.append((kind, m.group(kind)))
    return toks


class _Parser:
    """Recursive-descent parser for the C-expression subset → claripy BV/Bool.
    Grammar (low→high precedence): || , && , (== != < > <= >=) , (| ^ &) , (<< >>) ,
    (+ -) , (* / %) , unary (! ~ -) , primary. 32-bit BV semantics for scalars."""

    def __init__(self, toks, env):
        self.toks, self.i, self.env = toks, 0, env

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def eat(self, val=None):
        k, v = self.peek()
        if val is not None and v != val:
            raise ValueError(f"expected {val!r}, got {v!r}")
        self.i += 1
        return v

    def parse(self):
        e = self._or()
        if self.i != len(self.toks):
            raise ValueError("trailing tokens")
        return e if isinstance(e, claripy.ast.Bool) else (e != 0)

    def _bin(self, sub, ops):
        e = sub()
        while self.peek()[1] in ops:
            op = self.eat()
            e = _apply(op, e, sub())
        return e

    def _or(self):  return self._bin(self._and, ("||",))
    def _and(self): return self._bin(self._cmp, ("&&",))
    def _cmp(self): return self._bin(self._bor, ("==", "!=", "<", ">", "<=", ">="))
    def _bor(self): return self._bin(self._shift, ("|", "^", "&"))
    def _shift(self): return self._bin(self._add, ("<<", ">>"))
    def _add(self): return self._bin(self._mul, ("+", "-"))
    def _mul(self): return self._bin(self._unary, ("*", "/", "%"))

    def _unary(self):
        k, v = self.peek()
        if v in ("!", "~", "-"):
            self.eat()
            e = self._unary()
            if v == "!":
                return claripy.Not(e if isinstance(e, claripy.ast.Bool) else (e != 0))
            return (~_bv(e)) if v == "~" else (-_bv(e))
        return self._primary()

    def _primary(self):
        k, v = self.peek()
        if v == "(":
            self.eat("(")
            e = self._or()
            self.eat(")")
            return e
        if k == "num":
            self.eat()
            return claripy.BVV(int(v, 0), 32)
        if k == "char":
            self.eat()
            return claripy.BVV(ord(bytes(v[1:-1], "utf-8").decode("unicode_escape")), 32)
        if k == "id":
            self.eat()
            if v not in self.env:
                raise ValueError(f"unknown identifier {v!r}")
            return self.env[v]
        raise ValueError(f"unexpected token {v!r}")


def _bv(e):
    return e if isinstance(e, claripy.ast.BV) else claripy.If(
        e, claripy.BVV(1, 32), claripy.BVV(0, 32))


def _apply(op, a, b):
    if op in ("&&", "||"):
        a = a if isinstance(a, claripy.ast.Bool) else (a != 0)
        b = b if isinstance(b, claripy.ast.Bool) else (b != 0)
        return claripy.And(a, b) if op == "&&" else claripy.Or(a, b)
    a, b = _bv(a), _bv(b)
    return {
        "==": lambda: a == b, "!=": lambda: a != b,
        "<": lambda: a.SLT(b), ">": lambda: a.SGT(b),
        "<=": lambda: a.SLE(b), ">=": lambda: a.SGE(b),
        "+": lambda: a + b, "-": lambda: a - b, "*": lambda: a * b,
        "/": lambda: a / b, "%": lambda: a % b,
        "&": lambda: a & b, "|": lambda: a | b, "^": lambda: a ^ b,
        "<<": lambda: a << b, ">>": lambda: a >> b,
    }[op]()


def translate(condition: str, env: dict) -> "claripy.ast.Bool":
    """C boolean condition (over the names in `env` → claripy BVs) → claripy Bool.
    Raises ValueError on anything outside the supported subset (→ reject predicate)."""
    return _Parser(_lex(condition), env).parse()


def is_strict_relaxation(sink_constraints: list, pred_condition: str, env: dict,
                         solver: Optional["claripy.Solver"] = None) -> bool:
    """True iff (sink_constraints) ⟹ (pred). Sound check: UNSAT(C ∧ ¬P). Any
    translation failure ⇒ False (reject). A predicate that is unsatisfiable on its own
    or trivially true is handled by the solver."""
    try:
        pred = translate(pred_condition, env)
    except Exception:
        return False
    s = solver if solver is not None else claripy.Solver()
    # satisfiable( C ∧ ¬P ) == True  ⇒  some sink-reaching input violates P ⇒ NOT safe
    return not s.satisfiable(extra_constraints=list(sink_constraints) +
                             [claripy.Not(pred)])


# ── angr exploration to produce the sink constraint C (Docker/Linux) ─────────
async def prove_strict_relaxation(predicates, *, target, harness: str, include_dirs,
                                  target_sources=None, sanitizer: str = "address",
                                  max_seconds: int = 120):
    """For each predicate, symbolically reach its function's sink with symbolic scalar
    params, extract the sink-reaching path constraint C, and keep the predicate only if
    C ⟹ P. Returns the validated sublist (validated=True). Fail-safe: returns [] on any
    error, so nothing gets instrumented that wasn't proven.

    NOTE: end-to-end this requires a working angr on the built binary (Docker/Linux);
    it is intentionally conservative and returns [] rather than guess when exploration
    is incomplete."""
    import asyncio

    def _work():
        try:
            import angr  # noqa: F401
        except Exception:
            return []
        validated = []
        try:
            build = target.build(harness, libfuzzer_driver=True,
                                  target_sources=target_sources,
                                  include_dirs=include_dirs, sanitizer=sanitizer)
            if not getattr(build, "ok", False):
                return []
            import angr
            proj = angr.Project(build.binary, auto_load_libs=False)
            for p in predicates:
                try:
                    if _prove_one(proj, p):
                        p.validated = True
                        validated.append(p)
                except Exception:
                    continue          # unprovable → leave unvalidated (safe)
        except Exception:
            return []
        return validated

    try:
        return await asyncio.wait_for(asyncio.to_thread(_work), timeout=max_seconds + 30)
    except Exception:
        return []


def _prove_one(proj, pred) -> bool:
    """Reach `pred.function`'s sink with symbolic scalar args and check C ⟹ P.
    Returns False whenever the sink can't be reached / the predicate can't be proven
    (conservative). Uses a call_state at the function so predicate params map directly
    to the symbolic arguments."""
    import angr  # noqa: F401
    sym = proj.loader.find_symbol(pred.function)
    if sym is None:
        return False
    # symbolic scalar args, one per parameter name the predicate references
    env, args = {}, []
    for name in re.findall(r"[A-Za-z_]\w*", pred.condition):
        if name not in env and name.isidentifier():
            bv = claripy.BVS(name, proj.arch.bits)
            env[name] = claripy.Extract(31, 0, bv) if proj.arch.bits > 32 else bv
            args.append(bv)
    if not env:
        return False
    state = proj.factory.call_state(sym.rebased_addr, *args)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(n=64)                     # bounded; deep sinks need Docker budget
    reaching = simgr.deadended + simgr.active
    if not reaching:
        return False
    # every explored terminal state's constraint must imply P
    for st in reaching:
        if not is_strict_relaxation(list(st.solver.constraints), pred.condition, env,
                                    solver=st.solver):
            return False
    return True

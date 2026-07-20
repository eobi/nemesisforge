"""Directed-fuzzing progress predicates (Locus): synthesis pre-filter, source
instrumentation, and the symbolic strict-relaxation soundness check."""
import asyncio

from forge.agents import predicates as P


class _LLM:
    available = True

    def __init__(self, preds):
        self._preds = preds

    def complete_json(self, system, prompt):
        return ({"predicates": self._preds}, {})


def test_synthesize_filters_unsafe_and_non_param():
    llm = _LLM([
        {"condition": "n > 0", "rationale": "len must be positive"},      # keep
        {"condition": "strlen(s) > 0", "rationale": "call"},              # drop (call)
        {"condition": "buf[0] == 1", "rationale": "deref"},               # drop (index)
        {"condition": "42 > 0", "rationale": "no param"},                 # drop (no param)
        {"condition": "len; return", "rationale": "stmt"},                # drop (unsafe)
    ])
    preds = asyncio.run(P.synthesize(
        llm, function="parse", params=["unsigned char *buf", "int n", "char *s"],
        guard_body="void parse(){}"))
    assert [p.condition for p in preds] == ["n > 0"]
    assert preds[0].function == "parse" and preds[0].order == 0


def test_synthesize_no_model_is_noop():
    assert asyncio.run(P.synthesize(None, function="f", params=["int n"],
                                    guard_body="")) == []


def test_return_stub_by_type():
    assert P._return_stub("int parse") == "0"
    assert P._return_stub("void handle") == ""
    assert P._return_stub("char *dup") == "NULL"
    assert P._return_stub("size_t len") == "0"
    assert P._return_stub("struct mg_str build") is None      # don't fabricate


def test_instrument_source_inserts_validated_early_exit():
    src = ("int parse(unsigned char *buf, int n) {\n"
           "    memcpy(dst, buf, n);\n"
           "    return 0;\n"
           "}\n")
    good = P.Predicate(order=0, function="parse", condition="n > 0", validated=True)
    unval = P.Predicate(order=1, function="parse", condition="n < 4096", validated=False)
    out, applied = P.instrument_source(src, "parse", [good, unval])
    assert "if (!(n > 0)) return 0;" in out          # validated one applied
    assert "n < 4096" not in out                     # unvalidated one skipped
    assert [p.condition for p in applied] == ["n > 0"]
    # inserted right after the opening brace, before the body
    assert out.index("if (!(n > 0))") < out.index("memcpy")


def test_instrument_skips_when_no_validated():
    src = "int f(int n){ return 0; }\n"
    out, applied = P.instrument_source(
        src, "f", [P.Predicate(0, "f", "n > 0", validated=False)])
    assert out == src and applied == []


# ── the soundness core: strict-relaxation via SMT (claripy) ──────────────────
def test_strict_relaxation_accepts_necessary_condition():
    import claripy
    from forge.agents import predicate_symbolic as PS
    n = claripy.BVS("n", 32)
    env = {"n": n}
    # sink reached only when n > 10; predicate "n > 0" is IMPLIED → safe to instrument
    assert PS.is_strict_relaxation([n.SGT(10)], "n > 0", env) is True
    assert PS.is_strict_relaxation([n.SGT(10)], "n != 0", env) is True


def test_strict_relaxation_rejects_over_constraining():
    import claripy
    from forge.agents import predicate_symbolic as PS
    n = claripy.BVS("n", 32)
    env = {"n": n}
    # sink reached when n > 10; predicate "n > 100" would prune n=50 which DOES reach
    assert PS.is_strict_relaxation([n.SGT(10)], "n > 100", env) is False


def test_strict_relaxation_rejects_untranslatable():
    import claripy
    from forge.agents import predicate_symbolic as PS
    env = {"n": claripy.BVS("n", 32)}
    assert PS.is_strict_relaxation([], "frobnicate(n)", env) is False


def test_translate_operator_subset():
    import claripy
    from forge.agents import predicate_symbolic as PS
    a, b = claripy.BVS("a", 32), claripy.BVS("b", 32)
    env = {"a": a, "b": b}
    # compound boolean with precedence + literals + hex/char
    expr = PS.translate("a > 0 && (b == 0x10 || a != b)", env)
    assert isinstance(expr, claripy.ast.Bool)
    expr2 = PS.translate("a", env)          # bare scalar → (a != 0)
    assert isinstance(expr2, claripy.ast.Bool)

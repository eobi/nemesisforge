"""The proof ladder — the spine everything else certifies against."""
from forge.ladder import (
    Rung, Outcome, Verdict, Candidate, CodeLoc, Finding, Primitive, PrimitiveKind,
    LadderState, advances, REPORTABLE, VENDOR_MIN,
)


def _v(rung, outcome=Outcome.PROVEN, oracle="test"):
    return Verdict(outcome=outcome, rung=rung, oracle=oracle)


def _c(bug="memory_safety", path="src/x.c", line=10):
    return Candidate(bug_class=bug, title="t", location=CodeLoc(path=path, line=line))


def test_rung_ordering_and_new_rungs():
    assert Rung.UNVERIFIED < Rung.PROVEN_FAULT < Rung.PROVEN_SECURITY
    # The weaponization rungs Forge adds beyond Nemesis Zero's rung-3 ceiling.
    assert Rung.PROVEN_SECURITY < Rung.PROVEN_PRIMITIVE < Rung.PROVEN_EXPLOIT < Rung.VENDOR_READY
    assert int(Rung.VENDOR_READY) == 6
    assert REPORTABLE == Rung.PROVEN_SECURITY and VENDOR_MIN == Rung.PROVEN_PRIMITIVE


def test_advances_only_upward_on_proven():
    assert advances(Rung.UNVERIFIED, _v(Rung.PROVEN_FAULT)) is True
    assert advances(Rung.PROVEN_FAULT, _v(Rung.PROVEN_EXPLOIT)) is True
    # not upward
    assert advances(Rung.PROVEN_EXPLOIT, _v(Rung.PROVEN_FAULT)) is False
    assert advances(Rung.PROVEN_FAULT, _v(Rung.PROVEN_FAULT)) is False  # same rung
    # refuted / inconclusive never advance
    assert advances(Rung.UNVERIFIED, _v(Rung.PROVEN_EXPLOIT, Outcome.REFUTED)) is False
    assert advances(Rung.UNVERIFIED, _v(Rung.PROVEN_EXPLOIT, Outcome.INCONCLUSIVE)) is False


def test_ladder_state_climbs_and_never_regresses():
    st = LadderState()
    c = _c()
    assert st.rung_of(c) == Rung.UNVERIFIED
    assert st.apply(c, _v(Rung.PROVEN_FAULT)) is True
    assert st.rung_of(c) == Rung.PROVEN_FAULT
    assert st.apply(c, _v(Rung.PROVEN_PRIMITIVE)) is True
    assert st.rung_of(c) == Rung.PROVEN_PRIMITIVE
    # a later weaker verdict must NOT pull the rung back down
    assert st.apply(c, _v(Rung.PROVEN_FAULT)) is False
    assert st.rung_of(c) == Rung.PROVEN_PRIMITIVE
    # history keeps every verdict
    assert len(st.history[st._key(c)]) == 3


def test_ladder_state_keys_distinct_candidates():
    st = LadderState()
    a, b = _c(line=10), _c(line=99)
    st.apply(a, _v(Rung.PROVEN_EXPLOIT))
    st.apply(b, _v(Rung.PROVEN_FAULT))
    assert st.rung_of(a) == Rung.PROVEN_EXPLOIT
    assert st.rung_of(b) == Rung.PROVEN_FAULT
    board = st.board()
    assert len(board) == 2
    # board is sorted highest-rung first
    assert board[0]["rung"] >= board[1]["rung"]


def test_finding_reportable_and_shippable_gates():
    c = _c()
    lo = Finding(candidate=c, verdict=_v(Rung.PROVEN_FAULT), rung=Rung.PROVEN_FAULT)
    assert lo.reportable is False and lo.vendor_shippable is False
    mid = Finding(candidate=c, verdict=_v(Rung.PROVEN_SECURITY), rung=Rung.PROVEN_SECURITY)
    assert mid.reportable is True and mid.vendor_shippable is False
    top = Finding(candidate=c, verdict=_v(Rung.VENDOR_READY), rung=Rung.VENDOR_READY,
                  primitive=Primitive(kind=PrimitiveKind.WRITE_WHAT_WHERE, controlled=True))
    assert top.reportable is True and top.vendor_shippable is True

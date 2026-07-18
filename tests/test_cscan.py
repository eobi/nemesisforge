"""Phase I — the dependency-free code-intelligence pass. Fast, no clang."""
from forge.analysis import cscan


SRC = r"""
#include <string.h>
#include <stdlib.h>
static int helper(const char *in, unsigned long n){
    char *b = malloc(8);
    memcpy(b, in, n);              /* input-influenced */
    return b[0];
}
int parse_packet(const unsigned char *data, size_t size){
    if(size<2) return 0;
    return helper((const char*)data, size);
}
int unrelated(void){ char x[4]; strcpy(x, "hi"); return 0; }
"""


def test_functions_callgraph_and_reachability():
    funcs, sinks = cscan.scan_text(SRC, file="demo.c")
    names = {f.name for f in funcs}
    assert {"helper", "parse_packet", "unrelated"} <= names
    parse = next(f for f in funcs if f.name == "parse_packet")
    assert "helper" in parse.calls               # call graph edge recovered

    ci = cscan.CodeIntel()
    for f in funcs:
        ci.funcs[f.name] = f
    ci.sinks = sinks
    assert "parse_packet" in {f.name for f in ci.entry_points()}
    reach = ci.reachable()
    assert {"parse_packet", "helper"} <= reach
    assert "unrelated" not in reach              # not reachable from an entry


def test_sink_detection_and_ranking():
    funcs, sinks = cscan.scan_text(SRC, file="demo.c")
    kinds = {(s.kind, s.func) for s in sinks}
    assert ("memcpy", "helper") in kinds
    assert ("malloc", "helper") in kinds
    # the input-influenced, reachable memcpy must outrank the unreachable strcpy
    ci = cscan.CodeIntel(funcs={f.name: f for f in funcs}, sinks=sinks)
    ranked = ci.ranked_sinks(limit=10)
    top = ranked[0]
    assert top.kind == "memcpy" and top.input_influenced and top.reachable
    strcpy = next(s for s in ranked if s.kind == "strcpy")
    assert top.score > strcpy.score


def test_comments_and_strings_do_not_confuse_scanner():
    tricky = r'''
int f(char *p){
    /* memcpy(x,y,z) in a comment must not count */
    const char *s = "strcpy(a,b) in a string";
    char *d = malloc(4);
    memcpy(d, p, 100);            /* the only real sink */
    return d[0];
}
'''
    _funcs, sinks = cscan.scan_text(tricky, file="t.c")
    memcpys = [s for s in sinks if s.kind == "memcpy"]
    assert len(memcpys) == 1                     # comment memcpy ignored
    assert not any(s.kind == "strcpy" for s in sinks)   # string strcpy ignored

# RETRACTED: jbig2dec, large allocation from a small input

**Status: not a finding.** Reported here because the engine's own oracle is what
removed it, and an engine that only ever confirms is not one worth trusting.

## What was observed

A 55-byte JBIG2 input drove `jbig2dec` (commit `6e8205ba`) to request a 6.85 GB
allocation:

```
==NNN==ERROR: libFuzzer: out-of-memory (malloc(6851940560))
    #8  jbig2_arith_iaid_ctx_new     jbig2_arith_iaid.c:65
    #9  jbig2_decode_symbol_dict     jbig2_symbol_dict.c:326
    #10 jbig2_symbol_dictionary      jbig2_symbol_dict.c:1073
```

The allocation size is attacker-influenced. `jbig2_arith_iaid.c:65` reads:

```c
ctx_size = (size_t) 1U << SBSYMCODELEN;
```

and `SBSYMCODELEN` is derived at `jbig2_symbol_dict.c:284` from `SDNUMINSYMS +
SDNUMNEWSYMS`, both of which come from a segment header. Nothing between the header
parse and the allocation checks them against the bytes actually available.

That much is true, and it is where a report would normally stop.

## Why it is not a finding

**Native replay.** The same input against the uninstrumented binary:

```
$ ./jbig2dec poc.jb2
jbig2dec FATAL ERROR page has no image, cannot be completed
exit 1
```

It exits cleanly. The library checks the allocation and recovers:

```c
result->IAIDx = jbig2_new(ctx, Jbig2ArithCx, ctx_size);
if (result->IAIDx == NULL) {
    jbig2_free(ctx->allocator, result);
    jbig2_error(ctx, JBIG2_SEVERITY_FATAL, ..., "failed to allocate symbol ID ...");
    return NULL;
}
```

With `ASAN_OPTIONS=allocator_may_return_null=1` and no fuzzer malloc cap, the
sanitizer build also runs clean.

**What was actually reported** was libFuzzer's own `-rss_limit_mb` policy firing on a
large request. That is a property of how the campaign was configured, not a defect in
the target.

**Corroboration.** A black-box fuzzer driving the native binary ran 82,923 executions
over 3h22m against the same target and found nothing. It was not losing to the
source-instrumented run. It was right, because there is nothing there.

## A second claim, also withdrawn

An earlier note flagged `(size_t) 1U << SBSYMCODELEN` as undefined behaviour when
`SBSYMCODELEN >= 32`, on the grounds that `1U` is a 32-bit type. That is wrong. The
cast binds tighter than the shift, so the expression is `((size_t)1U) << n`, a 64-bit
shift, well defined for `n < 64`. UBSan confirms it: no diagnostic at `n = 40`.

Written `(size_t)(1U << SBSYMCODELEN)` it would be undefined. One pair of parentheses
apart.

## The lesson this is kept for

A resource policy is not a defect. The separating test is one native replay with no
fuzzer in the process and no artificial cap, and then reading whether the target
handles the refusal. Without that step this would have been filed as a denial of
service against a library that behaves correctly.

Nothing was reported to the maintainers, because there is nothing to report.

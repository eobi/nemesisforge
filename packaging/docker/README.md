# Nemesis Forge — Linux hunting environment (Docker)

macOS blocks aggressive hard-target hunting at every step: the EndpointSecurity
per-exec tax, angr's weak Mach-O backend, cmake loose-object relocation errors, and
broken vendored builds. Linux is the native home (the same environment OSS-Fuzz
uses). This image runs Forge there, where **every lens works**: build-system
integration, MSan, angr on ELF, and multi-file/vendored builds link cleanly.

## Build (once)

```sh
cd <repo root>            # the Nemesis Forge checkout
docker build -f packaging/docker/Dockerfile -t nemesis-forge .
```

## Run a campaign

`.env` (API keys) is **mounted read-only at runtime, never baked into the image**.
`runs/` is mounted so artifacts land on the host.

```sh
docker run --rm \
  -v "$PWD/.env:/forge/.env:ro" \
  -v "$PWD/runs:/forge/runs" \
  nemesis-forge <git-url> [campaign_minutes] [max_targets] [sanitizer]

# examples
docker run --rm -v "$PWD/.env:/forge/.env:ro" -v "$PWD/runs:/forge/runs" \
  nemesis-forge https://github.com/redis/librdb 25 4          # the hard target that failed on macOS
docker run --rm -v "$PWD/.env:/forge/.env:ro" -v "$PWD/runs:/forge/runs" \
  nemesis-forge https://github.com/dvidelabs/flatcc 25 4 address,undefined
```

## Why hard targets work here (and not on macOS)

| Obstacle on macOS | On Linux |
| --- | --- |
| Nemesis Blue EDR ~14s/exec tax | none — no EndpointSecurity |
| angr Mach-O backend degraded, unicorn off | angr on ELF is effective |
| cmake loose `.o` → `invalid r_symbolnum` link errors | native ELF objects link cleanly |
| vendored builds (librdb/hiredis) need openssl + full make | apt has the deps; make works |
| MSan needs instrumented deps | build-system instruments the whole tree |

## Notes

- Multi-core helps: libFuzzer + the parallel harness fleet scale with cores. Give
  the container CPUs (`--cpus`) for deep campaigns.
- For a long run, use `-d` (detached) and `docker logs -f <id>`, or run several
  targets by launching multiple containers.
- MSan: pass `memory` as the sanitizer arg to hunt for uninitialized-memory bugs
  (only meaningful here, where the build system instruments dependencies too).

# Nemesis Forge — Linux hunting environment.
#
# WHY: macOS blocks aggressive hard-target hunting at every step (EndpointSecurity
# per-exec tax, angr's weak Mach-O backend, cmake loose-object relocations, broken
# vendored builds). Linux is the native home — the same environment OSS-Fuzz uses:
# clang ships libFuzzer, MSan works, angr handles ELF, and multi-file/vendored builds
# link cleanly. This image gives Forge that environment.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang lld llvm libclang-rt-18-dev \
      perl python3-dev libtool-bin \
      cmake make autoconf automake libtool pkg-config \
      build-essential git ca-certificates \
      python3 python3-pip python3-venv \
      libssl-dev zlib1g-dev \
      gdb \
 && rm -rf /var/lib/apt/lists/*
# gdb is REQUIRED for the exploitability/ACI debug path (faulting-instruction
# backtrace → write-what-where grade). Without it that oracle silently degrades.
# libclang-rt-18-dev is REQUIRED: the base clang package ships the compiler but
# NOT the compiler-rt runtime (libclang_rt.fuzzer/asan), so -fsanitize=fuzzer,address
# fails to link and every hunt would be hollow. This provides those runtime archives.

# libFuzzer-capable clang is /usr/bin/clang on Linux (no Homebrew LLVM needed).
ENV FORGE_CLANG=/usr/bin/clang

# Python deps driven from requirements.txt (single source of truth, shared with
# the Windows package). The LLM client uses raw HTTP (urllib) — no vendor SDK.
WORKDIR /forge
COPY requirements.txt /forge/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages \
      -r /forge/requirements.txt
COPY . /forge
ENV PYTHONPATH=/forge

# .env with API keys is MOUNTED at runtime, never baked into the image:
#   docker run --rm -v "$PWD/.env:/forge/.env:ro" -v "$PWD/runs:/forge/runs" \
#     nemesis-forge <git-url> [campaign_minutes] [max_targets]
ENTRYPOINT ["/forge/packaging/docker/hunt.sh"]

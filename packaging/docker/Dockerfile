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
 && rm -rf /var/lib/apt/lists/*
# libclang-rt-18-dev is REQUIRED: the base clang package ships the compiler but
# NOT the compiler-rt runtime (libclang_rt.fuzzer/asan), so -fsanitize=fuzzer,address
# fails to link and every hunt would be hollow. This provides those runtime archives.

# libFuzzer-capable clang is /usr/bin/clang on Linux (no Homebrew LLVM needed).
ENV FORGE_CLANG=/usr/bin/clang

# Python deps: the engine's web layer + angr for the (now effective) symbolic lens.
# The LLM client uses raw HTTP (urllib), so no vendor SDK is required.
RUN python3 -m pip install --no-cache-dir --break-system-packages \
      "fastapi>=0.110" "uvicorn>=0.29" "pydantic>=2" \
      "pytest>=8" "httpx>=0.27" angr

WORKDIR /forge
COPY . /forge
ENV PYTHONPATH=/forge

# .env with API keys is MOUNTED at runtime, never baked into the image:
#   docker run --rm -v "$PWD/.env:/forge/.env:ro" -v "$PWD/runs:/forge/runs" \
#     nemesis-forge <git-url> [campaign_minutes] [max_targets]
ENTRYPOINT ["/forge/packaging/docker/hunt.sh"]

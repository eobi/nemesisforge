#!/usr/bin/env bash
# Run the variant hunt across HARD/enterprise targets in Docker (Linux), on OpenAI.
# These are widely-deployed but UNDER-fuzzed libraries whose build systems fail on
# macOS but work in the container. Bounded concurrency so the machine doesn't thrash.
#
# Usage: scripts/docker_fleet.sh <minutes> <git-url> [<git-url> ...]
set -euo pipefail
MINS="${1:-15}"; shift
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAXC="${FORGE_MAXC:-3}"          # max concurrent containers

for url in "$@"; do
  # wait for a free slot
  while [ "$(docker ps -q --filter 'name=forge-hunt-' | wc -l | tr -d ' ')" -ge "$MAXC" ]; do
    sleep 15
  done
  name="hunt-$(basename "$url" | tr -c 'a-zA-Z0-9_.-' '-')"
  docker rm -f "forge-$name" >/dev/null 2>&1 || true
  docker run -d --rm \
    -e FORGE_PROVIDER=openai -e FORGE_MODEL=gpt-5.1 -e FORGE_SAN=address \
    -v "$ROOT/.env:/forge/.env:ro" \
    -v "$ROOT/runs:/forge/runs" \
    --name "forge-$name" nemesis-forge "$url" "$MINS" 4 >/dev/null
  echo "launched forge-$name  ($url)"
done
echo "all launched; watch: docker ps ; docker logs -f forge-<name>"

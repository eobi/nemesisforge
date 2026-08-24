#!/usr/bin/env bash
# Reproduce each selected ARVO vulnerability and keep three things per bug:
#   - the sanitizer report from the VULNERABLE build   (gives the class)
#   - the sanitizer report from the FIXED build        (the differential check)
#   - the PoC input itself                             (what we extract features from)
#
# The PoC path inside the image is discovered rather than assumed: ARVO's entrypoint
# knows where it puts the input, and guessing a path would fail silently on some images.
#
# Usage: ./02-reproduce.sh selected.json outdir [max]
set -uo pipefail
PLAT="${ARVO_PLATFORM:---platform linux/amd64}"   # amd64-only images; emulated on arm64 hosts
SEL="${1:-selected.json}"; OUT="${2:-corpus}"; MAX="${3:-0}"
mkdir -p "$OUT"/{reports,poc}
command -v docker >/dev/null || { echo "docker missing; run 00-provision.sh"; exit 1; }

ids=$(python3 -c "
import json,sys
recs=json.load(open('$SEL'))
seen=set()
for r in recs:
    if r['id'] in seen: continue
    seen.add(r['id']); print(r['id'], r['project'], r['cls'])
")
total=$(echo "$ids" | wc -l | tr -d ' '); n=0; ok=0; fail=0
echo "reproducing $total ARVO bugs -> $OUT"

while read -r id proj cls; do
  [ -z "$id" ] && continue
  n=$((n+1))
  [ "$MAX" -gt 0 ] && [ "$n" -gt "$MAX" ] && break
  vimg="n132/arvo:${id}-vul"; fimg="n132/arvo:${id}-fix"
  printf "[%4d/%s] %-24s %-6s id=%-8s " "$n" "$total" "$proj" "$cls" "$id"

  if ! docker pull -q $PLAT "$vimg" >/dev/null 2>&1; then
    echo "no image"; fail=$((fail+1)); continue
  fi
  # vulnerable side: the report that gives us the label
  docker run --rm $PLAT --network=none "$vimg" arvo > "$OUT/reports/${id}.vul.txt" 2>&1
  # fixed side: the differential. Absence of a crash here is the oracle passing.
  if docker pull -q $PLAT "$fimg" >/dev/null 2>&1; then
    docker run --rm $PLAT --network=none "$fimg" arvo > "$OUT/reports/${id}.fix.txt" 2>&1
  else
    : > "$OUT/reports/${id}.fix.txt"
  fi

  # extract the PoC. Discover its path from the image rather than hardcoding one.
  poc=$(docker run --rm $PLAT --entrypoint /bin/sh "$vimg" -c '
      for p in /tmp/poc /tmp/input /poc /arvo/poc "$POC" ; do
        [ -n "$p" ] && [ -f "$p" ] && { echo "$p"; exit 0; }
      done
      find / -maxdepth 3 -name "poc*" -type f 2>/dev/null | head -1
  ' 2>/dev/null | tr -d "\r")
  if [ -n "$poc" ]; then
    cid=$(docker create $PLAT "$vimg")
    docker cp "$cid:$poc" "$OUT/poc/${id}" >/dev/null 2>&1 && ok=$((ok+1)) || fail=$((fail+1))
    docker rm -f "$cid" >/dev/null 2>&1
    echo "ok"
  else
    echo "poc not found"; fail=$((fail+1))
  fi
  docker rmi -f "$vimg" "$fimg" >/dev/null 2>&1 || true   # images are large; do not hoard
done <<< "$ids"

echo
echo "reproduced with PoC: $ok   failed: $fail"
echo "next: python3 03-label.py $OUT -o labels_arvo.csv"

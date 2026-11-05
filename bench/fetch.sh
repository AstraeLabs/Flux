#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."

BIN="${N_M3U8DL_RE:-N_m3u8DL-RE}"
IDS=""; RANGE_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2;;
    --ids) IDS="$2"; shift 2;;
    --range) RANGE_OVERRIDE="$2"; shift 2;;
    *) echo "unknown argument: $1" >&2; exit 1;;
  esac
done

PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys' >/dev/null 2>&1; then PY="$cand"; break; fi
done
[ -n "$PY" ] || { echo "python3 not found (the Windows Store alias does not count)" >&2; exit 1; }
DIR=".test-streams/bench"
TITLES="$DIR/titles.local.json"
[ -f "$TITLES" ] || { echo "missing $TITLES (copy bench/titles.example.json and fill it in)" >&2; exit 1; }

# id <TAB> manifest <TAB> select_video <TAB> range
"$PY" - "$TITLES" "$IDS" <<'EOF' | tr -d '\r' | while IFS=$'\t' read -r id manifest select range; do
import json, sys
wanted = set(filter(None, sys.argv[2].split(",")))
for t in json.load(open(sys.argv[1])):
    if wanted and t["id"] not in wanted:
        continue
    print("\t".join([t["id"], t["manifest"], t.get("select_video", "best"), t.get("range", "")]))
EOF
  [ -n "$RANGE_OVERRIDE" ] && range="$RANGE_OVERRIDE"
  out="$DIR/$id"
  rm -rf "$out"; mkdir -p "$out"
  echo "== $id (range: ${range:-all}) =="
  extra=()
  [ -n "$range" ] && extra+=(--custom-range "$range")
  t0="$(date +%s.%N)"
  "$BIN" "$manifest" -sv "$select" -da for=all -ds for=all \
    --save-dir "$out" --save-name video --tmp-dir "$out/tmp" \
    --no-ansi-color --disable-update-check --del-after-done "${extra[@]}"
  t1="$(date +%s.%N)"
  # Whatever name the downloader picked, the biggest file is the video track.
  f="$(ls -S "$out"/*.mp4 "$out"/*.m4s "$out"/*.ts 2>/dev/null | head -1 || true)"
  [ -n "$f" ] || { echo "no output file in $out" >&2; exit 1; }
  [ "$f" = "$out/video.mp4" ] || mv "$f" "$out/video.mp4"
  rm -rf "$out/tmp"
  ls -l "$out/video.mp4"
  # Network context for the live numbers: wall time of the downloader (download + its own merge), bytes, range.
  "$PY" - "$out" "$t0" "$t1" "$range" <<'EOF'
import json, os, sys
out, t0, t1, rng = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
size = os.path.getsize(os.path.join(out, "video.mp4"))
secs = t1 - t0
json.dump({"download_seconds": round(secs, 2), "bytes": size, "range": rng,
           "download_mbps": round(size * 8 / 1e6 / secs, 1), "downloader_threads": 28},
          open(os.path.join(out, "download.json"), "w"), indent=1)
print("download: %.1f s for %.2f GB (%.0f Mbit/s)" % (secs, size / 1e9, size * 8 / 1e6 / secs))
EOF
  if command -v flux >/dev/null 2>&1; then flux "$out/video.mp4" --dump || true; fi
done

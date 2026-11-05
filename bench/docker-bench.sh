#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$(pwd)"
if command -v cygpath >/dev/null 2>&1; then ROOT="$(cygpath -m "$ROOT")"; fi
export MSYS_NO_PATHCONV=1   # Git Bash must not rewrite the container paths below

mkdir -p bench/results
docker build -f bench/Dockerfile -t flux-bench .

status=0
for cs in ${CPUSETS:-all 0}; do
  args=()
  [ "$cs" != all ] && args+=(--cpuset-cpus="$cs")
  docker run --rm --privileged "${args[@]}" \
    -v flux-bench-data:/data \
    -v "$ROOT/.test-streams/bench:/in:ro" \
    -v "$ROOT/bench/results:/out" \
    flux-bench run --label "cpus-$cs" "$@" || status=$?
done
exit $status

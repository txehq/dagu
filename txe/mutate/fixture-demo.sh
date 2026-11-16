#!/usr/bin/env bash
# The TXE-7549 acceptance demonstration, on sentinel-only fake caches; never the real ones.
#
#   1. Sandboxed: testdata/fixture's mutant runs `go clean -modcache` with the environment it was
#      given. It reaches only the sandbox: the fake shared caches and their sentinels are
#      unchanged, the mutant SURVIVES (a deletion is not a kill) and the runner exits 0.
#   2. Sandbox off (--unsafe-host-run-for-fixture): the same mutant, run on the host with the fake
#      caches as its environment, deletes the fake GOMODCACHE, and the runner fails loudly on the
#      identity check with exit 3.
#
# Usage: fixture-demo.sh <evidence-dir> [image]
# Needs a docker daemon and the image present locally (the sandbox has no network and this script
# pulls nothing). Writes only under a directory it creates with mktemp -d, and the evidence dir.
set -uo pipefail

evidence=${1:?usage: fixture-demo.sh <evidence-dir> [image]}
image=${2:-golang:1.27.3-bookworm}
here=$(cd "$(dirname "$0")" && pwd)
runner="$here/mutate-sandboxed.py"
mkdir -p "$evidence"

if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "image $image is not present locally; this demonstration pulls nothing" >&2
  exit 2
fi

root=$(mktemp -d "${TMPDIR:-/tmp}/txe-7549-fixture.XXXXXX")
modcache="$root/fake-gopath/pkg/mod"
gocache="$root/fake-gocache"
mkdir -p "$modcache/cache/download" "$gocache" "$root/work"
for d in "$modcache" "$gocache"; do
  printf 'TXE-7549 fixture sentinel\n' >"$d/.mutate-sandboxed-fixture-sentinel"
done

state() { # identity and content of the fake caches
  for p in "$modcache" "$modcache/cache/download" "$gocache" \
    "$modcache/.mutate-sandboxed-fixture-sentinel" "$gocache/.mutate-sandboxed-fixture-sentinel"; do
    if [ -e "$p" ]; then
      printf '%s %s\n' "$(stat -f '%d %i %B' "$p" 2>/dev/null || stat -c '%d %i %W' "$p")" "$p"
    else
      printf 'ABSENT %s\n' "$p"
    fi
  done
  shasum -a 256 "$modcache/.mutate-sandboxed-fixture-sentinel" 2>/dev/null || echo "ABSENT sentinel content"
}

run() { # label, extra runner args...
  local label=$1
  shift
  {
    echo "== $label $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "-- fake caches before"
    state
    python3 -I "$runner" --mutants "$here/testdata/fixture/mutants.json" --tree "$here/testdata/fixture" \
      --shared-modcache "$modcache" --shared-gocache "$gocache" --workdir-root "$root/work" \
      --image "$image" --no-seed --report "$evidence/$label.report.json" --timeout 600 "$@" -- go test ./...
    echo "-- runner exit $?"
    echo "-- fake caches after"
    state
  } >"$evidence/$label.log" 2>&1
  cat "$evidence/$label.log"
}

echo "image $(docker image inspect --format '{{.Id}} {{join .RepoDigests ","}}' "$image")" >"$evidence/image.txt"
run 1-sandboxed
run 2-sandbox-off --unsafe-host-run-for-fixture
echo "fixture root (fake caches, kept for inspection): $root"

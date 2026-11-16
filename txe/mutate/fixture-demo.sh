#!/usr/bin/env bash
# The TXE-7549 acceptance demonstration. Each step needs its own go-ahead; run one per call.
#
#   fixture-demo.sh sandboxed <evidence-dir> <image-id>
#     Step 1. testdata/fixture's mutant runs `go clean -modcache` with the environment it is
#     given, through the runner's real sandbox on this machine, against sentinel-only fake
#     caches under a fresh mktemp directory (--no-seed: the real module cache is not read).
#     Expected: runner exit 0, the mutant SURVIVED, the fake caches and sentinels unchanged.
#
#   fixture-demo.sh outer-negative <evidence-dir> <image-id>
#     Step 2. Inside an OUTER container (no network, no capabilities, no mount but a read-only
#     copy of txe/mutate, no Docker socket, no credentials), negative-in-outer.sh gives the runner
#     a docker that leaks the caller's environment; the same mutant deletes the outer container's
#     own fake cache and the runner must exit 3. Nothing runs on this machine but `docker run`.
#
# <image-id> is an image already present locally, named by its immutable id (sha256:...). Every
# docker run here uses --pull never. Writes only under one mktemp directory, which it removes at
# the end, and the evidence directory.
set -uo pipefail

step=${1:?usage: fixture-demo.sh sandboxed|outer-negative <evidence-dir> <image-id>}
evidence=${2:?evidence dir}
image=${3:?image id (sha256:...)}
here=$(cd "$(dirname "$0")" && pwd)
case "$image" in
  sha256:*) ;;
  *) echo "give the image by its immutable id (sha256:...), not a tag" >&2; exit 2 ;;
esac
if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "image $image is not present locally; this demonstration pulls nothing" >&2
  exit 2
fi
mkdir -p "$evidence"
root=$(mktemp -d "${TMPDIR:-/tmp}/txe-7549-$step.XXXXXX")
log="$evidence/$step.log"
: >|"$log"
say() { printf '%s\n' "$*" | tee -a "$log"; }
say "== $step $(date -u +%Y-%m-%dT%H:%M:%SZ) image $image root $root"

case "$step" in
  sandboxed)
    modcache="$root/fake-gopath/pkg/mod"
    gocache="$root/fake-gocache"
    mkdir -p "$modcache/cache/download/example.com" "$gocache" "$root/work"
    for d in "$modcache" "$gocache"; do
      printf 'TXE-7549 fixture sentinel\n' >"$d/.mutate-sandboxed-fixture-sentinel"
    done
    cp -R "$here/testdata/fixture" "$root/fixture"
    state() {
      for p in "$modcache" "$modcache/cache/download" "$gocache" \
        "$modcache/.mutate-sandboxed-fixture-sentinel" "$gocache/.mutate-sandboxed-fixture-sentinel"; do
        if [ -e "$p" ]; then stat -f '%d %i %B %N' "$p"; else echo "ABSENT $p"; fi
      done
      shasum -a 256 "$modcache/.mutate-sandboxed-fixture-sentinel" "$gocache/.mutate-sandboxed-fixture-sentinel" 2>&1
    }
    { echo "-- fake caches before"; state; } | tee -a "$log"
    python3 -I "$here/mutate-sandboxed.py" --mutants "$root/fixture/mutants.json" --tree "$root/fixture" \
      --shared-modcache "$modcache" --shared-gocache "$gocache" --workdir-root "$root/work" \
      --image "$image" --no-seed --memory 2g --cpus 2 --pids 512 --timeout 600 \
      --report "$evidence/$step.report.json" -- go test ./... 2>&1 | tee -a "$log"
    rc=${PIPESTATUS[0]}
    { echo "-- runner exit $rc (expected 0)"; echo "-- fake caches after"; state; } | tee -a "$log"
    want=0
    ;;
  outer-negative)
    mkdir -p "$root/runner"
    cp -R "$here/mutate-sandboxed.py" "$here/negative-in-outer.sh" "$here/testdata" "$root/runner/"
    docker run --rm --pull never --name "txe-7549-outer-$$" --network none --cap-drop ALL \
      --security-opt no-new-privileges --pids-limit 512 --memory 2g --cpus 2 \
      --mount "type=bind,source=$root/runner,target=/runner,readonly" --workdir / --entrypoint "" \
      "$image" bash /runner/negative-in-outer.sh 2>&1 | tee -a "$log"
    rc=${PIPESTATUS[0]}
    say "-- outer container exit $rc (expected 0: the runner inside exited 3)"
    want=0
    ;;
  *)
    echo "unknown step $step" >&2
    exit 2
    ;;
esac

# Teardown: only the directory this script created, found by the path it printed.
if [ -d "$root" ] && [ "${root#"${TMPDIR:-/tmp}"/txe-7549-}" != "$root" ]; then
  chmod -R u+w "$root" 2>/dev/null
  find "$root" -depth -mindepth 1 -delete && rmdir "$root" && say "-- removed $root"
fi
[ "$rc" -eq "$want" ]

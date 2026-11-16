#!/usr/bin/env bash
# TXE-7549 step 2: the alarm fires when the sandbox boundary is gone. Runs ONLY inside the outer
# container fixture-demo.sh starts (no network, no capabilities, no mount but a read-only copy of
# txe/mutate at /runner, no Docker socket, no credentials, no variable from the Mac). Inside it,
# /fakehost plays the host: its fake GOMODCACHE and GOCACHE are the "shared" caches. The runner
# is given testdata/leaky-docker.py as its docker, which runs the mutant with the caller's
# environment; the fixture's mutant then runs `go clean -modcache` against /fakehost's cache, and
# the runner must stop with exit 3. HOME is not set: it is the image user's default.
set -u
if [ ! -e /.dockerenv ]; then
  echo "negative-in-outer: refused: only inside the outer container" >&2
  exit 2
fi
fake=/fakehost
mod="$fake/go/pkg/mod"
mkdir -p "$mod/cache/download/example.com" "$fake/gocache" "$fake/work"
for d in "$mod" "$fake/gocache"; do
  printf 'TXE-7549 fixture sentinel\n' >"$d/.mutate-sandboxed-fixture-sentinel"
done
cp -R /runner/testdata/fixture "$fake/fixture"
export GOPATH="$fake/go" GOMODCACHE="$mod" GOCACHE="$fake/gocache" GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-modcacherw GOENV=off

state() {
  for p in "$mod" "$mod/cache/download" "$fake/gocache" "$mod/.mutate-sandboxed-fixture-sentinel"; do
    if [ -e "$p" ]; then stat -c '%d %i %W %n' "$p"; else echo "ABSENT $p"; fi
  done
}
echo "== outer: $(uname -a); HOME=${HOME-unset}; uid=$(id -u)"
echo "-- fake caches before"
state
python3 -I /runner/mutate-sandboxed.py --mutants "$fake/fixture/mutants.json" --tree "$fake/fixture" \
  --docker /runner/testdata/leaky-docker.py --image outer-image --no-seed --workdir-root "$fake/work" \
  --timeout 300 --report "$fake/report.json" -- go test ./...
rc=$?
echo "-- runner exit $rc (expected 3)"
echo "-- fake caches after"
state
echo "-- report"
cat "$fake/report.json"
[ "$rc" -eq 3 ]

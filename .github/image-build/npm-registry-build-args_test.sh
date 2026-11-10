#!/usr/bin/env bash
# Runs npm-registry-build-args.sh (TXE-6359) under the runners it meets: GitHub-hosted with no
# npm registry, and one whose LAN npm cache answers, errors or is silent. A local HTTP server
# stands in for the cache and a closed port for a silent one. No network is used.
#
# It also fails a Dockerfile that fetches Node packages without both registry ARGs in that
# stage, and a workflow with an image build that does not pass the helper's output, so a new
# Dockerfile or image build cannot silently go back to registry.npmjs.org.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
HELPER="$ROOT/.github/image-build/npm-registry-build-args.sh"
WORK="$(mktemp -d)"
server_pid=
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf "${WORK:?}"
}
trap cleanup EXIT

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

closed_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
mkdir -p "$WORK/www/-"
echo pong > "$WORK/www/-/ping"
python3 -u -m http.server 0 --bind 127.0.0.1 --directory "$WORK/www" > "$WORK/server.log" 2>&1 &
server_pid=$!
open_port=
for _ in $(seq 1 50); do
  open_port="$(sed -n 's/.*port \([0-9][0-9]*\).*/\1/p' "$WORK/server.log" | head -1)"
  if [ -n "$open_port" ] && curl -s -o /dev/null --noproxy '*' "http://127.0.0.1:$open_port/"; then break; fi
  sleep 0.1
done
[ -n "$open_port" ] || { echo "the stand-in npm cache did not start"; cat "$WORK/server.log"; exit 1; }
live="http://127.0.0.1:$open_port/"
dead="http://127.0.0.1:$closed_port/"
errors="http://127.0.0.1:$open_port/no-such-registry/"

# run VAR=VALUE...: the helper's build-args output under exactly that environment.
run() {
  : > "$WORK/output"
  env -i PATH="$PATH" HOME="$WORK" GITHUB_OUTPUT="$WORK/output" "$@" bash "$HELPER" 2> "$WORK/stderr" \
    || fail "the helper exited non-zero under: $*"
  [ "$(sed -n '1p' "$WORK/output")" = 'build-args<<TXE_NPM_ROUTES_EOF' ] || fail "no output header under: $*"
  [ "$(sed -n '$p' "$WORK/output")" = 'TXE_NPM_ROUTES_EOF' ] || fail "no output terminator under: $*"
  sed '1d;$d' "$WORK/output"
}
expect() { # name, expected, actual
  [ "$3" = "$2" ] || fail "$1: expected [$2], got [$3]"
}
expect_both="npm_config_registry=$live
pnpm_config_registry=$live"

expect "a runner with no npm registry passes nothing" "" "$(run)"
grep -q 'registry.npmjs.org' "$WORK/stderr" || fail "the public fallback is not reported"

expect "an answering cache goes to both names" "$expect_both" "$(run npm_config_registry="$live")"
if grep -qF "$live" "$WORK/stderr"; then fail "the registry URL reached the job log"; fi

expect "the cache is reached without the proxy" "$expect_both" \
  "$(run npm_config_registry="$live" HTTPS_PROXY="$dead" HTTP_PROXY="$dead" http_proxy="$dead" all_proxy="$dead")"
expect "pnpm's name alone is not read" "" "$(run pnpm_config_registry="$live")"

expect "a silent cache falls back" "" "$(run npm_config_registry="$dead")"
grep -q 'did not answer' "$WORK/stderr" || fail "a silent cache is not reported"
expect "an HTTP error falls back" "" "$(run npm_config_registry="$errors")"
grep -q 'did not answer' "$WORK/stderr" || fail "an erroring cache is not reported"

expect "a URL with credentials passes nothing" "" "$(run npm_config_registry="http://user:secret@127.0.0.1:$open_port/")"
if grep -q 'secret' "$WORK/stderr"; then fail "the credential reached the job log"; fi
expect "a URL with a query passes nothing" "" "$(run npm_config_registry="http://127.0.0.1:$open_port/?token=secret")"
if grep -q 'secret' "$WORK/stderr"; then fail "the query reached the job log"; fi
expect "a URL with a fragment passes nothing" "" "$(run npm_config_registry="http://127.0.0.1:$open_port/#secret")"
expect "a non-URL registry passes nothing" "" "$(run npm_config_registry=registry.local)"
expect "a value that would add an output line passes nothing" "" "$(run npm_config_registry="$live
EVIL=1")"

# Every Dockerfile that fetches Node packages declares both ARGs in that stage, before the fetch.
while IFS= read -r dockerfile; do
  missing="$(awk '
    /^[[:space:]]*#/ { next }
    toupper($1) == "FROM" { npm = 0; pnpm = 0; next }
    toupper($1) == "ARG" && $2 ~ /^npm_config_registry(=|$)/ { npm = 1 }
    toupper($1) == "ARG" && $2 ~ /^pnpm_config_registry(=|$)/ { pnpm = 1 }
    /(^|[^[:alnum:]_.-])(pnpm +(install|i|fetch)|npm +(ci|install|i)|yarn +install)([[:space:];&|]|$)/ && !(npm && pnpm) { print FNR }
  ' "$ROOT/$dockerfile")"
  [ -z "$missing" ] || fail "$dockerfile: line(s) $(echo "$missing" | tr '\n' ' ')fetch Node packages without both registry ARGs in scope"
done < <(git -C "$ROOT" ls-files | grep -E '(^|/)Dockerfile[^/]*$')

# Every image build passes the helper's output, and every workflow with one runs the helper.
for workflow in "$ROOT"/.github/workflows/*.y*ml; do
  builds="$(grep -cE '^[[:space:]-]*uses:[[:space:]]*["'"'"']?[[:alnum:]_.-]+/(docker-)?build-push-action@' "$workflow" || true)"
  [ "$builds" -gt 0 ] || continue
  passed="$(grep -cF "\${{ steps.npm-routes.outputs.build-args }}" "$workflow" || true)"
  routed="$(grep -cE '^[[:space:]]*(run: bash )\S*\.github/image-build/npm-registry-build-args\.sh[[:space:]]*$' "$workflow" || true)"
  if [ "$builds" != "$passed" ] || [ "$builds" != "$routed" ]; then
    fail "${workflow#"$ROOT"/}: $builds image build(s), $routed helper step(s), $passed build-args that pass its output"
  fi
  # A workflow that builds another ref runs its own copy of the helper, before any registry login.
  if grep -E '^[[:space:]]*ref:' "$workflow" | grep -qvF 'github.sha'; then
    run_line="$(grep -nE 'run: bash \.workflow-npm-routes/\.github/image-build/npm-registry-build-args\.sh' "$workflow" | head -1 | cut -d: -f1 || true)"
    login_line="$(grep -nE 'uses:[[:space:]]*docker/login-action@' "$workflow" | head -1 | cut -d: -f1 || true)"
    if [ -z "$run_line" ]; then
      fail "${workflow#"$ROOT"/}: builds another ref but does not run the workflow's own copy of the helper"
    elif [ -n "$login_line" ] && [ "$run_line" -gt "$login_line" ]; then
      fail "${workflow#"$ROOT"/}: runs the helper after the registry login"
    fi
  fi
done

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "npm-registry-build-args: all checks passed"

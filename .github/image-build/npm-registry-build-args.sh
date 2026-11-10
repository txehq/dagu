#!/usr/bin/env bash
# Write the `build-args` step output that sends the Dockerfiles' Node package fetches to the
# runner's npm cache (TXE-6359). Every image build in .github/workflows passes that output to
# build-push-action.
#
# BuildKit starts each RUN step without the job's environment, so a `pnpm install` in a
# Dockerfile goes to registry.npmjs.org even on a runner whose own steps use a LAN npm cache.
# Each Dockerfile declares `ARG npm_config_registry` and `ARG pnpm_config_registry` with no
# default; this passes the runner's npm_config_registry as both when that registry answers
# /-/ping with a 2xx within 2 s. pnpm before 11 reads the first name, pnpm 11 only the second.
#
# The output is empty when the runner sets no registry (GitHub-hosted runners) or the registry
# does not answer. The ARGs then stay unset, the install layers keep their usual cache key, and
# the build fetches from registry.npmjs.org. The lockfile's integrity hashes decide what is
# installed either way.
#
# This repository is public, and a pushed image's provenance records its build arguments and a
# job log can be read by anyone. So a URL that could carry a credential (userinfo, a query or a
# fragment) is refused, and the URL is not logged. The ARGs stay out of the final stage of every
# Dockerfile, where a passed value would enter the image's history.
set -euo pipefail

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must name the step output file}"

args=()
registry=${npm_config_registry:-}
case $registry in
  "")
    echo "npm routes: the runner sets no npm registry; the build uses registry.npmjs.org" >&2
    ;;
  *[[:space:]]* | *@* | *\?* | *#*)
    echo "::warning::npm routes: the runner's npm registry is not a plain URL without credentials; the build uses registry.npmjs.org" >&2
    ;;
  http://* | https://*)
    if curl -fs -o /dev/null --noproxy '*' --connect-timeout 2 --max-time 2 "${registry%/}/-/ping" 2>/dev/null; then
      args=("npm_config_registry=$registry" "pnpm_config_registry=$registry")
      echo "npm routes: the build uses the runner's npm cache" >&2
    else
      echo "::warning::npm routes: the runner's npm cache did not answer within 2 s; the build uses registry.npmjs.org" >&2
    fi
    ;;
  *)
    echo "::warning::npm routes: the runner's npm registry is not an http(s) URL; the build uses registry.npmjs.org" >&2
    ;;
esac

{
  echo 'build-args<<TXE_NPM_ROUTES_EOF'
  if [ "${#args[@]}" -gt 0 ]; then printf '%s\n' "${args[@]}"; fi
  echo 'TXE_NPM_ROUTES_EOF'
} >> "$GITHUB_OUTPUT"

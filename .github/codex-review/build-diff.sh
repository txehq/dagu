#!/usr/bin/env bash
# The diff Codex is given, from two read-only checkouts, by sha.
#
#   build-diff.sh <pr-checkout> <merge-base-checkout> <base-sha> <head-sha> <out>
#
# The merge base's commit is fetched into the PR checkout from the local merge-base checkout, so
# no credential is needed, and both shas are checked before git diffs them. No external diff
# driver or textconv runs (a PR's .gitattributes cannot make git execute anything).
set -euo pipefail
[ "$#" -eq 5 ] || { echo "usage: build-diff.sh <pr> <merge-base> <base-sha> <head-sha> <out>" >&2; exit 2; }
pr="$1"; mb="$2"; base="$3"; head="$4"; out="$5"
[[ "$base" =~ ^[0-9a-f]{40}$ && "$head" =~ ^[0-9a-f]{40}$ ]] || { echo "build-diff: the shas are not 40-hex" >&2; exit 1; }
git -C "$pr" fetch --quiet --no-tags --depth=1 "$(cd "$mb" && pwd)" HEAD
[ "$(git -C "$pr" rev-parse FETCH_HEAD)" = "$base" ] || { echo "build-diff: the merge-base checkout is not $base" >&2; exit 1; }
[ "$(git -C "$pr" rev-parse HEAD)" = "$head" ] || { echo "build-diff: the PR checkout is not $head" >&2; exit 1; }
git -C "$pr" -c core.quotePath=false -c diff.external= diff --no-ext-diff --no-textconv --no-color --no-renames \
  "$base" "$head" >"$out"
echo "build-diff: $(wc -c <"$out") bytes, $(git -C "$pr" diff --no-renames --name-only "$base" "$head" | wc -l) files"

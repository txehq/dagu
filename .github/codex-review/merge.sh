#!/usr/bin/env bash
# merge.sh — merge a txehq/dagu PR only after MAIN's copy of the codex-review check passes on the
# exact head being merged (TXE-4719).
#
#   git fetch -q origin main && git show origin/main:.github/codex-review/merge.sh | bash -s -- <pr> <head-sha>
#
# Why it exists: a pull_request run executes the PR's own copy of codex-review.yml and of the
# check, so a PR can edit the check that judges it. This wrapper, read from origin/main and never
# from the PR, re-runs origin/main's copy of codex-review-check.sh (no wait) and then merges with
# --match-head-commit, so GitHub refuses the merge if the head moved after the check.
#
# Refuses (exit 1) when: the PR is not open, is a draft, or its head is not <head-sha>; its base is
# not main; main's check does not pass on that head. Exit 2: usage or a read failure.
set -euo pipefail

repo="${GH_REPO:-txehq/dagu}"
pr="${1:-}"; want="${2:-}"
[[ "$pr" =~ ^[0-9]+$ && "$want" =~ ^[0-9a-f]{40}$ ]] || { echo "usage: merge.sh <pr-number> <40-hex head sha>" >&2; exit 2; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# main's copy of the check, from the remote, never the working tree or the PR.
gh api "repos/$repo/contents/.github/codex-review/codex-review-check.sh?ref=main" --jq .content \
  | base64 -d >"$tmp/check.sh" || { echo "merge.sh: could not read main's codex-review-check.sh" >&2; exit 2; }
[ -s "$tmp/check.sh" ] || { echo "merge.sh: main has no codex-review-check.sh" >&2; exit 2; }

read -r state draft head base < <(gh api "repos/$repo/pulls/$pr" --jq '[.state, .draft, .head.sha, .base.ref] | @tsv') \
  || { echo "merge.sh: could not read PR #$pr" >&2; exit 2; }
[ "$state" = open ] || { echo "merge.sh: PR #$pr is $state" >&2; exit 1; }
[ "$draft" = false ] || { echo "merge.sh: PR #$pr is a draft" >&2; exit 1; }
[ "$head" = "$want" ] || { echo "merge.sh: PR #$pr's head is $head, not $want" >&2; exit 1; }
[ "$base" = main ] || { echo "merge.sh: PR #$pr's base is $base, not main" >&2; exit 1; }

GH_REPO="$repo" PR_NUMBER="$pr" CODEX_REVIEW_WAIT_SECONDS=0 bash "$tmp/check.sh" \
  || { echo "merge.sh: main's codex-review check does not pass on $want; not merging" >&2; exit 1; }

gh pr merge "$pr" -R "$repo" --squash --match-head-commit "$want"

#!/usr/bin/env bash
# merge.sh — merge a txehq/dagu PR only when, on the exact head being merged, MAIN's codex-review
# check passes now and every CI run on that head has finished green (TXE-4719).
#
#   git fetch -q origin main && git show origin/main:.github/codex-review/merge.sh | bash -s -- <pr> <head-sha>
#
# Why it exists. The codex-review workflow already runs main's copy (pull_request_target), but its
# verdict is a result of the past: it polled up to 15 minutes, and a review, a label or a push can
# come after it. This fork's main has no branch protection, so nothing else stops a merge with CI
# failing or still running. This wrapper, read from origin/main and never from the PR:
#   1. refuses a PR that is not open, is a draft, is not on main, or whose head is not <head-sha>;
#   2. requires main's codex-review WORKFLOW RUN (.github/workflows/codex-review.yml) on that head (pull_request_target, created on every
#      push, so its presence also shows the push's other runs were created) to be completed/success;
#   3. requires every other workflow run (latest run per workflow file and event; run numbers count
#      per workflow), every check run (latest per app, check suite and name) and the combined commit
#      status on that head to be finished and green: success, skipped or neutral; pending, missing reads, failure,
#      cancelled, timed out or action required refuse. Path-filtered workflows that did not match
#      the PR have no run, and that is not a failure;
#   4. re-runs main's codex-review-check.sh at that head, with no wait and never in fixture mode;
#   5. merges with --match-head-commit, so GitHub refuses the merge if the head moved after 1-4.
#
# Residual window, stated rather than hidden: a connector review or a run that changes on the SAME
# head in the seconds between 4 and 5 is not seen; run this once the connector's state is final.
#
# Exit 0 merged; 1 refused; 2 usage or a read failure (nothing merged).
set -euo pipefail

repo="${GH_REPO:-txehq/dagu}"
pr="${1:-}"; want="${2:-}"
[[ "$pr" =~ ^[0-9]+$ && "$want" =~ ^[0-9a-f]{40}$ ]] || { echo "usage: merge.sh <pr-number> <40-hex head sha>" >&2; exit 2; }
refuse() { echo "merge.sh: $*; not merging" >&2; exit 1; }
unread() { echo "merge.sh: could not read $*; not merging" >&2; exit 2; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# main's copy of the check, from the remote, never the working tree or the PR.
gh api "repos/$repo/contents/.github/codex-review/codex-review-check.sh?ref=main" --jq .content >"$tmp/check.b64" \
  || unread "main's codex-review-check.sh"
base64 -d <"$tmp/check.b64" >"$tmp/check.sh" || unread "main's codex-review-check.sh (not base64)"
[ -s "$tmp/check.sh" ] || unread "main's codex-review-check.sh (empty: main has none)"

gh api "repos/$repo/pulls/$pr" --jq '[.state, .draft, .head.sha, .base.ref] | @tsv' >"$tmp/pull.tsv" || unread "PR #$pr"
read -r state draft head base <"$tmp/pull.tsv" || unread "PR #$pr (no fields)"
[ "$state" = open ] || refuse "PR #$pr is $state"
[ "$draft" = false ] || refuse "PR #$pr is a draft"
[ "$head" = "$want" ] || refuse "PR #$pr's head is $head, not $want"
[ "$base" = main ] || refuse "PR #$pr's base is $base, not main"

# ── CI on the exact head: workflow runs (latest attempt per workflow), check runs, statuses ──
gh api --paginate "repos/$repo/actions/runs?head_sha=$want&per_page=100" --jq '.workflow_runs[]' >"$tmp/runs.jsonl" \
  || unread "the workflow runs on $want"
gh api --paginate "repos/$repo/commits/$want/check-runs?per_page=100" --jq '.check_runs[]' >"$tmp/checks.jsonl" \
  || unread "the check runs on $want"
gh api "repos/$repo/commits/$want/status" --jq '[.state, .total_count] | @tsv' >"$tmp/status.tsv" \
  || unread "the commit status of $want"
jq -s -e 'all(.[]; type == "object")' "$tmp/runs.jsonl" "$tmp/checks.jsonl" >/dev/null 2>&1 \
  || unread "the CI payloads (not objects)"
# The gate is identified by its workflow FILE on main, not its display name, which another
# workflow could share.
# The API has returned the bare path here; GitHub also documents a ref-qualified one
# (".github/workflows/codex-review.yml@main"), so any "@<ref>" suffix is ignored.
gate="$(jq -s -r '[.[] | select(((.path // "") | sub("@.*$"; "")) == ".github/workflows/codex-review.yml" and .event == "pull_request_target")]
  | max_by(.run_number) // empty | "\(.status) \(.conclusion)"' "$tmp/runs.jsonl")"
[ "$gate" = "completed success" ] || refuse "main's codex-review run on $want is '${gate:-missing}', not completed success"
bad="$(jq -s -r '
  group_by([.workflow_id, .event]) | map(max_by(.run_number))[]
  | select(.status != "completed" or ((.conclusion // "") | IN("success","skipped","neutral") | not))
  | "workflow \(.name) (\(.path)): \(.status)/\(.conclusion // "none")"' "$tmp/runs.jsonl")
$(jq -s -r '
  group_by([.app.id, .check_suite.id, .name]) | map(max_by(.started_at // ""))[]
  | select(.status != "completed" or ((.conclusion // "") | IN("success","skipped","neutral") | not))
  | "check \(.name): \(.status)/\(.conclusion // "none")"' "$tmp/checks.jsonl")"
bad="$(printf '%s\n' "$bad" | sed '/^$/d')"
[ -z "$bad" ] || refuse "CI on $want is not finished green:
$bad"
read -r cstate ccount <"$tmp/status.tsv" || unread "the commit status of $want (no fields)"
[ "$ccount" = 0 ] || [ "$cstate" = success ] || refuse "the combined commit status of $want is $cstate"

# Never fixture mode: an inherited CODEX_REVIEW_FIXTURE_DIR would judge local files and merge the live PR.
env -u CODEX_REVIEW_FIXTURE_DIR GH_REPO="$repo" PR_NUMBER="$pr" CODEX_REVIEW_WAIT_SECONDS=0 bash "$tmp/check.sh" \
  || refuse "main's codex-review check does not pass on $want"

gh pr merge "$pr" -R "$repo" --squash --match-head-commit "$want"

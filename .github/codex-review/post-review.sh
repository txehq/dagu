#!/usr/bin/env bash
# Post one codex-review pass as a PR review on the head it reviewed (the post job).
#
#   post-review.sh <review.md> <meta.json>
#   env: GH_TOKEN REPO PR HEAD_SHA RUN_URL
#
# Posts nothing when the PR's head has moved since the review job read it (the newer head gets
# its own pass), or when the text holds a key-shaped string. The body starts with the marker
# build_prompt.py counts passes by: <!-- codex-review pass=N head=<sha> run=<url> -->.
# Afterwards the label codex-review-again is removed, so adding it again starts one more pass.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: post-review.sh <review.md> <meta.json>" >&2; exit 2; }
review="$1"; meta="$2"
: "${GH_TOKEN:?}" "${REPO:?}" "${PR:?}" "${HEAD_SHA:?}" "${RUN_URL:?}"
[[ "$PR" =~ ^[0-9]+$ && "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "post-review: PR or HEAD_SHA malformed" >&2; exit 1; }
[ -s "$review" ] || { echo "post-review: the review is empty" >&2; exit 1; }

pass="$(jq -r .pass "$meta")"
[ "$(jq -r .head "$meta")" = "$HEAD_SHA" ] || { echo "post-review: the review's meta names another head" >&2; exit 1; }
[[ "$pass" =~ ^[0-9]+$ ]] || { echo "post-review: pass is not a number" >&2; exit 1; }

if python3 -I - "$review" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
sys.exit(0 if re.search(r"sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}", text) else 1)
PY
then
  echo "::error::post-review: the review holds a key-shaped string; nothing is posted" >&2
  exit 1
fi

live="$(gh api "repos/$REPO/pulls/$PR" --jq '[.state, .head.sha] | @tsv')"
if [ "$live" != "$(printf 'open\t%s' "$HEAD_SHA")" ]; then
  echo "::notice::post-review: PR #$PR is closed or no longer at $HEAD_SHA; this pass is not posted"
  exit 0
fi

body="$(mktemp)"
trap 'rm -f -- "$body"' EXIT
{
  printf '<!-- codex-review pass=%s head=%s run=%s -->\n' "$pass" "$HEAD_SHA" "$RUN_URL"
  python3 -I - "$review" "$RUN_URL" <<'PY'
import sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read().rstrip("\n")
limit = 64_000
if len(text) > limit:
    text = text[:limit] + f"\n\n_(Cut at {limit} characters; the full review is the run's artifact: {sys.argv[2]})_"
print(text)
PY
} >"$body"

jq -n --rawfile body "$body" --arg sha "$HEAD_SHA" '{commit_id: $sha, event: "COMMENT", body: $body}' \
  | gh api -X POST "repos/$REPO/pulls/$PR/reviews" --input - --jq '"post-review: posted review \(.id) on \(.commit_id)"'

gh api -X DELETE "repos/$REPO/issues/$PR/labels/codex-review-again" >/dev/null 2>&1 || true

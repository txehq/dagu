#!/usr/bin/env bash
# test-codex-review-check.sh — .github/codex-review/codex-review-check.sh over recorded connector payloads (TXE-4664).
#
#   bash .github/codex-review/test-codex-review-check.sh
#
# THE PAYLOADS ARE RECORDED (then reduced by testdata/sanitize.py to the structure the check reads,
# because they come from private repositories and this one is public, TXE-4719), THE CASES ARE DERIVED. .github/codex-review/testdata/pr290/ holds
# txehq/sub2api PR 290 as the API returned it on 2026-10-17 (pull.json trimmed to the fields
# the check reads):
#   gh api repos/txehq/sub2api/pulls/290/reviews     > reviews.json
#   gh api repos/txehq/sub2api/pulls/290/comments    > review-comments.json
#   gh api repos/txehq/sub2api/issues/290/comments   > issue-comments.json
#   gh api repos/txehq/sub2api/issues/290/events     > issue-events.json
# At that moment the connector had completed a clean review of the head c6f314a380 (state
# block only, no review object) after three reviews with P2 findings on earlier heads. Each
# case below is that recording with the ONE edit named beside it, made here in jq so the edit
# is reviewed with the test rather than hidden in a copied file.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="$ROOT/.github/codex-review/codex-review-check.sh"
BASE="$ROOT/.github/codex-review/testdata/pr290"
HEAD_RECORDED="c6f314a3806a7acbadf6b906b2b95c7afbcff82d"
HEAD_PREVIOUS="2bf1311d2bb87741c536af0694229f85e885be44"   # the head connector review 5550906105 reviewed
HEAD_UNREVIEWED="5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e" # a push the connector has not seen yet
P2_ON_PREVIOUS=4297056843                                  # an inline P2 finding of review 5550906105

TMP="$(mktemp -d "${TMPDIR:-/tmp}/codex-review-test.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

# with_head_repo <dir> <owner/name> — the recordings were trimmed of .head.repo, which the API
# always returns; the fork's check reads it (TXE-4719), so each case gets the PR's own repository.
with_head_repo() {
    jq --arg r "$2" '.head.repo = {full_name: $r}' "$1/pull.json" >"$1/pull.json.new" && mv "$1/pull.json.new" "$1/pull.json" || exit 2
}

# derive <case> [<file> <jq program>]... — a case directory: the recording, with each named edit
derive() {
    local dir="$TMP/$1"; shift
    mkdir -p "$dir" && cp "$BASE"/*.json "$dir/" || exit 2
    with_head_repo "$dir" txehq/sub2api
    while [ "$#" -ge 2 ]; do
        if ! { jq "$2" "$dir/$1.json" >"$dir/$1.json.new" && mv "$dir/$1.json.new" "$dir/$1.json"; }; then
            echo "FATAL: could not apply the $1 edit for $dir" >&2; exit 2
        fi
        shift 2
    done
}

# expect <case> <exit code> <substring> [VAR=value]... — run the check on the case, assert both
expect() {
    local c="$1" want_rc="$2" want="$3" out rc
    shift 3
    : >"$TMP/$c.summary"
    out="$(env CODEX_REVIEW_FIXTURE_DIR="$TMP/$c" GH_REPO=txehq/sub2api PR_NUMBER=290 \
        GITHUB_STEP_SUMMARY="$TMP/$c.summary" "$@" bash "$CHECK" 2>&1)"; rc=$?
    set -- "$c" "$want_rc" "$want"
    case "$rc:$out" in
        "$2:"*"$3"*) PASS=$((PASS + 1)); printf '  ok   %s (exit %s)\n' "$1" "$rc" ;;
        *) FAIL=$((FAIL + 1)); printf '  FAIL %s: want exit %s and %s\n       got exit %s:\n%s\n' \
               "$1" "$2" "$3" "$rc" "$(printf '%s' "$out" | sed 's/^/         /')" ;;
    esac
}

# 1. clean — the recording as is: completed on the head, no review object on it.
derive clean
expect clean 0 "PASS: the connector completed its review of $HEAD_RECORDED with no review object on it"

# 2. stale-head — a push after the review: the head moves, the state block does not.
derive stale-head pull ".head.sha = \"$HEAD_UNREVIEWED\""
expect stale-head 1 "is of $HEAD_RECORDED, not the current head $HEAD_UNREVIEWED"

# 2b. a PR from another repository (TXE-4719): the recording, its head in a fork. It runs its own
#     copy of the check, so a clean connector state does not pass it; nor does a deleted fork.
derive fork-pr pull '.head.repo = {full_name: "someone/sub2api"}'
expect fork-pr 1 "FAIL: PR #290's head is in someone/sub2api, not txehq/sub2api"
derive fork-deleted pull '.head.repo = null'
expect fork-deleted 1 "head is in a missing or deleted repository"

# 3. P1-present — the moment review 5550906105 landed on the previous head, with one of its
#    findings a P1: head and state block at that head, and the finding's badge raised P2 -> P1.
SET_STATE_SHA=".[] |= (.body |= sub(\"\\\"commit_sha\\\":\\\"$HEAD_RECORDED\\\"\"; \"\\\"commit_sha\\\":\\\"$HEAD_PREVIOUS\\\"\"))"
derive p1-present pull ".head.sha = \"$HEAD_PREVIOUS\"" issue-comments "$SET_STATE_SHA" \
    review-comments "map(if .id == $P2_ON_PREVIOUS then .body |= sub(\"P2 Badge\"; \"P1 Badge\") else . end)"
expect p1-present 1 "synthetic/file2.go:"
expect p1-present 1 "has P0/P1 findings"

# 3b. the same moment as recorded, P2 findings only: a review on the head that does not block.
derive p2-on-head pull ".head.sha = \"$HEAD_PREVIOUS\"" issue-comments "$SET_STATE_SHA"
expect p2-on-head 0 "none of its findings there is P0 or P1"

# 4. override — the stale head, with a person's review-override label and its labeled event.
derive override pull ".head.sha = \"$HEAD_UNREVIEWED\" | .labels += [{name: \"review-override\"}]" \
    issue-events '. + [{event: "labeled", actor: {login: "a-maintainer", type: "User"},
                        created_at: "2026-10-17T03:00:00Z", label: {name: "review-override", color: "b60205"}}]'
expect override 0 "review-override label added by a-maintainer at 2026-10-17T03:00:00Z"
# 4a. a fork PR a person overrides (TXE-4719): the override is read from the API before the fork rule.
derive fork-override pull '.head.repo = {full_name: "someone/sub2api"} | .labels += [{name: "review-override"}]' \
    issue-events '. + [{event: "labeled", actor: {login: "a-maintainer", type: "User"},
                        created_at: "2026-10-17T03:00:00Z", label: {name: "review-override", color: "b60205"}}]'
expect fork-override 0 "review-override label added by a-maintainer"
if grep -q 'a-maintainer at 2026-10-17T03:00:00Z' "$TMP/override.summary"; then
    PASS=$((PASS + 1)); printf '  ok   override names its actor in the step summary\n'
else
    FAIL=$((FAIL + 1)); printf '  FAIL override: the step summary does not name the actor\n'
fi

# 4b. the label with no labeled event: nobody can be named, so it does not pass.
derive override-unattributed pull ".labels += [{name: \"review-override\"}]"
expect override-unattributed 1 "no labeled event for it was found"

# 4c. the label added by a bot: not a person's decision, so it does not pass.
derive override-bot pull ".head.sha = \"$HEAD_UNREVIEWED\" | .labels += [{name: \"review-override\"}]" \
    issue-events '. + [{event: "labeled", actor: {login: "github-actions[bot]", type: "Bot"},
                        created_at: "2026-10-17T03:00:00Z", label: {name: "review-override", color: "b60205"}}]'
expect override-bot 1 "review-override was added by a bot (github-actions[bot] at 2026-10-17T03:00:00Z)"

# 5. no state block yet — the connector has not reviewed the PR at all.
derive no-state issue-comments 'map(select(.user.login != "chatgpt-codex-connector[bot]"))'
expect no-state 1 "no connector summary comment with a codex-review-state block yet"

# 6. a review still running on the head.
derive running issue-comments '.[] |= (.body |= sub("\"status\":\"completed\""; "\"status\":\"in_progress\""))'
expect running 1 "code review is 'in_progress'"

# 6b. the state block reports findings on the head, but no connector review of the head exists.
derive findings-without-review issue-comments '.[] |= (.body |= sub("\"has_any_findings\":false"; "\"has_any_findings\":true"))'
expect findings-without-review 1 "reports findings on $HEAD_RECORDED but no connector review"

# 6b2. no review object and a state block that does not say has_any_findings false: not clean.
derive findings-unstated issue-comments '.[] |= (.body |= sub(",?\"has_any_findings\":false"; ""))'
expect findings-unstated 1 "gives has_any_findings as null on $HEAD_RECORDED, not false"
derive findings-malformed issue-comments '.[] |= (.body |= sub("\"has_any_findings\":false"; "\"has_any_findings\":\"false\""))'
expect findings-malformed 1 "gives has_any_findings as \"false\""

# 6c. the base changed (TXE-4666): the head is unchanged and the review completed on it, but it
#     may be a review of the old diff. Only a force-push after the change, to the head or to a
#     commit the head descends from, AND a review completed after that push, let the check pass
#     again. compare.json is the compare API's answer, which each case that needs one writes.
#     The recording's Code Review row says it completed at 2026-10-16T17:12:43.617739Z.
base_event() { # base_event <event> <created_at> — the jq edit that appends one base-change event
    printf '. + [{event: "%s", actor: {login: "a-maintainer", type: "User"}, created_at: "%s", commit_id: null}]' "$1" "$2"
}
push_event() { # push_event <created_at> <commit> — the jq edit that appends one force-push event
    printf '. + [{event: "head_ref_force_pushed", actor: {login: "a-maintainer", type: "User"}, created_at: "%s", commit_id: "%s"}]' "$1" "$2"
}
OLDER="0123456789abcdef0123456789abcdef01234567"
derive base-changed issue-events "$(base_event base_ref_changed 2026-10-17T03:00:00Z)"
expect base-changed 1 "the PR's base changed at 2026-10-17T03:00:00Z and the head branch has not been force-pushed since (latest: none)"
derive base-pushed issue-events "$(base_event base_ref_force_pushed 2026-10-17T03:00:00Z)"
expect base-pushed 1 "rebase onto the new base and force-push"
# 6d. a force-push BEFORE the change, of the head itself: it predates the change, so it fails.
derive pushed-before issue-events "$(push_event 2026-10-16T12:00:00Z "$HEAD_RECORDED") | $(base_event base_ref_changed 2026-10-16T13:00:00Z)"
expect pushed-before 1 "has not been force-pushed since (latest: 2026-10-16T12:00:00Z)"
# 6e. a force-push of the head AFTER the change (rebased onto the new base): passes.
derive pushed-after issue-events "$(base_event base_ref_changed 2026-10-16T12:00:00Z) | $(push_event 2026-10-16T12:05:00Z "$HEAD_RECORDED")"
expect pushed-after 0 "PASS: the connector completed its review of $HEAD_RECORDED with no review object on it"
# 6f. a force-push after the change to an older commit, then ordinary pushes on top of it: the
#     head descends from it (compare says ahead), so it passes; diverged, it fails.
derive pushed-then-commits issue-events "$(base_event base_ref_changed 2026-10-16T12:00:00Z) | $(push_event 2026-10-16T12:05:00Z "$OLDER")"
printf '{"status": "ahead", "ahead_by": 2, "behind_by": 0}' >"$TMP/pushed-then-commits/compare.json"
expect pushed-then-commits 0 "PASS: the connector completed its review of $HEAD_RECORDED with no review object on it"
derive pushed-diverged issue-events "$(base_event base_ref_changed 2026-10-16T12:00:00Z) | $(push_event 2026-10-16T12:05:00Z "$OLDER")"
printf '{"status": "diverged", "ahead_by": 1, "behind_by": 1}' >"$TMP/pushed-diverged/compare.json"
expect pushed-diverged 1 "does not descend from $OLDER"
# 6f2. a reviewed SHA restored after the change: force-pushed back to the head at 17:30, after
#      the review the state block records (17:12:43), so that review cannot be of the restored
#      head's new diff; it fails until the connector reviews again.
derive pushed-restored issue-events "$(base_event base_ref_changed 2026-10-16T17:20:00Z) | $(push_event 2026-10-16T17:25:00Z "$OLDER") | $(push_event 2026-10-16T17:30:00Z "$HEAD_RECORDED")"
expect pushed-restored 1 "force-pushed at 2026-10-16T17:30:00Z, but the connector's code review is dated 2026-10-16T17:12:43Z"
# 6f3. the force-push in the same second as the review's completion: fails.
derive pushed-review-same-second issue-events "$(base_event base_ref_changed 2026-10-16T17:00:00Z) | $(push_event 2026-10-16T17:12:43Z "$HEAD_RECORDED")"
expect pushed-review-same-second 1 "is dated 2026-10-16T17:12:43Z (its Code Review row), not after that push"
# 6f4. a pushed head and a Code Review row with no readable time: fails rather than guesses.
derive pushed-undated issue-events "$(base_event base_ref_changed 2026-10-16T12:00:00Z) | $(push_event 2026-10-16T12:05:00Z "$HEAD_RECORDED")" \
    issue-comments '.[] |= (.body |= gsub("datetime=\"[^\"]*\""; ""))'
expect pushed-undated 1 "is dated nowhere (its Code Review row)"

# 6f5. RECORDED events, not manufactured ones: txehq/txe PR 3713's base change and force-pushes
#      as gh api repos/txehq/txe/issues/3713/events returned them on 2026-10-18 (trimmed to the
#      fields read), in pr3713-base-and-force-push-events.json. Its head d470ad541b was set by
#      the force-push at 06:20:36Z, 11 s after the retarget at 06:20:25Z, and that REST event's
#      commit_id is the push's after-commit: GraphQL HeadRefForcePushedEvent.afterCommit read the
#      same day gives d470ad541ba0 for it, and e58808443e25 for the 05:59:30Z one (the same holds
#      on PRs 3700 and 3923, 8 events in all). Grafted onto the recorded clean pass: the head
#      and the state block moved to d470ad541b, the review dated 06:25:00Z, so it passes; dated
#      06:20:00Z, before the push, it fails.
EV3713="$ROOT/.github/codex-review/testdata/pr3713-base-and-force-push-events.json"
HEAD_3713="d470ad541ba0caace510acd80c9766e7694d7849"
derive_with_events() { # derive_with_events <case> <review datetime> — the clean pass at HEAD_3713, with the recorded events
    derive "$1" pull ".head.sha = \"$HEAD_3713\""
    jq --arg old "\"commit_sha\":\"$HEAD_RECORDED\"" --arg new "\"commit_sha\":\"$HEAD_3713\"" --arg t "$2" \
        '.[] |= (.body |= (split($old) | join($new) | gsub("datetime=\"[^\"]*\""; "datetime=\"" + $t + "\"")))' \
        "$TMP/$1/issue-comments.json" >"$TMP/$1/issue-comments.json.new" && mv "$TMP/$1/issue-comments.json.new" "$TMP/$1/issue-comments.json" || exit 2
    jq --slurpfile rec "$EV3713" '. + $rec[0]' "$TMP/$1/issue-events.json" >"$TMP/$1/issue-events.json.new" \
        && mv "$TMP/$1/issue-events.json.new" "$TMP/$1/issue-events.json" || exit 2
}
derive_with_events recorded-3713-reviewed-after 2026-10-15T06:25:00.000000Z
expect recorded-3713-reviewed-after 0 "PASS: the connector completed its review of $HEAD_3713"
derive_with_events recorded-3713-reviewed-before 2026-10-15T06:20:00.000000Z
expect recorded-3713-reviewed-before 1 "force-pushed at 2026-10-15T06:20:36Z, but the connector's code review is dated 2026-10-15T06:20:00Z"

# 6g. the same second as the change: the order cannot be told, so it fails.
derive pushed-same-second issue-events "$(base_event base_ref_changed 2026-10-16T12:00:00Z) | $(push_event 2026-10-16T12:00:00Z "$HEAD_RECORDED")"
expect pushed-same-second 1 "has not been force-pushed since (latest: 2026-10-16T12:00:00Z)"
# 6h. a force-push event that names no commit is not evidence: not what the API returns.
derive pushed-no-commit issue-events "$(base_event base_ref_changed 2026-10-16T12:00:00Z) | . + [{event: \"head_ref_force_pushed\", created_at: \"2026-10-16T12:05:00Z\", commit_id: null}]"
expect pushed-no-commit 2 "could not read PR #290's force-push events"

# 7. the poll, timing out — the stale head with a 2 s wait: the coordinator's timeout line.
expect stale-head 1 "connector has not reviewed $HEAD_UNREVIEWED within 2 s; re-run this check or push" \
    CODEX_REVIEW_WAIT_SECONDS=2 CODEX_REVIEW_POLL_SECONDS=1

# 8. the poll, answered — a review running on the head, then the connector finishes cleanly
#    (the recording) a second later: the comment edit no event reports, seen by the poll.
derive arrives issue-comments '.[] |= (.body |= sub("\"status\":\"completed\""; "\"status\":\"in_progress\""))'
( sleep 1; cp "$BASE/issue-comments.json" "$TMP/arrives/issue-comments.json.new" \
    && mv "$TMP/arrives/issue-comments.json.new" "$TMP/arrives/issue-comments.json" ) &
expect arrives 0 "of 20 s): the connector's code review is 'in_progress'" \
    CODEX_REVIEW_WAIT_SECONDS=20 CODEX_REVIEW_POLL_SECONDS=1
wait
if grep -q "PASS: the connector completed its review of $HEAD_RECORDED" "$TMP/arrives.summary"; then
    PASS=$((PASS + 1)); printf '  ok   arrives passes once the state block reaches the head\n'
else
    FAIL=$((FAIL + 1)); printf '  FAIL arrives: the step summary has no PASS on the head\n'
fi

# 9. A txe clean pass, recorded (TXE-4666). On txe a clean pass ALSO posts a
#    `<!-- codex-review-receipt:v1 -->` comment ("Didn't find any major issues"), which the
#    sub2api recording above does not carry. .github/codex-review/testdata/pr3953/ is txehq/txe
#    PR 3953, a TXE-4670 canary sibling, as the API returned it on 2026-10-18 (pull.json trimmed
#    to the fields the check reads), recorded with the four reads in the header plus
#    gh api repos/txehq/txe/issues/3953/events. The check keys on the state block, so the
#    receipt beside it changes nothing.
BASE_TXE="$ROOT/.github/codex-review/testdata/pr3953"
if jq -e '[.[] | select(.user.login == "chatgpt-codex-connector[bot]" and (.body | contains("<!-- codex-review-receipt:v1 -->")))] | length == 1' \
        "$BASE_TXE/issue-comments.json" >/dev/null; then
    PASS=$((PASS + 1)); printf '  ok   the txe recording carries the connector receipt comment\n'
else
    FAIL=$((FAIL + 1)); printf '  FAIL the txe recording carries no connector receipt comment\n'
fi
mkdir -p "$TMP/txe-clean-with-receipt" && cp "$BASE_TXE"/*.json "$TMP/txe-clean-with-receipt/" || exit 2
with_head_repo "$TMP/txe-clean-with-receipt" txehq/txe
out="$(env CODEX_REVIEW_FIXTURE_DIR="$TMP/txe-clean-with-receipt" GH_REPO=txehq/txe PR_NUMBER=3953 \
    GITHUB_STEP_SUMMARY=/dev/null bash "$CHECK" 2>&1)"; rc=$?
case "$rc:$out" in
    "0:"*"PASS: the connector completed its review of b3619dcaf6162dad638caf4d7be5e57dfe77f022 with no review object on it"*)
        PASS=$((PASS + 1)); printf '  ok   txe-clean-with-receipt (exit 0)\n' ;;
    *) FAIL=$((FAIL + 1)); printf '  FAIL txe-clean-with-receipt: got exit %s:\n%s\n' "$rc" "$(printf '%s' "$out" | sed 's/^/         /')" ;;
esac

# 10. A clean re-review after a fix loop, recorded (TXE-4666): txehq/txe PR 4022 at 83822e7eb, as
#     the API returned it on 2026-10-18 (pull.json trimmed). The connector posted receipt
#     6241141339 ("Didn't find any major issues", Reviewed commit 83822e7ebb) at 21:09:56Z and no
#     review object on the head, and its state block still says has_any_findings true, from the
#     earlier passes' threads. The receipt is what makes it a pass.
HEAD_4022="83822e7ebb31ca9e2c81d3a13a53a8774d5250cf"
BASE4022="$ROOT/.github/codex-review/testdata/pr4022"
txe4022() { # txe4022 <case> [<file> <jq program>]... — the PR 4022 recording, with each edit
    local c="$1"; shift
    mkdir -p "$TMP/$c" && cp "$BASE4022"/*.json "$TMP/$c/" || exit 2
    with_head_repo "$TMP/$c" txehq/txe
    while [ "$#" -ge 2 ]; do
        jq "$2" "$TMP/$c/$1.json" >"$TMP/$c/$1.json.new" && mv "$TMP/$c/$1.json.new" "$TMP/$c/$1.json" || exit 2
        shift 2
    done
}
expect4022() { # expect4022 <case> <exit code> <substring>
    local out rc
    out="$(env CODEX_REVIEW_FIXTURE_DIR="$TMP/$1" GH_REPO=txehq/txe PR_NUMBER=4022 GITHUB_STEP_SUMMARY=/dev/null bash "$CHECK" 2>&1)"; rc=$?
    case "$rc:$out" in
        "$2:"*"$3"*) PASS=$((PASS + 1)); printf '  ok   %s (exit %s)\n' "$1" "$rc" ;;
        *) FAIL=$((FAIL + 1)); printf '  FAIL %s: want exit %s and %s\n       got exit %s:\n%s\n' "$1" "$2" "$3" "$rc" "$(printf '%s' "$out" | sed 's/^/         /')" ;;
    esac
}
txe4022 receipt-after-fix-loop
expect4022 receipt-after-fix-loop 0 "its receipt 6241141339 at 2026-10-17T21:09:56Z says no major issues there"
# 10b. without the receipt, has_any_findings true and no review on the head still fails.
txe4022 no-receipt issue-comments 'map(select((.body | contains("<!-- codex-review-receipt:v1 -->")) | not))'
expect4022 no-receipt 1 "no connector review of $HEAD_4022 and no clean-pass receipt for it were found"
# 10c. a receipt naming another commit is not a receipt for the head.
txe4022 receipt-other-commit issue-comments 'map(if .id == 6241141339 then .body |= sub("83822e7ebb"; "0fd56af346") else . end)'
expect4022 receipt-other-commit 1 "no clean-pass receipt for it were found"
# 10d. a receipt of the same SHA from an earlier pass (an hour before this review completed).
txe4022 receipt-earlier-pass issue-comments 'map(if .id == 6241141339 then .created_at = "2026-10-17T20:09:56Z" else . end)'
expect4022 receipt-earlier-pass 1 "no clean-pass receipt for it were found"
# 10e. a receipt written by someone other than the connector does not count.
txe4022 receipt-not-connector issue-comments 'map(if .id == 6241141339 then .user.login = "connorwang" | .user.type = "User" else . end)'
expect4022 receipt-not-connector 1 "no clean-pass receipt for it were found"

# 11. LIVE reads that fail (TXE-4719): no fixture directory, a stand-in gh that serves the recorded
#     clean case, except that ONE read prints a partial page and exits 1, as a broken API page
#     would. The clean case passes when every read works, so each refusal below is that read's.
#     Every list read is `gh api --paginate | jq -s` under pipefail: a failed gh must never become
#     an empty list, which for reviews would turn "no review on the head" into a pass.
mkdir -p "$TMP/livebin" "$TMP/live" && cp "$BASE"/*.json "$TMP/live/" || exit 2
with_head_repo "$TMP/live" txehq/sub2api
cat >"$TMP/livebin/gh" <<'GH'
#!/usr/bin/env bash
path=""; for a in "$@"; do case "$a" in repos/*) path="${a%%\?*}" ;; esac; done
case "$path" in
  */pulls/290) f=pull ;; */issues/290/comments) f=issue-comments ;; */issues/290/events) f=issue-events ;;
  */pulls/290/reviews) f=reviews ;; */pulls/290/comments) f=review-comments ;; *) echo "unexpected $*" >&2; exit 9 ;;
esac
if [ "$f" = "$LIVE_FAIL" ]; then printf '[]'; exit 1; fi  # a valid but partial page, then failure
cat "$LIVE_DIR/$f.json"
GH
chmod +x "$TMP/livebin/gh"
live() { # live <name> <failing read or ""> <want exit> <want substring>
    local out rc
    out="$(env -u CODEX_REVIEW_FIXTURE_DIR PATH="$TMP/livebin:$PATH" LIVE_DIR="$TMP/live" LIVE_FAIL="$2" \
        GH_REPO=txehq/sub2api PR_NUMBER=290 GITHUB_STEP_SUMMARY=/dev/null bash "$CHECK" 2>&1)"; rc=$?
    case "$rc:$out" in
        "$3:"*"$4"*) PASS=$((PASS + 1)); printf '  ok   %s (exit %s)\n' "$1" "$rc" ;;
        *) FAIL=$((FAIL + 1)); printf '  FAIL %s: want exit %s and %s\n       got exit %s:\n%s\n' "$1" "$3" "$4" "$rc" "$(printf '%s' "$out" | sed 's/^/         /')" ;;
    esac
}
live live-clean           ""               0 "PASS: the connector completed its review of $HEAD_RECORDED"
live live-pull-unread     pull             2 "could not read PR #290"
live live-comments-unread issue-comments   2 "could not read PR #290's comments"
live live-reviews-unread  reviews          2 "could not read PR #290's reviews"

printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

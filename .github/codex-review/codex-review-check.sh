#!/usr/bin/env bash
# codex-review-check.sh — the `codex-review` check (TXE-4664; ported to txehq/dagu by TXE-4719 from
# txehq/txe ops/ci/codex-review-check.sh at b708112c4, adding rule 0 for PRs from other
# repositories): has the Codex GitHub connector
# finished reviewing this PR's CURRENT head, with no P0 or P1 finding on it?
#
#   GH_REPO=txehq/dagu PR_NUMBER=134 .github/codex-review/codex-review-check.sh
#   CODEX_REVIEW_WAIT_SECONDS=900 GH_REPO=… PR_NUMBER=… .github/codex-review/codex-review-check.sh   # poll first
#   CODEX_REVIEW_FIXTURE_DIR=<dir> GH_REPO=… PR_NUMBER=… .github/codex-review/codex-review-check.sh  # recorded payloads
#
# .github/workflows/codex-review.yml runs it; .github/codex-review/test-codex-review-check.sh runs it over
# recorded payloads. Everything is re-read from the API here, never from the event payload.
#
# PASSES when the PR carries the `review-override` label (a person's decision: the labeled
# event's actor and time are printed, and written to the step summary; a label whose latest
# labeled event was a Bot's does not pass), or when ALL of:
#   1. the connector's summary issue comment carries `<!-- codex-review-state:v1 {…} -->` with
#      code_review.status == "completed" and code_review.commit_sha == the PR's head;
#   2. no inline comment of a connector review whose commit_id is the head carries the
#      `P0 Badge` or `P1 Badge` image alt text the connector writes on each finding — of EVERY
#      such review, not only the newest: two reviews of one head are reviews of the same code;
#   3. and when no connector review of the head exists, the state block says
#      has_any_findings: false, exactly (a missing or malformed field is not a clean pass) — OR
#      it says true and the connector's clean-pass receipt names the head: an issue comment
#      carrying `<!-- codex-review-receipt:v1 -->`, "major issues", and a "Reviewed commit"
#      the head starts with, posted within RECEIPT_WINDOW_S of the Code Review row's completion
#      (so it belongs to the review the state block records at the head, not to an earlier pass
#      of the same SHA). A clean re-review after a fix loop keeps has_any_findings true while
#      earlier findings' threads stay open (measured on PR 4022 at 83822e7eb, TXE-4666), so
#      the receipt is what a clean pass reads then;
#      — OR, with neither a review of the head nor a receipt naming it, the connector's LIVE
#      findings at the head (TXE-4791, the port of txehq/txe TXE-4786 and TXE-4920) are none or
#      P2/P3, or each live P0/P1 thread was resolved by a user. A live P0/P1 is a review thread
#      whose first comment is the connector's (GraphQL author typed Bot, login
#      chatgpt-codex-connector) and carries `P0 Badge` or `P1 Badge`, and which is not outdated,
#      whatever commit it was posted on: GitHub keeps a thread no push has outdated on the current
#      head, and the commit it reports is not read, so a late repositioning cannot hide one. A
#      connector thread with a P2 or P3 badge, or with no badge, never blocks (txe's rule); a
#      thread a person or another app opened is not a connector finding, whatever badge or login
#      it shows. A thread counts as resolved by a user only when its resolvedBy is typed User and
#      its login does not end in `[bot]`: resolved by a Bot, by an actor of another or no type,
#      by a `[bot]` login or by no named user (resolvedBy is typed User in GitHub's schema, so a
#      thread an App resolves comes back null) blocks. The resolving login is printed like the
#      override label's actor: a named decision, not authentication. Every page of one paginated
#      GraphQL read of the PR's reviewThreads is checked, and what cannot be read is a read that
#      failed (exit 2), never "no findings": a page with errors, or without its threads or a
#      boolean pageInfo.hasNextPage; pages whose hasNextPage is not true on every page but the last
#      and false on the last; an empty page among several; a cursor of a non-last page missing or
#      repeated; a page whose errors are not absent, null or empty, whatever their message says; a
#      thread without boolean isResolved and isOutdated, without a first comment with a numeric
#      databaseId, a string body and an author typed and named (non-empty strings both); or a
#      resolvedBy that is neither null nor typed and named the same way. (A thread whose first comment's author is a deleted
#      account, null in GraphQL, is therefore unreadable too: the receipt or a person's
#      review-override is the way past it.) Measured on txehq/dagu PRs 185
#      (b0eb595ab, every live thread a P2: failed until a manual `@codex review` posted a receipt)
#      and 175 (0503dc32f, one open live P1, which this rule still blocks). has_any_findings null
#      or malformed is NOT decided here: it fails as below (txe's TXE-5123 receipt-only rule for
#      null is not ported);
#   4. and the review saw the PR's current base (TXE-4666, the connector's P1s on PR 4022). A
#      retarget, or a force-push of a stacked PR's base (`base_ref_changed`,
#      `base_ref_force_pushed` issue events), changes the diff without moving the head. The
#      connector records neither the base it reviewed against nor when a review started, so
#      after the latest such event T the check passes only when ALL of:
#        a. the PR's latest `head_ref_force_pushed` event F is later than T;
#        b. the head is the commit F set, or descends from it (the compare API); and
#        c. the summary's Code Review row says the review completed after F, so the state
#           block is not one written before F about a SHA that F then restored.
#      After a retarget the author rebases onto the new base and force-pushes, and the connector
#      reviews the pushed head. The evidence is events GitHub and the connector write on this
#      PR, naming a commit and a time: no workflow run, which a re-run, a retarget's own
#      `edited` run or a deletion can make or unmake, and no timing margin. The review is dated
#      by its own row, never by the comment's updated_at, which a security review also
#      advances; a row with no readable time, or a time in the same second as F, fails.
#
# ⚠️ THE STATE BLOCK IS THE AUTHORITY, NOT A REVIEW OBJECT ON THE HEAD. The ticket's first rule
# was "the newest connector review has commit_id == head". The connector posts a review object
# only when it has findings: a clean pass updates the state block and reacts +1 on the PR, and
# nothing else. Measured on txehq/sub2api PR 290 (2026-10-17): head c6f314a380, state block
# completed at that head with no findings, newest connector review on the previous head
# 2bf1311d2b. The literal rule would fail every clean head, so the coordinator ruled the state
# block the authority (TXE-4664) and that rule is gone. No connector review on the head
# therefore means no findings on it. security_review is printed, never gated on.
#
# ⚠️ AND THAT IS WHY IT POLLS. A clean pass edits a comment and adds a reaction, and neither
# fires a pull_request or pull_request_review event, so a run that decided at once on the push
# would fail "not reviewed yet" minutes before the connector finished, and nothing would run it
# again. With CODEX_REVIEW_WAIT_SECONDS > 0 (the workflow sets 900 on every event, review events
# included: a person's review cancels a polling run through the workflow's concurrency group,
# so its run must keep polling too) the state block is re-read every CODEX_REVIEW_POLL_SECONDS
# (30) until it is completed at the head or the wait runs out. The merge runs main's copy with 0 (README.md).
#
# EXIT: 0 pass, 1 fail, 2 a read failed or a payload was not what the API returns.
set -uo pipefail

CONNECTOR_LOGIN="chatgpt-codex-connector[bot]"
CONNECTOR_GRAPHQL_LOGIN="chatgpt-codex-connector"   # GraphQL names a Bot without the [bot] suffix
OVERRIDE_LABEL="review-override"
STATE_MARKER="<!-- codex-review-state:v1 "
BLOCKING_BADGES='P0 Badge|P1 Badge'
RECEIPT_MARKER="<!-- codex-review-receipt:v1 -->"
# The receipt is posted 1 to 3 s before the Code Review row's completion time (PR 3953: 17:23:33Z
# against 17:23:35.8Z; PR 4022: 21:09:56Z against 21:09:57.6Z); a pass takes minutes, so 120 s
# cannot reach a receipt of the previous pass.
RECEIPT_WINDOW_S=120
# Every review thread of the PR with its first comment: what rule 3's live-thread read needs.
# shellcheck disable=SC2016  # GraphQL variables, not shell ones
THREADS_QUERY='query($owner: String!, $name: String!, $pr: Int!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $pr) {
      reviewThreads(first: 100, after: $endCursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          isResolved isOutdated line originalLine
          resolvedBy { __typename login }
          comments(first: 1) { nodes { databaseId author { __typename login } path body } }
        }
      }
    }
  }
}'

repo="${GH_REPO:?GH_REPO (owner/name) is required}"
pr="${PR_NUMBER:?PR_NUMBER is required}"
wait_s="${CODEX_REVIEW_WAIT_SECONDS:-0}"
poll_s="${CODEX_REVIEW_POLL_SECONDS:-30}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
case "$wait_s$poll_s" in *[!0-9]*) echo "CODEX_REVIEW_WAIT_SECONDS and CODEX_REVIEW_POLL_SECONDS are whole seconds" >&2; exit 2 ;; esac

say() { printf '%s\n' "$*"; }
verdict() { # verdict <exit code> <line> — the decision, on stdout and in the step summary
    say "$2"
    printf '### codex-review\n\n%s\n' "$2" >>"$summary"
    exit "$1"
}
die_read() { say "codex-review: could not read $1 — not a verdict, re-run the job" >&2; exit 2; }

# fetch <fixture name> <api path> [list] — the payload, from CODEX_REVIEW_FIXTURE_DIR or the API.
# A list endpoint is read with --paginate and its pages joined into one array.
fetch() {
    if [ -n "${CODEX_REVIEW_FIXTURE_DIR:-}" ]; then
        cat "$CODEX_REVIEW_FIXTURE_DIR/$1.json"
    elif [ "${3:-}" = list ]; then
        gh api --paginate "$2?per_page=100" | jq -s 'add // []'
    else
        gh api "$2"
    fi
}

# decide_on_live_threads — the end of rule 3 when the connector completed its review of the head
# with has_any_findings true and posted neither a review of the head nor a receipt naming it: the
# verdict on its live P0/P1 threads at the head. Never returns.
decide_on_live_threads() {
    local pages bad live named blocking
    if [ -n "${CODEX_REVIEW_FIXTURE_DIR:-}" ]; then
        pages="$(cat "$CODEX_REVIEW_FIXTURE_DIR/review-threads.json")" || die_read "PR #$pr's review threads"
    else
        pages="$(gh api graphql --paginate -F owner="${repo%%/*}" -F name="${repo#*/}" -F pr="$pr" \
            -f query="$THREADS_QUERY" | jq -s .)" || die_read "PR #$pr's review threads (the GraphQL error is above)"
    fi
    # Any error fails the read, whatever its text: errors absent, null or [] on every page, or no verdict.
    bad="$(printf '%s' "$pages" | jq -r '[ .[]?
        | if type != "object" then "a page that is not an object"
          elif .errors == null then empty
          elif (.errors | type) != "array" then "errors that are not a list"
          else .errors[] | if type == "object" and (.message | type) == "string" and .message != ""
                           then .message else "an error without a message" end end ] | join("; ")')" \
        || die_read "PR #$pr's review threads (not JSON)"
    [ -z "$bad" ] || die_read "PR #$pr's review threads (GraphQL: $bad)"
    # One row per live P0/P1 of the connector at the head: ok|block, comment id, path:line, who, first line.
    live="$(printf '%s' "$pages" | jq -er --arg bot "$CONNECTOR_GRAPHQL_LOGIN" --arg b "$BLOCKING_BADGES" '
        def named(a): (a.__typename | type) == "string" and a.__typename != ""
                      and (a.login | type) == "string" and a.login != "";
        if type != "array" or length == 0 then error("no pages") else . end
        | [ .[] | .data.repository.pullRequest.reviewThreads
                | if type != "object" or (.pageInfo.hasNextPage | type) != "boolean" or (.nodes | type) != "array"
                  then error("a page without its threads or its pageInfo") else . end ] as $p
        | ($p | length) as $n
        | if [ $p[] | .pageInfo.hasNextPage ] != [ range(0; $n) | . < $n - 1 ]
          then error("pages that do not end where pageInfo says") else . end
        | if $n > 1 and any($p[]; (.nodes | length) == 0) then error("an empty page among several") else . end
        | [ $p[:-1][] | .pageInfo.endCursor ] as $cur
        | if any($cur[]; type != "string" or . == "") or ($cur | unique | length) != ($cur | length)
          then error("a page cursor missing or repeated") else . end
        | [ $p[] | .nodes[] ]
        | map(if (.isResolved | type) == "boolean" and (.isOutdated | type) == "boolean"
                 and (.comments.nodes[0] | (.databaseId | type) == "number" and (.body | type) == "string"
                      and (.author | type) == "object" and named(.author))
                 and (.resolvedBy == null or ((.resolvedBy | type) == "object" and named(.resolvedBy)))
              then . else error("a thread whose resolution, first comment, author or resolver cannot be read") end)
        | map(.comments.nodes[0] as $c
              | select($c.author.login == $bot and $c.author.__typename == "Bot"
                       and .isOutdated == false and (($c.body // "") | test($b)))
              | (.resolvedBy.login // "") as $who
              | (.resolvedBy.__typename // "") as $kind
              | [ (if .isResolved and $who != "" and $kind == "User" and ($who | endswith("[bot]") | not)
                    then "ok" else "block" end),
                  ($c.databaseId | tostring), "\($c.path):\(.line // .originalLine // "?")",
                  (if (.isResolved | not) then "unresolved"
                   elif $who == "" then "resolved by no named user"
                   elif $kind == "Bot" or ($who | endswith("[bot]")) then "resolved by a bot, \($who)"
                   elif $kind != "User" then "resolved by \($who), not a User: \($kind)"
                   else "resolved by \($who)" end),
                  ($c.body | split("\n") | first) ] | @tsv)
        | join("\n")')" || die_read "PR #$pr's review threads (not what GraphQL returns for reviewThreads)"
    if [ -z "$live" ]; then
        verdict 0 "PASS: the connector completed its review of $head with no review object or receipt on it, and the connector's live findings at $head are none or P2/P3; has_any_findings carries over from earlier passes"
    fi
    printf '%s\n' "$live" | awk -F'\t' '{ printf "  thread %s %s, %s: %s\n", $2, $3, $4, $5 }'
    named="$(printf '%s\n' "$live" | awk -F'\t' '{ printf "%sthread %s at %s %s", (NR > 1 ? "; " : ""), $2, $3, $4 }')"
    blocking="$(printf '%s\n' "$live" | awk -F'\t' '$1 == "block" { printf "%sthread %s at %s (%s)", (n++ ? "; " : ""), $2, $3, $4 }')"
    if [ -z "$blocking" ]; then
        verdict 0 "PASS: the connector completed its review of $head with no review object or receipt on it, and every live P0/P1 thread of the connector there was resolved by a user: $named"
    fi
    verdict 1 "FAIL: the connector's state block reports findings on $head with no review of it and no receipt for it, and its live P0/P1 findings there are not resolved by a user: $blocking — fix them and push; or reply in the thread with evidence and have a person resolve it, then re-run this check; or comment @codex review once, then re-run this check"
}

# read_state — set head, and NOT_YET to why the connector has not finished on it ("" once it
# has). Exits on an override, a read failure or a missing labeled event.
read_state() {
    local pull comments events who state cr_status cr_sha based pushed pushed_at pushed_sha cmp reviewed
    pull="$(fetch pull "repos/$repo/pulls/$pr")" || die_read "PR #$pr"
    head="$(printf '%s' "$pull" | jq -er '.head.sha | select(type == "string" and test("^[0-9a-f]{40}$"))')" \
        || die_read "PR #$pr's head sha"

    # ── the override: a person's decision, attributed ──
    if printf '%s' "$pull" | jq -e --arg l "$OVERRIDE_LABEL" '[.labels[]?.name] | index($l) != null' >/dev/null; then
        events="$(fetch issue-events "repos/$repo/issues/$pr/events" list)" || die_read "PR #$pr's events"
        who="$(printf '%s' "$events" | jq -er --arg l "$OVERRIDE_LABEL" '
            [ .[] | select(.event == "labeled" and .label.name == $l) ] | last
            | select(. != null) | "\(.actor.type)\t\(.actor.login) at \(.created_at)"')" \
            || verdict 1 "FAIL: PR #$pr carries $OVERRIDE_LABEL but no labeled event for it was found, so who added it cannot be shown"
        # Human-only: an App or workflow token adding the label is not a person's decision.
        # (Agents act through their operator's own account, so a User actor is printed, not
        # authenticated: the check names who added it and cannot tell a person from an agent.)
        if [ "${who%%$'\t'*}" = "Bot" ]; then
            verdict 1 "FAIL: $OVERRIDE_LABEL was added by a bot (${who#*$'\t'}); only a person's label overrides"
        fi
        verdict 0 "PASS: $OVERRIDE_LABEL label added by ${who#*$'\t'} on $head — the connector review was not evaluated"
    fi

    # ── 0. txehq/dagu is public: a PR from another repository is not merged on the connector's
    #    review alone; only a person's override (checked above, by the API) passes it. A head
    #    repository that is missing or deleted is treated the same way (TXE-4719). ──
    head_repo="$(printf '%s' "$pull" | jq -r 'if (.head | has("repo")) and .head.repo != null then (.head.repo.full_name // "") else "" end')"
    if [ "$head_repo" != "$repo" ]; then
        verdict 1 "FAIL: PR #$pr's head is in ${head_repo:-a missing or deleted repository}, not $repo; a PR from another repository is not merged on the connector's review alone, so only a person's $OVERRIDE_LABEL passes it"
    fi

    # ── 1. the connector's state block, on the head ──
    comments="$(fetch issue-comments "repos/$repo/issues/$pr/comments" list)" || die_read "PR #$pr's comments"
    state="$(printf '%s' "$comments" | jq -c --arg bot "$CONNECTOR_LOGIN" --arg m "$STATE_MARKER" '
        [ .[] | select(.user.login == $bot and .user.type == "Bot" and (.body | type) == "string"
                       and (.body | contains($m))) ]
        | sort_by(.updated_at) | last
        | if . == null then null
          else (.body | capture("<!-- codex-review-state:v1 (?<j>.*?) -->") | .j | fromjson)
               + {_reviewed: ((.body | capture("[*][*]Code Review[*][*][^\n]*?datetime=\"(?<t>[^\"]+)\"") | .t) // null)}
          end')" \
        || die_read "the connector's state block (it did not parse as JSON)"
    if [ "$state" = "null" ]; then
        NOT_YET="no connector summary comment with a codex-review-state block yet"
        return
    fi
    # The Code Review row's completion time, to the second; "" when the row carries none.
    reviewed="$(printf '%s' "$state" | jq -r '._reviewed // "" | select(test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?Z$")) | .[0:19] + "Z"')"
    COMMENTS="$comments"; REVIEWED="$reviewed"
    state="$(printf '%s' "$state" | jq -c 'del(._reviewed)')"
    STATE="$state"
    cr_status="$(printf '%s' "$state" | jq -r '.code_review.status // "null"')"
    cr_sha="$(printf '%s' "$state" | jq -r '.code_review.commit_sha // "null"')"
    if [ "$cr_status" != completed ]; then
        NOT_YET="the connector's code review is '$cr_status' (at $cr_sha), not completed"
    elif [ "$cr_sha" != "$head" ]; then
        NOT_YET="the connector's completed review is of $cr_sha, not the current head $head"
    else
        # ── 4. the base the review saw is still the base ──
        events="$(fetch issue-events "repos/$repo/issues/$pr/events" list)" || die_read "PR #$pr's events"
        based="$(printf '%s' "$events" | jq -er '
            [ .[] | select(.event == "base_ref_changed" or .event == "base_ref_force_pushed") | .created_at ]
            | if any(.[]; type != "string") then error("an event without a created_at") else (max // "") end')" \
            || die_read "PR #$pr's base-change events"
        NOT_YET=""
        if [ -n "$based" ]; then
            # the latest force-push of the PR's head branch: "<created_at> <commit>", or ""
            pushed="$(printf '%s' "$events" | jq -er '
                [ .[] | select(.event == "head_ref_force_pushed") ] | max_by(.created_at)
                | if . == null then ""
                  elif (.created_at | type) != "string" or (.commit_id | type) != "string"
                       or (.commit_id | test("^[0-9a-f]{40}$") | not) then error("a force-push event without its time or commit")
                  else "\(.created_at) \(.commit_id)" end')" \
                || die_read "PR #$pr's force-push events"
            pushed_at="${pushed%% *}"; pushed_sha="${pushed#* }"
            if [ -z "$pushed" ] || [[ ! "$pushed_at" > "$based" ]]; then
                NOT_YET="the PR's base changed at $based and the head branch has not been force-pushed since (latest: ${pushed_at:-none}), so the review of $head may be of the old diff — rebase onto the new base and force-push"
            elif [ "$pushed_sha" != "$head" ]; then
                cmp="$(fetch compare "repos/$repo/compare/$pushed_sha...$head")" || die_read "the compare of $pushed_sha...$head"
                case "$(printf '%s' "$cmp" | jq -r '.status // "null"')" in
                    ahead) ;;   # the head descends from the commit the push after the change set
                    *) NOT_YET="the PR's base changed at $based, and the head $head does not descend from $pushed_sha, the commit its force-push at $pushed_at set — rebase onto the new base and force-push" ;;
                esac
            fi
            if [ -z "$NOT_YET" ] && { [ -z "$reviewed" ] || [[ ! "$reviewed" > "$pushed_at" ]]; }; then
                NOT_YET="the PR's base changed at $based and its head was force-pushed at $pushed_at, but the connector's code review is dated ${reviewed:-nowhere} (its Code Review row), not after that push — comment @codex review for a review of the pushed head"
            fi
        fi
    fi
}

head=""; NOT_YET=""; STATE="null"; COMMENTS="[]"; REVIEWED=""
start="$(date +%s)"
while :; do
    read_state
    [ -n "$NOT_YET" ] || break
    elapsed=$(( $(date +%s) - start ))
    if [ "$elapsed" -ge "$wait_s" ]; then
        if [ "$wait_s" -eq 0 ]; then verdict 1 "FAIL: $NOT_YET"; fi
        if [ $((wait_s % 60)) -eq 0 ]; then within="$((wait_s / 60)) min"; else within="${wait_s} s"; fi
        verdict 1 "FAIL: connector has not reviewed $head within $within; re-run this check or push ($NOT_YET)"
    fi
    say "waiting ${poll_s} s (${elapsed} s of ${wait_s} s): $NOT_YET"
    sleep "$poll_s"
done
say "PR #$pr head: $head"
say "connector state: $STATE"
say "security review (recorded, not gated): $(printf '%s' "$STATE" | jq -c '.security_review // null')"

# ── 2. no P0/P1 finding from a connector review of the head ──────────────────
reviews="$(fetch reviews "repos/$repo/pulls/$pr/reviews" list)" || die_read "PR #$pr's reviews"
ids="$(printf '%s' "$reviews" | jq -ec --arg bot "$CONNECTOR_LOGIN" --arg h "$head" '
    [ .[] | select(.user.login == $bot and .user.type == "Bot" and .commit_id == $h) | .id ]')" \
    || die_read "PR #$pr's reviews (not a list of reviews)"
if [ "$ids" = "[]" ]; then
    # The state block saying it found something while no review of the head carries it is a
    # disagreement between the connector's two records, not a clean head.
    case "$(printf '%s' "$STATE" | jq -c '.code_review.has_any_findings')" in
        false) ;;
        true)
            receipt=""
            if [ -n "$REVIEWED" ]; then
                receipt="$(printf '%s' "$COMMENTS" | jq -r --arg bot "$CONNECTOR_LOGIN" --arg m "$RECEIPT_MARKER" \
                    --arg h "$head" --arg r "$REVIEWED" --argjson w "$RECEIPT_WINDOW_S" '
                    ($r | fromdateiso8601) as $rt
                    | [ .[] | select(.user.login == $bot and .user.type == "Bot" and (.body | type) == "string"
                                     and (.body | contains($m)) and (.body | test("major issues")))
                          | . as $c
                          | ($c.body | capture("Reviewed commit:[*]* *`(?<s>[0-9a-f]{7,40})`") | .s) as $s
                          | select($h | startswith($s))
                          | (($c.created_at | fromdateiso8601) - $rt) as $d
                          | select((if $d < 0 then -$d else $d end) <= $w)
                          | "\($c.id) at \($c.created_at)" ] | last // ""')" || die_read "the connector's receipt comments"
            fi
            [ -z "$receipt" ] || verdict 0 "PASS: the connector completed its review of $head with no review object on it, and its receipt $receipt says no major issues there (has_any_findings stays true from earlier passes)"
            decide_on_live_threads ;;
        *) verdict 1 "FAIL: the connector's state block gives has_any_findings as $(printf '%s' "$STATE" | jq -c '.code_review.has_any_findings') on $head, not false, and no connector review of $head was found — re-run this check" ;;
    esac
    verdict 0 "PASS: the connector completed its review of $head with no review object on it, so no findings"
fi
inline="$(fetch review-comments "repos/$repo/pulls/$pr/comments" list)" || die_read "PR #$pr's review comments"
blocking="$(printf '%s' "$inline" | jq -er --arg bot "$CONNECTOR_LOGIN" --argjson ids "$ids" --arg b "$BLOCKING_BADGES" '
    [ .[] | select(.user.login == $bot and .user.type == "Bot"
                   and (.pull_request_review_id as $r | $ids | index($r) != null)
                   and ((.body // "") | test($b))) ]
    | map("  \(.path):\(.line // .original_line // "?") \((.body | split("\n") | first))") | join("\n")')" \
    || die_read "PR #$pr's review comments (not a list of comments)"
if [ -n "$blocking" ]; then
    say "$blocking"
    verdict 1 "FAIL: the connector's review of $head has P0/P1 findings — fix them and push, or a person decides on $OVERRIDE_LABEL"
fi
verdict 0 "PASS: the connector completed its review of $head and none of its findings there is P0 or P1"

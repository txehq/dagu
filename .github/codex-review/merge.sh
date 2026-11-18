#!/usr/bin/env bash
# merge.sh — merge a txehq/dagu PR only when, on the exact head being merged, MAIN's codex-review
# check passes now and every CI run on that head has finished green (TXE-4719).
#
#   git fetch -q origin main && git show origin/main:.github/codex-review/merge.sh | bash -s -- <pr> <head-sha>
#   git show origin/main:.github/codex-review/merge.sh \
#     | bash -s -- --method merge --expect-ancestor <sha> [--repair] <pr> <head-sha>
#   git show origin/main:.github/codex-review/merge.sh \
#     | bash -s -- --base maint/txe-v<x.y.z>-<n> --base-sha <base tip> <pr> <head-sha>
#
# Why it exists. The codex-review workflow already runs main's copy (pull_request_target), but its
# verdict is a result of the past: it polled up to 15 minutes, and a review, a label or a push can
# come after it. This fork's main has no branch protection, so nothing else stops a merge with CI
# failing or still running. This wrapper, read from origin/main and never from the PR:
#   1. refuses a PR that is not open, is a draft, is not on main (or the --base given), or whose
#      head is not <head-sha>;
#   2. requires main's codex-review WORKFLOW RUN (.github/workflows/codex-review.yml) on that head (pull_request_target, created on every
#      push, so its presence also shows the push's other runs were created) to be completed/success;
#   3. requires every other workflow run (latest run per workflow file and event; run numbers count
#      per workflow), every check run (latest per app, check suite and name) and the combined commit
#      status on that head to be finished and green: success, skipped or neutral; pending, missing reads, failure,
#      cancelled, timed out or action required refuse. Path-filtered workflows that did not match
#      the PR have no run, and that is not a failure;
#   4. re-runs main's codex-review-check.sh at that head, with no wait and never in fixture mode,
#      bracketed by two reads of the PR (state, head, base name and sha, sorted labels): one just
#      before the check, one as the last read before the merge (TXE-7847);
#   5. as the last calls before the merge, re-reads main's codex-review runs on the head and the PR,
#      and refuses when a gate run newer than the one judged in 2 exists (a label, an edit or a
#      re-run starts one; matched by id, run number and attempt), when that run is no longer
#      completed/success, or when the PR differs from the read before the check (a label added or
#      removed, review-override included, a retarget, a new base sha); a re-read that fails refuses;
#   6. merges with --match-head-commit, so GitHub refuses the merge if the head moved after 1-5.
#
# The merge method (TXE-6221). The default is a squash, as it always was. A squash keeps the tree
# and drops the history, which is right for a PR made of its author's own commits and wrong for a
# PR whose point is the history it carries: an upstream sync (PR #230 brought upstream v2.25.8 in
# and its squash left v2.25.8 unreachable from main) or a provenance repair. So:
#   - the default squash refuses a PR that carries history main does not have: a commit of the PR
#     that is not on the PR's own first-parent line back to main came in through a merge's other
#     parent. An ordinary PR, including one that merged main into its branch, has none; a sync has;
#   - `--method merge --expect-ancestor <sha>` merges with a merge commit, after every check above,
#     and in addition requires the repository to allow merge commits (read, never assumed), the
#     expected ancestor to be a commit's own id (an annotated tag's object id is refused, never
#     peeled to something else), reachable from the head and not yet from main, and, after the
#     merge, reads the merge commit back and proves the ancestor is now reachable from it;
#   - `--repair` declares a provenance repair that changes no file: the head's tree must equal
#     main's, and its parents must be exactly main's current tip and the expected ancestor, so a
#     main that moved, a wrong parent or any file change refuses. A head with main's tree is
#     accepted only this way; `--repair` with a changed tree is refused.
# None of this bypasses anything: both methods run the same checks 1-5 and merge with
# --match-head-commit. There is no flag that skips a check.
#
# Residual window, stated rather than hidden. GitHub's merge call binds the head
# (--match-head-commit) and nothing else: no label, no base, no check run. So a change made after
# the last reads of 5 is not seen. For the labels and the base that is from the moment GitHub
# answers the PR read to the moment it performs the merge: the rest of that call, then
# `gh pr merge`'s own PR lookup and its merge mutation. For the gate's runs it starts one read
# earlier. Measured from a Mac on 2026-11-19, each of those calls (the gate-runs read, the PR read,
# a `gh pr view` lookup) took 0.7-1.5 s, so the window is roughly 2-3 s for the labels and base and
# 3-4 s for the gate's runs. Nothing here bounds it: a slow call widens it. A label change is also
# only as visible as GitHub's API makes it at the moment of the read. A connector review or a
# check run that changes on the SAME head after the check (4) is not re-read: only the gate's own
# run is; run this once the connector's state is final.
# The PR's base sha is the one GitHub records on the PR (it moves on a retarget or a PR event, not
# on every push to the base), so it is not a live read of main; on a maintenance base the base's
# live tip is re-read separately, just before 5.
# --match-head-commit pins the PR's head, not main: there is no atomic check of main's tip against
# the merge. For a repair, main's tip is re-read as the last call before the merge and a moved main
# refuses, but a move in the seconds after that read is merged by GitHub onto the new tip. So the
# readback judges what was merged, from the merge commit itself: its second parent must be the
# head, it must reach the expected ancestor, and for a repair its tree must equal its ACTUAL first
# parent's tree (main as it was at the merge), not the tip read earlier, so a main that moved late
# and took the repair with no file change is accepted and reported, while a merge commit that
# differs from its first parent is reported as MERGED with an error (exit 1) and left as it is:
# nothing is retried or rewritten, and the person reads main.
#
# Maintenance bases (TXE-7556). `--base maint/txe-v<upstream>-<n> --base-sha <40-hex>` merges a PR
# into a declared maintenance branch instead of main, under the same checks 1-6, each made against
# THAT base's tip, and these in addition:
#   - the base is named exactly (maint/txe-v<x.y.z>-<n>), and the PR's base is that name;
#   - the base's tip is <base-sha> when it is read first and again as the last read before the
#     merge, so the merge is bound to the base the caller reviewed as well as to the head;
#   - the base's .github/workflows/codex-review.yml is main's byte for byte: pull_request_target
#     runs the BASE's copy of the gate workflow, so a maintenance base cannot carry a gate of its own;
#   - the codex-review run on the head names this PR on this base (its pull_requests entry);
#   - the merge is a squash: --method merge and --repair are refused on a maintenance base;
#   - the squash is read back: its only parent must be <base-sha>; a base that moved in the seconds
#     after the last read is reported as MERGED with an error (exit 1) and left as it is.
# The check script and this wrapper are still main's, read at main's tip as one commit.
#
# Exit 0 merged (and, for --method merge, the readback confirmed); 1 refused, or merged but the
# readback did not confirm (the message says which); 2 usage or a read failure (nothing merged).
set -euo pipefail

repo="${GH_REPO:-txehq/dagu}"
usage() {
  echo "usage: merge.sh [--base main | --base maint/txe-v<x.y.z>-<n> --base-sha <40-hex sha>] [--method squash|merge] [--expect-ancestor <40-hex sha>] [--repair] <pr-number> <40-hex head sha>" >&2
  exit 2
}
method=squash; anc=""; repair=false; want_base=main; base_sha=""
while [ $# -gt 0 ]; do
  case "$1" in
    --base) [ $# -ge 2 ] || usage; want_base="$2"; shift 2 ;;
    --base-sha) [ $# -ge 2 ] || usage; base_sha="$2"; shift 2 ;;
    --method) [ $# -ge 2 ] || usage; method="$2"; shift 2 ;;
    --expect-ancestor) [ $# -ge 2 ] || usage; anc="$2"; shift 2 ;;
    --repair) repair=true; shift ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
pr="${1:-}"; want="${2:-}"
[ $# -eq 2 ] || usage
[[ "$pr" =~ ^[0-9]+$ && "$want" =~ ^[0-9a-f]{40}$ ]] || usage
case "$method" in
  squash) if [ -n "$anc" ] || [ "$repair" = true ]; then echo "merge.sh: --expect-ancestor and --repair go with --method merge" >&2; exit 2; fi ;;
  merge) [[ "$anc" =~ ^[0-9a-f]{40}$ ]] || { echo "merge.sh: --method merge needs --expect-ancestor <40-hex sha>" >&2; exit 2; } ;;
  *) echo "merge.sh: --method is squash or merge, not '$method'" >&2; exit 2 ;;
esac
maint=false
if [ "$want_base" = main ]; then
  [ -z "$base_sha" ] || { echo "merge.sh: --base-sha goes with a maintenance --base" >&2; exit 2; }
elif [[ "$want_base" =~ ^maint/txe-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]]; then
  maint=true
  [[ "$base_sha" =~ ^[0-9a-f]{40}$ ]] || { echo "merge.sh: --base $want_base needs --base-sha <40-hex sha of its reviewed tip>" >&2; exit 2; }
  [ "$method" = squash ] || { echo "merge.sh: a maintenance base is merged by squash only; --method merge and --repair are refused" >&2; exit 2; }
else
  echo "merge.sh: --base is main or maint/txe-v<x.y.z>-<n>, not '$want_base'" >&2; exit 2
fi
# The base in messages: "main" as before, or the maintenance branch's name.
bn="$want_base"
refuse() { echo "merge.sh: $*; not merging" >&2; exit 1; }
unread() { echo "merge.sh: could not read $*; not merging" >&2; exit 2; }
read_tip() { # <branch> <out file> <what>: the branch's tip, a 40-hex sha
  gh api "repos/$repo/branches/$1" --jq .commit.sha >"$2" || unread "$3"
  local t; read -r t <"$2" || unread "$3 (empty)"
  [[ "$t" =~ ^[0-9a-f]{40}$ ]] || unread "$3 (not a sha)"
  printf '%s\n' "$t" >"$2"
}

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# main's tip, read once: main's copy of the check is read AT this commit, so the check, and on a
# maintenance base the gate workflow it is compared with, come from one immutable main commit.
read_tip main "$tmp/main.sha" "main's tip"
read -r maintip <"$tmp/main.sha"
# main's copy of the check, from the remote, never the working tree or the PR.
gh api "repos/$repo/contents/.github/codex-review/codex-review-check.sh?ref=$maintip" --jq .content >"$tmp/check.b64" \
  || unread "main's codex-review-check.sh"
base64 -d <"$tmp/check.b64" >"$tmp/check.sh" || unread "main's codex-review-check.sh (not base64)"
[ -s "$tmp/check.sh" ] || unread "main's codex-review-check.sh (empty: main has none)"

gh api "repos/$repo/pulls/$pr" --jq '[.state, .draft, .head.sha, .base.ref] | @tsv' >"$tmp/pull.tsv" || unread "PR #$pr"
read -r state draft head base <"$tmp/pull.tsv" || unread "PR #$pr (no fields)"
[ "$state" = open ] || refuse "PR #$pr is $state"
[ "$draft" = false ] || refuse "PR #$pr is a draft"
[ "$head" = "$want" ] || refuse "PR #$pr's head is $head, not $want"
[ "$base" = "$want_base" ] || refuse "PR #$pr's base is $base, not $want_base"

if [ "$maint" = true ]; then
  read_tip "$want_base" "$tmp/base.sha" "$bn's tip"
  read -r basetip <"$tmp/base.sha"
  [ "$basetip" = "$base_sha" ] || refuse "$bn's tip is $basetip, not $base_sha"
  # pull_request_target runs the base's copy of the gate workflow: it must be main's.
  wf=.github/workflows/codex-review.yml
  gh api "repos/$repo/contents/$wf?ref=$maintip" --jq .content >"$tmp/wf-main.b64" || unread "main's $wf"
  gh api "repos/$repo/contents/$wf?ref=$basetip" --jq .content >"$tmp/wf-base.b64" || unread "$bn's $wf"
  base64 -d <"$tmp/wf-main.b64" >"$tmp/wf-main" || unread "main's $wf (not base64)"
  base64 -d <"$tmp/wf-base.b64" >"$tmp/wf-base" || unread "$bn's $wf (not base64)"
  [ -s "$tmp/wf-main" ] || unread "main's $wf (empty)"
  cmp -s "$tmp/wf-main" "$tmp/wf-base" \
    || refuse "$bn's $wf at $basetip is not main's at $maintip: the gate that ran on this base is not main's; bring the base's copy to main's first (a root-accepted step, README.md \"Maintenance bases\")"
else
  basetip="$maintip"
fi

# ── The history the PR brings: the base's tip, the head's tree and parents, the commits it lacks ──
# compare's status is read from the API's point of view: "<a>...<b>" is "ahead" when b is ahead
# of a, that is when a is an ancestor of b; "behind" when b is an ancestor of a; "identical" when
# they are one commit; "diverged" otherwise.
compare_status() {
  gh api "repos/$repo/compare/$1...$2?per_page=1" --jq '[.status, .total_commits] | @tsv'
}
commit_tsv='[.tree.sha, (.parents | map(.sha) | join(","))] | @tsv'
gh api "repos/$repo/git/commits/$want" --jq "$commit_tsv" >"$tmp/head.tsv" || unread "the head commit $want"
read -r headtree headparents <"$tmp/head.tsv" || unread "the head commit $want (no fields)"
gh api "repos/$repo/git/commits/$basetip" --jq "$commit_tsv" >"$tmp/main.tsv" || unread "$bn's tip commit $basetip"
read -r basetree _ <"$tmp/main.tsv" || unread "$bn's tip commit $basetip (no fields)"
compare_status "$basetip" "$want" >"$tmp/compare.tsv" || unread "the comparison of $bn with $want"
read -r cmpstatus total <"$tmp/compare.tsv" || unread "the comparison of $bn with $want (no fields)"
case "$cmpstatus" in
  ahead|diverged) ;;
  *) refuse "PR #$pr's head $want brings $bn no commit (compare says $cmpstatus)" ;;
esac
# Every commit reachable from the head and not from the base, with its parents. A parent that is
# not in this set is reachable from the base.
gh api --paginate "repos/$repo/compare/$basetip...$want?per_page=100" \
  --jq '.commits[] | "\(.sha) \(.parents | map(.sha) | join(" "))"' >"$tmp/commits.txt" \
  || unread "the commits of PR #$pr"
[ "$(wc -l <"$tmp/commits.txt" | tr -d ' ')" = "$total" ] \
  || unread "the commits of PR #$pr (got $(wc -l <"$tmp/commits.txt" | tr -d ' ') of $total)"
# The PR's own line is its first-parent history back to the base. A commit of the set that is not on
# that line came in through a merge's other parent: history the base lacks, which a squash would drop.
# A branch that merged the base into itself has the base on the other side: all on its own line.
# The API lists the commits oldest first, so the walk starts from the head given, not a line.
foreign="$(awk -v head="$want" 'NR == FNR { parent[$1] = $2; next }
  FNR == 1 { for (c = head; c in parent; c = parent[c]) own[c] = 1 }
  !($1 in own) { n++; if (n == 1) first = $1 }
  END { if (n) print n, first }' "$tmp/commits.txt" "$tmp/commits.txt")"

case "$method" in
  squash)
    [ -z "$foreign" ] || refuse "PR #$pr carries history $bn does not have: ${foreign%% *} commit(s) off its own first-parent line, such as ${foreign#* }; a squash would drop them. Merge it with --method merge --expect-ancestor <the sha the PR must keep reachable>, or rebase it onto $bn if that history is not meant to be kept"
    [ "$headtree" != "$basetree" ] || refuse "PR #$pr's head has $bn's tree: a squash would record nothing; a provenance repair is merged with --method merge --expect-ancestor <sha> --repair"
    ;;
  merge)
    gh api "repos/$repo" --jq .allow_merge_commit >"$tmp/allow.txt" || unread "the repository's merge settings"
    [ "$(cat "$tmp/allow.txt")" = true ] || refuse "the repository does not allow merge commits (allow_merge_commit is $(cat "$tmp/allow.txt"))"
    # The ancestor is a commit's own id: git/commits answers for nothing else, so an annotated tag's
    # object id (whose commit is another sha) or a tree is a read failure, never a different ancestor.
    gh api "repos/$repo/git/commits/$anc" --jq .sha >"$tmp/anc.sha" \
      || unread "the expected ancestor $anc as a commit (if it is an annotated tag's object, pass the commit it points to)"
    [ "$(cat "$tmp/anc.sha")" = "$anc" ] || unread "the expected ancestor $anc as a commit (the API answered for $(cat "$tmp/anc.sha"))"
    compare_status "$anc" "$want" >"$tmp/anc-head.tsv" || unread "the comparison of $anc with $want"
    read -r ancstatus _ <"$tmp/anc-head.tsv" || unread "the comparison of $anc with $want (no fields)"
    case "$ancstatus" in
      ahead|identical) ;;
      *) refuse "PR #$pr's head $want does not reach the expected ancestor $anc (compare says $ancstatus)" ;;
    esac
    compare_status "$maintip" "$anc" >"$tmp/main-anc.tsv" || unread "the comparison of main with $anc"
    read -r mainanc _ <"$tmp/main-anc.tsv" || unread "the comparison of main with $anc (no fields)"
    case "$mainanc" in
      behind|identical) refuse "the expected ancestor $anc is already reachable from main; there is no history to record" ;;
    esac
    if [ "$repair" = true ]; then
      [ "$headparents" = "$maintip,$anc" ] || refuse "a repair's parents must be main's tip and the expected ancestor ($maintip,$anc); PR #$pr's head has $headparents (if main moved, rebuild the repair on its tip)"
      [ "$headtree" = "$basetree" ] || refuse "PR #$pr is declared a repair but its tree $headtree is not main's $basetree: it changes files"
    else
      [ "$headtree" != "$basetree" ] || refuse "PR #$pr's head has main's tree, which only a provenance repair has; declare it with --repair"
    fi
    ;;
esac

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
gate_runs='[.[] | select(((.path // "") | sub("@.*$"; "")) == ".github/workflows/codex-review.yml" and .event == "pull_request_target")]
  | max_by(.run_number) // empty'
gate="$(jq -s -r "$gate_runs"' | "\(.status) \(.conclusion)"' "$tmp/runs.jsonl")"
[ "$gate" = "completed success" ] || refuse "main's codex-review run on $want is '${gate:-missing}', not completed success"
if [ "$maint" = true ]; then
  # On a maintenance base the run must have judged THIS PR on THIS base: GitHub lists the PR, with
  # its base, on a pull_request_target run of a PR from this repository. Missing is a refusal.
  jq -s -e --argjson pr "$pr" --arg base "$want_base" "$gate_runs"' | any(.pull_requests[]?; .number == $pr and .base.ref == $base)' \
    "$tmp/runs.jsonl" >/dev/null \
    || refuse "main's codex-review run on $want does not name PR #$pr on $want_base"
fi
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

# The gate run judged above: the newest codex-review run on the head, by its identity.
gate_id='"\(.id) \(.run_number) \(.run_attempt)"'
judged="$(jq -s -r "$gate_runs | $gate_id" "$tmp/runs.jsonl")"

# ── The state main's check reads, bracketed (TXE-7847) ──
# The PR as one line: state, draft, head, base name and sha, and the sorted label names. Read just
# before the check and again as the last read before the merge; any difference refuses, so a label
# added or removed (review-override included), a retarget or a base that moved while the check ran
# or after it is not merged on the earlier read.
pull_state='{state, draft, head: .head.sha, base: .base.ref, base_sha: .base.sha, labels: ([.labels[]?.name] | sort)} | tojson'
read_pull_state() { # <out file> <what>
  gh api "repos/$repo/pulls/$pr" --jq "$pull_state" >"$1" || unread "$2"
  jq -e 'type == "object"' "$1" >/dev/null 2>&1 || unread "$2 (not an object)"
}
read_pull_state "$tmp/pull-before.json" "PR #$pr's labels and base before main's check"
jq -e --arg h "$want" --arg b "$want_base" '.state == "open" and .draft == false and .head == $h and .base == $b' \
  "$tmp/pull-before.json" >/dev/null || refuse "PR #$pr changed before main's check: $(cat "$tmp/pull-before.json")"

# Never fixture mode: an inherited CODEX_REVIEW_FIXTURE_DIR would judge local files and merge the live PR.
env -u CODEX_REVIEW_FIXTURE_DIR GH_REPO="$repo" PR_NUMBER="$pr" CODEX_REVIEW_WAIT_SECONDS=0 bash "$tmp/check.sh" \
  || refuse "main's codex-review check does not pass on $want"

# The last reads before every merge call below (TXE-7847): the gate's runs on the head, then the PR.
# A gate run newer than the judged one (a label, an edit or a re-run starts one), a newest run that
# is not completed/success, or any change to the PR's line above refuses. A read that fails refuses
# (exit 2). This narrows the window to these reads and the merge call; it does not close it.
final_reread() {
  gh api --paginate "repos/$repo/actions/workflows/codex-review.yml/runs?head_sha=$want&event=pull_request_target&per_page=100" \
    --jq '.workflow_runs[]' >"$tmp/runs-last.jsonl" || unread "the codex-review runs on $want before the merge"
  jq -s -e 'all(.[]; type == "object")' "$tmp/runs-last.jsonl" >/dev/null 2>&1 \
    || unread "the codex-review runs on $want before the merge (not objects)"
  local last lastgate
  last="$(jq -s -r "$gate_runs | $gate_id" "$tmp/runs-last.jsonl")"
  lastgate="$(jq -s -r "$gate_runs"' | "\(.status) \(.conclusion)"' "$tmp/runs-last.jsonl")"
  [ "$last" = "$judged" ] || refuse "the newest codex-review run on $want is now '${last:-missing}' (id, number, attempt), not the judged '$judged' ($lastgate): a newer run started after the check; re-run this once it has finished"
  [ "$lastgate" = "completed success" ] || refuse "the judged codex-review run on $want is now '${lastgate:-missing}', not completed success"
  read_pull_state "$tmp/pull-last.json" "PR #$pr's labels and base before the merge"
  cmp -s "$tmp/pull-before.json" "$tmp/pull-last.json" \
    || refuse "PR #$pr changed after main's check (labels or base): was $(cat "$tmp/pull-before.json"), now $(cat "$tmp/pull-last.json")"
}

if [ "$method" = squash ] && [ "$maint" = false ]; then
  final_reread
  gh pr merge "$pr" -R "$repo" --squash --match-head-commit "$want"
  exit 0
fi
merged_but() { echo "merge.sh: PR #$pr was merged, but $*; check $bn by hand" >&2; exit 1; }
if [ "$maint" = true ]; then
  # The last read before the merge: the base must still be the tip the caller named. A move after
  # this read is judged by the readback (not an atomic check, stated above).
  read_tip "$want_base" "$tmp/base2.sha" "$bn's tip before the merge"
  read -r basetip2 <"$tmp/base2.sha"
  [ "$basetip2" = "$base_sha" ] || refuse "$bn moved from $base_sha to $basetip2 while the PR was checked; review the PR against the new tip and pass it as --base-sha"
  final_reread
  gh pr merge "$pr" -R "$repo" --squash --match-head-commit "$want"
  # Readback: the squash is one commit whose only parent is the base tip the checks were made on.
  gh api "repos/$repo/pulls/$pr" --jq '[.merged, .merge_commit_sha] | @tsv' >"$tmp/merged.tsv" || merged_but "its merge commit could not be read"
  read -r merged mergesha <"$tmp/merged.tsv" || merged_but "its merge commit could not be read (no fields)"
  if [ "$merged" != true ] || ! [[ "$mergesha" =~ ^[0-9a-f]{40}$ ]]; then merged_but "the API does not show it merged ($merged, '$mergesha')"; fi
  gh api "repos/$repo/git/commits/$mergesha" --jq "$commit_tsv" >"$tmp/merge.tsv" || merged_but "its merge commit $mergesha could not be read"
  read -r _ mergeparents <"$tmp/merge.tsv" || merged_but "its merge commit $mergesha could not be read (no fields)"
  [ "$mergeparents" = "$base_sha" ] \
    || merged_but "its squash commit $mergesha has parents '$mergeparents', not the checked tip $base_sha of $bn: the base moved after the last read"
  echo "merge.sh: merged PR #$pr into $bn as $mergesha (parent $base_sha)"
  exit 0
fi
if [ "$repair" = true ]; then
  # The last read before the merge: a main that moved is refused here; a move after this read is
  # judged by the readback below. Neither is an atomic check (stated above).
  gh api "repos/$repo/branches/main" --jq .commit.sha >"$tmp/main2.sha" || unread "main's tip before the merge"
  read -r maintip2 <"$tmp/main2.sha" || unread "main's tip before the merge (empty)"
  [ "$maintip2" = "$maintip" ] || refuse "main moved from $maintip to $maintip2 while the repair was checked; rebuild the repair on its tip"
fi
final_reread
gh pr merge "$pr" -R "$repo" --merge --match-head-commit "$want"

# ── Readback: the merge commit exists, reaches the expected ancestor and, for a repair, kept the tree ──
gh api "repos/$repo/pulls/$pr" --jq '[.merged, .merge_commit_sha] | @tsv' >"$tmp/merged.tsv" || merged_but "its merge commit could not be read"
read -r merged mergesha <"$tmp/merged.tsv" || merged_but "its merge commit could not be read (no fields)"
if [ "$merged" != true ] || ! [[ "$mergesha" =~ ^[0-9a-f]{40}$ ]]; then merged_but "the API does not show it merged ($merged, '$mergesha')"; fi
compare_status "$anc" "$mergesha" >"$tmp/anc-merge.tsv" || merged_but "whether $mergesha reaches $anc could not be read"
read -r reach _ <"$tmp/anc-merge.tsv" || merged_but "whether $mergesha reaches $anc could not be read (no fields)"
case "$reach" in
  ahead|identical) ;;
  *) merged_but "its merge commit $mergesha does not reach $anc (compare says $reach)" ;;
esac
gh api "repos/$repo/git/commits/$mergesha" --jq "$commit_tsv" >"$tmp/merge.tsv" || merged_but "its merge commit $mergesha could not be read"
read -r mergetree mergeparents <"$tmp/merge.tsv" || merged_but "its merge commit $mergesha could not be read (no fields)"
# GitHub's merge commit has main as it was at the merge first and the PR head second.
p1="${mergeparents%%,*}"; p2="${mergeparents#*,}"
if [ "$p2" != "$want" ] || ! [[ "$p1" =~ ^[0-9a-f]{40}$ ]] || [ "$p1" = "$p2" ]; then
  merged_but "its merge commit $mergesha has parents '$mergeparents', not main and the head $want"
fi
moved=""
[ "$p1" = "$maintip" ] || moved=" (main had moved from $maintip to $p1 by the merge)"
if [ "$repair" = true ]; then
  gh api "repos/$repo/git/commits/$p1" --jq "$commit_tsv" >"$tmp/p1.tsv" || merged_but "its merge commit's first parent $p1 could not be read"
  read -r p1tree _ <"$tmp/p1.tsv" || merged_but "its merge commit's first parent $p1 could not be read (no fields)"
  [ "$mergetree" = "$p1tree" ] || merged_but "the repair's merge commit $mergesha has tree $mergetree, not its first parent's $p1tree: the repair changed files$moved"
fi
echo "merge.sh: merged PR #$pr as $mergesha (parents $mergeparents, tree $mergetree)$moved; $anc is reachable from it"

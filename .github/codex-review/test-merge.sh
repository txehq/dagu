#!/usr/bin/env bash
# test-merge.sh — merge.sh with a stand-in gh (TXE-4719). It merges only an open, ready PR on main
# whose head is the given SHA, whose CI on that head finished green with main's codex-review run
# among it, and on which MAIN's check passes now; and then only with --match-head-commit.
# shellcheck disable=SC2016  # check bodies are main's script, expanded when it runs
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/merge-test.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT
H=1111111111111111111111111111111111111111
M=3333333333333333333333333333333333333333  # main's tip
TREE=4444444444444444444444444444444444444444  # the head's tree
MAIN_TREE=5555555555555555555555555555555555555555
mkdir -p "$TMP/bin"
# The stand-in gh answers each read with the already-shaped value merge.sh's --jq would produce;
# FAIL_ON names a read that fails (with partial output), as a broken API page would.
cat >"$TMP/bin/gh" <<'GH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_LOG"
fail() { case "$*" in *"$FAIL_ON"*) [ -n "$FAIL_ON" ] && { printf '{"partial":'; exit 1; } ;; esac; }
case "$*" in
  *contents/.github/codex-review/codex-review-check.sh*) fail "$@"; printf '%s' "$MAIN_CHECK" | base64 ;;
  "api repos/txehq/dagu/pulls/7 "*) fail "$@"; printf '%s\n' "$PR_TSV" ;;
  *branches/main*) fail "$@"; printf '%s\n' "$MAIN_TIP" ;;
  *git/commits/"$MAIN_TIP"*) fail "$@"; printf '%s\n' "$MAIN_COMMIT_TSV" ;;
  *git/commits/*) fail "$@"; printf '%s\n' "$COMMIT_TSV" ;;
  *compare/*per_page=1\ *) fail "$@"; printf '%s\n' "$COMPARE" ;;
  *compare/*per_page=100*) fail "$@"; printf '%s\n' "$COMMITS" ;;
  *actions/runs*) fail "$@"; printf '%s' "$RUNS" ;;
  *check-runs*) fail "$@"; printf '%s' "$CHECKS" ;;
  */status*) fail "$@"; printf '%s\n' "$STATUS" ;;
  "pr merge"*) echo merged ;;
  *) echo "unexpected gh $*" >&2; exit 9 ;;
esac
GH
chmod +x "$TMP/bin/gh"
PASS=0; FAIL=0
GATE='{"name":"codex-review","path":".github/workflows/codex-review.yml","workflow_id":101,"event":"pull_request_target","run_number":5,"status":"completed","conclusion":"success"}'
CI='{"name":"CI","path":".github/workflows/ci.yaml","workflow_id":102,"event":"pull_request","run_number":9,"status":"completed","conclusion":"success"}'
CHK='{"name":"Go Linter (linux)","app":{"id":15368},"check_suite":{"id":7},"status":"completed","conclusion":"success","started_at":"2026-10-20T10:00:00Z"}'
OK_CHECK='echo "PASS: main check"; exit 0'
# run <name> <want exit> <want substring> <merged|not-merged> [VAR=value]... (defaults: all green)
run() {
    local name="$1" want_rc="$2" want="$3" merged="$4" out rc log="$TMP/$1.log"
    shift 4
    : >"$log"
    out="$(env PATH="$TMP/bin:$PATH" GH_LOG="$log" FAIL_ON="" PR_TSV="open	false	$H	main" \
        MAIN_TIP="$M" COMMIT_TSV="$TREE	$M" MAIN_COMMIT_TSV="$MAIN_TREE	0000000000000000000000000000000000000000" \
        COMPARE="ahead	1" COMMITS="$H $M" \
        RUNS="$GATE
$CI" CHECKS="$CHK" STATUS="success	1" MAIN_CHECK="$OK_CHECK" "$@" bash "$HERE/merge.sh" 7 "$H" 2>&1)"; rc=$?
    if [ "$rc" = "$want_rc" ] && [[ "$out" == *"$want"* ]] \
       && { { [ "$merged" = merged ] && grep -q -- "pr merge 7 -R txehq/dagu --squash --match-head-commit $H" "$log"; } \
            || { [ "$merged" = not-merged ] && ! grep -q '^pr merge' "$log"; }; }; then
        PASS=$((PASS + 1)); printf '  ok   %s\n' "$name"
    else
        FAIL=$((FAIL + 1)); printf '  FAIL %s: exit %s, output:\n%s\n  gh calls:\n%s\n' "$name" "$rc" "$out" "$(cat "$log")"
    fi
}
run passes        0 merged                                merged
run moved         1 "head is 2222"                        not-merged PR_TSV="open	false	2222222222222222222222222222222222222222	main"
run draft         1 "is a draft"                          not-merged PR_TSV="open	true	$H	main"
run closed        1 "is closed"                           not-merged PR_TSV="closed	false	$H	main"
run other-base    1 "base is release"                     not-merged PR_TSV="open	false	$H	release"
run check-fail    1 "check does not pass"                 not-merged MAIN_CHECK='echo "FAIL: P1"; exit 1'
run no-check      2 "main has none"                       not-merged MAIN_CHECK=''
run fixture-env   1 "check does not pass"                 not-merged CODEX_REVIEW_FIXTURE_DIR="$TMP/fixtures" \
    MAIN_CHECK='[ -n "${CODEX_REVIEW_FIXTURE_DIR:-}" ] && exit 0; exit 1'
# CI on the head
run gate-missing  1 "codex-review run on $H is 'missing'" not-merged RUNS="$CI"
run gate-running  1 "is 'in_progress null'"               not-merged \
    RUNS='{"name":"codex-review","path":".github/workflows/codex-review.yml","workflow_id":101,"event":"pull_request_target","run_number":5,"status":"in_progress","conclusion":null}'
run gate-from-pr  1 "is 'missing'"                        not-merged \
    RUNS='{"name":"codex-review","path":".github/workflows/codex-review.yml","workflow_id":101,"event":"pull_request","run_number":5,"status":"completed","conclusion":"success"}'
# The documented ref-qualified path form is the same gate.
run gate-ref-path 0 merged                                merged RUNS="$CI
"'{"name":"codex-review","path":".github/workflows/codex-review.yml@main","workflow_id":101,"event":"pull_request_target","run_number":5,"status":"completed","conclusion":"success"}'
run gate-ref-full 0 merged                                merged RUNS="$CI
"'{"name":"codex-review","path":".github/workflows/codex-review.yml@refs/heads/main","workflow_id":101,"event":"pull_request_target","run_number":5,"status":"completed","conclusion":"success"}'
# Another workflow file that calls itself codex-review is not the gate.
run gate-by-name  1 "is 'missing'"                        not-merged \
    RUNS='{"name":"codex-review","path":".github/workflows/other.yml","workflow_id":109,"event":"pull_request_target","run_number":50,"status":"completed","conclusion":"success"}'
run ci-failing    1 "workflow CI (.github/workflows/ci.yaml): completed/failure" not-merged RUNS="$GATE
"'{"name":"CI","path":".github/workflows/ci.yaml","workflow_id":102,"event":"pull_request","run_number":9,"status":"completed","conclusion":"failure"}'
run ci-pending    1 "workflow CI (.github/workflows/ci.yaml): queued/none" not-merged RUNS="$GATE
"'{"name":"CI","path":".github/workflows/ci.yaml","workflow_id":102,"event":"pull_request","run_number":9,"status":"queued","conclusion":null}'
run ci-rerun-ok   0 merged                                merged RUNS="$GATE
"'{"name":"CI","path":".github/workflows/ci.yaml","workflow_id":102,"event":"pull_request","run_number":8,"status":"completed","conclusion":"failure"}
{"name":"CI","path":".github/workflows/ci.yaml","workflow_id":102,"event":"pull_request","run_number":9,"status":"completed","conclusion":"success"}'
# Two workflow files with one display name: a later green run of one never hides the other's failure.
run same-name     1 "workflow CI (.github/workflows/ci-extra.yaml): completed/failure" not-merged RUNS="$GATE
$CI
"'{"name":"CI","path":".github/workflows/ci-extra.yaml","workflow_id":103,"event":"pull_request","run_number":3,"status":"completed","conclusion":"failure"}'
run check-failing 1 "check Go Linter (linux): completed/failure" not-merged \
    CHECKS='{"name":"Go Linter (linux)","app":{"id":15368},"check_suite":{"id":7},"status":"completed","conclusion":"failure","started_at":"2026-10-20T10:00:00Z"}'
# One check name in two suites: the later green one never hides the other's failure.
run check-same-name 1 "check Go Linter (linux): completed/failure" not-merged CHECKS="$CHK
"'{"name":"Go Linter (linux)","app":{"id":15368},"check_suite":{"id":8},"status":"completed","conclusion":"failure","started_at":"2026-10-20T09:00:00Z"}'
run status-failed 1 "combined commit status of $H is failure" not-merged STATUS="failure	2"
run status-none   0 merged                                merged STATUS="pending	0"
# A read that fails, even with partial output, never merges
run runs-unread   2 "could not read the workflow runs"    not-merged FAIL_ON=actions/runs
run checks-unread 2 "could not read the check runs"       not-merged FAIL_ON=check-runs
run status-unread 2 "could not read the commit status"    not-merged FAIL_ON=/status
run pull-unread   2 "could not read PR #7"                not-merged FAIL_ON=pulls/7
# The history the PR brings (TXE-6221); the real git cases are in test-merge-git.sh.
A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
run tip-unread    2 "could not read main's tip"           not-merged FAIL_ON=branches/main
run head-unread   2 "could not read the head commit $H"   not-merged FAIL_ON="git/commits/$H"
run compare-unread 2 "could not read the comparison of main with $H" not-merged FAIL_ON=compare/
run commits-short 2 "commits of PR #7 (got 1 of 3)"       not-merged COMPARE="ahead	3"
run no-commits    1 "brings main no commit (compare says behind)" not-merged COMPARE="behind	0" COMMITS=""
# A PR that merged main into its branch has a merge commit with one parent in main: squash is fine.
run merged-main   0 merged                                merged COMPARE="ahead	2" COMMITS="$A $M
$H $A $M"
# A PR whose commit merges two lines main lacks is an upstream sync: squash refuses and names the mode.
run sync-squash   1 "carries history main does not have: 1 commit(s) off its own first-parent line, such as $B; a squash would drop them. Merge it with --method merge" not-merged \
    COMPARE="ahead	3" COMMITS="$B 0000000000000000000000000000000000000000
$A $M
$H $A $B"
# The sync's shape when the merge sits directly on main's tip: upstream is the merge's second parent.
run sync-on-tip-squash 1 "2 commit(s) off its own first-parent line, such as $A" not-merged \
    COMPARE="ahead	3" COMMITS="$A 0000000000000000000000000000000000000000
$B $A
$H $M $B"
run same-tree-squash 1 "head has main's tree: a squash would record nothing" not-merged COMMIT_TSV="$MAIN_TREE	$M"
# Arguments: nothing is read and nothing merged.
usage() {
    local name="$1" want="$2" out rc; shift 2
    out="$(env PATH="$TMP/bin:$PATH" GH_LOG="$TMP/usage.log" bash "$HERE/merge.sh" "$@" 2>&1)"; rc=$?
    if [ "$rc" = 2 ] && [[ "$out" == *"$want"* ]] && [ ! -s "$TMP/usage.log" ]; then
        PASS=$((PASS + 1)); printf '  ok   %s\n' "$name"
    else
        FAIL=$((FAIL + 1)); printf '  FAIL %s: exit %s, output:\n%s\n' "$name" "$rc" "$out"
    fi
}
usage method-rebase   "--method is squash or merge"            --method rebase 7 "$H"
usage merge-no-anc    "needs --expect-ancestor"                --method merge 7 "$H"
usage merge-short-anc "needs --expect-ancestor"                --method merge --expect-ancestor abc 7 "$H"
usage squash-anc      "go with --method merge"                 --expect-ancestor "$A" 7 "$H"
usage repair-alone    "go with --method merge"                 --repair 7 "$H"
usage unknown-flag    "usage:"                                 --force 7 "$H"
usage three-args      "usage:"                                 7 "$H" extra
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

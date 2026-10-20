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
  *actions/runs*) fail "$@"; printf '%s' "$RUNS" ;;
  *check-runs*) fail "$@"; printf '%s' "$CHECKS" ;;
  */status*) fail "$@"; printf '%s\n' "$STATUS" ;;
  "pr merge"*) echo merged ;;
  *) echo "unexpected gh $*" >&2; exit 9 ;;
esac
GH
chmod +x "$TMP/bin/gh"
PASS=0; FAIL=0
GATE='{"name":"codex-review","event":"pull_request_target","run_number":5,"status":"completed","conclusion":"success"}'
CI='{"name":"CI","event":"pull_request","run_number":9,"status":"completed","conclusion":"success"}'
CHK='{"name":"Go Linter (linux)","status":"completed","conclusion":"success","started_at":"2026-10-20T10:00:00Z"}'
OK_CHECK='echo "PASS: main check"; exit 0'
# run <name> <want exit> <want substring> <merged|not-merged> [VAR=value]... (defaults: all green)
run() {
    local name="$1" want_rc="$2" want="$3" merged="$4" out rc log="$TMP/$1.log"
    shift 4
    : >"$log"
    out="$(env PATH="$TMP/bin:$PATH" GH_LOG="$log" FAIL_ON="" PR_TSV="open	false	$H	main" \
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
    RUNS='{"name":"codex-review","event":"pull_request_target","run_number":5,"status":"in_progress","conclusion":null}'
run gate-from-pr  1 "is 'missing'"                        not-merged \
    RUNS='{"name":"codex-review","event":"pull_request","run_number":5,"status":"completed","conclusion":"success"}'
run ci-failing    1 "workflow CI: completed/failure"      not-merged RUNS="$GATE
"'{"name":"CI","event":"pull_request","run_number":9,"status":"completed","conclusion":"failure"}'
run ci-pending    1 "workflow CI: queued/none"            not-merged RUNS="$GATE
"'{"name":"CI","event":"pull_request","run_number":9,"status":"queued","conclusion":null}'
run ci-rerun-ok   0 merged                                merged RUNS="$GATE
"'{"name":"CI","event":"pull_request","run_number":8,"status":"completed","conclusion":"failure"}
{"name":"CI","event":"pull_request","run_number":9,"status":"completed","conclusion":"success"}'
run check-failing 1 "check Go Linter (linux): completed/failure" not-merged \
    CHECKS='{"name":"Go Linter (linux)","status":"completed","conclusion":"failure","started_at":"2026-10-20T10:00:00Z"}'
run status-failed 1 "combined commit status of $H is failure" not-merged STATUS="failure	2"
run status-none   0 merged                                merged STATUS="pending	0"
# A read that fails, even with partial output, never merges
run runs-unread   2 "could not read the workflow runs"    not-merged FAIL_ON=actions/runs
run checks-unread 2 "could not read the check runs"       not-merged FAIL_ON=check-runs
run status-unread 2 "could not read the commit status"    not-merged FAIL_ON=/status
run pull-unread   2 "could not read PR #7"                not-merged FAIL_ON=pulls/7
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

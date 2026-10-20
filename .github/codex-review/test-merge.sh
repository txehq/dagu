#!/usr/bin/env bash
# test-merge.sh — merge.sh with a stand-in gh (TXE-4719): it merges only an open, ready PR on main
# whose head is the given SHA and on which MAIN's check passes, and then with --match-head-commit.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/merge-test.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT
H=1111111111111111111111111111111111111111
mkdir -p "$TMP/bin"
# The stand-in gh: PR fields from $PR_TSV, main's check from $MAIN_CHECK, every call logged.
cat >"$TMP/bin/gh" <<'GH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_LOG"
case "$*" in
  *contents/.github/codex-review/codex-review-check.sh*) printf '%s' "$MAIN_CHECK" | base64 ;;
  "api repos/txehq/dagu/pulls/7 --jq"*) printf '%s\n' "$PR_TSV" ;;
  "pr merge"*) echo merged ;;
  *) echo "unexpected gh $*" >&2; exit 9 ;;
esac
GH
chmod +x "$TMP/bin/gh"
PASS=0; FAIL=0
# run <name> <want exit> <want substring> <pr tsv> <main check body> [merged|not-merged]
run() {
    local out rc log="$TMP/$1.log"
    : >"$log"
    out="$(env PATH="$TMP/bin:$PATH" GH_LOG="$log" PR_TSV="$4" MAIN_CHECK="$5" bash "$HERE/merge.sh" 7 "$H" 2>&1)"; rc=$?
    if [ "$rc" = "$2" ] && [[ "$out" == *"$3"* ]] \
       && { [ "$6" = merged ] && grep -q -- "pr merge 7 -R txehq/dagu --squash --match-head-commit $H" "$log" \
            || { [ "$6" = not-merged ] && ! grep -q '^pr merge' "$log"; }; }; then
        PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"
    else
        FAIL=$((FAIL + 1)); printf '  FAIL %s: exit %s, output:\n%s\n  gh calls:\n%s\n' "$1" "$rc" "$out" "$(cat "$log")"
    fi
}
ok_check='echo "PASS: main check"; exit 0'
run passes     0 merged                         "open	false	$H	main"  "$ok_check" merged
run moved      1 "head is 2222"                 "open	false	2222222222222222222222222222222222222222	main" "$ok_check" not-merged
run draft      1 "is a draft"                   "open	true	$H	main"  "$ok_check" not-merged
run closed     1 "is closed"                    "closed	false	$H	main" "$ok_check" not-merged
run other-base 1 "base is release"              "open	false	$H	release" "$ok_check" not-merged
run check-fail 1 "does not pass"                "open	false	$H	main"  'echo "FAIL: P1"; exit 1' not-merged
run no-check   2 "main has no codex-review-check.sh" "open	false	$H	main" '' not-merged
# An inherited fixture directory never reaches main's check: here the check would pass only in fixture mode.
export CODEX_REVIEW_FIXTURE_DIR="$TMP/fixtures"
# shellcheck disable=SC2016  # the body is main's check, expanded when it runs
run fixture-env 1 "does not pass" "open	false	$H	main" '[ -n "${CODEX_REVIEW_FIXTURE_DIR:-}" ] && exit 0; exit 1' not-merged
unset CODEX_REVIEW_FIXTURE_DIR
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

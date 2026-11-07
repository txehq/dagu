#!/usr/bin/env bash
# test-merge-git.sh — merge.sh's merge method over a real git history (TXE-6221). A stand-in gh
# answers the history reads (main's tip, commits, compare) from a fixture repository and performs
# `pr merge` on it the way GitHub does: a squash is one commit with the head's tree; a merge is a
# merge commit with main and the head as parents. The CI and review answers are all green here;
# test-merge.sh covers those refusals.
#
# The fixture: fork main with one commit past the common base; an upstream line tagged v9.9.9 with a
# later commit the fork never took; a sync branch that merged v9.9.9 (PR #230's shape); a plain
# branch; a branch that merged main into itself; and the repair shapes: `merge -s ours v9.9.9` on
# main's tip, the same with a file added, and an empty commit.
# shellcheck disable=SC2016  # the stand-in gh's body is expanded when it runs
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/merge-git-test.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid \
  GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
F="$TMP/fixture"
g() { git -C "$F" "$@"; }
commit() { # <file> <message>
    echo "$1" >"$F/$1" && g add "$1" && g commit -q -m "$2"
}
git init -q -b main "$F"
commit base "base"
g checkout -q -b upstream
commit up1 "upstream 1"
commit up2 "upstream 2"
g tag v9.9.9
g tag -a -m "the same release, annotated" v9.9.9-annotated
commit up3 "upstream 3, after the pin"
g checkout -q main
commit fork1 "fork 1"
g checkout -q -b sync main
g merge -q --no-ff -m "merge upstream v9.9.9 into the fork" v9.9.9
commit fix "fork fix on top of the merge"
g checkout -q -b plain main
commit plain "a plain change"
g checkout -q -b merged-main "$(g rev-parse main~1)"
commit feature "a feature started before fork 1"
g merge -q --no-ff -m "merge main into the feature" main
g checkout -q -b repair main
g merge -q -s ours --no-ff -m "record upstream v9.9.9 as merged, no file change" v9.9.9
g checkout -q -b repair-changed main
g merge -q -s ours --no-ff -m "record upstream v9.9.9" v9.9.9
echo extra >"$F/extra" && g add extra && g commit -q --amend --no-edit
g checkout -q -b repair-empty main
g commit -q --allow-empty -m "an empty commit on main"
g checkout -q -b repair-swapped v9.9.9
g merge -q -s ours --no-ff -m "main recorded onto upstream: the parents the wrong way round" main
g checkout -q main
TAG="$(g rev-parse 'v9.9.9^{commit}')"; UP1="$(g rev-parse 'v9.9.9~1')"; UP3="$(g rev-parse upstream)"; MAIN="$(g rev-parse main)"; BASE="$(g rev-parse main~1)"
MAIN_TREE="$(g rev-parse 'main^{tree}')"; TAGOBJ="$(g rev-parse v9.9.9-annotated)"
if [ "$TAGOBJ" = "$TAG" ] || [ "$(g cat-file -t "$TAGOBJ")" != tag ]; then echo "fixture: the annotated tag should be its own object" >&2; exit 2; fi
[ "$(g rev-parse 'repair^{tree}')" = "$MAIN_TREE" ] || { echo "fixture: the repair should have main's tree" >&2; exit 2; }

mkdir -p "$TMP/bin"
cat >"$TMP/bin/gh" <<'GH'
#!/usr/bin/env bash
all="$*"; printf '%s\n' "$all" >>"$GH_LOG"
g() { git -C "$REPO" "$@"; }
fail() { case "$*" in *"$FAIL_ON"*) [ -n "$FAIL_ON" ] && { printf '{"partial":'; exit 1; } ;; esac; }
head="$(g rev-parse "$PR_HEAD")"
compare() { # <a> <b>: the API's status of a...b
  local mb
  g cat-file -e "$1^{commit}" 2>/dev/null && g cat-file -e "$2^{commit}" 2>/dev/null || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
  mb="$(g merge-base "$1" "$2" 2>/dev/null || true)"
  if [ "$1" = "$2" ]; then echo identical; elif [ "$mb" = "$1" ]; then echo ahead; elif [ "$mb" = "$2" ]; then echo behind; else echo diverged; fi
}
merge_into_main() { # <squash|merge>
  [ "${*: -1}" = "$head" ] || { echo "gh: head mismatch" >&2; exit 1; }  # --match-head-commit
  g checkout -q main || exit 1
  if [ -n "${ADVANCE_MAIN_AT_MERGE:-}" ]; then echo late >"$REPO/late" && g add late && g commit -q -m "main moved after the last read, before the merge"; fi
  if [ "$1" = squash ] || [ "${MERGE_AS:-}" = squash ]; then g merge -q --squash "$head" >/dev/null && g commit -q -m "PR #7 squashed" || exit 1
  else g merge -q --no-ff -m "Merge pull request #7" "$head" || exit 1; fi
  # MERGE_TAINT: what GitHub must not do, a merge commit whose tree is not its first parent's.
  if [ -n "${MERGE_TAINT:-}" ]; then echo taint >"$REPO/taint" && g add taint && g commit -q --amend --no-edit; fi
  g rev-parse HEAD >"$REPO/.merged"; echo merged
}
case "$*" in
  *contents/.github/codex-review/codex-review-check.sh*) printf 'exit 0' | base64 ;;
  *"pulls/7 --jq [.merged"*) fail "$@"; if [ -s "$REPO/.merged" ]; then printf 'true\t%s\n' "$(cat "$REPO/.merged")"; else printf 'false\t\n'; fi ;;
  *pulls/7*) if [ -s "$REPO/.merged" ]; then state=closed; else state=open; fi; printf '%s\tfalse\t%s\tmain\n' "$state" "$head" ;;
  *branches/main*) g rev-parse main ;;
  *git/commits/*) sha="${all#*git/commits/}"; sha="${sha%% *}"; [ "$(g cat-file -t "$sha" 2>/dev/null)" = commit ] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
    case "$all" in *"--jq .sha") echo "$sha" ;; *) printf '%s\t%s\n' "$(g rev-parse "$sha^{tree}")" "$(g log -1 --format=%P "$sha" | tr ' ' ',')" ;; esac ;;
  *compare/*) spec="${all#*compare/}"; spec="${spec%%\?*}"; a="${spec%%...*}"; b="${spec##*...}"; st="$(compare "$a" "$b")" || exit 1
    case "$*" in *"per_page=1 "*) printf '%s\t%s\n' "$st" "$(g rev-list --count "$b" "^$a")" ;; *) g rev-list --reverse --parents "$b" "^$a" ;; esac ;;
  "api repos/txehq/dagu --jq .allow_merge_commit") echo "${ALLOW_MERGE:-true}" ;;
  *actions/runs*) printf '%s\n' '{"name":"codex-review","path":".github/workflows/codex-review.yml","workflow_id":101,"event":"pull_request_target","run_number":5,"status":"completed","conclusion":"success"}' ;;
  *check-runs*) if [ -n "${ADVANCE_MAIN_AT_CHECKS:-}" ]; then g checkout -q main && echo moved >"$REPO/moved" && g add moved && g commit -q -m "main moved during the checks"; fi; printf '%s\n' '{"name":"CI","app":{"id":1},"check_suite":{"id":7},"status":"completed","conclusion":"success","started_at":"2026-11-08T00:00:00Z"}' ;;
  */status*) printf 'success\t1\n' ;;
  "pr merge 7 -R txehq/dagu --squash --match-head-commit "*) merge_into_main squash "$@" ;;
  "pr merge 7 -R txehq/dagu --merge --match-head-commit "*) merge_into_main merge "$@" ;;
  *) echo "unexpected gh $*" >&2; exit 9 ;;
esac
GH
chmod +x "$TMP/bin/gh"
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s: %s\n' "$1" "$2"; }
check() { if eval "$2"; then ok "$1"; else bad "$1" "the copy's main: $(r log --format='%h %P %s' -3 main | tr '\n' ';')"; fi; }  # <name> <condition>
# fresh <name>: a copy of the fixture to merge into; REPO points at it.
fresh() { REPO="$TMP/$1"; rm -rf "$REPO"; cp -R "$F" "$REPO"; }
r() { git -C "$REPO" "$@"; }
reaches() { r merge-base --is-ancestor "$1" main; }  # <sha> is an ancestor of the copy's main
# run <name> <want exit> <want substring> <merged|not-merged> <head branch> [merge.sh flags]...
# Then the caller checks the copy's main.
run() {
    local name="$1" want_rc="$2" want="$3" merged="$4" branch="$5" out rc log; shift 5
    fresh "$name"; log="$TMP/$name.log"; : >"$log"
    out="$(env PATH="$TMP/bin:$PATH" GH_LOG="$log" FAIL_ON="${FAIL_ON:-}" ALLOW_MERGE="${ALLOW_MERGE:-true}" MERGE_AS="${MERGE_AS:-}" \
        ADVANCE_MAIN_AT_CHECKS="${ADVANCE_MAIN_AT_CHECKS:-}" ADVANCE_MAIN_AT_MERGE="${ADVANCE_MAIN_AT_MERGE:-}" MERGE_TAINT="${MERGE_TAINT:-}" \
        REPO="$REPO" PR_HEAD="$branch" \
        bash "$HERE/merge.sh" "$@" 7 "$(r rev-parse "$branch")" 2>&1)"; rc=$?
    if [ "$rc" = "$want_rc" ] && [[ "$out" == *"$want"* ]] \
       && { { [ "$merged" = merged ] && [ -s "$REPO/.merged" ]; } || { [ "$merged" = not-merged ] && [ ! -e "$REPO/.merged" ] && [ "$(r rev-parse main)" = "$MAIN" ]; } \
            || { [ "$merged" = not-merged-moved ] && [ ! -e "$REPO/.merged" ]; }; }; then
        ok "$name"
    else
        bad "$name" "exit $rc (wanted $want_rc), main $(r rev-parse --short main), output:
$out
  gh calls:
$(cat "$log")"
    fi
}

# The control, in git alone: what PR #230's squash did, and what a merge commit does instead.
fresh control-squash; r merge -q --squash sync >/dev/null && r commit -q -m squash
if ! reaches "$TAG" && [ "$(r rev-parse 'main^{tree}')" = "$(g rev-parse 'sync^{tree}')" ]; then ok "control: a squash keeps the sync's tree and loses v9.9.9"; else bad "control-squash" "unexpected"; fi
fresh control-merge; r merge -q --no-ff -m merge sync
if reaches "$TAG" && [ "$(r rev-parse 'main^{tree}')" = "$(g rev-parse 'sync^{tree}')" ]; then ok "control: a merge commit keeps the tree and v9.9.9"; else bad "control-merge" "unexpected"; fi

# The default squash, unchanged for ordinary PRs.
run plain-squash   0 merged     merged     plain
check "plain-squash: main has the plain tree as one commit" \
    '[ "$(r rev-parse "main^{tree}")" = "$(g rev-parse "plain^{tree}")" ] && [ "$(r rev-list --count main)" = 3 ]'
run merged-main-squash 0 merged merged     merged-main
# The guard: the sync's merge commit has two parents main does not reach.
run sync-squash    1 "carries history main does not have: 2 commit(s) off its own first-parent line, such as $UP1; a squash would drop them" not-merged sync
check "sync-squash: v9.9.9 still not reachable" '! reaches "$TAG"'
# The merge method keeps the ancestry.
run sync-merge     0 "is reachable from it" merged sync --method merge --expect-ancestor "$TAG"
check "sync-merge: v9.9.9 reachable, tree is the sync's, parents are main and the head" \
    'reaches "$TAG" && [ "$(r rev-parse "main^{tree}")" = "$(g rev-parse "sync^{tree}")" ] && [ "$(r log -1 --format=%P main)" = "$MAIN $(g rev-parse sync)" ]'
run plain-merge    0 "is reachable from it" merged plain --method merge --expect-ancestor "$(g rev-parse plain)"
run sync-wrong-anc 1 "does not reach the expected ancestor $UP3 (compare says diverged)" not-merged sync --method merge --expect-ancestor "$UP3"
# The ancestor is a commit id: the annotated tag's own object is a read failure, not peeled to v9.9.9.
run sync-anc-tag-object 2 "could not read the expected ancestor $TAGOBJ as a commit (if it is an annotated tag's object" not-merged sync --method merge --expect-ancestor "$TAGOBJ"
run sync-anc-in-main 1 "already reachable from main" not-merged sync --method merge --expect-ancestor "$BASE"
run sync-anc-is-main 1 "already reachable from main" not-merged sync --method merge --expect-ancestor "$MAIN"
ALLOW_MERGE=false run sync-no-merge-commits 1 "does not allow merge commits (allow_merge_commit is false)" not-merged sync --method merge --expect-ancestor "$TAG"
# The repair: a tree-identical head whose parents are main's tip and the ancestor, declared.
run repair         0 "is reachable from it" merged repair --method merge --expect-ancestor "$TAG" --repair
check "repair: v9.9.9 reachable, main's tree unchanged, parents are main and the repair" \
    'reaches "$TAG" && [ "$(r rev-parse "main^{tree}")" = "$MAIN_TREE" ] && [ "$(r log -1 --format=%P main)" = "$MAIN $(g rev-parse repair)" ]'
run repair-undeclared 1 "head has main's tree, which only a provenance repair has; declare it with --repair" not-merged repair --method merge --expect-ancestor "$TAG"
run repair-squash  1 "carries history main does not have" not-merged repair
run empty-squash   1 "head has main's tree: a squash would record nothing" not-merged repair-empty
run repair-empty   1 "does not reach the expected ancestor $TAG" not-merged repair-empty --method merge --expect-ancestor "$TAG" --repair
run repair-swapped 1 "a repair's parents must be main's tip and the expected ancestor ($MAIN,$TAG); PR #7's head has $TAG,$MAIN" not-merged repair-swapped --method merge --expect-ancestor "$TAG" --repair
run repair-wrong-anc 1 "does not reach the expected ancestor $UP3" not-merged repair --method merge --expect-ancestor "$UP3" --repair
run repair-changed 1 "declared a repair but its tree" not-merged repair-changed --method merge --expect-ancestor "$TAG" --repair
run repair-changed-is-a-sync 0 "is reachable from it" merged repair-changed --method merge --expect-ancestor "$TAG"
# Main moves between the checks and the merge: the last read before the merge refuses.
ADVANCE_MAIN_AT_CHECKS=1 run repair-main-moves-late 1 "main moved from $MAIN to " not-merged-moved repair --method merge --expect-ancestor "$TAG" --repair
# Main moves after the last read, before the merge: GitHub merges the repair onto the new tip. The
# merge commit's tree is its first parent's (the new main) and it reaches v9.9.9, so it is accepted
# and the move is reported.
ADVANCE_MAIN_AT_MERGE=1 run repair-main-moves-after-last-read 0 "(main had moved from $MAIN to " merged repair --method merge --expect-ancestor "$TAG" --repair
check "repair-main-moves-after-last-read: tree is the new main's, v9.9.9 reachable, second parent is the repair" \
    'reaches "$TAG" && [ "$(r rev-parse "main^{tree}")" = "$(r rev-parse "main^1^{tree}")" ] && [ -e "$REPO/late" ] && [ "$(r rev-parse main^2)" = "$(g rev-parse repair)" ]'
# A merge commit whose tree is not its first parent'"'"'s is reported as merged, with an error, and left.
MERGE_TAINT=1 run repair-tainted-merge 1 "PR #7 was merged, but the repair's merge commit" merged repair --method merge --expect-ancestor "$TAG" --repair
check "repair-tainted-merge: the message names the tree and nothing was rewritten" \
    '[[ "$(cat "$TMP/repair-tainted-merge.log")" == *"git/commits/$(r rev-parse main) "* ]] && [ -e "$REPO/taint" ] && reaches "$TAG"'
# Main moved after the repair was built: its first parent is no longer main's tip.
fresh repair-stale-build; r checkout -q main && echo later >"$REPO/later" && r add later && r commit -q -m "fork 2, after the repair was built"
STALE="$TMP/repair-stale-build"
run_stale() {
    local out rc log="$TMP/repair-stale.log"; REPO="$STALE"; : >"$log"
    out="$(env PATH="$TMP/bin:$PATH" GH_LOG="$log" FAIL_ON="" ALLOW_MERGE=true REPO="$REPO" PR_HEAD=repair \
        bash "$HERE/merge.sh" --method merge --expect-ancestor "$TAG" --repair 7 "$(r rev-parse repair)" 2>&1)"; rc=$?
    if [ "$rc" = 1 ] && [[ "$out" == *"a repair's parents must be main's tip and the expected ancestor ($(r rev-parse main),$TAG)"*"(if main moved, rebuild the repair on its tip)"* ]] && [ ! -e "$REPO/.merged" ]; then
        ok "repair-stale: main moved, the repair is refused"
    else bad "repair-stale" "exit $rc, output:
$out"; fi
}
run_stale
# The readback is a real check: a merge that came out as a squash (MERGE_AS makes the stand-in do
# what GitHub must not) is reported, exit 1, with the PR named as merged.
MERGE_AS=squash run readback-no-reach 1 "PR #7 was merged, but its merge commit" merged sync --method merge --expect-ancestor "$TAG"
check "readback-no-reach: the message says the ancestor is not reached" '[[ "$(cat "$TMP/readback-no-reach.log")" == *"compare/$TAG..."* ]] && ! reaches "$TAG"'
# A readback that cannot be completed exits 1 and says the PR was merged.
FAIL_ON="pulls/7 --jq [.merged" run readback-unread 1 "PR #7 was merged, but its merge commit could not be read" merged sync --method merge --expect-ancestor "$TAG"
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

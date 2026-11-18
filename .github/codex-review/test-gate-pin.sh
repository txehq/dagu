#!/usr/bin/env bash
# test-gate-pin.sh — the gate's maintenance-base pin (TXE-7556). codex-review.yml runs
# .github/codex-review from CODEX_REVIEW_GATE_SHA on a maint/txe-v* base, never the base's own
# copy. This fails when:
#   - the workflow no longer triggers on maintenance bases, or no longer takes the scripts from main's
#     tip on main and from the pin elsewhere (a downgrade to github.sha would run the base's copy);
#   - the pin is not one full commit id, or main does not reach it;
#   - main's copy of a file the gate runs differs from the pin's, so a maintenance base would be
#     judged by an older check than main. The fix is a PR that moves the pin to main's commit that
#     last changed those files; this names it;
#   - the workflow's base guard accepts a base it should refuse, or refuses one it should accept.
#   - the workflow's concurrency lets anything but a new head (synchronize) cancel the run in
#     progress, or adds a job-level group or a queue key (TXE-7843, README.md "Same-head re-checks").
#
#   bash .github/codex-review/test-gate-pin.sh [<main ref>]   # default origin/main; needs main's history
# shellcheck disable=SC2016  # the stand-in gh's body is expanded when it runs
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)" || exit 2
WF="$ROOT/.github/workflows/codex-review.yml"
MAIN_REF="${1:-origin/main}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/gate-pin-test.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s: %s\n' "$1" "$2"; }

# ── The workflow's shape ──
if grep -qE "^    branches: \[main, 'maint/txe-v\*'\]$" "$WF"; then ok "triggers on main and maint/txe-v*"
else bad "trigger" "the pull_request_target branches are not [main, 'maint/txe-v*']"; fi
refs="$(grep -E '^ +ref: ' "$WF")"
if [ "$refs" = "          ref: \${{ github.base_ref == 'main' && github.sha || env.CODEX_REVIEW_GATE_SHA }}" ]; then
    ok "checks out main's tip on main and the pin elsewhere, and nothing else"
else bad "checkout ref" "expected the one checkout ref to choose github.sha on main and the pin elsewhere; got: $refs"; fi
if grep -q 'persist-credentials: false' "$WF" && grep -q 'sparse-checkout: .github/codex-review' "$WF"; then
    ok "the checkout keeps no credential and takes .github/codex-review only"
else bad "checkout scope" "persist-credentials: false and sparse-checkout: .github/codex-review are required"; fi
perms="$(awk '/^permissions:/{p=1; next} p && /^[^ ]/{exit} p' "$WF" | tr -d ' ')"
if [ "$perms" = "$(printf 'contents:read\npull-requests:read')" ]; then ok "the token is read-only"
else bad "permissions" "expected contents: read and pull-requests: read only; got: $perms"; fi
if grep -E 'pull_request_target' "$WF" >/dev/null && ! grep -E 'github\.(head_ref|event\.pull_request\.head)' "$WF" >/dev/null; then
    ok "nothing of the PR's head is referenced"
else bad "head refs" "the gate must not reference the PR's head (head_ref or event.pull_request.head)"; fi

# ── Concurrency (TXE-7843): only a new head cancels the run in progress ──
# One workflow-level group per PR; cancel-in-progress true for `synchronize` alone, so a same-head
# re-check (edited, labeled, unlabeled, reopened, ready_for_review) waits as pending instead of
# cancelling the active run. No job-level concurrency (a second group would cancel on its own), and
# no `queue:` key: queue `max` refuses a cancel-in-progress expression, and `single` is the default
# whose pending replacement README.md "Same-head re-checks" measured.
conc="$(awk '/^concurrency:/{p=1; print; next} p && /^[^ ]/{exit} p' "$WF")"
want_conc="concurrency:
  group: codex-review-\${{ github.event.pull_request.number }}
  cancel-in-progress: \${{ github.event.action == 'synchronize' }}"
if [ "$conc" = "$want_conc" ]; then ok "one group per PR; only synchronize cancels the run in progress"
else bad "concurrency" "expected exactly:
$want_conc
got:
$conc"; fi
if [ "$(grep -c '^concurrency:' "$WF")" = 1 ] && ! grep -qE '^ +concurrency:' "$WF"; then
    ok "one workflow-level concurrency block and no job-level one"
else bad "job concurrency" "a job-level concurrency group would cancel same-head runs on its own"; fi
if ! grep -qE '^ *queue:' "$WF"; then ok "no queue key (GitHub's default: one pending run per group)"
else bad "queue" "a queue key changes the measured pending semantics; see README.md \"Same-head re-checks\""; fi
types="$(sed -n 's/^    types: \[\(.*\)\]$/\1/p' "$WF")"
if [ "$types" = "opened, reopened, synchronize, ready_for_review, edited, labeled, unlabeled" ]; then
    ok "the trigger types are unchanged: synchronize is the only new-head type"
else bad "trigger types" "the types changed ($types); decide which of them may cancel the run in progress"; fi

# ── The pin ──
pins="$(grep -cE '^  CODEX_REVIEW_GATE_SHA: ' "$WF")"
pin="$(sed -n 's/^  CODEX_REVIEW_GATE_SHA: \([0-9a-f]\{40\}\)$/\1/p' "$WF")"
if [ "$pins" = 1 ] && [[ "$pin" =~ ^[0-9a-f]{40}$ ]]; then ok "one pin, a full commit id"
else bad "pin form" "CODEX_REVIEW_GATE_SHA must appear once as 40 hex digits (found $pins: '$pin')"; pin=""; fi
if ! git -C "$ROOT" rev-parse -q --verify "$MAIN_REF^{commit}" >/dev/null; then
    bad "main ref" "$MAIN_REF is not in this clone; fetch main first"
elif [ -n "$pin" ]; then
    if git -C "$ROOT" merge-base --is-ancestor "$pin" "$MAIN_REF" 2>/dev/null; then ok "main reaches the pin $pin"
    else bad "pin on main" "$pin is not a commit main ($MAIN_REF) reaches"; fi
    # The files the gate runs: every .github/codex-review path its steps name, and the recorded
    # payloads its test reads.
    run_files=()
    while IFS= read -r line; do run_files+=("$line"); done < <(grep -oE '\.github/codex-review/[A-Za-z0-9_.-]+' "$WF" | sort -u)
    run_files+=(.github/codex-review/testdata)
    if [ "${#run_files[@]}" -lt 3 ]; then bad "gate files" "found only: ${run_files[*]}"
    elif git -C "$ROOT" diff --quiet "$pin" "$MAIN_REF" -- "${run_files[@]}" 2>/dev/null; then
        ok "the pin has main's copy of ${run_files[*]}"
    else
        last="$(git -C "$ROOT" log -1 --format=%H "$MAIN_REF" -- "${run_files[@]}")"
        bad "pin current" "main changed what the gate runs after the pin $pin; move CODEX_REVIEW_GATE_SHA to $last"
    fi
fi

# ── The base guard, run as the workflow runs it, with a stand-in gh ──
guard="$(awk '/# >>> base-guard/{p=1; next} /# <<< base-guard/{p=0} p' "$WF" | sed 's/^          //')"
[ -n "$guard" ] || bad "guard" "no '# >>> base-guard' block in $WF"
printf '%s\n' "$guard" >"$TMP/guard.sh"
mkdir -p "$TMP/bin"
cat >"$TMP/bin/gh" <<'GH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_LOG"
[ -n "${GH_FAIL:-}" ] && exit 1
printf '%s\n' "$COMPARE"
GH
chmod +x "$TMP/bin/gh"
P=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# guard <name> <want exit> <want substring> <base> [VAR=value]...
guard() {
    local name="$1" want_rc="$2" want="$3" base="$4" out rc; shift 4
    : >"$TMP/gh.log"
    out="$(env PATH="$TMP/bin:$PATH" GH_LOG="$TMP/gh.log" GH_REPO=txehq/dagu BASE_REF="$base" \
        CODEX_REVIEW_GATE_SHA="$P" COMPARE=ahead "$@" bash "$TMP/guard.sh" 2>&1)"; rc=$?
    if [ "$rc" = "$want_rc" ] && [[ "$out" == *"$want"* ]]; then ok "guard: $name"
    else bad "guard: $name" "exit $rc (wanted $want_rc), output: $out"; fi
}
guard main             0 "gate runs main's tip"                main
guard maint            0 "runs main's commit $P"               maint/txe-v2.18.2-19
if grep -q "compare/$P...main" "$TMP/gh.log"; then ok "guard: reads whether main reaches the pin"
else bad "guard: compare" "gh calls: $(cat "$TMP/gh.log")"; fi
guard maint-identical  0 "runs main's commit $P"               maint/txe-v2.18.2-19 COMPARE=identical
guard pin-off-main     1 "is not a main commit (compare says diverged)" maint/txe-v2.18.2-19 COMPARE=diverged
guard pin-ahead-main   1 "is not a main commit (compare says behind)"   maint/txe-v2.18.2-19 COMPARE=behind
guard pin-unread       1 "could not read whether main reaches" maint/txe-v2.18.2-19 GH_FAIL=1
guard pin-short        1 "not a full commit id"                maint/txe-v2.18.2-19 CODEX_REVIEW_GATE_SHA=efd1c83
guard name-glob        1 "neither main nor maint/txe-v"        maint/txe-vX
guard name-no-n        1 "neither main nor maint/txe-v"        maint/txe-v2.18.2
guard name-nested      1 "neither main nor maint/txe-v"        "maint/txe-v2.18.2-19/x"
guard name-other       1 "neither main nor maint/txe-v"        release
guard name-shell       1 "neither main nor maint/txe-v"        'maint/txe-v1.2.3-4$(id)'

printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

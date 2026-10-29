# Review on txehq/dagu: the Codex connector (TXE-4719)

Every PR is reviewed by the Codex GitHub connector (GitHub App `chatgpt-codex-connector`), and the
`codex-review` check (`.github/workflows/codex-review.yml`, rule in `codex-review-check.sh`)
turns its review into a merge decision. This replaced the Tokun-backed workflow (TXE-4204), which
stopped on 2026-10-20 (TXE-4714). The rule is the same as txehq/txe's
(`ops/ci/codex-review-check.sh`, `docs/workflow/review-loop.md` there), plus rule 0: this
repository is public, so the check runs main's copy (`pull_request_target`, which executes no PR
code), and a PR from another repository fails unless a person adds `review-override`.

## The author's loop

1. Open the PR ready for review. The connector does not review drafts.
2. Wait for the connector's state block on your head:

   ```bash
   gh api repos/txehq/dagu/issues/<n>/comments --paginate \
     --jq '.[] | select(.user.login == "chatgpt-codex-connector[bot]") | .body' \
     | sed -n 's/.*<!-- codex-review-state:v1 \(.*\) -->.*/\1/p' | jq .code_review
   ```

   It is done when `commit_sha` is your head and `status` is `completed`, usually 2 to 8 minutes.
3. Read every finding. Fix every P0 and P1 and push; a P2 or P3 never blocks. When the connector
   completes a re-review of your head with `has_any_findings: true` but posts neither a review of
   the head nor a receipt naming it (dagu PRs 175 and 185), the check decides on its live threads
   (TXE-4791): it passes when no thread it opened carries a P0 or P1 badge without being outdated,
   or a person (resolvedBy typed User, not a `[bot]` login) resolved each one. Answer such a thread
   with evidence, have a person resolve it, then re-run the check: resolving a thread fires no
   event this workflow runs on. A thread read that is incomplete or unreadable is a failed read,
   never a pass.
4. Each new head needs a review of that head. If the connector has not started one (no 👀 on the PR,
   no "Running" row in its summary) within a few minutes, comment `@codex review` **once** for that
   head. Never comment it again on the same head to get a different answer. After a change of base,
   rebase onto it and force-push.
5. Merge only through **main's** merge wrapper. This fork's main has no branch protection, so the
   wrapper is what enforces the gate at the merge boundary. On the exact head it requires main's
   codex-review run completed/success, every other workflow run, check run and the combined status
   finished green (pending or unreadable refuses), and main's check passing again with no wait; it
   then merges with `--match-head-commit`:

   ```bash
   git fetch -q origin main
   git show origin/main:.github/codex-review/merge.sh | bash -s -- <n> <head sha>
   ```

   Bootstrap: the PR that introduced this check (TXE-4719) could not be judged by a copy on main;
   it was merged after an independent review of its source and a canary of the connector on its
   own head.

`review-override` is a person's decision: the check names who added it, and refuses one a bot
added. Adding or removing the label re-runs the check, so removing it revokes the pass.

## Settings this depends on (not in this repository)

- The connector installation on txehq lists txehq/dagu among its selected repositories.
- ChatGPT Codex code-review settings, repository txehq/dagu: reviews for **All PRs** (the only
  scope the settings offer).

What was observed when this was set up (TXE-4719, PR #139, 2026-10-20): the connector started no
review on its own, neither when the PR was opened ready (18:34Z) nor after a push (18:41Z); one
`@codex review` (18:47Z) started a review within 35 s, which completed in about 4 minutes. So the
manual comment in step 4 is the working path until an automatic start is observed. The gate does
not depend on how a review started: it requires a completed review of the current head either way.

`test-codex-review-check.sh` runs the check over recorded connector payloads (`testdata/`, from
txehq/sub2api, txehq/txe and txehq/dagu PRs, reduced by `testdata/sanitize.py`); `codex-review-test.yaml` runs it with shellcheck.

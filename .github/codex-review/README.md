# Review on txehq/dagu: the Codex connector (TXE-4719)

Every PR is reviewed by the Codex GitHub connector (GitHub App `chatgpt-codex-connector`), and the
`codex-review` check (`.github/workflows/codex-review.yml`, rule in `codex-review-check.sh`)
turns its review into a merge decision. This replaced the Tokun-backed workflow (TXE-4204), which
stopped on 2026-10-20 (TXE-4714). The rule is the same as txehq/txe's
(`ops/ci/codex-review-check.sh`, `docs/workflow/review-loop.md` there), plus rule 0: this
repository is public, so a PR from another repository fails unless a person adds `review-override`.

## The author's loop

1. Open the PR ready for review. The connector does not review drafts.
2. Wait for the connector's state block on your head:

   ```bash
   gh api repos/txehq/dagu/issues/<n>/comments --paginate \
     --jq '.[] | select(.user.login == "chatgpt-codex-connector[bot]") | .body' \
     | sed -n 's/.*<!-- codex-review-state:v1 \(.*\) -->.*/\1/p' | jq .code_review
   ```

   It is done when `commit_sha` is your head and `status` is `completed`, usually 2 to 8 minutes.
3. Read every finding. Fix every P0 and P1 and push; a P2 or P3 never blocks.
4. A push starts the next review. If none starts within a few minutes, comment `@codex review`.
   After a change of base, rebase onto it and force-push.
5. Merge only when `codex-review` and CI are green, after running **main's** copy of the check
   once more at the merge boundary (a pull_request run executes the PR's own copy):

   ```bash
   git fetch -q origin main
   git show origin/main:.github/codex-review/codex-review-check.sh > "$TMPDIR/codex-review-check.sh"
   GH_REPO=txehq/dagu PR_NUMBER=<n> CODEX_REVIEW_WAIT_SECONDS=0 bash "$TMPDIR/codex-review-check.sh" \
     && gh pr merge <n> -R txehq/dagu --squash
   ```

`review-override` is a person's decision: the check names who added it, and refuses one a bot
added. Adding the label runs nothing by itself; re-run the check after it.

## Settings this depends on (not in this repository)

- The connector installation on txehq lists txehq/dagu among its selected repositories.
- chatgpt.com/settings/code-review, repository txehq/dagu: automatic review on for all PRs,
  triggered on every push; minimum automatic severity High, manual (`@codex review`) Medium.

`test-codex-review-check.sh` runs the check over recorded connector payloads (`testdata/`, from
txehq/sub2api and txehq/txe PRs); `codex-review-test.yaml` runs it with shellcheck.

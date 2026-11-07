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
   never a pass, and the threads are read only 120 s after the Code Review row's completion time
   (a conservative visibility delay, not a consistency guarantee; the merge wrapper re-reads
   everything at the exact head).
4. Each new head needs a review of that head. A review silent for 10 minutes is re-requested once
   by the nudge job (txehq/action-runner-ops `jobs/codex-review-nudge/`: an `@codex review` comment
   from `connorwang` carrying `<!-- codex-nudge:v1 <sha> -->`); one still silent 10 minutes after
   that gets a second comment asking for a new head: push one empty commit. Do not re-request by
   hand inside those windows. After a change of base, rebase onto it and force-push. After a change
   to the gate lands on main, an open PR picks it up only through a new `pull_request_target` event
   (edit the PR description, or push); re-running an existing `codex-review` run reuses the main
   commit it was created with.
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

## The merge method (TXE-6221)

The wrapper squashes by default, and a squash keeps the PR's tree while dropping its history. That
is right for a PR made of its author's own commits and wrong for a PR whose point is the history it
carries. PR #230 merged upstream v2.25.8 into the fork and was squashed (main `025b6847a`), so
v2.25.8 is not an ancestor of main and the next sync would conflict again on everything it changed.
Two rules, both in `merge.sh` and both behind every check above:

- **The default squash refuses history it would drop.** The PR's own line is its first-parent
  history back to main. A commit of the PR that is not on that line came in through a merge's other
  parent (an upstream release, another branch); the wrapper names it and refuses. A PR that merged
  main into its branch is all on its own line and squashes as before. Rebase a PR whose foreign
  history is not meant to be kept; merge one whose history is with the mode below.
- **`--method merge --expect-ancestor <sha>` keeps the history**, for an upstream sync or a
  provenance repair. It merges with a merge commit, after the same checks, and in addition requires
  the repository to allow merge commits (read from the API, never assumed), the expected ancestor to
  be a commit's own id, reachable from the head and not yet from main, and then reads the merge
  commit back and prints it only once the ancestor is reachable from it. For a repair it re-reads
  main's tip as the last thing before the merge and refuses if main moved. `--repair` declares a provenance repair that
  changes no file (`git merge -s ours --no-ff <upstream>` on main's tip): the head's parents must be
  exactly main's current tip and the expected ancestor, and its tree must be main's; a main that
  moved, a wrong parent or any file change refuses. A head with main's tree is accepted only this
  way.

   ```bash
   # the commit the upstream tag points to, from upstream's own repository: .object.type is
   # "commit" for a lightweight tag; for an annotated tag ("tag") read git/tags/<sha> and take its
   # .object.sha. The wrapper takes a commit id only and refuses a tag object rather than peel it.
   gh api repos/dagucloud/dagu/git/ref/tags/v2.25.8 --jq '.object | "\(.type) \(.sha)"'
   anc=<that commit sha>   # v2.25.8: 28022fee38b59c1474491fecf571791fbde8e9e7, a lightweight tag (read 2026-11-08)
   git show origin/main:.github/codex-review/merge.sh | bash -s -- --method merge --expect-ancestor "$anc" <n> <head sha>
   # a provenance repair: no file changes
   git show origin/main:.github/codex-review/merge.sh | bash -s -- --method merge --expect-ancestor "$anc" --repair <n> <head sha>
   ```

   GitHub's merge method always makes its own merge commit: main's new tip has main's old tip and
   the PR head as parents, and the expected ancestor is reachable through the head. Neither mode
   has a flag that skips a check, and neither replaces the wrapper with a direct push.
   `test-merge-git.sh` runs both methods over a real git fixture: the squash of a sync loses the
   tag and the merge keeps it, the guard refuses the sync under squash, and the repair path refuses
   a moved main, swapped parents, a wrong ancestor and a changed tree.

`review-override` is a person's decision: the check names who added it, and refuses one a bot
added. Adding or removing the label re-runs the check, so removing it revokes the pass.

## Settings this depends on (not in this repository)

- The connector installation on txehq lists txehq/dagu among its selected repositories.
- ChatGPT Codex code-review settings, repository txehq/dagu: reviews for **All PRs** (the only
  scope the settings offer).

What was observed when this was set up (TXE-4719, PR #139, 2026-10-20): the connector started no
review on its own, neither when the PR was opened ready (18:34Z) nor after a push (18:41Z); one
`@codex review` (18:47Z) started a review within 35 s, which completed in about 4 minutes. So the
nudge job's comment in step 4 is the working path until an automatic start is observed. The gate
does not depend on how a review started: it requires a completed review of the current head
either way.

`test-codex-review-check.sh` runs the check over recorded connector payloads (`testdata/`, from
txehq/sub2api, txehq/txe and txehq/dagu PRs, reduced by `testdata/sanitize.py`); `test-merge.sh`
runs the wrapper's refusals with a stand-in `gh`, and `test-merge-git.sh` its merge methods over a
real git history; `codex-review-test.yaml` runs them with shellcheck.

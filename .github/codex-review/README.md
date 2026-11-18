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

## Same-head re-checks (TXE-7843)

An edit or a label change on an unchanged head starts a new gate run. Until TXE-7843 it cancelled
the run in progress (`cancel-in-progress: true`), and the cancelled `codex-review` check run stayed
in its own check suite on that head, so the wrapper refused the merge until that run was re-run
(PR #282, head `df1d4f7f`: run 766, `ready_for_review`, cancelled by run 767, `edited`). The
wrapper is unchanged: it still judges every check run on the head on its own. The workflow changed
instead: `cancel-in-progress` is true only for a run whose event action is `synchronize` (a
new head, or a re-run of such a run). Every other event waits.

What GitHub does (docs, "Control the concurrency of workflows and jobs"): a run whose group already
has one running "will be `pending`"; "any existing `pending` job or workflow in the same
concurrency group will be canceled and the new queued job or workflow will take its place"; that is
`queue: single`, the default, at most one pending run per group. `queue: max` keeps up to 100
pending runs, but "ordering is not guaranteed" and it cannot be combined with
`cancel-in-progress: true`, so it is not used. A group keyed on the head alone would not help:
with `cancel-in-progress: true`, same-head runs share that group and still cancel each other.

Measured on 2026-11-18 (raw payloads on TXE-7843): one orphan commit pushed to six
scratch branches, so all six runs were on one head and in one group, with `cancel-in-progress`
true only for a branch ending in `-cancel`:

| run | event, at | outcome | check runs in its suite |
| --- | --- | --- | --- |
| 1 | queue, 18:05:45Z | ran 18:05:47–18:07:50Z, success: runs 2 and 3 did not cancel it | 1 (success) |
| 2 | queue, 18:06:17Z | pending, then cancelled at 18:06:36Z when run 3 arrived | **0** |
| 3 | queue, 18:06:35Z | pending until run 1 ended, ran 18:07:54–18:09:59Z, success | 1 (success) |
| 4 | queue, 18:10:37Z | running; cancelled at 18:11:34Z by run 5 | 1 (cancelled) |
| 5 | `-cancel`, 18:11:19Z | ran 18:11:36–18:13:38Z, success | 1 (success) |
| 6 | queue, 18:11:37Z | pending behind run 5, ran 18:13:41–18:15:47Z, success | 1 (success) |

The wrapper's own selection, applied to those payloads: runs 1–3 merge (newest run 3 success, no
check run off green; while run 3 was pending, the newest was pending and refused); runs 1–6 refuse
on run 4's cancelled check run, the old behaviour. On a PR that now happens across a head change,
where the cancelled run is on the previous head and is never read, and in one same-head case: a
person re-running an earlier run of a `synchronize` event while a re-check is active. The re-run
keeps its event's action, so it cancels the active run, and the wrapper refuses until that run is
re-run. That costs a re-run, never a pass.

So for a PR:

- **An edit or label during a run** waits as `pending`, then runs and reads the labels, the base and
  the connector's state as they are then. The run in progress finishes and keeps its verdict in its
  own suite. The wrapper takes the newest gate run on the exact head (`max_by(.run_number)`), so a
  pending or running re-check it can see refuses: it blocks the older success. It also re-runs
  main's check at the merge, which reads the labels again, and after it re-reads the gate's runs and
  the PR's labels and base as its last calls before the merge ("The last reads before the merge"
  below). What is left is the seconds between those reads and the merge.
- **Several rapid re-checks**: the replaced pending run is cancelled before it starts and leaves no
  check run; the newest pending run carries the newest state. The newest gate run being cancelled,
  failed or missing refuses.
- **A new head** (`synchronize`) cancels the run in progress and any pending one. Nothing of the
  previous head counts: the wrapper reads runs, check runs and the status at the exact head only.
- **A run that failed** (for example a 15-minute poll that ended before the review) still refuses
  after a later green run on the same head, as before: re-run that run.

`test-gate-pin.sh` fails when the workflow's concurrency changes; `test-merge.sh` runs the wrapper
over these shapes.

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
  commit back and prints it only once the ancestor is reachable from it and its second parent is
  the head. For a repair it re-reads main's tip as the last thing before the merge and refuses if
  main moved. That is not an atomic check (`--match-head-commit` pins the head, not main): a move
  in the seconds after that read is merged by GitHub onto the new tip, and the readback judges the
  merge commit itself: a tree equal to its actual first parent's (main as it was at the merge) is
  accepted and the move reported; a tree that differs is reported as **merged, with an error**
  (exit 1) and left as it is, for a person to read main. Nothing is retried or rewritten. `--repair` declares a provenance repair that
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
   a moved main, swapped parents, a wrong ancestor and a changed tree, accepts a main that moved
   after the last read, and reports a merge commit that differs from its first parent.

## Maintenance bases (TXE-7556)

A maintenance release is cut from a branch named exactly `maint/txe-v<x.y.z>-<n>` (for example
`maint/txe-v2.18.2-19`), and every change to it is a PR reviewed and merged under the same gate as
main. Nothing here creates such a branch: creating one, and any ruleset on it, is a separate step
that root accepts explicitly.

- **The check runs, with main's scripts.** `codex-review.yml` triggers on `main` and
  `maint/txe-v*`. `pull_request_target` runs the *base's* copy of that file, and there
  `github.sha` is the base's tip, so on a maintenance base the job checks out `.github/codex-review`
  at `CODEX_REVIEW_GATE_SHA`: a main commit named by its full id. Its first step refuses any other
  base name and a pin that main does not reach. On main nothing changed: main's tip runs.
- **The pin follows main, loudly.** `test-gate-pin.sh` (in `codex-review-test.yaml`, on PRs and on
  main) fails when main's copy of a file the gate runs differs from the pin's, and names the main
  commit to move the pin to. So a PR that changes `codex-review-check.sh` or its fixtures is
  followed by a PR that moves the pin; until then main's push run of `codex-review-test` is red.
  The same test fails when the workflow stops triggering on maintenance bases, takes the scripts
  from anywhere but main's tip or the pin, or widens its token.
- **The merge is bound to the base and the head.** Merge with main's wrapper, naming the base and
  the tip you reviewed against:

   ```bash
   git fetch -q origin main
   git show origin/main:.github/codex-review/merge.sh \
     | bash -s -- --base maint/txe-v2.18.2-19 --base-sha <the base's tip> <n> <head sha>
   ```

  It runs every check above against that base's tip: the PR's base is that name, the history rule
  is measured against the base, main's codex-review run on the head is completed/success and names
  this PR on this base, every other run is green, and main's check (read at main's tip) passes
  now. In addition it refuses when the base's tip is not `--base-sha` at the first read or at the
  last read before the merge, and when the base's `.github/workflows/codex-review.yml` is not
  main's byte for byte (the gate that ran there would not be main's). A maintenance base is merged
  by squash only: `--method merge` and `--repair` are refused. After the squash it reads the merge
  commit back: its only parent must be `--base-sha`; a base that moved in the seconds after the
  last read is reported as merged, with an error (exit 1), and left as it is.
- **When main's `codex-review.yml` changes**, every live maintenance base's copy differs and its
  PRs are refused until that copy is brought to main's again. That is the same root-accepted step
  as creating the base (a commit that makes `git diff origin/main <base> --
  .github/workflows/codex-review.yml` empty), never a bypass of the wrapper.

What the other workflows do on a maintenance base (inventory, 2026-11-16): `ci.yaml`,
`frontend-ci.yaml`, `conformance.yml`, `desktop-e2e.yaml`, `docker-browser-smoke.yaml`,
`image-security.yaml`, `image-build-test.yaml`, `chart-ci.yaml` and `codex-review-test.yaml` run on
`pull_request` with no branch filter (path filters only), so they run on a PR into any base, using
the head's workflow files, as they do on main; the wrapper requires all of them green on the head.
Their `push` triggers are `main` only, so a merge into a maintenance base starts no push run.
`txe-image.yaml`, `release.yaml` and `docker.yaml` start on a tag push, whatever branch the tagged
commit is on. Nothing else names a base.

`review-override` is a person's decision: the check names who added it, and refuses one a bot
added. Adding or removing the label re-runs the check, so removing it revokes the pass, and the
merge wrapper refuses a label set that changed after its own check (TXE-7847).

## The last reads before the merge (TXE-7847)

Main's check reads the labels once, and GitHub's merge call pins only the head
(`--match-head-commit`), so a `review-override` removed, a label added or a retarget between the
check and the merge used to be merged on the earlier read. The wrapper now brackets the check:

- **Just before the check** it reads the PR as one line: state, draft, head, base name, base sha
  and the sorted label names. It must be open, ready, at the given head and on the given base.
- **As the last calls before `gh pr merge`**, on every path (the squash on main, `--method merge`,
  `--repair`, and a maintenance base after its own last tip read), it re-reads main's
  `codex-review.yml` runs on the head (`pull_request_target`), then the same PR line. It refuses
  when the newest gate run is not the run it judged (by id, run number and attempt: a label, an
  edit or a re-run starts a new run or attempt, even one that later succeeds), when that run is no
  longer completed/success, or when the PR line differs in any field (a label added or removed, a
  retarget, a new base sha). A re-read that fails, or answers something that is not an object,
  refuses (exit 2). Nothing is retried.

What it does not do, stated: GitHub's merge API binds no label, base or check run, so the window
is narrowed, not closed. A change after the last reads is not seen. For the labels and the base
that is the rest of the PR read plus `gh pr merge`'s own PR lookup and merge mutation; for the
gate's runs, one read more. Measured from a Mac on 2026-11-19 at 0.7-1.5 s per call, that is
roughly 2-3 s for the labels and base and 3-4 s for the gate's runs, and nothing bounds a slow
call. The base sha compared is the one GitHub records on the PR (it changes on a retarget or a PR
event, not on every push to the base); on a maintenance base the base's live tip is also re-read
and must still be `--base-sha`. A connector review or another check run that changes on the same
head after the check is not re-read: only the gate's own run is.

`test-merge.sh` covers each refusal with the stand-in `gh` (a gate run created after the check,
queued or green; a re-run attempt of the judged run; the gate run gone; `review-override` removed;
a label added; a retarget; a new base sha; each re-read failing or garbled; the read before the
check failing) and the order of the calls: the PR line read before the check and again after it,
then the gate's runs and the PR as the last reads before the merge, on main and on a maintenance
base. `test-merge-git.sh` refuses a label change after the check on `--method merge`, `--repair`
and a maintenance base.

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
real git history, maintenance bases included; `test-gate-pin.sh` checks the gate workflow's
maintenance-base pin and base guard; `codex-review-test.yaml` runs them with shellcheck.

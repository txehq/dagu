# TXE periodic reviewer

The reviewer continues a registered job after the coding session that created
it is gone. It is two DAGs per machine, rendered by `dagu txe review render`
and installed on the service:

| DAG | Purpose |
| --- | --- |
| `txe-reviewer-<machine>` | A scheduled tick. Each run reviews at most one due job: `prepare` claims it and builds a context packet, `agent` asks a fresh agent CLI for one structured decision, `apply` records the result. |
| `txe-decide-<machine>` | One run per proposal. It stops at a native human task and, once answered, runs the single effect an approval authorizes. |

`<machine>` is the registry machine id without its `mch_` prefix, because
Dagu rejects DAG names of 40 characters or more. Read the names from a
proposal's `native_task`; do not build them.

## What the agent can do

Nothing but answer. It is launched with no tools, no MCP servers, no user or
project settings and no saved session, and it is given only the packet. Its
answer is a request: `apply` runs an action only when the job's saved policy
declares it `routine`, files any other declared action as a proposal, and
turns anything undeclared into a question. Parameters reach an action as
`TXE_PARAM_<NAME>` environment variables, never as shell text.

## Reviewer profile

Set `AgentConfigDir` to an agent profile that is already logged in on the
machine that runs the worker. The profile is used by reference only: do not
copy it or its credentials anywhere.

The rendered agent step isolates the review from that profile's everyday
configuration. It passes an empty tool list, an empty settings source list
(so the profile's settings, hooks and plugins are not loaded), no MCP
servers and no saved session. Measured with claude 2.1.295 on a shared
interactive profile: about 4.7k input tokens per review with these flags,
against about 38k when they are missing.

Disabling the profile's settings also drops its model choice. To keep
reviews on the model the profile is configured with, read the `model` value
from that profile's settings and pass it as `AgentModel`; leave it empty to
use the CLI's default.

If the profile's login expires, the review records a
`reviewer_authentication_required` exception for the machine and defers the
job's next review by one cadence; it does not retry on every tick and leaves
no session waiting.

## Environment

Dagu passes a step only an allowlist of the worker's environment (`PATH`,
`HOME`, and the `DAGU_`, `DAG_`, `LC_` and `KUBERNETES_` prefixes). Anything
else a review step needs must be rendered into the DAG:

| Variable | Set by | Meaning |
| --- | --- | --- |
| `TXE_DAGU_REVIEWER=1` | always | Marks a review. Job registration refuses to run under it, so a review cannot register work or start another reviewer. |
| `CLAUDE_CONFIG_DIR` | `AgentConfigDir` | The reviewer profile. |

## Bounds

- Concurrency: `max_active_runs: 1` and `overlap_policy: skip` on the tick,
  plus one fenced claim per job in the registry.
- Duration: a run timeout, a shorter agent step timeout, and a per-action
  timeout. The claim TTL must exceed the run timeout plus the worker's
  disconnect cancellation window.
- Attempts: a routine action that failed `max_attempts` times in a row is
  proposed instead of tried again. An action whose outcome is unknown is
  never retried: a declared `reconcile` probe settles it, or the owner
  answers its escalation. Until then the same action on the same target is
  not run again, and only the answer `retry` allows it, for one attempt.
- Retrying a run: `dagu.retry_run` is bound to one failed execution of the
  run (attempt id and queued time), the DAG snapshot it ran and the job's
  package. A run of an older version is never retried, and nothing is
  dispatched once the run has moved on from that execution. A retry the
  reviewer proposes runs from its decision run once the owner answers
  `retry`; one the owner requests directly is already decided and is run by
  the next tick. Either way it is dispatched at most once, and it is
  recorded as done only when another execution is seen on the run; the
  receipt is that execution's reference and says what it was doing, not
  that the job succeeded. A dispatch whose result was not seen is recorded
  as uncertain and is settled from the run later or put to the owner.
- Leases: an action starts only if the claim outlives its timeout, and its
  process is killed when its grant ends. A process frozen between that
  check and its start can still act late; a destination that must exclude
  this has to enforce the attempt's key itself.

## What a review is shown of the job's runs

- One result per run: its latest execution. An execution is an attempt as
  queued at one time. A retry keeps the run id; Dagu either starts a new
  attempt for it or queues the latest attempt again under the same attempt
  id, so the pair of attempt id and queued time is what identifies it. The
  service lists only the latest. An execution that was replaced by a retry
  between two reviews is therefore never reviewed. Each review records what
  it covered as run and execution (`covered_executions`), so a review of a
  run is never read as a review of every execution of it.
- A retried run is shown again when its new execution ends, on either
  retry path. Two results with the same end time are told apart by run and
  execution. A result reported late, with an end time before results
  already covered, is still shown: a run seen unfinished stays owed until a
  review has been shown its result.
- A listing that takes several requests is read twice, and only results
  that both passes saw finished are returned. A result whose run is retried
  while its evidence is being read is held back for the next review, so the
  status of one execution is never paired with the output of another.
- This rests on one assumption the service does not guarantee: a run that
  starts after a checkpoint ends after everything that checkpoint covered.
  A job's runs are on one machine and their times come from its clock, so
  it fails only if that clock is set back between two runs.
- Bounds: at most 50 runs per review, and a cursor of bounded size kept
  apart from what the agent is shown. The supported bound is exact: at most
  512 results of one job sharing one end timestamp, and at most 512 of its
  runs queued, executing or owed a review at once. Nothing is dropped or
  approximated to fit. A job beyond either gets a `review_runs_untrackable`
  exception saying which bound and by how much, its review is deferred by
  one cadence and its coverage is left exactly as it was, so no result is
  passed over. Reviews resume when the job is within the bound again; a
  job that stays beyond it stays unreviewed and visible. Raising the bound
  is capacity work, not part of this phase.

## Declared actions

An action's `command` must exit `0` only when its effect was applied and
print its external receipt as the last line of stdout. Exit `3` states that
nothing was applied. `idempotency` tells the reviewer how to read any other
ending:

| Class | Non-zero exit | Timeout or crash |
| --- | --- | --- |
| `read_only` | failed | failed |
| `keyed` (destination deduplicates on `TXE_IDEMPOTENCY_KEY`) | uncertain | uncertain |
| `none` | uncertain | uncertain |

`TXE_IDEMPOTENCY_KEY` is the id of one attempt. It lets a destination ignore
a repeat of that same attempt; a later review's attempt has a new key.

A `reconcile` probe exits `0` if the effect is present at the destination,
`3` if it is absent, and anything else if it cannot tell. Only presence
settles an interrupted attempt. Absence does not prove a request already
sent will not still take effect, so the attempt goes to the owner instead of
being closed as not applied.

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

- Machine: a reviewer reviews and acts only on jobs registered on its own
  machine (`--machine`). Handed a job of another machine, by a decision run
  enqueued for the wrong machine or by a mistaken call, it claims nothing
  and runs nothing, whatever decision exists: the job's commands, package
  and credentials are that machine's.
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
  run (attempt id and queue marker), the DAG snapshot it ran and the job's
  package. A run of an older version is never retried. The retry is sent
  with the execution it is for, and the service admits it only while that
  is the run's latest execution, checking it as it admits the retry; a run
  that moved on is refused there, whatever the reviewer read a moment
  before. A retry the reviewer proposes runs from its decision run once the
  owner answers `retry`; one the owner requests directly is already decided
  and is run by the next tick. Either way it is sent at most once.
  What is recorded: done, only when the service admitted the request and
  another execution of the run is seen queued, running or over, with that
  execution's reference as receipt and its status, never "the job
  succeeded"; not dispatched, only for the two refusals the service makes
  before starting anything (`execution_changed`,
  `conditional_retry_unsupported`); uncertain for everything else. An
  attempt that was created but is not started is a reservation, not a
  retry. An uncertain retry the service had admitted is settled from the
  run when its execution shows up; while the run shows only the
  reservation it stays uncertain and is looked at again by every review,
  however long a worker takes, and the owner is not asked, because an
  action put to the owner is not probed again. The service does not name
  the execution it admits, so the receipt is the first execution seen
  after the retried one and the record says so: if that execution has
  already finished and been retried by someone else, the receipt names
  the later one (open, needs the service to name the admitted execution).
  One whose answer was never known, such
  as a failed request or a reviewer that died first, is not settled from
  the run, because a newer execution may be someone else's retry: it goes
  to the owner. Nothing is ever sent again because time passed.
- Leases: an action starts only if the claim outlives its timeout, and its
  process is killed when its grant ends. A process frozen between that
  check and its start can still act late; a destination that must exclude
  this has to enforce the attempt's key itself.

## What a review is shown of the job's runs

- One result per run: its latest execution. An execution is an attempt as
  queued at one time. A retry keeps the run id; Dagu either starts a new
  attempt for it or queues the latest attempt again under the same attempt
  id, so the pair of attempt id and queue marker is what identifies it. The
  service lists only the latest. An execution that was replaced by a retry
  between two reviews is therefore never reviewed, and nothing here claims
  otherwise.
- What has been covered is what the job's recorded reviews say they
  covered. Each review records the results it was shown by run and
  execution (`covered_executions`), and a result is shown to reviews until
  a recorded review names it. There is no cursor that could move past a
  result: a result is covered only once the review that was shown it has
  been persisted, and a crash, a failed read or a review that was never
  recorded covers nothing.
- So a retried run is shown again when its new execution ends, on either
  retry path; results with the same end time are separate results; a
  result reported late, a run created while the history was being listed
  and a queued run that ends later are all returned, whatever their times.
  End times only order what one review is shown.
- A result whose run is retried while its evidence is being read is not
  returned that time, so the status of one execution is never paired with
  the output of another. No review names it, so the next review meets the
  run's latest execution.
- Evidence that does not fit is shortened, never dropped silently: a run
  with more than 12 steps keeps failed, aborted and rejected steps first
  (the earliest of them always), then any other status that is not a plain
  success, then steps that did not run, and successes last, and it states
  by status how many steps it left out (`omitted_steps`), and step output is cut to its end only when one run
  alone is too large. Such a run is marked `evidence_trimmed`, the agent is
  told not to pass it on what it cannot see, and the review that covers it
  records it in `trimmed_executions`. A step that printed more than the end
  that is shown is marked `truncated`. When the reviewer recommends
  completing or retiring a job, the question put to the owner names
  everything the review was not shown: runs with evidence left out, runs
  whose steps printed more than was shown, runs not shown at all, and other
  records left out to fit.
- Bounds: at most 50 runs per review, oldest first, and a packet of at
  most 120 KiB; the rest wait for the next one. The size is what the
  process hand-off allows: the packet travels as a step output, which the
  service puts into the environment of the later steps, and Linux starts no
  process with an environment string over 128 KiB. No number of results, unfinished runs or queued runs stops a
  job's reviews.
- Cost: every review reads the job's whole review history and run list.
  The registry's review list has no paging yet. This is the plain, exact
  form; making it cheaper is capacity work and must keep the same meaning
  of covered.
- The service must identify executions. A finished run reported without
  an attempt id fails the review step with an explicit error naming the
  run; it is never recorded under its run id alone, which would pass off a
  later retry of it as already reviewed. A review recorded before coverage
  was by execution names no executions and covers nothing: its runs are
  shown again, not taken for covered.

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

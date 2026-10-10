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
`TXE_PARAM_<NAME>` environment variables, never as shell text. The registry
validates the values against the `param_schema` the job declares for the
action before it grants an attempt, as JSON and without coercion. The
reviewer carries every value as text and sends it as the JSON type its
property declares (`integer`, `number`, `boolean`) when the text is exactly
a value of that type, and as a string otherwise; a value the schema does not
allow runs nothing and is recorded on the review with the registry's reason.

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

A job's declared action and reconcile commands are started from the review
step, and do not inherit what is the reviewer's own. Removed before the
command starts: every `DAGU_*` and `TXE_DAGU_*` variable
(the hub client's context and the service's settings; also `TXE_FIXTURE_*`,
the bindings of the test fixture's reviewer), the review's own variables
(`TXE_PACKET`, `TXE_DECISION`, `TXE_PROPOSAL_ID`, `TXE_DECISION_ID`, and
every `TXE_PARAM_*`, which could otherwise pass for a parameter of the
action), and the agent's profile and keys (`CLAUDE_*`, `ANTHROPIC_*`,
`CODEX_*`, `OPENAI_*`). Kept: `TXE_DAGU_REVIEWER=1`, so the command cannot
register work either. Set afresh for each command: the action's own
variables (`TXE_JOB_ID`, `TXE_OWNER_ID`, `TXE_ACTION_ID`, `TXE_ACTION_NAME`,
`TXE_TARGET_ID`, `TXE_IDEMPOTENCY_KEY`, `TXE_PARAM_<NAME>`). Everything else
the step has is inherited, so what a job's command needs to reach its
resources is rendered into the DAG like any other variable and reaches it:
`KUBECONFIG`, and the credential references a job declares, which have
`TXE_` names of their own (`TXE_KUBECONFIG`, `TXE_KUBE_CONTEXT`). A variable
with one of the removed names or prefixes cannot be given to a job's command
this way.

A credential the job declares in `credential_refs` is the deliberate way a
credential reaches its command, and it is supplied whatever its name: each
reference is resolved on the job's machine when the command is started (a
`file` is read as it is, an `env` variable is copied from the review step's
environment) and set under the name the job gave it, replacing anything
inherited under that name. A job that declares its own `OPENAI_API_KEY` gets
the declared one, not the review agent's (unless its declaration names the
agent's own key or file as the source, which is the owner's choice at
registration). A reference that cannot be
resolved stops the command before it starts, as it stops a run, and the
record names the reference and the kind of failure: not a value, and not
where the credential is kept. A reference cannot use a name that
identifies the action or marks the review. The references are not part of
what the review agent is shown. They are trusted input to the reviewer: it
reads whatever a reference names.

So what a job's commands are, and what they are given, is not taken on the
registry's word. The registry's record of a version can be changed after
registration by whoever can write to it. `dagu txe review` reads this
machine's own record of the registration (the request `dagu txe register`
filed beside the version's receipt) and starts a job's commands only when
the registry's current version is the version this machine registered:
the whole of it, not a list of fields. Both are put into the registry's own
stored form and through the registry's own rule for storing a version
(its validation, its defaults, the fields it derives), so the version this
machine filed becomes exactly what an honest registry stored, and nothing
of that rule is repeated in the reviewer. A version the rule refuses is
not a registered version, on either side. That rule validates by today's
rules: a job whose version was stored when the rules were laxer, and no
longer passes them, runs no command although nothing about it was altered.
Its exception says so and says to update the job from its machine, which
stores it under the current rules. What the registry assigns at
commit (owner, version number, stamps) is left out, each parameter schema
is compared decoded, and what means nothing (absent, null, empty, zero,
false) is the same however it is spelled, except inside a parameter schema
and inside a target's stable id, which is the target's identity and is
compared member for member.
So the package, the DAG text,
the schedule, the targets, the expected outcome, the review policy with
every permitted action, and the title and purpose the review agent reads
are all bound, and a field the registry later starts keeping is bound
without anyone remembering to add it. The job's owner must be the one this
machine registered it for, and the registry's current version must not be
older than the newest version this machine has sent, finished or not: an
older one may match what was once registered and was replaced. This holds
for every job, with or without credentials. The credential references
used are the local ones. What a job is doing now is not part of it: its
availability, lifecycle, runs, and people's decisions.

If this machine has no usable record of the version, or anything differs,
none of the job's commands is started: no routine action, no approved
action (its decision is kept for later), no reconcile probe. Nothing is
read, and the job's declaration is not used to settle an interrupted
action either: it stays unresolved. The job is still reviewed and questions still reach the owner, and
the exception `job_commands_unbound` says which part of the version
differs, without any value from it. It is filed under a scope of its own (`binding`), about that
version of the job: it changes neither the job's nor the reviewer's
availability, a recorded review does not clear it, and it ends when the
reviewer reports the job bound again or the job gets a new version. `dagu txe update <job id> -f <spec>
--expected-version <n>` from that machine binds it and keeps the job and
its history (a job cannot be registered a second time); an update that
was interrupted is finished with `dagu txe resume <request id>`. While an
update is in flight the registry is ahead of this machine's record and
the job's commands wait. A retry
of a run is the service's own operation and is not affected.

This protects a job registered from its machine against a changed
registry record. It is not isolation from the service that dispatches work
to the machine, nor from other code running as the same user.

A job's credential files are read with the checks this machine
applies to them elsewhere (an absolute, clean path to a regular file that
is not a symbolic link and that only its owner can write). On Windows that
read inspects no ownership or access list and its symbolic-link check can
be raced, so it is weaker there.

This removes accidental inheritance. It is not isolation: the command runs
as the same operating-system user as the reviewer and can read the same
files.

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
  What is recorded: done, only when the service admitted the request,
  named the execution it admitted it as, and that execution is seen on
  the run queued, running or over, with its reference as receipt and its
  status, never "the job succeeded"; not dispatched, only for the two
  refusals the service makes before starting anything
  (`execution_changed`, `conditional_retry_unsupported`); uncertain for
  everything else. The named execution while it is created but not
  started is a reservation, not a retry: the action stays uncertain and
  is looked at again by every review, however long a worker takes, and
  the owner is not asked meanwhile, because an action put to the owner is
  not probed again. A reservation still not started 30 minutes after the
  registry granted that attempt (both ends of the time are the
  registry's: the grant and the review's claim; the reviewer host's
  clock is not used, and the time only decides when the owner is told)
  is reported once as the exception `retry_reservation_stalled`
  about that attempt of the action, naming the execution and the machine:
  check that a worker for the job is connected and can take queued work.
  It asks for no decision and allows no retry; do not retry the run by
  hand while the execution can still start. The registry resolves it when
  the attempt is settled. Any other execution on the run is not this retry's,
  even a newer one: the admitted execution may have finished and been
  retried by someone else. That, and an admission that names no
  execution (a service without the answer body
  `{attemptId, queuedAt, executionRef}`), go to the owner; nothing on the
  run is recorded as the retry.
  One whose answer was never known, such
  as a failed request or a reviewer that died first, is not settled from
  the run, because a newer execution may be someone else's retry: it goes
  to the owner. Nothing is ever sent again because time passed.
  The service can admit a retry, create its execution and then abandon
  the preparation without dispatching it; it records that. A retry is
  settled as not dispatched only by that record for exactly the admitted
  execution, read before any receipt is settled. The retried execution
  being the latest again, a reservation that is gone, a record about
  another execution of the run, a record the service does not vouch for,
  or a service that keeps or returns no such records settle nothing: the
  retry stays uncertain or goes to the owner. A failed admitted execution
  is taken for a retry that ran only when the records show no abandonment
  of it. In review evidence a failed run carries `preparation`:
  `abandoned_before_dispatch` when the service recorded that it never
  started, `unknown` when it could not say.
  When the owner answers `retry` to the question about an attempt whose
  outcome is unknown, the question's decision run executes the original
  decision once more: for a run retry, with the same expected execution,
  so a run that has moved on since is refused and never retargeted. The
  registry allows a run retry two attempts; the question about the second
  offers no `retry`.
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

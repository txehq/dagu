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

## Installing the pair

Install them from the machine itself:

```sh
dagu txe review install --state-dir <durable dir> --agent-config-dir <profile> --agent-model <model> [--schedule <cron>]
```

It takes `render`'s flags, renders the pair for this machine (machine.json) and creates or updates
each DAG on the hub, the decision DAG first, then reads each write back. A DAG of that name that
the renderer did not write is left alone. A repeated install with the same flags changes nothing.

An update never resets a setting silently. When the installed reviewer's schedule, agent model,
agent profile, state directory, TXE home or review command differs from what the install would
render, it stops and names each one; give that flag with the installed value to keep it, or with a
new one to change it.

Both DAGs are checked before either is written. If the second write fails, the first stays, the
output says so, and running the install again finishes it.

**Credentials.** The install writes through this machine's hub connection. On a hub that enforces
owners (`txe.authz.mode: enforce`), only a person or CLI sign-in of the machine's owner may write a
machine's DAGs: sign in first with `dagu txe login`. The platform administrator cannot write them.
Without a sign-in, the context's API key is used, as before, which a hub that does not enforce
owners accepts. A refused sign-in is reported and never retried with the API key.

**Installed is not runnable.** The DAGs run only when this machine's worker is connected. The hub
does not show an owner's sign-in its workers, so the output then says `runnable: unknown`.

Each rendered document is pinned to its own machine with a literal `worker_selector` and declares
no name of its own, as the hub requires for a machine's DAGs.

## Pausing and resuming the schedules

To stop new reviews for a while (maintenance, a broken agent profile), suspend the pair and resume
it afterwards, with the machine owner's sign-in as the bearer:

```sh
POST /api/v1/dags/txe-reviewer-<machine>/suspend   {"suspend": true}    # false resumes
POST /api/v1/dags/txe-decide-<machine>/suspend     {"suspend": true}
GET  /api/v1/dags/txe-reviewer-<machine>                                 # "suspended" reads it back
```

Suspension is only the scheduler's flag. The spec, its schedule and the run history are kept, and a
reinstall while suspended leaves it suspended. A run already running carries on; stop it on its own
run's route. Queued runs differ by what started them. One the schedule started (a scheduled, catch-up
or retry run) is aborted and dequeued while the DAG is suspended, not held until it resumes. One
started by hand, by a webhook or as a sub-DAG run is dispatched as usual.

On a hub that enforces owners, the call is decided by the machine's owner, as running its DAGs is.
A person or CLI sign-in of the owner may suspend and resume. Another owner's sign-in and a legacy API
key get 404, and the platform administrator gets 403. On a hub that does not, the hub's own checks
apply, as before. The hub's `run_dags` permission must be on, which is the default.

**Placement under enforce.** Besides the install rules above, every non-empty `worker_selector`
in a machine's DAG, on a document or a step, must name `txe.machine` of this machine, written
without surrounding spaces. A step may call only this machine's own DAGs. The coordinator also hands
a machine's worker only tasks pinned to that machine. Unpinned DAGs wait for a worker that is no
machine's.

Enforce is a source-level capability here: live `txe.authz.mode: enforce` activation has not been
performed on any hub.

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
stored form and given the registry's own defaults and derived fields, by
the function registration itself uses, so the version this machine filed
becomes exactly what an honest registry stored and nothing of that is
repeated in the reviewer. It is not the registry's admission check: a
version stored when the rules were laxer is still the version that was
registered, and its commands run. A derived field (the job id, the DAG's
name, the digest of its text) is filled in only where a side leaves it out;
one the registry's copy states is compared as stated. What the registry assigns at
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
- Registration: a job whose registration is not `ready` is not reviewed. That
  is an update that was interrupted (until `dagu txe resume` finishes it) or
  the losing record of a registration made twice. The registry grants no
  review claim on such a job, so no agent is started and no action of the
  job is requested;
  the tick names the job and the state in its log and goes on to the next
  one. A tick that finds only such jobs has no work and succeeds. This is
  about review claims only: when the reviewer is handed a job that has
  ended (retired or completed), it may still take a reconcile claim to
  settle actions left open on it, whatever its registration, and that
  never starts an action again. A job
  that cannot be read or claimed for any other reason (the service
  unavailable, a rejected login, a registration state this reviewer does
  not know, a refusal the job's record does not explain) still fails the
  tick when nothing else was reviewed.
- Updates: a job updated while it is being reviewed ends that review. The
  registry ends the review's claim with the update and refuses a write
  made against another version than the job's, and every proposal, review
  and checkpoint is sent with the version the review read. A review that meets this at any of
  its writes is abandoned: it leaves the checkpoint where it was, raises
  no exception about being abandoned, and its run succeeds, saying why (`aborted`) and what it
  had already written, which stays written (a review record made just
  before the update is kept and completed by the next review; a report
  that the job's target is unreachable, already made, stands until the
  next review's finding replaces it). The next tick reviews the job
  as it now is. An action already begun is in the journal: the registry
  interrupts it with the claim, a later review settles it, and it is never
  run again. A claim that is stale for another reason (it expired and was
  taken) on a job that did not change still fails the step.
- Cadence: a job's `review_policy.cadence` is a cron expression, and a
  job's next review is that expression's next occurrence in the timezone of
  the job's own schedule (`schedule.timezone`; UTC when a version carries
  none). The cadence names no zone of its own: one that starts with `TZ=`
  or `CRON_TZ=` is refused as unreadable. A plain duration such as `1h` is accepted as well and is
  counted from the review. The agent may ask to look again sooner, never
  later; while more runs are waiting than one review covers, the next
  review is a minute away; and no review is set less than a minute ahead,
  also when one is put off because the job could not be reviewed or the
  agent failed.
  A cadence that is neither a cron expression nor a duration, a cron
  expression that never occurs (31 February), or a text longer than 256
  bytes, is not taken for one: the job is reviewed every hour, and the exception
  `review_cadence_invalid` says so for that version of the job, quoting
  what was declared, until the job gets a version whose cadence can be
  read (`dagu txe update`). A job that declares no cadence at all is
  reviewed every hour. The reviewer's tick (`--schedule`) is only how
  often it looks for due jobs.
- History: both DAGs declare `hist_retention_days: 36500`, as every DAG TXE
  renders does (see the contract's job DAG). A review's packet and decision
  are run artifacts, and a decision run holds the person's answer, so none
  of them gets Dagu's 30-day default or a base configuration's. A copy
  installed from an earlier render declares nothing until it is rendered
  and installed again; a run started with local storage still does not
  prune it, because it carries TXE's machine selector.
- Concurrency: `max_active_runs: 1` and `overlap_policy: skip` on the tick,
  plus one fenced claim per job in the registry.
- Duration: a run timeout, a shorter agent step timeout, and a per-action
  timeout. The claim TTL must exceed the run timeout plus the worker's
  disconnect cancellation window.
- A dead claim: a tick that dies (the worker or the service restarted
  under it) keeps its job claimed for the claim's whole lifetime, 20
  minutes. The registry cannot tell a dead holder from a slow one, and no
  claim is released on the assumption that its holder died. Reviews of
  that job wait for the claim to end. A decision approved meanwhile waits
  too, and then runs by itself: the decision DAG's execute step exits 75
  when the job is claimed by another holder, and is retried on that code
  alone, once a minute, 22 times, which is longer than a claim lives. Each
  try reads the decision, the proposal and the job again, so an approval
  that stopped holding while it waited runs nothing. Tries do not add
  up to more than the registry allows: an action that succeeded is never
  granted again, one whose outcome is unknown is settled by a probe or a
  person before anything else, and a further attempt after a failure
  follows the job's attempt limit. The decision DAG carries its own run
  timeout (the waits, one whole try, and five minutes), so a shorter
  timeout in a base configuration cannot end the wait early. Any other failure of the step
  is not retried and fails the run. If the worker is interrupted again
  during that wait, or the wait runs out, the decision run ends failed and
  a person retries it from the dashboard; the approval is not lost and
  still runs at most once.
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
  The request also says which attempt of which action it is made for
  (`retryRequest`: the registry's action id, the attempt number, the
  action's binding digest, all taken from the registry's record). The
  service records that on the execution it admits, and the registry takes
  an execution for this retry's only by that record, so a later retry of
  the run by anyone is never taken for this one. A retry the registry's
  record gives no attempt or binding digest for is not sent. The answer
  names this request's execution only if it carries the request's id
  (`retryRequestId`, derived by the service's own function); an answer
  without it, or with another id, names none.
  When the answer is lost (the request fails, the service says the
  dispatch is uncertain, the reviewer dies first, or the answer names no
  execution), the reviewer asks the service for its record of the request
  by that id (`GET /dag-runs/{name}/{dagRunId}/retry-requests/{id}`), at
  once and again in every later review while the attempt is unresolved.
  The record answers only when all of it is this request's: the same id,
  action, attempt, binding digest and retried execution, an execution
  reference its attempt and queued time give, and a state of `admitted`
  or `abandoned`. `admitted` names the retry's execution, which is then
  read like one whose answer arrived. `abandoned` is proof, for this
  request, that nothing ran: the retry is recorded as not dispatched.
  No record (404), a refusal to show it, or a record that is not this
  request's is no answer, and never proof that nothing was admitted: the
  request may still be admitted later, or the run's history may be gone.
  The retry then stays unknown and goes to the owner, as before.
  A read that fails (the service unreachable, a server error, a reply
  that cannot be decoded) is different: the service was not asked. The
  owner is not asked a question, because a question ends the probing; the
  action stays uncertain and every review reads again. If that lasts 30
  minutes from the registry's grant of the attempt, the exception
  `retry_record_unreadable` is reported about that attempt: check that the
  service's API can read the run's executions. It asks for no decision.
  An execution the record names is written on the action: with the
  outcome that settles it, or, while the action stays uncertain (the
  execution is still a reservation, or the registry does not take it as
  dispatched yet), on its own. The registry checks it against the run's
  history for this attempt's request, stores it once and never replaces
  it, and holds every later outcome of the attempt to it. From then on
  the retry is read from the run by that execution, and the record of
  the request is not asked for again: if the service later loses the
  record or cannot read it, the retry is still the reservation it was
  seen to be. It is not sent again, not put to the owner as unknown, and
  not taken for a retry that had no effect.
  A run that cannot be read (the service unreachable, a server error) is
  treated like a record that cannot be read: it says nothing about a known
  execution, so the action stays uncertain, the owner is not asked a
  question, and every review reads the run again. After 30 minutes from
  the registry's grant of the attempt the exception `retry_run_unreadable`
  is reported about that attempt: it names the execution and says to check
  that the service's API can read the run. It is a kind of its own, so it
  is reported even when `retry_record_unreadable` was reported for the same
  attempt before. It asks for no decision.
  A run the service answers it does not have, or will not show (404, 401,
  403), is an answer and not a failed read: the run will not come back, so
  the retry goes to the owner with the execution named. It is not recorded
  as not dispatched.
  If the registry refuses to store it (an execution abandoned in the
  meantime, or a registry older than this), the review goes on, the
  refusal is printed in the step's log, and the next review reads the
  record again. Only until it is stored can the service saying it has no
  record of the request send the retry to the owner.
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
  execution from a service that has no record of the request either, go
  to the owner; nothing on the run is recorded as the retry.
  One whose answer was never known, such
  as a failed request or a reviewer that died first, is not settled from
  the run, because a newer execution may be someone else's retry: without
  the service's record of the request it goes to the owner. Nothing is
  ever sent again because time passed.
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
  While an execution of the run has been created and not yet handed to a
  worker, the registry answers `409 not_ready` to proposing, granting and
  settling a retry of that run, and says to ask again. That answer is never
  read as an outcome. A retry whose admitted execution the run shows
  dispatched, and which the registry does not settle yet, is recorded as
  uncertain with that execution and settled by a later review. If the
  registry still refuses 30 minutes after it granted the attempt (the same
  two registry times as for a stalled reservation), the exception
  `retry_settlement_blocked` is reported about that attempt: the cause is
  the service's record of the execution's preparation on the hub, not an
  absent worker. It asks for no decision; the action stays uncertain and
  keeps being probed. A decision
  whose run shows another execution only being prepared is not ended as
  skipped: its step fails and is tried again by its retry policy (five
  times, a minute apart), nothing is journaled and the decision keeps its
  attempt. If the preparation outlasts that, the decision's run ends
  failed with that reason, visibly, instead of succeeding with nothing done.
  This is a known limitation with a manual recovery: nothing runs the
  decision again by itself. The decision is kept as it is in the registry,
  decided and not carried out, and no action is journaled for it. To carry
  it out, retry the failed decision run (`txe-decide-...`) once the other
  execution is dispatched or abandoned, from the dashboard (Retry on the
  run) or the service's API
  (`POST /dag-runs/{name}/{dagRunId}/retry` with the JSON body
  `{"dagRunId": "<the same run id>"}`). Either way it takes a signed-in
  person who may run DAGs in the run's workspace, on a service that
  allows running DAGs; a viewer is refused. The `dagu retry` command
  does not do it: it refuses a DAG that has a worker selector, which the
  decision DAG has. The `execute` step then runs again, reads the
  registry's decision, and either retries the run or ends as skipped
  because the run has moved on. Do not record the decision as done by
  hand. This recovery was exercised on a local hub through the API, with
  the other execution simulated in the reviewer's view of the run; it has
  not been exercised against a real preparation by another caller.
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
- The reviewer reads the job's whole run history from the start. Asked for
  no range, the service lists only runs since its local midnight, and a run
  that ended before it would never be reviewed.
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

An attempt settled on its probe is recorded as done, and its record says
that a probe found it: the receipt is `probe:<action id>:<attempt>:<review
run>`, naming the attempt and the review run that ran the probe, and the
outcome carries `confirmed_by: probe`, that run, and a SHA-256 digest of
what the probe wrote to its standard output (of the last 64 KiB of it, if
it wrote more; absent if it wrote nothing). Nothing a probe prints leaves
the review process: its output is only counted into that digest, and its
error output is discarded and not written to the step's log as an
action's is. A probe is given what the job's commands are given,
credentials among it, and an outcome is kept with the action and shown to
people without the masking step output gets. What a probe found is its
exit code. The digest is not salted, so it does not hide a short or
guessable output; a probe should print nothing it would mind being
guessed. The attempt is never given the receipt the action itself would
have printed.

A command that does not return before its timeout is stopped when the
attempt's grant ends, and the attempt is then uncertain (failed, for a
`read_only` action). The registry marks an attempt whose grant has ended
the same way by itself, before it looks at any write, so the reviewer's
record of that outcome arrives second and is refused. The refusal carries
the attempt as the registry held it. The review goes on only when that is
this same attempt (action, grant, attempt number, job version, name,
target, parameters) in the outcome being recorded, including the execution
it was seen to admit; any difference fails the step. The same comparison
is made against a read of the job's actions when the refusal carries no
attempt, when the registry says the action is no longer in flight, and
when the record got no answer at all and may have been written.

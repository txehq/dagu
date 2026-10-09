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

Use a dedicated agent profile for reviews and set it as `AgentConfigDir`.
A shared interactive profile loads that profile's global instructions into
every review (measured: about 38k tokens with the shared profile) and may
carry session hooks.

The profile must:

- be logged in once, interactively, on the machine that runs the worker;
- contain no hooks, plugins, MCP servers or global instruction files;
- live outside any worktree.

Do not copy credentials into it from another profile. If its login expires,
the review records a `reviewer_authentication_required` exception for the
machine and defers the job's next review by one cadence; it does not retry
on every tick and leaves no session waiting.

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
  never retried: a declared `reconcile` probe settles it, or a human does.

## Declared actions

An action's `command` must exit `0` only when its effect was applied and
print its external receipt as the last line of stdout. Exit `3` states that
nothing was applied. `idempotency` tells the reviewer how to read any other
ending:

| Class | Non-zero exit | Timeout or crash |
| --- | --- | --- |
| `read_only` | failed | failed |
| `keyed` (destination deduplicates on `TXE_IDEMPOTENCY_KEY`) | failed | uncertain |
| `none` | uncertain | uncertain |

A `reconcile` probe exits `0` if the effect is present at the destination,
`3` if it is absent, and anything else if it cannot tell.

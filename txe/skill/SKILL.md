---
name: txe-dagu-jobs
description: Register, find, inspect and update durable scheduled jobs that must keep running after this coding session and its worktree are gone, using `dagu txe`. Use when the user asks to keep monitoring, collecting or validating something over time, to leave a check running, to convert a background loop or timer into something durable, or before removing a worktree that a scheduled script depends on.
---

# Durable jobs with `dagu txe`

A job registered here outlives the session that created it. The hub schedules it, this machine's worker runs it from a read-only copy of its files, and a later reviewer reads its results with no access to this conversation. So registration has to capture two things: the files the job needs, and enough context that a stranger can judge its results.

A background shell process, a `sleep` loop or a session timer is not a durable job. It stops when the session does.

## Before you register

1. **Check the machine.** Run `dagu txe doctor`. Fix what it reports before going further; each failed check names the action.
2. **Look for an existing job.** Another session may already have registered this work.
   - `dagu txe list --target <part of the resource's id or name>`
   - `dagu txe list --job-key <the key you would use>`
   - If one matches, run `dagu txe inspect <job id>` and read its purpose. Update that job instead of registering a second one.

## Write the job spec

Put a `job.yaml` beside the script. Start from one of the examples in `examples/` (health check, data collector, validation that completes). Every field below is required unless marked optional; registration refuses a spec with gaps and lists all of them.

| Field | What to write |
|---|---|
| `job_key` | A stable lowercase name for this job within its project, such as `hub-volume-health`. Registering the same key twice is refused. |
| `title`, `purpose` | What the job is for, written for someone who never saw this conversation. |
| `targets` | The resource the job watches or acts on: `kind`, and a `stable_id` that survives a rename or a recreation (a UID, not a name). |
| `schedule` | `cron` (five fields), `timezone`, `timeout_sec`. Optional: `overlap`, `retry` with `retry_interval_sec`, `catchup_window`. |
| `package` | `include`: the files and directories the job needs, relative to the spec. `entrypoint`: the command. Uncommitted files are packaged as they are. |
| `env` | Optional. Literal, non-secret settings for the script. |
| `credential_refs` | Optional. See "Credentials" below. |
| `expected_outcome` | `success_criteria`: what a good result looks like. `deliverables`: optional, see "Results" below. |
| `lifetime` | `expires_at`, or `open_ended: true` if the job really has no end date. |
| `review_policy` | `cadence` (cron) and `brief`: what a reviewer should look for and what it may do. Optional `permitted_actions` and `human_decision_conditions`. |
| `retirement_rules` | Optional. What happens when the target is deleted or replaced, or the job completes. |

Review cadence is separate from the schedule. A check can run every five minutes and be reviewed once a day.

### Bound what a reviewer may pass to an action

A permitted action that takes parameters should say which ones. Give the action a `param_schema`: a JSON Schema, written as a YAML mapping.

```yaml
review_policy:
  permitted_actions:
    - name: reopen-ticket
      command: ./reopen.sh
      timeout_sec: 60
      param_schema:
        type: object
        properties:
          reason: {type: string, maxLength: 200}
        required: [reason]
        additionalProperties: false
```

- A registry that enforces schemas checks a reviewer's parameters against the schema before it grants an attempt of the action, and refuses parameters that do not match. An action with no `param_schema` has its parameters checked by nothing.
- Registration refuses a spec with a `param_schema` on a hub whose registry does not say it enforces them, because that registry would store the schema and check nothing. The fix is to upgrade the hub, not to remove the schema.
- Parameters reach the command as variables named `TXE_PARAM_<NAME>`, each a string. Declare each one as `type: string`, and set `additionalProperties: false` so that nothing undeclared is passed.
- Such a registry admits JSON Schema draft 2020-12 and only the keywords it enforces exactly. It refuses `format`, `multipleOf`, unknown keywords and references to other documents. `pattern` is read as RE2.
- A `param_schema` that is a list, a single value, or a key left with no value is refused when the spec is read. So is one that uses a YAML merge key (`<<`), which could replace a bound written beside it: write the schema out in full.

## Write the script for an unattended worker

The script runs on this machine, started by the worker, not by a shell you have open. Three things differ from running it yourself.

- **The package is read-only.** Write nothing beside the script. Use the directories the job is given:
  - `TXE_OUTPUT_DIR`: state the job keeps between runs.
  - `TXE_RUN_OUTPUT_DIR`: where this execution writes its results. Deliverables are taken from here. For a job with deliverables the directory exists and is empty when the script starts.
- **The environment is nearly empty.** The script gets `PATH`, `HOME` and little else. A variable exported in your shell is not there. Pass settings through `env` in the spec, and credentials through `credential_refs`.
- **Nobody is logged in.** A browser session, a connector or an interactive `kubectl` or `gh` login in your terminal proves nothing about the worker. Test the access the job needs as described under "Credentials".

## Credentials

A package never contains a credential, and registration refuses files that look like one (`.env`, private keys, kubeconfigs, token files).

Name each credential in `credential_refs` instead:

```yaml
credential_refs:
  - name: LINEAR_API_KEY          # the variable the script reads
    kind: file
    locator: /Users/you/.config/txe/linear-token   # a 0600 file on this machine
```

The worker reads the file when a run starts and gives its content to the script in that variable. Only the path is stored in the job. The value is masked in the step output the hub receives.

Rules for the script:

- Do not write a credential into a deliverable or into a file under the output directories. Files are published as they are; only step output is masked.
- Do not print a multi-line credential one line at a time. A value is masked when it appears whole.
- For Kubernetes, prefer `kubectl --context <name>` over a credential reference. The worker's `HOME` holds the kubeconfig.

If the file is missing or unreadable when a run starts, the run fails before the script starts, and the run's log on the hub names the reference. That is a login to repair on this machine, not a reason to retire the job.

## Results

Step output (stdout and stderr) reaches the hub as the run's log. Keep it short and structured; one JSON line per run works well.

Files reach the hub only if the spec declares them:

```yaml
expected_outcome:
  deliverables:
    - name: snapshot
      path: snapshot.json      # exact name under TXE_RUN_OUTPUT_DIR
      delivery: hub            # also uploaded as a run artifact
      required: true           # a run that does not produce it fails
    - name: raw
      path: raw/export.csv
      delivery: machine        # digest recorded; bytes stay on this machine
```

A `path` is an exact file name: names of letters, digits, `.`, `-` and `_`, separated by `/`, each starting with a letter, digit or `_`. Spaces, patterns, `..`, hidden files and symbolic links are refused, and so is a path that starts with `txe-attempts`. Nothing else the script writes leaves the machine. A `machine` deliverable is recorded as stored on this machine; it cannot be fetched through the hub.

A retried run keeps its run id, and every execution of the script starts with an empty `TXE_RUN_OUTPUT_DIR`. What an earlier execution wrote stays on the machine and is never written over, so do not expect to find a previous try's files there; keep anything a retry should pick up under `TXE_OUTPUT_DIR`. When the script succeeds, its results are sealed: the directory is moved to `runs/<run id>/executions/<reference>/` under `TXE_OUTPUT_DIR` and the digest of every file is recorded. The publish step publishes sealed files only and refuses one that was changed afterwards, so do not leave a process running that keeps writing there. A retry that only repeats the publish step publishes the same sealed files.

## Register

```sh
dagu txe register -f job.yaml --dry-run   # checks the spec, builds the package, shows the DAG
dagu txe register -f job.yaml
```

Registration prints a receipt only when the hub has marked the job ready. Until then nothing is durable.

| Outcome | What it means | What to do |
|---|---|---|
| Receipt | The job is registered and its package is in place. | Continue to "Before removing the worktree". |
| The spec is incomplete | Listed fields are missing. | Fill them in. Do not guess a target or a purpose; ask the user. |
| Duplicate | The job key is already registered. | `inspect` the job named in the message and update it. |
| Incomplete, with a request id | The run was interrupted. No receipt exists. | `dagu txe resume <request id>`. This cannot create a second job. |

Add `--json` to any command for structured output.

Every change records the session that made it. A Claude Code session is recognised by itself. Any other session, including a Codex thread started from a Claude session, must pass `--session <its own identity>` or set `TXE_SESSION`; the command refuses otherwise.

## Before removing the worktree

```sh
dagu txe package verify <job id>
```

A pass means the job's files are intact outside the worktree and the hub has marked the job ready. Only then is the worktree safe to remove as far as this job is concerned. Wait for one scheduled run and check it with `dagu txe inspect <job id>` if the job matters.

A session-exit hook is not the place to register. Register while the session can still read the answer.

## Change a job

```sh
dagu txe inspect <job id>                         # note the version
dagu txe update <job id> -f job.yaml --expected-version <n>
```

An update names the version it was made against. If another session has updated the job since, it is refused and nothing changes: inspect the job again, merge the difference into the spec, and update against the new version. Earlier versions' packages and receipts are kept.

## When the work is over, or the target changes

Say so in the registry, so dependent jobs are reviewed or retired instead of failing forever. `dagu txe --help` lists the lifecycle commands available in this build (retire, pause, resource events). Record a deletion only when it is confirmed. An unreachable target, a denied permission or an expired login is not a deletion.

## Reference

- `dagu txe doctor`: checks this machine, the hub and unfinished registrations.
- `dagu txe list`, `dagu txe inspect <job id>`: every session sees every job. The owner is the same whichever session created it; `created by` records the session.
- `examples/`: three job scripts with the behaviour a reviewer expects (structured output, state under `TXE_OUTPUT_DIR`, a completion signal).

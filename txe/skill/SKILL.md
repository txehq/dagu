---
name: txe-dagu-jobs
description: Register, find, inspect and update durable scheduled jobs that must keep running after this coding session and its worktree are gone, using `dagu txe`. Use when the user asks to keep monitoring, collecting or validating something over time, to leave a check running, to convert a background loop or timer into something durable, or before removing a worktree that a scheduled script depends on.
---

# Durable jobs with `dagu txe`

A job registered here outlives the session that created it. The hub schedules it, this machine's worker runs it from a read-only copy of its files, and a later reviewer reads its results with no access to this conversation. So registration has to capture two things: the files the job needs, and enough context that a stranger can judge its results.

A background shell process, a `sleep` loop or a session timer is not a durable job. It stops when the session does.

## Which `dagu` to run

Every command here is written `dagu txe ...`. Run the `dagu` that the worker installer put in the TXE home, by its full path:

```sh
~/.local/share/txe-dagu/bin/dagu txe doctor
```

The TXE home is `~/.local/share/txe-dagu` unless `TXE_DAGU_HOME` names another directory, and then the binary is `$TXE_DAGU_HOME/bin/dagu`. That binary is the one this machine's jobs run. Nothing makes it the same build as the hub: `dagu txe doctor` prints both builds, and if they differ, tell the user before you register. It is not put on `PATH`: a bare `dagu` may be missing, or may be another build that has no `txe` command.

## Signing in to the hub

A machine that has never talked to the hub signs in once, through the browser. It needs no API key, and no token is ever copied:

```sh
dagu txe login --hub https://<the hub's address>
```

- `--hub` names the hub the first time. The command creates this machine's `txe` context with no API key, then opens the identity provider's sign-in page in this machine's browser.
- Signing in grants nothing by itself. Login says whether the hub gives this identity access yet. If it does not, the person opens the hub in a browser, signs in with the same account, and asks for access; the hub's administrator approves it. `dagu txe whoami` shows the state at any time.
- A machine that already has a `txe` context, such as one with a worker, keeps it: run `dagu txe login` with no `--hub`.
- Without an API key, a command the hub does not take a sign-in on is refused by the hub. Registering and inspecting jobs are taken on a sign-in.

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
| `targets` | The resource the job watches or acts on: `kind`, and a `stable_id` that survives a rename or a recreation (a UID, not a name). See "Targets" below. |
| `schedule` | `cron` (five fields), `timezone`, `timeout_sec`. Optional: `overlap`, `retry` with `retry_interval_sec`, `catchup_window`. |
| `package` | `include`: the files and directories the job needs, relative to the spec. `entrypoint`: the command. Uncommitted files are packaged as they are. |
| `env` | Optional. Literal, non-secret settings for the script. |
| `credential_refs` | Optional. See "Credentials" below. |
| `expected_outcome` | `success_criteria`: what a good result looks like. `deliverables`: optional, see "Results" below. |
| `lifetime` | `expires_at`, or `open_ended: true` if the job really has no end date. |
| `review_policy` | `cadence` (cron) and `brief`: what a reviewer should look for and what it may do. Optional `permitted_actions` and `human_decision_conditions`. |
| `retirement_rules` | Optional. What the registry does when the target is deleted or replaced. See "When the work is over, or the target changes". |

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
- Such a registry admits JSON Schema draft 2020-12 and only the keywords it enforces exactly. It refuses `format`, `multipleOf`, unknown keywords and references to other documents. A number in the schema must be one it can compare exactly: an integer up to 2^53, or a fraction such as 0.5 that is exact in binary. `pattern` is read as RE2.
- A `param_schema` that is a list, a single value, or a key left with no value is refused when the spec is read. So is one that uses a YAML merge key (`<<`), which could replace a bound written beside it: write the schema out in full.
- Write every number in a `param_schema` in plain decimal, as JSON does: `10`, `-3`, `0.5`. The spec is refused when it is read if what would be sent is not what is written. That covers a number that would be sent as a different one (`0.49999999999999999` would be sent as `0.5`), a spelling YAML reads its own way (`012`, `0x10`, `1_000`, `+5`, `.5`), a YAML tag (`!!float`), and an unquoted value such as `1e3` that would be sent as text. Put a value in quotes when text is meant.
- A number is accepted only if the JSON number sent for it has the same value. Ordinary integers and short decimals (`10`, `-3`, `0.25`) do. A very long, very large or very small number may not, and is then refused. Do not shorten a refused number to make the spec load: a rounded bound is a different bound. Decide which bound you intend and write that.
- Reading the spec only makes sure the registry is sent the number you wrote. Whether that number can be a bound is the registry's rule, above: `0.1` is sent as `0.1`, and a registry that compares binary fractions then refuses the registration.
- Write every key in a `param_schema` as text. A key such as `1`, `1.0` or `true` is refused, because it would be sent as text that may not match what is written: put it in quotes (`"1"`). A key written with `?` is refused too.
- A spec that gives any action a `param_schema` must be written out in full: no anchors (`&name`), references (`*name`) or merge keys (`<<`) anywhere in the file. A reference can be read as something other than what is written above it, so the spec is refused and the line that uses one is named. A job spec is one YAML document: a file with a second one after `---` is refused, because only the first would be read. A spec with no `param_schema` may use them as before.

## Targets

A target is the resource the job watches or acts on. Give it an identity that survives a rename or a recreation, and say how its existence is observed:

| `existence_check` | Who checks | When |
|---|---|---|
| `pre_run` | this machine, before the job's command | every run, retries included; the job does not run when the target is gone or cannot be observed |
| `reconcile` | this machine's periodic check | between runs |
| `event_only` (or left out) | nobody; someone records a change in the registry | never automatically |

`pre_run` and `reconcile` work only for kinds a probe knows, and the job must declare the credential the probe reads. Anything else is refused at registration, because a target nobody can observe would stop every run.

```yaml
targets:
  - kind: kubernetes.deployment      # also configmap, secret, service, persistentvolumeclaim, statefulset, job, cronjob, namespace
    environment: dev                 # the cluster's name
    display_name: my-namespace/my-app   # "namespace/name"; just "name" for kubernetes.namespace
    stable_id:
      cluster_uid: <uid of the cluster's kube-system namespace>
      uid: <the object's metadata.uid>
    existence_check: pre_run
  - kind: linear.issue
    stable_id:
      id: <the issue's UUID, not TXE-123>
    existence_check: reconcile
credential_refs:
  - {name: TXE_KUBECONFIG, kind: file, locator: /Users/you/.kube/config}   # required for a Kubernetes target
  - {name: TXE_KUBE_CONTEXT, kind: env, locator: TXE_KUBE_CONTEXT}         # optional: the context to use
  - {name: LINEAR_API_KEY, kind: file, locator: /Users/you/.config/txe/linear-token}   # required for a Linear target
```

The three names are fixed: they are what the probe looks up. A reference's name is also the variable your script receives, holding the file's content for a `file` reference. So `TXE_KUBECONFIG` holds the kubeconfig's text, not a path: if your script runs `kubectl`, point it at the file with a setting of your own under `env`, such as `KUBECONFIG: /Users/you/.kube/config`.

A check that cannot see the target (expired login, unreachable cluster, timeout) stops the run and is recorded as such. It is never recorded as a deletion.

### Linear: the target check and your script are two things

- **The check of a Linear target** (`existence_check: pre_run` or `reconcile` on a `linear.issue`) is made by the probe, and the probe reads only the credential reference named `LINEAR_API_KEY`. For `reconcile`, make it a `file` reference: the periodic check does not receive one of kind `env`. For `pre_run`, either kind works, as long as the worker can resolve it. If this machine has no Linear API key to refer to, declare the target `event_only`; registration refuses the other two without the reference. Do not create a key or copy one from elsewhere to get past this: say that the target is not checked, and why.
- **Your script reading Linear** does not need that key on a machine where the Orca app runs. The Orca CLI reads Linear through the app's own connection:

  ```sh
  /Applications/Orca.app/Contents/Resources/bin/orca linear issue <issue id> --json
  ```

  The job declares no credential for this. Call the CLI by its full path, and print only the fields you need.

That route is not a credential the worker holds, and what is known about it is one observation: on a Mac, a job started by the worker read an issue this way while the Orca app was open and connected to Linear. What happens when the app is closed, or when nobody is logged in to the machine, has not been tested. Do not tell the user the job keeps reading Linear under those conditions; if it matters, check a scheduled run under the conditions the job will really run in.

When the call fails, have the script print a short reason, exit non-zero, and leave it at that: a failed read says nothing about whether the issue still exists, so it is not a deletion and not a reason to retire the job. Call it a login problem only when the failure says so; a missing CLI, a network fault or a wrong issue id fail the same call.

A job that must not depend on the Orca app has to read Linear itself, with the API key from a `LINEAR_API_KEY` reference. Adding the reference to a script that still calls Orca changes nothing.

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
- For your script's own Kubernetes calls, prefer `kubectl --context <name>` over a credential reference. The worker's `HOME` holds the kubeconfig. That does not cover a target check: a Kubernetes target with `pre_run` or `reconcile` still needs the `TXE_KUBECONFIG` file reference described under Targets, and registration refuses the job without it.

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

Say so in the registry, so dependent jobs are reviewed or retired instead of failing forever. Record a deletion only when it is confirmed. An unreachable target, a denied permission or an expired login is not a deletion.

What ends a job:

- **What the spec said at registration.** A job is not run after `lifetime.expires_at`. `retirement_rules` say what the registry does when a deletion or a replacement of the target is recorded: `on_target_deleted` and `on_replacement`, each `retire`, `review` (ask a person) or `keep`. Set these when you register, so the job ends without anyone having to remember it. `on_completion` is different: it is recorded for the reviewer and ends nothing by itself.
- **The owner, with this CLI.** Both stop new and queued runs, close open proposals and keep every run, artifact and decision:

  ```sh
  dagu txe complete <job id> --detail "<why its purpose is met>" --evidence <run id or link>
  dagu txe retire <job id> --reason manual|replaced|target_deleted --detail "<why it is no longer wanted>"
  ```

  `--active-runs finish|cancel` says what happens to a run already going (default: the job's `retirement_rules`). Use `complete` for a fulfilled purpose and `retire` for one that is no longer wanted; `target_deleted` only for a confirmed deletion. The hub decides whether this sign-in or key may write the owner's jobs, and refuses otherwise. Ask the person before ending a job you did not register: only a person can bring a completed or retired job back, so never end one to try something out.
- **Pausing or resuming** has no command here. It is a request to the hub, `POST /api/v1/txe/jobs/<job id>/lifecycle` with `{"op": "pause", "detail": "why"}`, by someone who may write the owner's jobs. If you cannot make it, give the person who runs the hub the job id and the reason.

Check the result with `dagu txe inspect <job id>`: it shows the lifecycle and, for a completed or retired job, the reason and time.

## Signing in to the hub

A hub that accepts sign-in identifies the developer by their account at its identity provider. `dagu txe login` opens the system browser on the provider's own page. The browser hands the result back to this machine, and the command keeps the sign-in for this hub only, readable only by this user. Every Claude Code or Codex session of this user on this machine then uses it, and it renews itself without asking while the provider allows it. A Codex thread still names its session with `--session` or `TXE_SESSION`.

- **Ask the person first.** The sign-in needs a person at a browser on this machine. Never type or paste a password, a code or a token into the terminal; the command asks for none.
- **Never run `login` from a job script.** A job step never uses a person's sign-in. It keeps the hub context's API key until machines hold their own credential.
- **Signing in grants nothing by itself.** The hub's administrator binds an identity to an owner. `dagu txe whoami` shows who this machine is signed in as. When the hub accepts the sign-in, it also shows how the hub sees it: unbound, pending or bound, and to which owner.
- **Other commands use the sign-in only on the routes the hub takes it on**, which the hub names: every `/txe` route, and on some hubs also `/dags`, `/dag-runs` and `/queues`. Every other request keeps the API key, and nothing changes for a machine that never signed in.
- **Two different failures:**
  - "run `dagu txe login`": the provider or the hub refused the sign-in. Ask the person to sign in again; do not retry the command in a loop.
  - "the identity provider did not answer": nothing was refused. Retry later, and do not sign in again or sign out because of it.
- **A machine the hub does not know yet.** `dagu txe enrol` and registration stop with "record it with `dagu txe machine create`". Ask the person, then run `dagu txe machine create` once, signed in as a person of the machine's owner. It writes `machine.json` if the machine has none, never changes an existing one, and sends only the sign-in.
- **Enrolling this machine's worker.** `dagu txe enrol --client-id <the machine's worker client>` is a second browser sign-in, by a person of the machine's owner, at the machine's own worker client. It writes the worker's credential and applies to the hub; a person of the owner then approves the application in the hub. Ask the person first, never run it from a job, and never copy the credential file anywhere.
- **Changing accounts.** `dagu txe login --prompt select_account` changes the account; the previous account's sign-in is revoked and not kept. `dagu txe logout` ends this machine's sign-in.

## Reference

- `dagu txe doctor`: checks this machine, the hub and unfinished registrations.
- `dagu txe list`, `dagu txe inspect <job id>`: every session of the same developer sees the same jobs. The owner is the same whichever session created it; `created by` records the session. A hub that enforces owners does not show you another developer's jobs unless they shared them.
- `dagu txe login`, `dagu txe whoami`, `dagu txe logout`: this machine's sign-in to the hub. See "Signing in to the hub".
- `examples/`: three job scripts with the behaviour a reviewer expects (structured output, state under `TXE_OUTPUT_DIR`, a completion signal).

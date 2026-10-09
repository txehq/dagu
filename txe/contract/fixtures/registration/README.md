# Registration fixtures

The bodies of the registry calls `dagu txe` makes when it registers a job, updates one and records a
run's deliverables. Owner of this directory: CC2 (TXE-3408). The registry's types and OpenAPI are
CC3's (`api/v1/api.yaml`, `/txe`).

**The request files are generated, not written.** `TestContractFixtures` in `internal/txe/client`
runs a registration against a fake registry and compares what the client sent with these files. Paths
on the machine, the package digest and the DAG hash are replaced by fixed values; everything else is
the client's own bytes. After a deliberate change, regenerate them and tell the registry's owner:

```sh
TXE_UPDATE_FIXTURES=1 go test -run TestContractFixtures ./internal/txe/client/
```

**The response files are the fake's answers.** They show the fields the client reads and nothing
more. The registry's real responses carry more; they are authoritative for their own shape.

| File | Call |
|---|---|
| `installation.response.200.json` | `GET /api/v1/txe/installation` (the hub's build comes from `GET /api/v1/health`) |
| `project.ensure.request.json`, `project.ensure.response.200.json` | `POST /api/v1/txe/projects`, get-or-create on `owner_id` + `key` |
| `register.request.json`, `register.response.201.json` | `POST /api/v1/txe/jobs` |
| `register.response.409.duplicate.json` | the same call when the `job_key` is already registered in the project |
| `ready.request.json`, `ready.response.200.json` | `POST /api/v1/txe/jobs/{job_id}/ready`; the response is the receipt |
| `version.request.json`, `version.response.409.version_conflict.json` | `POST /api/v1/txe/jobs/{job_id}/versions` with an outdated `expected_version` |
| `artifacts.publish.request.json` | `POST /api/v1/txe/jobs/{job_id}/runs/{run_id}/artifacts`, sent by the job's last step |
| `deliverable-paths.json` | no call: the deliverable paths the CLI and the registry both accept and both refuse |
| `execution-refs.json` | no call: executions and the reference both sides derive from them |

What the client relies on:

- **Replay.** The same `job_id`, `request_id` and body sent again returns the stored job. It is never
  a 409. The client resumes an interrupted registration by sending the saved bytes again.
- **Duplicate.** A different job with a `job_key` already used in the project is refused with 409 and
  `details.code` `duplicate`; `details.current` is the existing job.
- **Stale update.** An `expected_version` that is not the job's current version is refused with 409
  and `details.code` `version_conflict`; `details.current` carries the current version.
- **Ready.** A job is `incomplete` until `ready` succeeds for its current package digest. Only that
  response is a receipt.
- **`version.dag.spec`** is the exact YAML the registry saves. It has no `name` key (the DAG is named
  after its file, the job id), it is a `chain`, its steps use `command`, and each credential
  reference is a `secrets` entry the worker resolves from its own machine.
- **No credential value** appears in any body. `credential_refs[].locator` is a path or a variable
  name on the assigned machine.
- **Deliverable paths.** `deliverable-paths.json` is written by hand. It states the rule and lists
  paths on each side of it. `TestCheckDeliverablePath` runs the CLI's check over every one; the
  registry's check is meant to run over the same file, so the two cannot drift apart unnoticed.
- **Executions.** A Dagu retry keeps the run ID. Dispatched directly it gets a new attempt ID; sent
  through a queue it executes again under the same attempt ID with a later `queuedAt`. One
  execution is named by both: `attempt_id` and `queued_at`, the run status's `queuedAt` byte for
  byte, empty for a run that was never queued. Its portable reference, the only form used in a
  path, is `attempt_id` + `-` + the first 8 bytes, in hex, of SHA-256 over `attempt_id`, a
  newline, `queued_at`. `execution-refs.json` holds cases both sides compute; the values there
  were worked out independently of the client's code.
- **Artifacts.** A run has one manifest per execution. `attempt_id` and `queued_at` name the
  execution the publish step runs in (`${context.attempt.id}`, `${context.attempt.queued_at}`);
  the registry accepts a manifest only from the run's latest execution, takes the same report
  again, and refuses another report for an execution it holds. `produced_in` names the execution
  whose run of the job wrote the files; it differs only when a retry ran the publish step alone.
  `path` is relative to that execution's sealed output directory on the machine,
  `outputs/<job>/runs/<run>/executions/<reference of produced_in>/`. `location` `hub` means the
  same bytes were also placed for upload at `txe-attempts/<reference of the publishing
  execution>/<path>` in the run's native artifact directory; the digest here is what that copy
  must match before it is shown as available. A deliverable the execution did not produce is
  sent as `{deliverable, path, missing: true}`.
- **What is published is what was sealed.** When the job's command succeeds, the client records
  the digest of every file it wrote. It publishes a deliverable only while the file still has
  that digest, and treats a file that appeared afterwards as not produced.

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
- **Artifacts.** `path` is relative to the run's output directory on the machine. `location` `hub`
  means the same bytes were also placed in the run's native artifact directory for upload; the
  digest here is what the hub copy must match before it is shown as available. A deliverable the
  run did not produce is sent as `{deliverable, path, missing: true}`.

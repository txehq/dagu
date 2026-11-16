# Isolated I5 harness (TXE-7516)

This harness gives isolated evidence for three I5 assertions that the earlier
TXE-5085/J17 rig could not make. It runs only on this Mac, on loopback, with its
own processes, directories and synthetic identities. **It is not the live I5 pass
on the shared installation.** That gate stays (section "What this does not
prove").

It does not repeat what J17 already proved at -17 (`~/.local/share/txe-dagu-acceptance/cc5/txe-5085-joined/evidence/acceptance-4d164866b/RESULT.md`):
- publish-only republish binding, `produced_in` and digest;
- one script effect;
- no job env or secret in the publish;
- the eight refusals;
- replay and lost response;
- rollback with the old executor.

The design is `evidence/txe-7516/01-i5-isolated-harness-design-20261116.md`. The
TXE-3401 root ruling (msg_f64163e22ee5) fixed:

| Ruling | Value |
|---|---|
| D1 | native, builtin auth, loopback; no IdP, no container, no image |
| D2 | tuple T2, never widened silently |
| D3 | no separate control arm |
| D4 | the coordinator chooses a profile that is not the live reviewer's |
| D5 | truthful fixture text, no retry of a declined review |

## What it asserts

| Id | Assertion | Needs TXE-7514 (A) |
|---|---|---|
| N1a | The packet the reviewer prepared for the lost run carries the hub's lease-expiry reason, the job version and a local seal marker | yes |
| N1 | The real agent (`claude-opus-5-5`), given that packet, proposes `dagu.retry_run` with `step: publish`, bound to the lost execution | yes, in substance |
| N2 | The loss is a real lease expiry caused by cutting the harness's own route while the worker process stays alive: the seal is written, the worker logs its owner timeout, the hub fails the run, the late status is fenced, and the same worker process carries out the republish | no |
| N3 | W and C are the installed binary's bytes (read-only copy, sha256 equal to the receipt); H and R are pinned source builds with their full build info and dependency delta | no |

## The pieces

| File | What |
|---|---|
| `rig.sh` | the steps below, each guarded: in order, at most once, and only while every pinned file still hashes to the manifest |
| `relay.py` | the harness's route. `cut` closes established connections and refuses new ones on every listener at once |
| `preflight.py` | the fail-loud gates: config, hub log, service registry, worker connections, shared-port log scan, free ports, pins |
| `procs.py` | starts each process as its own group leader; stops it only if its pid, group, executable and kernel start time still match |
| `pin.py` | copies the installed W/C read-only, builds H and R from `git archive` plus picks, reports A's changed files against the reviewer's dependency closure, writes the manifest |
| `check_seal.py` | one begun execution, one seal, `attempts/` empty, and every sealed file still hashing to its seal |
| `fixture-job.yaml.tmpl`, `fixture-run.sh` | the harmless fixture: it counts itself, waits for the harness's go marker, then writes one result unique to its run |

**Why the coordinator binds `[::1]`.**
- A worker sends its owner-routed calls (claim ack, `RunHeartbeat`, `ReportStatus`, logs) to the address the coordinator registers. That address is its advertise host plus its own listen port (`internal/cmd/coord.go`).
- If the coordinator listened on 127.0.0.1, a relay could only sit on a different port, and heartbeats would bypass it.
- So the coordinator binds `[::1]:28255` and advertises `127.0.0.1`, and the relay owns `127.0.0.1:28255`.
- `preflight.py config`, `hub-log`, `registry` and `conns` hold this before anything runs. Each has negative tests in `preflight_test.go`.

**Why R installs the reviewer.**
- `txe review install` renders the reviewer and decision DAGs with the installing binary's embedded prompt and decision schema (`internal/txe/review/dag.go` `RenderDAGs`).
- TXE-7514 changes that prompt (`txe/reviewer/prompt.md`).
- So `rig.sh` installs with R, and every review step calls R through `--review-command`. Installed by C, the agent would read the base prompt whatever R's code does.
- `TestRigInstallsTheReviewerWithTheReviewerBinary` holds this.

## Ports and paths

| What | Where |
|---|---|
| Hub frontend (the harness observes here) | `127.0.0.1:28980` |
| Relay → frontend (the machine's CLI, publish and reviewer) | `127.0.0.1:28981` |
| Hub coordinator bind | `[::1]:28255` |
| Relay → coordinator (registered, advertised; the worker's only route) | `127.0.0.1:28255` |
| Rig root | `~/.local/share/txe-dagu-acceptance/cc8/txe-7516-i5/` (proposed; anything except the shared TXE home) |

The shared installation's ports (`preflight.py` `SHARED_PORTS`) and its TXE home are
refused by the code. `rig_test.go` checks that `rig.sh` never mentions launchd,
`pkill`, `kill -9`, kubectl, docker or those ports.

## Before the slot: pin the tuple and freeze the manifest

Both inputs must exist first:
- **the accepted window-10 receipt**, or its unwind receipt: it names B, meaning the hub tag and the worker tag and sha256 actually live;
- **A's merge commit(s)** on main.

Nothing below runs a hub or a worker.

```sh
H=txe/i5harness; RIG=~/.local/share/txe-dagu-acceptance/cc8/txe-7516-i5; PIN=$RIG-pin
# W/C: the installed binary, read-only, hash-checked against the receipt.
python3 -I $H/pin.py copy-installed --src ~/.local/share/txe-dagu/bin/dagu-<B worker version> \
  --dest $PIN/bin/dagu-wc --expect-sha <receipt sha256> --record $PIN/wc.json
# H: the hub tag. R: B's worker tag plus A's commit(s), in order.
python3 -I $H/pin.py build --role H --repo . --base <B hub tag> --version <hub version> \
  --workdir $PIN/work-h --out $PIN/bin/dagu-h --record $PIN/h.json
python3 -I $H/pin.py build --role R --repo . --base <B worker tag> --pick <A sha>.. --version <ver>+txe7514 \
  --workdir $PIN/work-r --out $PIN/bin/dagu-r --record $PIN/r.json
# A's delta against the reviewer's dependency closure: returned for assessment, never acted on.
python3 -I $H/pin.py closure --repo . --base <B worker tag> --pick <A sha>.. --workdir $PIN/work-c --record $PIN/closure.json
python3 -I $H/pin.py manifest --out $PIN/manifest.json --harness-dir $H \
  --record $PIN/wc.json --record $PIN/h.json --record $PIN/r.json --record $PIN/closure.json \
  --extra profile=$PIN/profile.json --extra slot=$PIN/slot.json
```

Then:
- `profile.json` records the coordinator's D4 choice;
- `slot.json` records the approved start, end and deadline;
- the manifest goes to cc3 and root;
- **no step below runs until both approve that manifest by its sha256.**

**If `closure.json` says `"assessment_required": true`:** A changed something outside `internal/txe/review/`. The harness stops there and returns the list. It does not switch to another tuple.

## The slot (≤ 90 min)

The slot starts no earlier than 2026-11-17 00:10Z, after window-10's recovery has ended and its receipt is accepted, and after A is merged.

| Step | Command | Pass | Stop (and `rig.sh down`) |
|---|---|---|---|
| P0 | record the shared worker's pid, `comm` and its ESTABLISHED peer, read-only (`ps -o comm=`, `lsof`) | recorded | anything unexpected |
| P1 | `rig.sh init --rig $RIG --manifest $PIN/manifest.json --hub-bin $PIN/bin/dagu-h --worker-bin $PIN/bin/dagu-wc --reviewer-bin $PIN/bin/dagu-r --profile <D4> --claude-bin-dir <dir of claude> --repo .` | pins match, ports free, config preflight OK | any preflight fail |
| P2 | `rig.sh up --rig $RIG` | hub-log + registry at the relay; `republish_sealed` listed; worker connects only to the relay; `claude auth status` passes; no shared port in logs | any preflight fail |
| P3 | `rig.sh loss --rig $RIG` | seal ≤ T0+90 s; hub run `failed` ≤ T0+240 s; worker owner-timeout line ≤ T0+300 s; no artifact on the hub during the cut | `evidence/loss/VERDICT` says inconclusive: stop, no second loss |
| P4 | `rig.sh restore --rig $RIG` | run stays failed; same worker process (`procs.py check`); worker only on the relay | worker replaced or run not failed |
| P5 | `rig.sh eligibility --rig $RIG` | one begun, one seal, bytes = seal, no open proposal or action | any |
| P6 | `rig.sh review-tick --rig $RIG` (**the one initial reviewer call**) | N1a in `evidence/tick1/reviews/*`; N1: one open `dagu.retry_run` proposal, `step: publish`, attempt_id/queued_at of the lost execution | the agent declines: record it verbatim and stop. No second tick, no changed guidance, no owner path |
| P7a | `rig.sh show-proposal --rig $RIG` | the proposal JSON goes to cc3 and root | |
| P7b | **Decision, only on explicit authority.** The person who authorises names the proposal id and the verdict in a message. Then: `rig.sh decide --rig $RIG --proposal <prp_…> --verdict retry --authority <that message id>`. It decides as the test hub's synthetic person (`synth-owner`, builtin auth, J17's decision path), once, after the native task is `waiting`. It records the authority in `evidence/decision/authority.json`. The harness never decides by itself | the decision is recorded | no authority: nothing happens |
| P8 | `rig.sh proof --rig $RIG` | one publish-only execution, `retryOf` = the lost execution; `produced_in` = the lost execution; digests = seal; action `succeeded`; counter unchanged; same worker process; seal bytes unchanged | any differs |
| P9 | `rig.sh review-tick --rig $RIG --post-decision` (the one post-decision observation, only if it is needed) | no new attempt, proposal or action; counter unchanged | |
| P10 | `rig.sh down --rig $RIG` | fixture retired; worker, relay and hub stopped by token; ports free; no shared port in logs; evidence read-only; shared worker equals P0 | a process that is not ours is refused and reported |

Evidence lives in `$RIG/evidence/`. At the end it is copied to
`~/Projects/k8sconfig/onprem-k3s/evidence/txe-7516/run-<UTC>/`, after the
secret-redaction filter from the common brief. The rig root keeps the synthetic
admin password, person token and API key in 0600 files, outside `evidence/`.
They are never copied.

## What this does not prove (the live I5 gate stays)

1. Production identity and authorization:
   - the production owner and Keycloak;
   - enforced `txe.authz`;
   - the native owner task in the production dashboard.
2. The production installation and its configuration.
3. The live route: the port-forward, or the HTTPS channel through Cloudflare after window-10.
4. A natural loss. The harness induces one by cutting its own route.
5. The live reviewer's profile and cadence, and the shared machine's real history.
6. The Linux hub image. H is a darwin build of the same commit.
7. A on the shared machine, through its own release, where `closure.json` and the release-binding check hold.

The owner's publish-only path (TXE-7515) is a different path. Nothing here can count it as reviewer-path coverage.

## Tests

`go test ./txe/i5harness/` runs everything:
- the relay against real sockets: an established connection cut, IPv6 loopback, loopback-only addresses;
- every preflight check, each with its negative cases, report 25's split ports among them;
- `procs.py`'s refusal of a reused pid;
- the seal check;
- `pin.py`'s read-only copy, its build, and its closure report on a small module;
- `rig.sh init` and its step guards;
- the decision-authority guard;
- the fixture.

Nothing in the tests starts a hub or a worker.

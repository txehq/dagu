# Worker channel over HTTPS (design)

Status: proposed, TXE-5550. The hub can serve the channel behind `coordinator.worker_channel.enabled`, default off. A worker opts in with `worker.hub_url`. Nothing here is live, and no Cloudflare path has been tried.

## Why

Today a worker reaches its hub through `kubectl port-forward` to `127.0.0.1:50055` and `127.0.0.1:18080`. So every machine that runs a worker needs a Kubernetes credential and a supervised tunnel. Connor chose outbound HTTPS through the existing entry point `dag.txeinternal.com`, with no kubeconfig and no VPN for an engineer. Tailscale stays optional.

## The idea

Change the transport and nothing above it.

```
worker                                                      hub (dagu start-all)
generated CoordinatorServiceClient                          generated CoordinatorServiceServer
  -> workerchannel.Conn (grpc.ClientConnInterface)            -> transportauth interceptors (enforce, machines only)
       Connect client, binary protobuf                          -> coordinator.Handler
                 |                                                 (leases, claim ack, report fence unchanged)
                 +--> Cloudflare --> cloudflared --> dagu:8080 ----^
```

Each carried method keeps its generated request and reply messages, its handler and its interceptor. The coordinator's gRPC port stays private, and this route never speaks gRPC.

## Options compared

| Option | Verdict | Why |
|---|---|---|
| **Connect protocol, `connectrpc.com/connect` v1.21.1** | **Chosen** | A maintained, versioned protocol over ordinary HTTP/1.1 and HTTP/2. It has its own framing, timeouts, error model and size limits, so none of that is ours. A small typed adapter fits the existing generated code, with no regenerated stubs. Apache-2.0; its only non-test dependency is protobuf, already here |
| Our own framing on the generated stubs | Rejected, after a prototype | The first version of this PR. It worked, and its wire was nearly Connect's, with every parser, timeout and error rule ours to maintain |
| Connect v2.0.2 | Not now | Released 2026-10-21, with a different package layout. v1 is the proven line. Moving later is an adapter change |
| gRPC-Web | Rejected | Needs its own proxy, or a server mode this repository does not use |
| JSON REST for each RPC | Rejected | Rewrites each call and its error semantics |
| Proxied gRPC through Cloudflare | Rejected | Needs a public TLS origin on 443. Tunnel public hostnames do not carry gRPC, which does not affect Connect: to the Tunnel, Connect is plain HTTP |
| WebSocket | Rejected | No method is bidirectional and the worker always dials out. Nothing demonstrates a need |

## What is carried

Eleven of the 23 coordinator methods, plus `Health/Check`. The table is `methods.go`, and `TestCarriedMethodsAreExactlyTheTable` holds it against `transportauth`'s policy: exactly the worker surface is carried. A method added later is closed until someone lists it. All other methods fail closed, as they do on an enforcing coordinator (TXE-4228).

| Method | Shape | Carried | Worker use |
|---|---|---|---|
| `Poll` | unary | yes | Take a task |
| `Heartbeat` | unary | yes | Worker liveness |
| `AckTaskClaim` | unary | yes | Confirm a claim |
| `RunHeartbeat` | unary | yes | Refresh a run's lease, every 1 s |
| `ReportStatus` | unary | yes | Status, including the final one |
| `ResolveSecretReference` | unary | yes | Secret reference for a running attempt |
| `ResolveRuntimeProfile` | unary | yes | Runtime profile for a running attempt |
| `ClaimAgentSessionCleanup` | unary | yes | Agent session cleanup |
| `CompleteAgentSessionCleanup` | unary | yes | Agent session cleanup |
| `StreamLogs` | client stream | yes | Step logs |
| `StreamArtifacts` | client stream | yes | Run artifacts |
| `GetWorkspaceBundle` | server stream | **no** | A task with a workspace bundle digest (`materializeTaskWorkspace`) |
| `GetDAG` | unary | **no** | Fallback when a local DAG store misses a definition (`remote_handler.go`) |
| `GetState`, `PutState`, `DeleteState`, `ListState` | unary | **no** | `state` steps |
| `GetDAGRunStatus`, `RequestCancel` | unary | **no** | Remote sub-DAGs |
| `Dispatch`, `GetWorkers`, `PutWorkspaceBundle`, `HasWorkspaceBundle` | mixed | **no** | Hub's own processes |

**Why exclusion does not break TXE jobs.** A bundle exists only for a DAG with file dependencies. `RenderDAG` writes a command chain with none, and a TXE task carries its definition. So `state` steps, sub-DAGs and bundles are out of reach of a TXE job. `TestARenderedJobHasNoFileDependencies` holds that for a rendered job, and the rig runs a real one. A non-TXE DAG that needs them fails closed on this channel. It can keep the private path, or wait for TXE-4228.

## Wire

Connect unary and client streaming, binary protobuf (`application/proto`, `application/connect+proto`). The route answers 415 to anything else, gRPC and JSON included. Compression is off, so size limits count real bytes.

**The end of a stream.** Connect ends a client stream with the end of the request body, with no end marker, as gRPC does with END_STREAM. A request that stops cleanly between messages therefore reads as finished. This was inspected, and it creates no false completion:

- A log is finalized only by a chunk with `is_final`. Without it the file stays incomplete (`TestALogIsNotFinalizedByTheEndOfARequest`).
- An artifact is committed only by its final chunk. Temporary files of uncommitted uploads are discarded when the stream ends.
- A worker believes a stream delivered only when it reads the reply. A log writer keeps its bytes until then and resends by offset. A response cut short is an error, because Connect requires its end-of-stream frame.
- A body cut inside a message is an error (`TestAStreamCutInsideAMessageIsAnError`).

**A status is not a refusal.** Connect maps a bare HTTP 403 to `permission_denied`, which would read as a refused machine. So a Conn believes only `connect.IsWireError`, an error the peer sent as a Connect error body. Everything else is `Unavailable`, an edge page, a 200 with the wrong content type and a redirect included. A genuine hub refusal is always a wire error, so it is never reclassified (`TestAHubsRefusalIsStillARefusal`).

This is classification, not authenticity. Nothing on the wire proves that a Connect error came from the hub. TLS ends at Cloudflare, so an edge could write one. The cost of that is availability only: a worker that believes a forged refusal stops within its refused-calls bound, and the hub's own decisions are unaffected. Failing the other way is deliberate too: if Cloudflare Access returned to this host, its 401 would be `Unavailable`, an outage that looks like one.

## Authorization

- **Independent of off/off.** The route's own `transportauth.Server` always enforces, needs no hub key and holds none. It requires `txe.authn` and refuses to start without it. Turning it on creates no `hub.key` and changes neither mode.
- **Admit before read.** A credential is verified, and the enrolment read, before any body byte is read.
- **Per call and per message.** The existing interceptors run unchanged: worker id and label compared with the enrolled machine, hub-only methods refused, a method nobody listed refused, and each stream message checked, with the enrolment re-read at most every second.
- **Attempts.** A worker id is proved to belong to the machine, and the handler's existing checks tie a lease, claim, attempt and secret reference to that worker id. Nothing new is needed there.
- **Machine pinning.** `Handler.machinePinning` follows `txe.authz.mode`, so under off a task with no machine selector could go to any machine that polls on gRPC. A call on this route carries `Caller.PinnedToMachine`, and `Poll` and `ClaimAgentSessionCleanup` use enforce pinning for it whatever the mode. A task with no machine selector is never handed over this route.
- **TXE-4228** is not a dependency. Hub-only `state`, sub-DAG and bundle calls are refused on the channel exactly as under enforce. TXE job DAGs are command chains and do not make them.

## Bounds

| Bound | Default | Why |
|---|---|---|
| Unary call | 30 s | Below Cloudflare's 125 s proxy read timeout |
| Poll wait | 25 s, then an empty reply | An empty Poll is the ordinary answer and counts as a success |
| Client stream | 110 s | Log writers checkpoint about every 2 s |
| Message | 16 MiB | The coordinator client's existing limit |
| Request | 32 MiB, configurable | Must fit the zone's request body limit, which is not confirmed and may be below the plan's maximum |
| Calls per machine | 256 | A worker holds one Poll per run slot (default 100) |
| Connection setup | 10 s dial, 10 s TLS | |
| Stalled body | The request's limit plus 1 s, by read deadline | Cancelling a context does not interrupt a read |

Cloudflare's published limits: proxy read 125 s, proxy write 30 s, proxy idle 900 s. A stream never idles past 30 s: a log writer closes its stream at each checkpoint, and artifact chunks are sent back to back.

**Artifacts.** Hub artifacts have no size limit today, so a request limit must not become one. Over the channel, a stream carries at most 16 MiB: the uploader rolls streams between files, and a larger file goes as a segmented upload. On gRPC nothing changes.

A segmented upload adds `byte_offset`, `total_size` and `sha256` to `ArtifactChunk` and `committed_offset` to its reply, all with numbers from 1001, clear of upstream's. The rules:

- **Presence, not zero.** `committed_offset` is an explicit `optional`, so 0 and absent differ on the wire. The worker sends the next stream only after the hub has acknowledged at least what was sent. Ahead is expected after a lost acknowledgment: the hub compared the replay, and the final chunk settles the exact size. A file never goes as a segmented upload unless it exceeds a stream, so an empty file and a small one keep the form every hub knows.
- **Binding.** Segments wait in `.dagu-artifact-segments/<hash>/` inside the attempt's archive. The hash covers attempt key, worker, job, run, root, attempt, execution marker, and the authenticated machine and owner. Listings leave that directory out.
- **Before any write.** Each chunk validates the attempt under its write lock, so an expired or superseded attempt changes nothing.
- **Exact bytes.** An offset past the end is refused. Bytes the hub already holds are compared: a match is a repeat after a lost acknowledgment, and a mismatch is refused.
- **Commit once.** The final chunk is checked against the whole file's size and SHA-256. A wrong one leaves whatever was committed. An identical committed artifact means the final acknowledgment was lost, and it succeeds without touching the file. A different one is another result and is left alone.
- **Links.** Everything goes through `os.Root`. New files are created exclusively, an existing name must be a regular file and the same file after opening, and a target that is not a regular file is refused.
- **Cleanup.** A directory goes only when the attempt's own fence refuses the identity recorded in it. Age proves nothing, so anything unreadable or not refused stays, and goes with the archive under retention.

| Worker | Hub | Result |
|---|---|---|
| gRPC, any version | any | Unchanged: no offsets, no stream limit |
| Channel, file within a stream | With segments | Unchanged form |
| Channel, large file | With segments | Segmented, committed once |
| Channel, large file | Channel but no segments (never released) | Stops at the first stream, nothing committed, the upload fails truthfully |
| Old, no offsets | With segments | Unchanged, no `committed_offset` in the reply |

**This is a source claim.** The hub half with channel and no segments is exercised by simulation (`TestAHubThatIgnoresTheOffsetCommitsNothing`, `TestAHubThatDoesNotKnowSegmentsGetsNoFinalChunk`). Real mixed versions are for the rig. Nothing replays an attempt that is no longer valid.

**A slow link.** Durable progress moves by whole chunks of 3 MiB, and each stream ends at 16 MiB or 55 s, half the stream limit, whichever comes first, so what is still in buffers can drain. A retry does not repeat what the hub holds. The worker sends an empty chunk at offset 0, which passes the same fences as any chunk, and the reply says the durable offset. It hashes that prefix from its own file and goes on from there, and the final chunk's size and SHA-256 still settle the whole file, so a file changed during the upload fails. A file the hub has acknowledged is not sent again by a retry of its directory. After a lost final acknowledgment, the final chunk alone settles it, against the committed artifact, and a different file is refused.

**The 3 minutes are a behaviour change for segmented uploads, and a visible tradeoff.** Hub artifacts are written before a run's terminal status, and the agent used to give that 3 minutes whatever the rate: about 36 MB at 200 KB/s, and a run with more failed with its job done. An uploader that sends segments now holds itself to 3 minutes with no durable progress, counted from before it reads the directory, and the agent gives it no fixed time. A large upload that is moving therefore extends the run's finishing phase, by its size over the link's rate. No constant was raised.

Only the hub's own word resets it: a higher offset than it has ever reported, or a newly committed file. A repeated acknowledgment, a repeated answer to the empty chunk, bytes sent but not acknowledged, and reading or hashing local files do not. The whole upload stays finite: a file has a size, and the offset only rises.

A stopped run's upload gets 3 minutes and nothing resets that. A job with a timeout never uploads past it by more than it always could: the upload has what is left of the timeout, or 3 minutes if that is more. The attempt's lease and the job's timeout are unchanged, and each chunk is still checked, so a superseded attempt stops at its next chunk. gRPC, and anything else that sends no segments, keeps exactly 3 minutes in all. An upload over the channel with no file above a stream's size keeps 3 minutes in all too.

The floor is a chunk within a stream's limit, about 28 KiB/s at 110 s. Below it nothing becomes durable, and the upload ends after 3 minutes saying so. A hub that runs out of time checking a chunk answers `DeadlineExceeded`, which the worker retries. Before this it answered `Internal`, which ended the run.

Logs fit already: a writer retains at most 16 MiB and sends chunks of at most 3 MiB, so a checkpoint is below 32 MiB. If the zone's limit is lower than that, the retained size must follow it.

## Liveness

Three things are often mistaken for one another:

- **HTTP/2 pings** (15 s, then 5 s) are between the worker and the first hop, Cloudflare's edge. They close a dead connection quickly. **They prove nothing about cloudflared, the hub or the coordinator.** An edge can answer pings while the origin is gone.
- **End-to-end liveness is the worker's own calls.** A `Heartbeat` or `RunHeartbeat` that returns has passed the edge, the tunnel, authentication and the coordinator's handler, and `RunHeartbeat` has refreshed the lease. These run with per-call deadlines, at 1 s per running task. That is what reports a worker connected, and what the 90 s owner timeout counts.
- **The hub's view** is the existing 30 s stale-worker threshold and 90 s lease.

So stale detection end to end is bounded by the call deadline plus the existing 90 s owner timeout, not by the ping interval.

## Failure behaviour

| Event | What happens |
|---|---|
| Network loss, an edge error or an edge page | The call is `Unavailable`. The existing client retries with backoff; the worker's connection state goes offline as it does today |
| Outage under 90 s | A running task continues; reports retry |
| Outage over 90 s | The worker cancels the run and the hub fails the lease, as today. The report is refused as a stale attempt. **No automatic replay.** Sealed outputs stay on disk and the owner's approved republish is the recovery |
| Response lost after a claim | The claim expires and the task is claimed again, as on gRPC. There is no exactly-once promise |
| Credential refused by the hub | `Unauthenticated`, which the worker's refused-calls bound already handles |
| Provider down | `Unavailable`; nothing is sent |
| Redirect | Never followed; the call is `Unavailable` and the credential goes nowhere else |

No new outbox and no longer lease are proposed. The fault tests decide whether either is needed.

## Delivery

One child ticket per PR, all under TXE-5550.

1. Library and this design.
2. Hub: `coordinator.worker_channel.enabled`, default off; mounted outside the API's auth middleware; start-all only; per-call pinning; refuse to start without `txe.authn`.
3. Worker: an opt-in hub URL. Calls go through `Conn`, an owner's advertised address is ignored, and a machine credential is required. Without the option nothing changes, so the port-forward stays as rollback, and old and new workers can run side by side. Adds the rendered-DAG test.
4. Artifact segments, as above.
5. Install: no tunnel agent, no `kubectl`, the context points at HTTPS; `status.sh` and `doctor` report the channel.
6. Worker-side REST: nothing at runtime names local 18080. Job, probe and reviewer steps use the machine's `txe` context, and their credential is bound to its address, so this is the procedure in `README.md`, not a code change.
7. Fault rig (below), then `txehq/txe` configuration in its own PR.

Cutover stages, each with its own GO: integration on the rig; review and merge; release tag; hub with the channel enabled and no worker using it; one worker on the channel, port-forward kept; tunnel removed last. Upstream TXE-5506 stays separate: the channel touches the client's connection type, one hub mount and, for artifacts, one additive field. v2.24.0 has the same 23 RPCs, and the new dependency does not conflict with it.

## Test plan

Library, in this PR: identity isolation, missing, expired and revoked credentials, reviewer class, forged worker id and label, on unary and streams; hub key refused; hub-only and unlisted methods refused; only Connect with protobuf accepted; the carried table; health needs a credential; Poll bound; cut and stalled requests; size and concurrency limits; edge answers and genuine refusals; redirects; base URL checks; the real log handler resuming and not finalizing early; TLS and HTTP/2.

Isolated rig, before cutover. The endpoint allowlist is set before a worker starts; live 18080 and 50055 are never used; run first against the port-forward as a baseline.

| # | Fault | Pass |
|---|---|---|
| R1 | Install and run on a machine with no `kubectl` or kubeconfig | Worker runs a job to success |
| R2 | Two owners, two machines | Each machine gets only its tasks, on Poll, reports, logs and artifacts |
| R3 | Blackhole 60 s, run in flight | Run finishes, no duplicate |
| R4 | Blackhole 120 s | One cancel, one terminal record, next due tick dispatches, sealed outputs intact, republish works |
| R5 | DNS loss 120 s | Same bounds |
| R6 | Silent packet drop | Stale detected within the stated bound |
| R7 | Mac sleep and wake | Reconnects with no restart |
| R8 | Hub restart; proxy restart | Reconnects; IDs and history kept |
| R9 | Offline 15 min | No duplicate queued work, expiry recorded truthfully, dispatch within a stated bound after return |
| R10 | Cut during log and artifact upload | Complete or truthfully failed |
| R11 | Duplicate claim and duplicate result | The fence refuses the second |
| R12 | Nudge catch-up with GitHub stubbed | Once-per-sha markers hold, current head rechecked, no duplicate post, no real post |
| R13 | A local proxy applying Cloudflare's limits, and cloudflared itself | No call meets them; Connect streams pass cloudflared |
| R14 | Artifacts larger than one request, interrupted | Resumed and committed once |

## Open before wiring

- The zone's real request body limit and whether any Cloudflare bot or rate rule touches a non-browser client on this host.
- Run-slot count on real workers: 100 pollers at 25 s is about 4 requests a second before heartbeats.
- `txe.authn` clients and the machine's enrolment on the hub, which are live changes for their own stage.

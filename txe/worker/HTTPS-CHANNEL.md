# Worker channel over HTTPS (design)

Status: proposed, TXE-5550. `internal/txe/workerchannel` is a library nothing imports yet. Nothing here is live.

## Why

Today a worker reaches its hub through `kubectl port-forward` to `127.0.0.1:50055` and `127.0.0.1:18080`. So every machine that runs a worker needs a Kubernetes credential and a supervised tunnel. Connor chose outbound HTTPS through the existing entry point `dag.txeinternal.com`, with no kubeconfig and no VPN for an engineer. Tailscale stays optional.

## The idea

Change the transport and nothing above it.

```
worker                                                       hub (dagu start-all)
generated CoordinatorServiceClient                           generated service descriptor
  -> workerchannel.Conn  (grpc.ClientConnInterface)            -> transportauth interceptors (enforce, machines only)
       POST https://dag.txeinternal.com/<mount>/<service>/<method>  -> coordinator.Handler
       protobuf body, bearer credential                          (leases, claim ack, report fence, unchanged)
                 |                                                 ^
                 +--> Cloudflare --> cloudflared --> dagu:8080 ----+
```

The generated client only needs a `grpc.ClientConnInterface`, and the generated `ServiceDesc` hands out each method's own handler. So the 23 RPCs are not rewritten: the same request and reply messages reach the same handler, behind the same interceptors. The coordinator's gRPC port stays private, and no raw gRPC or admin proxy is exposed.

## Options compared

| Option | Verdict | Why |
|---|---|---|
| Bounded HTTP with generated protobuf, on the generated stubs and descriptor | **Chosen** | No new dependency, no RPC semantics rewritten, works through the Tunnel host as ordinary HTTP |
| JSON REST for each RPC | Rejected | Rewrites 23 calls and their error semantics; two descriptions of one protocol |
| Connect or gRPC-Web | Rejected | A new dependency or proxy and regenerated code for what two small files do. Cloudflare Tunnel public hostnames do not carry gRPC at all |
| Proxied gRPC through Cloudflare | Rejected | Needs a public TLS origin on 443 |
| WebSocket | Rejected | 23 RPCs: 19 unary, 3 client streams, 1 server stream, none bidirectional. The worker always dials out. Nothing demonstrates a need |

## Wire

- `POST <mount>/<service>/<method>`, `Authorization: Bearer <machine token>`, one header exactly.
- Unary: the body is the request message. The response is the reply message.
- Client stream: one request whose body is frames, a 4-byte big-endian length and a message, ended by the length `0xFFFFFFFF`. A body that ends anywhere else is a call cut short, never a finished stream. The reply comes when the handler returns.
- Every channel response has `X-Txe-Worker-Channel: 1` and `X-Txe-Channel-Code: <gRPC code>`; a refusal's text is the body, at most 1 KiB. A response without the mark is an edge's and is `Unavailable`, whatever its status. So a Cloudflare 403 can never read as "this machine is refused".
- No server streams are carried. Their one worker use, `GetWorkspaceBundle`, has no resource authorizer, and is refused on enforce today (TXE-4228).

## Authorization

- **Independent of off/off.** The route's own `transportauth.Server` always enforces, needs no hub key and holds none. It requires `txe.authn` and refuses to start without it. Turning it on creates no `hub.key` and changes neither mode.
- **Admit before read.** A credential is verified, and the enrolment read, before any body byte is read.
- **Per call and per message.** The existing interceptors run unchanged: worker id and label compared with the enrolled machine, hub-only methods refused, a method nobody listed refused, and each stream message checked, with the enrolment re-read at most every second.
- **Attempts.** A worker id is proved to belong to the machine, and the handler's existing checks tie a lease, claim, attempt and secret reference to that worker id. Nothing new is needed there.
- **Machine pinning: a gap to close before wiring.** `Handler.machinePinning` comes from `txe.authz.mode`, so under off a task with no machine selector could go to any machine that polls. The hub wiring must make pinning `enforce` for every call that arrived on this route, in `Poll` and `ClaimAgentSessionCleanup`, whatever the mode.
- **TXE-4228** is not a dependency. Hub-only `state`, sub-DAG and bundle calls are refused on the channel exactly as under enforce. TXE job DAGs are command chains and do not make them.

## Bounds

| Bound | Default | Why |
|---|---|---|
| Unary call | 30 s | Below Cloudflare's 125 s proxy read timeout |
| Poll wait | 25 s, then an empty reply | An empty Poll is the ordinary answer and counts as a success |
| Client stream | 110 s | Logs already checkpoint every ~2 s; artifacts are one upload |
| Message | 16 MiB | The coordinator client's existing limit |
| Stream | 64 MiB | Below the 100 MB body limit expected on Cloudflare's lower plans. **The zone's limit must be confirmed** |
| Calls per machine | 256 | A worker holds one Poll per run slot (default 100) |
| Connection setup | 10 s dial, 10 s TLS | |
| Dead connection | HTTP/2 ping at 15 s, 5 s to answer | Bounded stale detection, which gRPC keepalive never gave here |

Cloudflare's published limits: proxy read 125 s, proxy write 30 s, proxy idle 900 s. A stream never idles past 30 s: a log writer closes its stream at each ~2 s checkpoint, and artifact chunks are sent back to back.

**Artifact limit.** One upload walks a whole directory on one stream, so a run's artifacts above 64 MiB fail with `ResourceExhausted`, a truthful failure. If a job needs more, roll the stream per file; that is a small change to the uploader, and it is not done until one does.

## Failure behaviour

| Event | What happens |
|---|---|
| Network loss or an edge error | The call is `Unavailable`. The existing client retries with backoff; the worker's connection state goes offline as it does today |
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
3. Worker: an opt-in hub URL. Calls go through `Conn`, an owner's advertised address is ignored, and a machine credential is required. Without the option, nothing changes, so the port-forward stays as rollback, and old and new workers can run side by side.
4. Install: no tunnel agent, no `kubectl`, the context points at HTTPS; `status.sh` and `doctor` report the channel.
5. Worker-side REST: job, probe and reviewer steps stop using local 18080 and present the machine's credential over HTTPS.
6. Fault rig (below), then `txehq/txe` configuration in its own PR.

Cutover stages, each with its own GO: integration on the rig; review and merge; release tag; hub with the channel enabled and no worker using it; one worker on the channel, port-forward kept; tunnel removed last. Upstream TXE-5506 stays separate: the channel touches only the client's connection type and one hub mount, and v2.24.0 has the same 23 RPCs.

## Test plan

Library, in this PR: identity isolation, missing, expired and revoked credentials, reviewer class, forged worker id and label, on unary and streams; hub key refused; hub-only and unlisted methods refused; health needs a credential; Poll bound; truncated stream; size and concurrency limits; edge answers; redirects; base URL checks; the real log handler resuming on a new request; TLS and HTTP/2.

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
| R13 | A local proxy applying Cloudflare's limits | No call meets them |

## Open before wiring

- The zone's request body limit and whether any Cloudflare bot or rate rule touches a non-browser client on this host.
- Run-slot count on real workers: 100 pollers at 25 s is about 4 requests a second before heartbeats.
- `txe.authn` clients and the machine's enrolment on the hub, which are live changes for their own stage.

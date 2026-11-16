#!/bin/bash
# Copyright (C) 2026 TXE
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The TXE-7516 isolated I5 harness: one test hub, one relay, one worker, one fixture
# job, all on loopback, all owned by this rig. README.md is the runbook; each
# subcommand is one of its steps, and each step checks its preconditions first.
#
#   rig.sh init   --rig D --manifest F --hub-bin F --worker-bin F --reviewer-bin F
#                 --profile D --claude-bin-dir D --repo D
#   rig.sh up            P2: hub, preflight, synthetic identities, relay, worker, fixture, reviewer
#   rig.sh loss          P3: one fixture run, relay cut, real lease expiry observed
#   rig.sh restore       P4: relay restored, fence observed, same worker process
#   rig.sh eligibility   P5
#   rig.sh review-tick [--post-decision]   P6 (once), P9 (once, only after a decision)
#   rig.sh show-proposal P7a: the proposal, for the person who decides
#   rig.sh decide --proposal ID --verdict retry --authority REF   P7b
#   rig.sh proof         P8
#   rig.sh down          P10
#
# Every subcommand after init reads --rig from I5_RIG or the first argument
# `--rig D`. Nothing here uses the shared installation: no launchd, not its
# TXE home, none of its ports (preflight.py SHARED_PORTS), no global network
# setting. rig_test.go holds that against this file's text.
# rig.env and ids.env, written by init and up, define the upper-case settings.
# shellcheck disable=SC1091,SC2153
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PY=${I5_PYTHON:-/usr/bin/python3}
MODEL=claude-opus-5-5
PORT_FRONT=28980
PORT_FRONT_RELAY=28981
PORT_COORD=28255
RELAY_COORD=127.0.0.1:$PORT_COORD
RELAY_FRONT=127.0.0.1:$PORT_FRONT_RELAY
API=http://127.0.0.1:$PORT_FRONT/api/v1        # the harness's own observation path
API_RELAY=http://127.0.0.1:$PORT_FRONT_RELAY/api/v1  # the machine's path, through the relay
WORKER_ID=rig-i5-worker

die() { echo "rig: $*" >&2; exit 1; }
say() { echo "$(date -u +%FT%TZ) $*" | tee -a "$RIG/logs/rig.log"; }
pf() { "$PY" -I "$HERE/preflight.py" "$@"; }
procs() { "$PY" -I "$HERE/procs.py" "$@"; }
relayctl() { "$PY" -I "$HERE/relay.py" ctl "$RIG/control/relay.sock" "$1"; }
json() { "$PY" -I -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
get() { curl -sf "$API$1" -H "Authorization: Bearer $(cat "$RIG/person-token")"; }
post() { curl -sf -X POST "$API$1" -H "Authorization: Bearer $(cat "$RIG/person-token")" -H 'Content-Type: application/json' -d "$2"; }

load() {
  if [ "${1:-}" = --rig ]; then RIG=$2; shift 2; else RIG=${I5_RIG:-}; fi
  [ -n "$RIG" ] || die "give --rig D or set I5_RIG"
  [ -f "$RIG/rig.env" ] || die "$RIG is not an initialised rig"
  # shellcheck source=/dev/null
  . "$RIG/rig.env"
  ARGS=("$@")
  pf pins --manifest "$MANIFEST" >/dev/null || die "the pinned files no longer match $MANIFEST"
}

step_done() { [ -e "$RIG/control/step-$1" ]; }
mark() { date -u +%FT%TZ > "$RIG/control/step-$1"; }
need() { step_done "$1" || die "step $1 has not completed"; }
once() { if step_done "$1"; then die "step $1 already ran; it runs once"; fi; }

cli() { # the machine's CLI, as a coding session on the test machine runs it
  env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$RIG/machine-userhome" TXE_DAGU_HOME="$RIG/machine-home" \
    TXE_SESSION=rig-7516 "$RIG/machine-home/bin/dagu" "$@"
}

# The reviewer binary R, run the same way. `txe review install` renders the
# reviewer and decision DAGs with R's embedded prompt and decision schema
# (internal/txe/review/dag.go RenderDAGs), so it must be R that installs them:
# installed by C, the agent would read the base prompt whatever R's code does.
reviewer_cli() {
  env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$RIG/machine-userhome" TXE_DAGU_HOME="$RIG/machine-home" \
    TXE_SESSION=rig-7516 "$REVIEWER_BIN" "$@"
}

cmd_init() {
  local manifest="" hub="" worker="" reviewer="" profile="" claude_dir="" repo=""
  while [ $# -gt 0 ]; do
    case $1 in
      --rig) RIG=$2 ;; --manifest) manifest=$2 ;; --hub-bin) hub=$2 ;; --worker-bin) worker=$2 ;;
      --reviewer-bin) reviewer=$2 ;; --profile) profile=$2 ;; --claude-bin-dir) claude_dir=$2 ;; --repo) repo=$2 ;;
      *) die "init: unknown argument $1" ;;
    esac
    shift 2
  done
  for v in RIG manifest hub worker reviewer profile claude_dir repo; do
    [ -n "${!v:-}" ] || die "init: --${v//_/-} is required"
  done
  case $RIG in "$HOME/.local/share/txe-dagu"|"$HOME/.local/share/txe-dagu/"*) die "init: that is the shared installation" ;; esac
  case $profile in "$HOME/.claude5"|"$HOME/.claude5/") die "init: ~/.claude5 is the live reviewer's profile" ;; esac
  [ -x "$claude_dir/claude" ] || die "init: no claude in $claude_dir"
  [ -x "$repo/txe/worker/mint-id.sh" ] || die "init: $repo has no txe/worker/mint-id.sh"
  if [ -e "$RIG" ] && [ -n "$(ls -A "$RIG" 2>/dev/null)" ]; then die "init: $RIG exists and is not empty"; fi
  pf pins --manifest "$manifest"
  for b in "$hub" "$worker" "$reviewer"; do
    grep -q "\"path\": \"$b\"" "$manifest" || die "init: $b is not a binary the manifest pins"
  done
  pf ports --free "$PORT_FRONT,$PORT_FRONT_RELAY,$PORT_COORD"
  mkdir -p "$RIG"/{hub,hub-userhome,worker-home,worker-userhome,machine-home/bin,machine-userhome,reviewer-state,control,logs,job,evidence}
  chmod 700 "$RIG/machine-home"
  ln -s "$worker" "$RIG/machine-home/bin/dagu"
  umask 077
  "$PY" -I -c 'import secrets; print(secrets.token_urlsafe(24), end="")' > "$RIG/admin-password"
  local secret; secret=$("$PY" -I -c 'import secrets; print(secrets.token_urlsafe(32))')
  cat > "$RIG/hub/config.yaml" <<EOF
host: 127.0.0.1
port: $PORT_FRONT
auth:
  mode: builtin
  builtin:
    initial_admin:
      username: synth-owner
      password: $(cat "$RIG/admin-password")
    token:
      secret: $secret
      ttl: 24h
coordinator:
  host: "[::1]"
  advertise: 127.0.0.1
  port: $PORT_COORD
EOF
  umask 022
  pf config --hub-config "$RIG/hub/config.yaml" --relay-coord "$RELAY_COORD" --relay-front "$RELAY_FRONT"
  cp "$HERE/fixture-run.sh" "$RIG/job/run.sh"; chmod 755 "$RIG/job/run.sh"
  sed "s|@RIG@|$RIG|g" "$HERE/fixture-job.yaml.tmpl" > "$RIG/job/job.yaml"
  cat > "$RIG/rig.env" <<EOF
MANIFEST=$manifest
HUB_BIN=$hub
WORKER_BIN=$worker
REVIEWER_BIN=$reviewer
PROFILE=$profile
CLAUDE_DIR=$claude_dir
REPO=$repo
EOF
  mark init
  say "initialised $RIG (hub $(basename "$hub"), worker/CLI $(basename "$worker"), reviewer $(basename "$reviewer"))"
}

wait_for() { # wait_for <seconds> <description> <command...>
  local limit=$1 what=$2; shift 2
  local start; start=$(date +%s)
  until "$@"; do
    [ $(( $(date +%s) - start )) -lt "$limit" ] || return 1
    sleep 1
  done
  : "$what"
}

health() { curl -sf "$API/health" >/dev/null; }
registered() { ls "$RIG/hub/data/service-registry/coordinator/"*.json >/dev/null 2>&1; }

cmd_up() {
  need init; once up
  pf ports --free "$PORT_FRONT,$PORT_FRONT_RELAY,$PORT_COORD"
  procs start --pidfile "$RIG/control/hub.pid" --log "$RIG/logs/hub.log" -- \
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$RIG/hub-userhome" DAGU_HOME="$RIG/hub" \
    "$HUB_BIN" start-all --config "$RIG/hub/config.yaml" --dagu-home "$RIG/hub"
  wait_for 60 "hub health" health || die "the hub did not become healthy in 60 s"
  wait_for 30 "coordinator registration" registered || die "no coordinator registration in 30 s"
  # The fail-loud gate: owner calls must reach the relay, or the cut proves nothing.
  pf hub-log --log "$RIG/logs/hub.log" --relay-coord "$RELAY_COORD" --bind "[::1]"
  pf registry --dir "$RIG/hub/data/service-registry/coordinator" --relay-coord "$RELAY_COORD"
  find "$RIG/hub/dags" -maxdepth 1 -name 'example-0*' -delete

  umask 077
  curl -sf -X POST "$API/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"synth-owner\",\"password\":\"$(cat "$RIG/admin-password")\"}" | json 'd["token"]' | tr -d '\n' > "$RIG/person-token"
  post /api-keys '{"name":"rig-machine","description":"TXE-7516 rig machine CLI and reviewer","role":"admin","allowedSurfaces":["rest_api"],"attributionClass":"service_account","serviceAccountName":"rig-machine"}' > "$RIG/apikey.json"
  umask 022
  get /txe/installation > "$RIG/evidence/installation.json"
  json '"republish_sealed" in json.dumps(d)' < "$RIG/evidence/installation.json" | grep -qx True \
    || die "the test installation does not list republish_sealed"

  local owner machine key
  owner=$(bash "$REPO/txe/worker/mint-id.sh" own); machine=$(bash "$REPO/txe/worker/mint-id.sh" mch)
  printf 'OWNER=%s\nMACHINE=%s\n' "$owner" "$machine" > "$RIG/ids.env"
  key=$(json 'd["key"]' < "$RIG/apikey.json")
  local act='{"kind":"cli","id":"rig-installer"}'
  curl -sf -X POST "$API/txe/owners" -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
    -d "{\"owner_id\":\"$owner\",\"display_name\":\"Synthetic Owner (TXE-7516 rig)\",\"actor\":$act}" >/dev/null
  curl -sf -X POST "$API/txe/machines" -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
    -d "{\"machine_id\":\"$machine\",\"owner_id\":\"$owner\",\"display_name\":\"rig-7516-mac\",\"actor\":$act}" >/dev/null
  printf '{"schema":1,"machine_id":"%s","owner_id":"%s","display_name":"rig-7516-mac"}' "$machine" "$owner" > "$RIG/machine-home/machine.json"
  chmod 600 "$RIG/machine-home/machine.json"
  cli context add txe --server="$API_RELAY" --api-key="$key" --dagu-home="$RIG/machine-home/client" >/dev/null 2>&1 \
    || die "context add failed"

  procs start --pidfile "$RIG/control/relay.pid" --log "$RIG/logs/relay.err" -- \
    "$PY" -I "$HERE/relay.py" serve --listen "$RELAY_COORD=[::1]:$PORT_COORD" \
    --listen "$RELAY_FRONT=127.0.0.1:$PORT_FRONT" --control "$RIG/control/relay.sock" --log "$RIG/logs/relay.jsonl"
  wait_for 10 "relay control" test -S "$RIG/control/relay.sock" || die "the relay did not start"

  procs start --pidfile "$RIG/control/worker.pid" --log "$RIG/logs/worker.log" -- \
    /usr/bin/env -i PATH="$CLAUDE_DIR:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$RIG/worker-userhome" DAGU_HOME="$RIG/worker-home" \
    "$WORKER_BIN" worker --dagu-home "$RIG/worker-home" --worker.id "$WORKER_ID" --worker.health-port 0 \
    --worker.labels "txe.machine=$machine" --worker.coordinators "$RELAY_COORD"
  sleep 8
  local wpid; wpid=$(json 'd["pid"]' < "$RIG/control/worker.pid")
  pf conns --pid "$wpid" --allow "$RELAY_COORD,$RELAY_FRONT" --require "$RELAY_COORD"
  get /workers > "$RIG/evidence/workers-up.json"

  (cd "$RIG/job" && cli txe register -f "$RIG/job/job.yaml") > "$RIG/evidence/register.txt" 2>&1 || die "register failed (evidence/register.txt)"
  local job; job=$(grep -o 'job_[0-9A-Z]\{26\}' "$RIG/evidence/register.txt" | head -1)
  [ -n "$job" ] || die "no job id in evidence/register.txt"
  echo "JOB=$job" >> "$RIG/ids.env"
  reviewer_cli txe review install --machine "$machine" --state-dir "$RIG/reviewer-state" --agent-config-dir "$PROFILE" \
    --agent-model "$MODEL" --schedule "0 4 1 1 *" --txe-home "$RIG/machine-home" \
    --review-command "$REVIEWER_BIN txe review" > "$RIG/evidence/review-install.txt" 2>&1 || die "review install failed"
  # The reviewer's own auth check, as its DAG will run it, under the worker's env.
  env -i PATH="$CLAUDE_DIR:/usr/bin:/bin" HOME="$RIG/worker-userhome" CLAUDE_CONFIG_DIR="$PROFILE" claude auth status \
    > "$RIG/evidence/agent-auth-status.txt" 2>&1 || die "claude auth status fails for $PROFILE under the worker env"
  pf logs "$RIG/logs/hub.log" "$RIG/logs/worker.log"
  mark up
  say "up: owner $owner machine $machine job $job"
}

ids() { . "$RIG/ids.env"; R=txe-reviewer-${MACHINE#mch_}; DD=txe-decide-${MACHINE#mch_}; }
label() { get "/dag-runs/$1/$2" | json 'd["dagRunDetails"]["statusLabel"]'; }
is_failed() { [ "$(label "$JOB" "$RUN")" = failed ]; }
# `artifacts begin` writes seals.json before the job runs, with a begun execution
# and no seal; only a seal entry means the result was sealed.
has_seal() {
  SEALS=$(find "$RIG/machine-home/outputs" -path "*runs/$RUN/seals.json" 2>/dev/null | head -1)
  [ -n "$SEALS" ] && "$PY" -I "$HERE/check_seal.py" --has-seal "$SEALS" >/dev/null
}
started() { [ -e "$RIG/control/started-$RUN" ]; }
owner_lost() { grep -q 'Owner coordinator unreachable' "$RIG/logs/worker.log"; }

cmd_loss() {
  need up; once loss; ids
  local out="$RIG/evidence/loss"; mkdir -p "$out"
  cp "$RIG/control/counter" "$out/counter-before" 2>/dev/null || echo 0 > "$out/counter-before"
  RUN=$(post "/dags/$JOB/enqueue" '{}' | json 'd["dagRunId"]'); echo "$RUN" > "$out/run-id"; echo "RUN=$RUN" >> "$RIG/ids.env"
  wait_for 120 "fixture started" started || die "the fixture did not start in 120 s"
  get "/dag-runs/$JOB/$RUN" > "$out/status-running.json"
  relayctl cut > "$out/relay-cut.json"
  local t0; t0=$(date +%s); date -u +%FT%TZ > "$out/T0"
  say "loss: relay cut at T0 for run $RUN"
  date -u +%FT%TZ > "$RIG/control/go-$RUN"
  local verdict=observed
  if wait_for 90 "seal" has_seal; then cp "$SEALS" "$out/seals.json"; echo "$(( $(date +%s) - t0 ))" > "$out/seal-after-sec"
  else verdict="inconclusive: no seal by T0+90s"; fi
  if [ "$verdict" = observed ]; then
    if wait_for $((240 - ($(date +%s) - t0))) "hub failure" is_failed; then echo "$(( $(date +%s) - t0 ))" > "$out/failed-after-sec"
    else verdict="inconclusive: the hub had not failed the run by T0+240s"; fi
  fi
  if [ "$verdict" = observed ]; then
    wait_for $((300 - ($(date +%s) - t0))) "worker owner timeout" owner_lost || verdict="inconclusive: no worker owner-timeout line by T0+300s"
  fi
  get "/dag-runs/$JOB/$RUN" > "$out/status-failed.json" || :
  get "/txe/jobs/$JOB/runs/$RUN/artifacts" > "$out/artifacts-during-cut.json" || :
  relayctl state > "$out/relay-state.json"
  grep -E 'Owner coordinator unreachable|stopped by the worker' "$RIG/logs/worker.log" > "$out/worker-owner-timeout.txt" || :
  cp "$RIG/control/counter" "$out/counter-after-loss"
  echo "$verdict" > "$out/VERDICT"
  say "loss: $verdict"
  [ "$verdict" = observed ] || die "stop: $verdict. The relay stays cut; run 'rig.sh down'."
  mark loss
}

cmd_restore() {
  need loss; once restore; ids; . "$RIG/ids.env"
  local out="$RIG/evidence/restore"; mkdir -p "$out"
  relayctl restore > "$out/relay-restore.json"
  say "restore: relay restored"
  sleep 20
  procs check --pidfile "$RIG/control/worker.pid" > "$out/worker-same-process.json" || die "the worker is not the process that ran the fixture"
  grep -E 'stale attempt' "$RIG/logs/worker.log" > "$out/stale-attempt.txt" || say "restore: no 'stale attempt' rejection in the worker log yet"
  get "/dag-runs/$JOB/$RUN" > "$out/run.json"
  get "/dag-runs/$JOB/$RUN/attempts" > "$out/attempts.json" || :
  get /workers > "$out/workers.json"
  [ "$(label "$JOB" "$RUN")" = failed ] || die "the run is not failed after restore"
  local wpid; wpid=$(json 'd["pid"]' < "$RIG/control/worker.pid")
  pf conns --pid "$wpid" --allow "$RELAY_COORD,$RELAY_FRONT" --require "$RELAY_COORD"
  mark restore
}

cmd_eligibility() {
  need restore; ids; . "$RIG/ids.env"
  local out="$RIG/evidence/eligibility"; mkdir -p "$out"
  get "/txe/jobs/$JOB" > "$out/job.json"
  get "/txe/jobs/$JOB/proposals" > "$out/proposals.json"
  get "/txe/jobs/$JOB/actions" > "$out/actions.json"
  get "/dag-runs/$JOB/$RUN" > "$out/run.json"
  cp "$RIG/evidence/loss/seals.json" "$out/seals.json"
  # Every sealed file still hashes to its seal (the harness reads, never writes, outputs).
  local rundir; rundir=$(dirname "$(find "$RIG/machine-home/outputs" -path "*runs/$RUN/seals.json" | head -1)")
  "$PY" -I "$HERE/check_seal.py" "$out/seals.json" "$rundir" > "$out/seal-bytes.txt" || die "the seal no longer matches its bytes"
  echo "$rundir" > "$RIG/control/run-dir"
  mark eligibility
}

cmd_review_tick() {
  local post=no; [ "${ARGS[0]:-}" = --post-decision ] && post=yes
  if [ "$post" = no ]; then need eligibility; once tick1; else need decided; once tick2; fi
  ids; . "$RIG/ids.env"
  local name; if [ "$post" = no ]; then name=tick1; else name=tick2; fi
  local out="$RIG/evidence/$name"; mkdir -p "$out"
  local tr; tr=$(post "/dags/$R/enqueue" '{}' | json 'd["dagRunId"]'); echo "$tr" > "$out/review-run-id"
  local st=""
  for _ in $(seq 1 330); do # the reviewer DAG's own timeout is 900 s
    st=$(label "$R" "$tr") || st=unreadable; case $st in succeeded|failed|partially_succeeded|aborted) break ;; esac; sleep 3
  done
  get "/dag-runs/$R/$tr" > "$out/review-run.json"
  get "/txe/jobs/$JOB/proposals" > "$out/proposals.json"
  get "/txe/jobs/$JOB/actions" > "$out/actions.json"
  get "/dag-runs/$JOB/$RUN" > "$out/run.json"
  cp -R "$RIG/reviewer-state/reviews" "$out/reviews" 2>/dev/null || :
  cp "$RIG/control/counter" "$out/counter"
  mark "$name"
  say "$name: review run $tr $st"
}

cmd_show_proposal() {
  need tick1; ids
  get "/txe/jobs/$JOB/proposals" | "$PY" -I -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get("open", []), indent=2))' \
    | tee "$RIG/evidence/proposal-for-decision.json"
}

cmd_decide() {
  local p="" v="" auth=""
  set -- "${ARGS[@]}"
  while [ $# -gt 0 ]; do
    case $1 in --proposal) p=$2 ;; --verdict) v=$2 ;; --authority) auth=$2 ;; *) die "decide: unknown argument $1" ;; esac
    shift 2
  done
  [ -n "$p" ] && [ -n "$v" ] && [ -n "$auth" ] || die "decide: --proposal, --verdict and --authority (the message that authorised this exact decision) are all required"
  need tick1; once decided; ids
  local out="$RIG/evidence/decision"; mkdir -p "$out"
  printf '{"authority":"%s","proposal":"%s","verdict":"%s","recorded_at":"%s"}\n' "$auth" "$p" "$v" "$(date -u +%FT%TZ)" > "$out/authority.json"
  get "/txe/jobs/$JOB/proposals" | "$PY" -I -c 'import json,sys; d=json.load(sys.stdin); m=[x for x in d["open"]+d["finished"] if x["proposal_id"]==sys.argv[1]]; print(json.dumps(m[0])) if m else sys.exit("no such proposal")' "$p" > "$out/proposal.json"
  "$PY" -I -c 'import json,sys,uuid; p=json.load(open(sys.argv[1])); print(json.dumps({"expected_proposal_revision":p["revision"],"binding_digest":p["binding_digest"],"verdict":sys.argv[2],"idempotency_key":"rig-7516-"+uuid.uuid4().hex}))' "$out/proposal.json" "$v" > "$out/decision-request.json"
  local task; task=$(json 'd["native_task"]["run_id"]' < "$out/proposal.json")
  for _ in $(seq 1 60); do [ "$(label "$DD" "$task")" = waiting ] && break; sleep 2; done
  local n=0 last
  while :; do
    n=$((n + 1))
    last="$out/decision-response-$n.txt"
    curl -s -w '\nHTTP %{http_code}\n' -X POST "$API/txe/jobs/$JOB/proposals/$p/decisions" -H "Authorization: Bearer $(cat "$RIG/person-token")" \
      -H 'Content-Type: application/json' -d "$(cat "$out/decision-request.json")" > "$last"
    # The same request is repeated, unchanged, only while the hub says the
    # decision is recorded and its follow-up pending (J17's decide.sh).
    if grep -q follow_up_pending "$last" && [ $n -lt 10 ]; then sleep 3; continue; fi
    break
  done
  if grep -q follow_up_pending "$last" || ! tail -1 "$last" | grep -qE '^HTTP 2[0-9][0-9]$'; then
    die "decide: the hub did not complete the decision ($(tail -1 "$last")); see $last. The step is not marked."
  fi
  mark decided
  say "decide: $v on $p under authority $auth"
}

cmd_proof() {
  need decided; ids; . "$RIG/ids.env"
  local out="$RIG/evidence/proof"; mkdir -p "$out"
  local prp action=3
  prp=$(json 'd["proposal"]' < "$RIG/evidence/decision/authority.json")
  for _ in $(seq 1 200); do # up to 10 min for the decided action to settle
    get "/txe/jobs/$JOB/actions" > "$out/actions.json" || { sleep 3; continue; }
    action=0; "$PY" -I "$HERE/actions.py" "$out/actions.json" "$prp" > "$out/action.json" || action=$?
    [ "$action" -eq 3 ] || break
    sleep 3
  done
  get "/dag-runs/$JOB/$RUN" > "$out/run-final.json"
  get "/dag-runs/$JOB/$RUN/attempts" > "$out/attempts.json" || :
  get "/txe/jobs/$JOB/runs/$RUN/artifacts" > "$out/artifacts.json"
  get "/txe/jobs/$JOB/events" > "$out/events.json"
  cp "$RIG/control/counter" "$out/counter"
  local broken=""
  case $action in
    0) ;;
    3) broken="the action for $prp did not settle in 10 min" ;;
    *) broken="the action for $prp did not succeed: $(cat "$out/action.json")" ;;
  esac
  "$PY" -I "$HERE/check_seal.py" "$RIG/evidence/loss/seals.json" "$(cat "$RIG/control/run-dir")" > "$out/seal-bytes-after.txt" \
    || broken="${broken:+$broken; }the sealed bytes changed"
  procs check --pidfile "$RIG/control/worker.pid" > "$out/worker-same-process.json" \
    || broken="${broken:+$broken; }the worker is not the process that ran the fixture"
  [ -z "$broken" ] || die "proof: $broken (evidence kept in $out). The step is not marked."
  mark proof
}

cmd_down() {
  need init
  # up can fail before it writes ids.env (at a preflight gate); teardown must
  # still reach the process stops.
  if [ -f "$RIG/ids.env" ]; then ids; fi
  local out="$RIG/evidence/teardown"; mkdir -p "$out"
  if [ -n "${JOB:-}" ] && step_done up; then cli txe retire "$JOB" > "$out/retire.txt" 2>&1 || say "down: retire failed (see evidence)"; fi
  for p in worker relay hub; do procs stop --pidfile "$RIG/control/$p.pid" >> "$out/stop.txt" 2>&1 || die "down: $p was not stopped (see $out/stop.txt)"; done
  pf ports --free "$PORT_FRONT,$PORT_FRONT_RELAY,$PORT_COORD" > "$out/ports-free.txt"
  pf logs "$RIG"/logs/*.log > "$out/no-shared-port.txt"
  mark down
  chmod -R a-w "$RIG/evidence" "$RIG/hub/data" "$RIG/machine-home/outputs" 2>/dev/null || :
  say "down: stopped; evidence made read-only"
}

main() {
  local sub=${1:-}; shift || :
  case $sub in
    init) cmd_init "$@" ;;
    up|loss|restore|eligibility|review-tick|show-proposal|decide|proof|down)
      load "$@"
      case $sub in
        review-tick) cmd_review_tick ;; show-proposal) cmd_show_proposal ;;
        *) "cmd_$sub" ;;
      esac ;;
    *) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
  esac
}

main "$@"

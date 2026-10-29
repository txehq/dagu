#!/usr/bin/env bash
# Report the local Dagu worker's state without changing anything (TXE-3727).
# Exit 0 when the tunnel and worker agents are running and the server answers.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=txe/worker/lib.sh
. "$here/lib.sh"

rc=0
machine="$TXE_DAGU_HOME/machine.json"
if [ -f "$machine" ]; then
  printf 'machine  %s\nowner    %s\n' "$(json_field "$machine" machine_id)" "$(json_field "$machine" owner_id)"
else
  echo "machine  (not installed)"; rc=1
fi
if [ -L "$TXE_DAGU_HOME/bin/dagu" ]; then
  printf 'binary   %s\n' "$(readlink "$TXE_DAGU_HOME/bin/dagu")"
fi

credential="$(python3 -I "$here/agents.py" credential "$TXE_DAGU_AGENTS_DIR/$TXE_DAGU_WORKER_LABEL.plist")"
if [ -n "$credential" ]; then
  printf 'credential %s\n' "$credential"
  if [ -f "$machine" ]; then
    python3 -I "$here/agents.py" check-credential "$credential" "$(json_field "$machine" machine_id)" >/dev/null || rc=1
  fi
else
  echo "credential (none: the worker presents no machine credential)"
  if [ -e "$TXE_DAGU_HOME/worker-credential.json" ]; then
    printf '  %s exists but the agent does not pass it (installed with --no-credential, or before enrolment)\n' \
      "$TXE_DAGU_HOME/worker-credential.json"
  fi
fi

expires="$TXE_DAGU_HOME/tunnel/kubeconfig.expires"
if [ -s "$expires" ]; then
  exp="$(cat "$expires")"
  left=$(( exp - $(date +%s) ))
  printf 'tunnel credential expires %s (%sh left)\n' "$(date -r "$exp" -u +%Y-%m-%dT%H:%M:%SZ)" $(( left / 3600 ))
  [ "$left" -gt 0 ] || { echo "  EXPIRED: run txe/worker/tunnel-credential.sh"; rc=1; }
else
  echo "tunnel credential (none)"; rc=1
fi

for label in "$TXE_DAGU_TUNNEL_LABEL" "$TXE_DAGU_WORKER_LABEL"; do
  state="$(launchctl print "gui/$(id -u)/$label" 2>/dev/null | awk -F'= ' '/^\tstate = /{print $2; exit}')"
  printf '%-22s %s\n' "$label" "${state:-not loaded}"
  [ "$state" = "running" ] || rc=1
done

# The tunnel supervisor's latest line (TXE-5398): whether it is watching a failing forward
# or last replaced one. Its lines name no argument, path or credential.
last="$(grep -a '^tunnel-supervise:' "$TXE_DAGU_HOME/logs/tunnel.log" 2>/dev/null | tail -n 1)"
# After a rotation (TXE-4724) the latest line may be in the newest rotated file.
if [ -z "$last" ]; then
  newest=""
  for f in "$TXE_DAGU_HOME"/logs/tunnel.log.*.gz; do [ -e "$f" ] && newest="$f"; done
  [ -z "$newest" ] || last="$(gzip -dc "$newest" 2>/dev/null | grep -a '^tunnel-supervise:' | tail -n 1)"
fi
[ -z "$last" ] || printf 'tunnel   %s\n' "${last#tunnel-supervise: }"

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$TXE_DAGU_UI_PORT/api/v1/health")"
printf 'server   http://127.0.0.1:%s/api/v1/health -> %s\n' "$TXE_DAGU_UI_PORT" "$code"
[ "$code" = "200" ] || rc=1
exit "$rc"

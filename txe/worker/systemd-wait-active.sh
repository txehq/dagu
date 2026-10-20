#!/usr/bin/env bash
# systemd-wait-active.sh UNIT... — wait until every systemd user unit is `active`, then require it
# to STAY active with no restart for a settle interval (TXE-4715). A Type=simple unit counts as
# started the moment its process is spawned, so `systemctl restart` succeeds even when the process
# exits at once (an expired kubeconfig, a port in use) and Restart=always then cycles it; a single
# late sample could catch a respawn in its brief active phase. So each unit's restart count
# (NRestarts) is read when the settle starts, the state is sampled every second through it, and the
# count must be unchanged at its end. TXE_DAGU_ACTIVE_WAIT (default 15) bounds the first wait,
# TXE_DAGU_ACTIVE_SETTLE (default 8, longer than RestartSec=5) the settle. Exit 1 names the unit.
set -uo pipefail
wait_s="${TXE_DAGU_ACTIVE_WAIT:-15}"; settle_s="${TXE_DAGU_ACTIVE_SETTLE:-8}"
state() { systemctl --user is-active "$1" 2>/dev/null || true; }
restarts() { systemctl --user show -p NRestarts --value "$1" 2>/dev/null || true; }
fail() { printf 'txe-dagu: %s %s; see: journalctl --user -u %s -n 50\n' "$1" "$2" "$1" >&2; exit 1; }
for unit in "$@"; do
  for _ in $(seq 1 "$wait_s"); do [ "$(state "$unit")" = active ] && break; sleep 1; done
done
units=("$@"); before=()
for i in "${!units[@]}"; do
  before[i]="$(restarts "${units[i]}")"
  [[ "${before[i]}" =~ ^[0-9]+$ ]] || fail "${units[i]}" "has no readable restart count"
done
for _ in $(seq 0 "$settle_s"); do
  for unit in "$@"; do
    s="$(state "$unit")"
    [ "$s" = active ] || fail "$unit" "is ${s:-unknown}, not active"
  done
  if [ "$settle_s" -gt 0 ]; then sleep 1; fi
done
for i in "${!units[@]}"; do
  [ "$(restarts "${units[i]}")" = "${before[i]}" ] || fail "${units[i]}" "restarted while settling (it is cycling), not active"
done

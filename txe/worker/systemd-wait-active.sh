#!/usr/bin/env bash
# systemd-wait-active.sh UNIT... — wait until every systemd user unit is `active` and stays so
# (TXE-4715). A Type=simple unit counts as started the moment its process is spawned, so
# `systemctl restart` succeeds even when the process exits at once (an expired kubeconfig, a port in
# use) and Restart=always then cycles it. This waits up to TXE_DAGU_ACTIVE_WAIT seconds (default 15)
# for each unit to report `active`, then checks again after TXE_DAGU_ACTIVE_SETTLE seconds (default
# 6, longer than RestartSec=5), and exits 1 naming the first unit that is not.
set -uo pipefail
wait_s="${TXE_DAGU_ACTIVE_WAIT:-15}"; settle_s="${TXE_DAGU_ACTIVE_SETTLE:-6}"
state() { systemctl --user is-active "$1" 2>/dev/null || true; }
for unit in "$@"; do
  for _ in $(seq 1 "$wait_s"); do [ "$(state "$unit")" = active ] && break; sleep 1; done
done
sleep "$settle_s"
for unit in "$@"; do
  s="$(state "$unit")"
  if [ "$s" != active ]; then
    printf 'txe-dagu: %s is %s, not active; see: journalctl --user -u %s -n 50\n' "$unit" "${s:-unknown}" "$unit" >&2
    exit 1
  fi
done

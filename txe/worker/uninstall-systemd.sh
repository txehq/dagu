#!/usr/bin/env bash
# Stop and remove the Linux worker's systemd user units (TXE-4715).
#
#   txe/worker/uninstall-systemd.sh           # stop, disable and remove both units; keep the TXE home
#   txe/worker/uninstall-systemd.sh --purge   # and then delete the TXE home (packages, outputs,
#                                             # machine.json, the machine credential): irreversible
#
# Without --purge nothing under TXE_DAGU_HOME is touched, so a later install-systemd.sh resumes as
# the same machine with the same credential. Revoking the machine's enrolment is done in the hub,
# separately; removing the files here does not revoke it.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=txe/worker/lib.sh
. "$here/lib.sh"
TXE_DAGU_UNITS_DIR="${TXE_DAGU_UNITS_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user}"

purge=0
case "${1:-}" in
  "") ;;
  --purge) purge=1 ;;
  *) die "usage: uninstall-systemd.sh [--purge]" ;;
esac
systemctl_bin="$(command -v systemctl)" || die "systemctl is not on PATH"

# A unit that fails to stop is an error, not a warning: --purge must never delete the home of a
# worker that is still running.
for unit in txe-dagu-worker.service txe-dagu-tunnel.service; do
  if [ -e "$TXE_DAGU_UNITS_DIR/$unit" ] || [ "$("$systemctl_bin" --user is-active "$unit" 2>/dev/null || true)" = active ]; then
    "$systemctl_bin" --user disable --now "$unit" >/dev/null || die "could not stop $unit; nothing was removed"
  fi
  state="$("$systemctl_bin" --user is-active "$unit" 2>/dev/null || true)"
  case "$state" in
    active|activating|deactivating|reloading) die "$unit is still $state; nothing was removed" ;;
  esac
  rm -f -- "$TXE_DAGU_UNITS_DIR/$unit"
  printf 'removed %s\n' "$unit"
done
"$systemctl_bin" --user daemon-reload || die "systemctl --user daemon-reload failed"

if [ "$purge" = 1 ]; then
  case "$TXE_DAGU_HOME" in
    ""|/|"$HOME") die "refusing to purge TXE_DAGU_HOME=$TXE_DAGU_HOME" ;;
  esac
  [ -f "$TXE_DAGU_HOME/machine.json" ] || die "refusing to purge $TXE_DAGU_HOME: it holds no machine.json"
  rm -rf -- "$TXE_DAGU_HOME"
  printf 'purged %s\n' "$TXE_DAGU_HOME"
else
  printf 'kept %s\n' "$TXE_DAGU_HOME"
fi

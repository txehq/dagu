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
  # is-active exits non-zero for an inactive unit, so its exit code is not the answer; its word is.
  # Only "inactive" or "failed" is safe; an empty or unknown answer (no user bus, a failed query)
  # fails closed.
  state="$("$systemctl_bin" --user is-active "$unit" 2>/dev/null || true)"
  case "$state" in
    inactive|failed) ;;
    "") die "could not confirm that $unit is stopped (systemctl gave no state); nothing was removed" ;;
    *) die "$unit is still $state; nothing was removed" ;;
  esac
  rm -f -- "$TXE_DAGU_UNITS_DIR/$unit"
  printf 'removed %s\n' "$unit"
done
"$systemctl_bin" --user daemon-reload || die "systemctl --user daemon-reload failed"

if [ "$purge" = 1 ]; then
  # Compare canonical paths: "$HOME/", "$HOME/." or a link to it must not pass as another
  # directory. The home itself, any directory that contains it, and / are refused.
  [ -n "$TXE_DAGU_HOME" ] && [ -d "$TXE_DAGU_HOME" ] || die "refusing to purge TXE_DAGU_HOME=$TXE_DAGU_HOME: not a directory"
  real="$(cd -P -- "$TXE_DAGU_HOME" && pwd -P)" || die "cannot resolve $TXE_DAGU_HOME"
  home_real="$(cd -P -- "$HOME" && pwd -P)" || die "cannot resolve HOME"
  case "$home_real/" in
    "$real"/*) die "refusing to purge $real: it is your home directory or contains it" ;;
  esac
  [ "$real" != / ] || die "refusing to purge /"
  [ -f "$real/machine.json" ] || die "refusing to purge $real: it holds no machine.json"
  rm -rf -- "$real"
  printf 'purged %s\n' "$real"
else
  printf 'kept %s\n' "$TXE_DAGU_HOME"
fi

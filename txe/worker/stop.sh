#!/usr/bin/env bash
# Stop every agent the kit installs (TXE-3727): the worker, the tunnel and the credential watch
# (TXE-7233), in the reverse of the order install.sh loads them. Data, packages, outputs,
# binaries and machine identity are kept; install.sh starts them again.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=txe/worker/lib.sh
. "$here/lib.sh"

for ((i = ${#TXE_DAGU_LABELS[@]} - 1; i >= 0; i--)); do
  label="${TXE_DAGU_LABELS[i]}"
  if launchctl bootout "gui/$(id -u)/$label" 2>/dev/null; then echo "stopped $label"; else echo "$label was not loaded"; fi
done

#!/usr/bin/env bash
# Stop the worker and tunnel agents (TXE-3727). Data, packages, outputs, binaries and
# machine identity are kept; install.sh starts them again.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=txe/worker/lib.sh
. "$here/lib.sh"

for label in "$TXE_DAGU_WORKER_LABEL" "$TXE_DAGU_TUNNEL_LABEL"; do
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null && echo "stopped $label" || echo "$label was not loaded"
done

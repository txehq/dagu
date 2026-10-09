#!/usr/bin/env bash
# Install or upgrade the native Dagu worker and its tunnel on this Mac (TXE-3727).
#
#   txe/worker/install.sh --tag txe-v2.18.2-1 --owner-id own_...   # first install
#   txe/worker/install.sh --tag txe-v2.18.3-1                       # upgrade
#
# It builds the worker from the same fork tag as the cluster image, keeps every
# earlier binary, and writes two launchd agents that run whether or not any coding
# session is open:
#
#   com.txe.dagu.tunnel  kubectl port-forward 127.0.0.1:18080 (UI/API) and
#                        127.0.0.1:50055 (coordinator) to svc/dagu, using the
#                        port-forward-only kubeconfig from tunnel-credential.sh
#   com.txe.dagu.worker  dagu worker, id = this machine's mch_ id, labels
#                        txe.machine and txe.owner, coordinator 127.0.0.1:50055
#
# machine.json is written once and never rewritten: a second install with a
# different --owner-id is refused, so a reinstall cannot change who owns this
# machine's work. Packages, outputs and logs are never touched.
#
# Upgrade while no job is running: restarting the worker ends its running tasks.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=txe/worker/lib.sh
. "$here/lib.sh"

tag="" owner_id=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) tag="${2:-}"; shift 2 ;;
    --owner-id) owner_id="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$tag" =~ ^txe-v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)$ ]] || die "--tag must be txe-v<major>.<minor>.<patch>-<n>"
version="${BASH_REMATCH[1]}-txe.${BASH_REMATCH[2]}"
[ -z "$owner_id" ] || [[ "$owner_id" =~ ^own_[0-9A-HJKMNP-TV-Z]{26}$ ]] || die "--owner-id must be own_<ULID>"

kubectl_bin="$(command -v kubectl)" || die "kubectl is not on PATH"
command -v go >/dev/null || die "go is not on PATH"

umask 077
mkdir -p "$TXE_DAGU_HOME"/{bin,packages,outputs,logs,tunnel,worker-home}

# Machine identity: minted once, then only read.
machine="$TXE_DAGU_HOME/machine.json"
if [ -f "$machine" ]; then
  machine_id="$(json_field "$machine" machine_id)"
  have_owner="$(json_field "$machine" owner_id)"
  [ -z "$owner_id" ] || [ "$owner_id" = "$have_owner" ] \
    || die "machine.json belongs to $have_owner; refusing to change it to $owner_id"
  owner_id="$have_owner"
else
  [ -n "$owner_id" ] || die "first install needs --owner-id own_<ULID>"
  machine_id="$("$here/mint-id.sh" mch)"
  python3 -I - "$machine" "$machine_id" "$owner_id" "$(scutil --get ComputerName 2>/dev/null || hostname)" <<'PY'
import datetime, json, os, sys, tempfile
path, machine_id, owner_id, display = sys.argv[1:]
record = {"schema": 1, "machine_id": machine_id, "owner_id": owner_id,
          "display_name": display,
          "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
# A uniquely named temporary file, so an interrupted install leaves nothing that
# blocks the next one; os.link publishes it only if machine.json does not exist
# yet, so a concurrent installer can never overwrite an identity.
fd, tmp = tempfile.mkstemp(prefix=".machine.", suffix=".tmp", dir=os.path.dirname(path))
try:
    with os.fdopen(fd, "w") as f:
        json.dump(record, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.link(tmp, path)
finally:
    os.unlink(tmp)
PY
fi

# Binary: built from the tag, kept beside every earlier version.
bin="$TXE_DAGU_HOME/bin/dagu-$version"
if [ ! -x "$bin" ]; then
  src="$(mktemp -d)"
  trap 'rm -rf "$src"' EXIT
  git clone --quiet --depth 1 --branch "$tag" "$TXE_DAGU_REPO" "$src/dagu"
  commit="$(git -C "$src/dagu" rev-parse HEAD)"
  # GOTOOLCHAIN=auto: build with the Go release go.mod names (checksum-verified
  # download), whatever the local default toolchain is.
  (cd "$src/dagu" && GOTOOLCHAIN=auto go build -ldflags "-X 'main.version=$version'" -o "$bin.tmp" ./cmd)
  mv "$bin.tmp" "$bin"
  python3 -I - "$TXE_DAGU_HOME/bin/dagu-$version.json" "$tag" "$commit" "$version" "$bin" <<'PY'
import hashlib, json, sys
path, tag, commit, version, binary = sys.argv[1:]
digest = hashlib.sha256(open(binary, "rb").read()).hexdigest()
json.dump({"tag": tag, "commit": commit, "version": version, "sha256": digest},
          open(path, "w"), indent=2)
PY
fi
DAGU_HOME="$TXE_DAGU_HOME/worker-home" "$bin" version 2>&1 | grep -q -- "$version" || die "$bin does not report version $version"
ln -sfn "dagu-$version" "$TXE_DAGU_HOME/bin/dagu.next"
mv -f "$TXE_DAGU_HOME/bin/dagu.next" "$TXE_DAGU_HOME/bin/dagu"

kubeconfig="$TXE_DAGU_HOME/tunnel/kubeconfig"
[ -f "$kubeconfig" ] || die "no tunnel credential at $kubeconfig; run txe/worker/tunnel-credential.sh first"

# launchd agents. PATH is the installing shell's, so scheduled scripts find the same
# tools; nothing else from the environment is copied, and no credential at all.
mkdir -p "$TXE_DAGU_AGENTS_DIR"
python3 -I - "$TXE_DAGU_AGENTS_DIR" "$TXE_DAGU_HOME" "$kubectl_bin" "$machine_id" "$owner_id" "$PATH" \
  "$TXE_DAGU_TUNNEL_LABEL" "$TXE_DAGU_WORKER_LABEL" "$TXE_DAGU_NAMESPACE" "$TXE_DAGU_SERVICE" \
  "$TXE_DAGU_UI_PORT" "$TXE_DAGU_COORD_PORT" <<'PY'
import os, plistlib, sys
(agents, home, kubectl, machine_id, owner_id, path, tunnel_label, worker_label,
 namespace, service, ui_port, coord_port) = sys.argv[1:]
common = {"RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 5,
          "ProcessType": "Background"}
tunnel = dict(common, Label=tunnel_label, ProgramArguments=[
    kubectl, "--kubeconfig", f"{home}/tunnel/kubeconfig", "-n", namespace,
    "port-forward", "--address", "127.0.0.1", service,
    f"{ui_port}:8080", f"{coord_port}:{coord_port}"],
    StandardOutPath=f"{home}/logs/tunnel.log", StandardErrorPath=f"{home}/logs/tunnel.log")
worker = dict(common, Label=worker_label, ProgramArguments=[
    f"{home}/bin/dagu", "worker",
    "--worker.id", machine_id,
    "--worker.labels", f"txe.machine={machine_id},txe.owner={owner_id}",
    "--worker.coordinators", f"127.0.0.1:{coord_port}"],
    EnvironmentVariables={"DAGU_HOME": f"{home}/worker-home", "PATH": path},
    WorkingDirectory=f"{home}/worker-home",
    StandardOutPath=f"{home}/logs/worker.log", StandardErrorPath=f"{home}/logs/worker.log")
for label, body in ((tunnel_label, tunnel), (worker_label, worker)):
    target = os.path.join(agents, f"{label}.plist")
    with open(target + ".tmp", "wb") as f:
        plistlib.dump(body, f)
    os.replace(target + ".tmp", target)
PY

for label in "$TXE_DAGU_TUNNEL_LABEL" "$TXE_DAGU_WORKER_LABEL"; do
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$TXE_DAGU_AGENTS_DIR/$label.plist"
done

printf 'installed %s (%s)\n  machine %s\n  owner   %s\n  home    %s\n' \
  "$version" "$tag" "$machine_id" "$owner_id" "$TXE_DAGU_HOME"
"$here/status.sh"

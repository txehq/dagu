#!/usr/bin/env bash
# Install or upgrade the native Dagu worker and its tunnel on this Mac (TXE-3727).
#
#   txe/worker/install.sh --tag txe-v2.18.2-2 --owner-id own_...   # first install
#   txe/worker/install.sh --tag txe-v2.18.3-1                       # upgrade
#   txe/worker/install.sh --tag txe-v2.18.3-1 --credential-file /abs/worker-credential.json
#   txe/worker/install.sh --tag txe-v2.18.3-1 --no-credential   # roll back; keeps the file
#
# It builds the worker from the same fork tag as the cluster image, keeps every
# earlier binary, and writes two launchd agents that run whether or not any coding
# session is open:
#
#   com.txe.dagu.tunnel  kubectl port-forward 127.0.0.1:18080 (UI/API) and
#                        127.0.0.1:50055 (coordinator) to svc/dagu, using the
#                        port-forward-only kubeconfig from tunnel-credential.sh,
#                        under tunnel-supervise.py, which replaces a forward whose
#                        connection is dead (TXE-5398)
#   com.txe.dagu.worker  dagu worker, id = this machine's mch_ id, labels
#                        txe.machine and txe.owner, coordinator 127.0.0.1:50055
#
# machine.json is written once and never rewritten: a second install with a
# different --owner-id is refused, so a reinstall cannot change who owns this
# machine's work. Packages, outputs and logs are never touched.
#
# Machine credential (TXE-4366). Once `dagu txe enrol` has written this machine's
# worker credential, install again: the worker agent then presents it to the
# coordinator. The credential is --credential-file, or else
# $TXE_DAGU_HOME/worker-credential.json (where enrol writes it) when that file
# exists; with neither, the agents are exactly those of an unenrolled machine. A
# credential that is not this machine's, not owner-only or not a worker's is
# refused before anything is written. The agent gets the file's path only, in
# DAGU_WORKER_AUTH_CREDENTIAL_FILE; no token is ever in the plist, an argument or
# a log. --no-credential (TXE-4418) writes the agent of an unenrolled machine and
# leaves the credential file where it is, so the next install without it passes the
# credential again. Revoking the enrolment in the hub changes nothing here.
#
# Upgrade while no job is running: restarting the worker ends its running tasks.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=txe/worker/lib.sh
. "$here/lib.sh"

tag="" owner_id="" credential="" credential_given=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) tag="${2:-}"; shift 2 ;;
    --owner-id) owner_id="${2:-}"; shift 2 ;;
    --credential-file)
      [ -n "${2:-}" ] || die "--credential-file needs the credential's absolute path"
      [ "$credential_given" != none ] || die "--credential-file and --no-credential cannot both be given"
      credential="$2" credential_given=1; shift 2 ;;
    --no-credential)
      [ "$credential_given" != 1 ] || die "--credential-file and --no-credential cannot both be given"
      credential_given=none; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$tag" =~ ^txe-v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)$ ]] || die "--tag must be txe-v<major>.<minor>.<patch>-<n>"
version="${BASH_REMATCH[1]}-txe.${BASH_REMATCH[2]}"
[ -z "$owner_id" ] || [[ "$owner_id" =~ ^own_[0-9A-HJKMNP-TV-Z]{26}$ ]] || die "--owner-id must be own_<ULID>"

kubectl_bin="$(command -v kubectl)" || die "kubectl is not on PATH"
command -v go >/dev/null || die "go is not on PATH"

umask 077
mkdir -p "$TXE_DAGU_HOME"/{bin,packages,outputs,receipts,client,skill,logs,tunnel,worker-home}

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

# Machine credential: a first check now, before the build, so a refused one changes
# nothing; the built binary checks it again below, as the worker will load it.
credential="$(worker_credential "$credential_given" "$credential" "$machine_id")" \
  || die "not installing: fix the machine credential, or give --credential-file"

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
# The worker built from this tag must load the credential, or the agents are not
# replaced: a worker that cannot load it would only be restarted by launchd forever.
if [ -n "$credential" ]; then
  env "TXE_DAGU_HOME=$TXE_DAGU_HOME" "DAGU_HOME=$TXE_DAGU_HOME/worker-home" "$bin" txe enrol check --credential-file "$credential" \
    || die "not installing: the worker built from $tag cannot load $credential (a tag before TXE-4366 has no 'txe enrol check')"
fi
ln -sfn "dagu-$version" "$TXE_DAGU_HOME/bin/dagu.next"
mv -f "$TXE_DAGU_HOME/bin/dagu.next" "$TXE_DAGU_HOME/bin/dagu"
link_dagu_on_path

kubeconfig="$TXE_DAGU_HOME/tunnel/kubeconfig"
[ -f "$kubeconfig" ] || die "no tunnel credential at $kubeconfig; run txe/worker/tunnel-credential.sh first"

# The tunnel supervisor (TXE-5398) runs from TXE_DAGU_HOME, never from a worktree, with
# the interpreter python3 resolves to now: a version manager's shim needs an environment
# the agent does not have.
python_bin="$(python3 -I -c 'import sys; print(sys.executable)')" || die "python3 is not on PATH"
install -m 0644 "$here/tunnel-supervise.py" "$TXE_DAGU_HOME/tunnel/tunnel-supervise.py.next"
mv -f "$TXE_DAGU_HOME/tunnel/tunnel-supervise.py.next" "$TXE_DAGU_HOME/tunnel/tunnel-supervise.py"

# launchd agents. PATH is the installing shell's, so scheduled scripts find the same
# tools; nothing else from the environment is copied, and no credential: the worker
# gets the machine credential's path, never its contents.
mkdir -p "$TXE_DAGU_AGENTS_DIR"
python3 -I "$here/agents.py" write "$TXE_DAGU_AGENTS_DIR" "$TXE_DAGU_HOME" "$kubectl_bin" "$machine_id" "$owner_id" "$PATH" \
  "$TXE_DAGU_TUNNEL_LABEL" "$TXE_DAGU_WORKER_LABEL" "$TXE_DAGU_NAMESPACE" "$TXE_DAGU_SERVICE" \
  "$TXE_DAGU_UI_PORT" "$TXE_DAGU_COORD_PORT" "$credential" "$python_bin"

for label in "$TXE_DAGU_TUNNEL_LABEL" "$TXE_DAGU_WORKER_LABEL"; do
  # Waits for launchd to finish removing the old agent before loading the new one
  # (TXE-4185); fails naming the label rather than leaving it unloaded.
  launchd_reload "$label" "$TXE_DAGU_AGENTS_DIR/$label.plist"
done

printf 'installed %s (%s)\n  machine %s\n  owner   %s\n  home    %s\n  credential %s\n' \
  "$version" "$tag" "$machine_id" "$owner_id" "$TXE_DAGU_HOME" "${credential:-none (the worker presents no machine credential)}"
if [ "$credential_given" = none ] && [ -e "$TXE_DAGU_HOME/worker-credential.json" ]; then
  printf '  kept %s; install again without --no-credential to pass it\n' "$TXE_DAGU_HOME/worker-credential.json"
fi
"$here/status.sh"

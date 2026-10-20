#!/usr/bin/env bash
# Install or upgrade the native Dagu worker and its tunnel on a Linux machine with systemd
# (TXE-4715). The Linux counterpart of install.sh: same flags, same TXE home, same machine
# identity and credential rules; systemd user units instead of launchd agents.
#
#   txe/worker/install-systemd.sh --tag txe-v2.18.2-12 --owner-id own_...   # first install
#   txe/worker/install-systemd.sh --tag txe-v2.18.3-1                       # upgrade
#   txe/worker/install-systemd.sh --tag txe-v2.18.3-1 --credential-file /abs/worker-credential.json
#   txe/worker/install-systemd.sh --tag txe-v2.18.3-1 --no-credential   # roll back; keeps the file
#
# Tested on Ubuntu 24.04 (arm64) in an isolated OrbStack machine with no host file sharing; other
# distributions with systemd user instances should work but are not claimed.
#
# It writes two units into ~/.config/systemd/user (units.py) and starts them:
#
#   txe-dagu-tunnel.service  kubectl port-forward 127.0.0.1:18080 (UI/API) and
#                            127.0.0.1:50055 (coordinator) to svc/dagu, using the
#                            port-forward-only kubeconfig from tunnel-credential.sh
#   txe-dagu-worker.service  dagu worker, id = this machine's mch_ id, labels
#                            txe.machine and txe.owner, coordinator 127.0.0.1:50055
#
# User units stop at logout unless lingering is on for the user (`loginctl enable-linger`, which
# may need an administrator); the install says which. machine.json, the credential rules and the
# build are exactly install.sh's; see its header. No token is ever in a unit, an argument or a log:
# the worker gets the credential file's path only, in DAGU_WORKER_AUTH_CREDENTIAL_FILE.
#
# Upgrade while no job is running: restarting the worker ends its running tasks.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=txe/worker/lib.sh
. "$here/lib.sh"
TXE_DAGU_UNITS_DIR="${TXE_DAGU_UNITS_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user}"
TXE_DAGU_TUNNEL_UNIT="txe-dagu-tunnel.service"
TXE_DAGU_WORKER_UNIT="txe-dagu-worker.service"

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

[ "$(uname -s)" = Linux ] || die "install-systemd.sh is for Linux; on macOS use txe/worker/install.sh"
[[ "$tag" =~ ^txe-v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)$ ]] || die "--tag must be txe-v<major>.<minor>.<patch>-<n>"
version="${BASH_REMATCH[1]}-txe.${BASH_REMATCH[2]}"
[ -z "$owner_id" ] || [[ "$owner_id" =~ ^own_[0-9A-HJKMNP-TV-Z]{26}$ ]] || die "--owner-id must be own_<ULID>"

systemctl_bin="$(command -v systemctl)" || die "systemctl is not on PATH; this install needs systemd"
kubectl_bin="$(command -v kubectl)" || die "kubectl is not on PATH"
command -v go >/dev/null || die "go is not on PATH"

umask 077
mkdir -p "$TXE_DAGU_HOME"/{bin,packages,outputs,receipts,client,skill,logs,tunnel,worker-home}

# machine.json: written once, never rewritten, exactly as install.sh does.
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
  python3 -I - "$machine" "$machine_id" "$owner_id" "$(hostname)" <<'PY'
import datetime, json, os, sys, tempfile
path, machine_id, owner_id, display = sys.argv[1:]
record = {"schema": 1, "machine_id": machine_id, "owner_id": owner_id,
          "display_name": display,
          "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
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

credential="$(worker_credential "$credential_given" "$credential" "$machine_id")" \
  || die "not installing: fix the machine credential, or give --credential-file"

bin="$TXE_DAGU_HOME/bin/dagu-$version"
if [ ! -x "$bin" ]; then
  src="$(mktemp -d)"
  trap 'rm -rf "$src"' EXIT
  git clone --quiet --depth 1 --branch "$tag" "$TXE_DAGU_REPO" "$src/dagu"
  commit="$(git -C "$src/dagu" rev-parse HEAD)"
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
# The worker built from this tag must load the credential, or the units are not replaced: a
# worker that cannot load it would only be restarted by systemd forever.
if [ -n "$credential" ]; then
  env "TXE_DAGU_HOME=$TXE_DAGU_HOME" "DAGU_HOME=$TXE_DAGU_HOME/worker-home" "$bin" txe enrol check --credential-file "$credential" \
    || die "not installing: the worker built from $tag cannot load $credential (a tag before TXE-4366 has no 'txe enrol check')"
fi
ln -sfn "dagu-$version" "$TXE_DAGU_HOME/bin/dagu.next"
mv -f "$TXE_DAGU_HOME/bin/dagu.next" "$TXE_DAGU_HOME/bin/dagu"
link_dagu_on_path

kubeconfig="$TXE_DAGU_HOME/tunnel/kubeconfig"
[ -f "$kubeconfig" ] || die "no tunnel credential at $kubeconfig; run txe/worker/tunnel-credential.sh first"

# PATH is the installing shell's, so scheduled scripts find the same tools; nothing else from the
# environment is copied, and no credential.
python3 -I "$here/units.py" write "$TXE_DAGU_UNITS_DIR" "$TXE_DAGU_HOME" "$kubectl_bin" "$machine_id" "$owner_id" "$PATH" \
  "$TXE_DAGU_TUNNEL_UNIT" "$TXE_DAGU_WORKER_UNIT" "$TXE_DAGU_NAMESPACE" "$TXE_DAGU_SERVICE" \
  "$TXE_DAGU_UI_PORT" "$TXE_DAGU_COORD_PORT" "$credential" || die "the units were not written"

"$systemctl_bin" --user daemon-reload
for unit in "$TXE_DAGU_TUNNEL_UNIT" "$TXE_DAGU_WORKER_UNIT"; do
  "$systemctl_bin" --user enable "$unit" >/dev/null 2>&1 || die "systemctl --user enable $unit failed"
  "$systemctl_bin" --user restart "$unit" || die "systemctl --user restart $unit failed"
done
# A unit that exits right after starting (expired kubeconfig, port in use) is a failed install.
"$here/systemd-wait-active.sh" "$TXE_DAGU_TUNNEL_UNIT" "$TXE_DAGU_WORKER_UNIT" \
  || die "installed, but a unit is not running; fix it and install again (the units stay installed)"

printf 'installed %s (%s)\n  machine %s\n  owner   %s\n  home    %s\n  credential %s\n' \
  "$version" "$tag" "$machine_id" "$owner_id" "$TXE_DAGU_HOME" "${credential:-none (the worker presents no machine credential)}"
if [ "$credential_given" = none ] && [ -e "$TXE_DAGU_HOME/worker-credential.json" ]; then
  printf '  kept %s; install again without --no-credential to pass it\n' "$TXE_DAGU_HOME/worker-credential.json"
fi
for unit in "$TXE_DAGU_TUNNEL_UNIT" "$TXE_DAGU_WORKER_UNIT"; do
  printf '  %s %s\n' "$unit" "$("$systemctl_bin" --user is-active "$unit" 2>/dev/null || true)"
done
linger="$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || true)"
if [ "$linger" = yes ]; then
  printf '  lingering on: the units run with no login session\n'
else
  printf '  lingering off: the units stop when this user logs out; run "loginctl enable-linger %s" (may need an administrator)\n' "$(id -un)" >&2
fi

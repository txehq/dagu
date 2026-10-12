# shellcheck shell=bash disable=SC2034  # sourced; the scripts read these settings
# Shared settings for the txe/worker scripts. Sourced, never run.
#
# Everything durable lives under TXE_DAGU_HOME, outside every git worktree, so
# deleting a coding session's worktree never removes a package, an output or the
# machine's identity.

TXE_DAGU_HOME="${TXE_DAGU_HOME:-$HOME/.local/share/txe-dagu}"
TXE_DAGU_REPO="${TXE_DAGU_REPO:-https://github.com/txehq/dagu.git}"
# The one cluster this tooling may talk to. Its kube-system UID is the identity
# txehq/txe config/contracts/staging.yaml binds; a context of the same name that
# reaches any other cluster is refused.
TXE_DAGU_CONTEXT="${TXE_DAGU_CONTEXT:-capso-txe-development}"
TXE_DAGU_CLUSTER_UID="f06a22da-b29c-4ac7-9b2b-b5dad50aed6a"
TXE_DAGU_NAMESPACE="dagu"
TXE_DAGU_TUNNEL_SA="dagu-tunnel"
TXE_DAGU_SERVICE="svc/dagu"
# The coordinator advertises 127.0.0.1:50055 as each task's owner address, so the
# tunnel must expose the coordinator on exactly that local port.
TXE_DAGU_UI_PORT=18080
TXE_DAGU_COORD_PORT=50055
TXE_DAGU_AGENTS_DIR="$HOME/Library/LaunchAgents"
# Where `dagu` is linked so that shells and coding-agent sessions find it by name.
# ~/.local/bin is on the PATH of this Mac's login shells and of the worker agent.
TXE_DAGU_LINK_DIR="${TXE_DAGU_LINK_DIR:-$HOME/.local/bin}"
TXE_DAGU_TUNNEL_LABEL="com.txe.dagu.tunnel"
TXE_DAGU_WORKER_LABEL="com.txe.dagu.worker"

die() { printf 'txe-dagu: %s\n' "$*" >&2; exit 1; }

# link_dagu_on_path: make `dagu` resolve to this install by linking
# TXE_DAGU_LINK_DIR/dagu to TXE_DAGU_HOME/bin/dagu, the link install.sh moves to
# each new version. A `dagu` already there that is not that link was put there by
# something else: it is named and left alone, never replaced. Neither case fails
# the install; the binary is always reachable by its full path.
link_dagu_on_path() {
  local target="$TXE_DAGU_HOME/bin/dagu" link="$TXE_DAGU_LINK_DIR/dagu"
  if [ -L "$link" ] && [ "$(readlink "$link")" = "$target" ]; then
    printf 'path     %s -> %s\n' "$link" "$target"
  elif [ -e "$link" ] || [ -L "$link" ]; then
    printf 'path     not linked: %s is not this install'"'"'s link; run %s, or remove it and install again\n' \
      "$link" "$target" >&2
    return 0
  elif mkdir -p "$TXE_DAGU_LINK_DIR" && ln -s "$target" "$link"; then
    # ln -s refuses an existing name, so a dagu that appears meanwhile is kept.
    printf 'path     %s -> %s\n' "$link" "$target"
  else
    printf 'path     not linked: could not create %s; run %s\n' "$link" "$target" >&2
    return 0
  fi
  case ":$PATH:" in
    *":$TXE_DAGU_LINK_DIR:"*) ;;
    *) printf 'path     %s is not on this shell'"'"'s PATH; add it so dagu resolves by name\n' \
         "$TXE_DAGU_LINK_DIR" >&2 ;;
  esac
}

# json_field FILE KEY: print one top-level string field of a JSON file.
json_field() {
  python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

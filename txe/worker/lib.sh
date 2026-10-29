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

# launchd_reload LABEL PLIST: replace a launchd agent with PLIST's definition
# (TXE-4185). `launchctl bootout` returns before launchd has finished removing the
# service, and a `bootstrap` inside that window fails with "5: Input/output error";
# the plain bootout/bootstrap pair therefore left an agent unloaded on the -6 cutover.
# Here the service is booted out, then `launchctl print` is polled, at most
# TXE_DAGU_LAUNCHD_WAIT_TRIES times TXE_DAGU_LAUNCHD_POLL_SECONDS apart (20 s), until
# launchd no longer finds it (exit 113); only then is it bootstrapped, with at most
# TXE_DAGU_LAUNCHD_BOOTSTRAP_TRIES attempts on exit 5. A service that was not loaded
# (bootout exit 3, "No such process") is bootstrapped at once. Every other launchctl
# failure, including a domain launchd cannot act on (print exit 125), ends the install
# with the label and launchd's own message, so an agent is never left silently
# unloaded; nothing here restarts a service beyond the one bootstrap.
launchd_reload() {
  local label="$1" plist="$2" domain out rc i
  domain="gui/$(id -u)"
  local tries="${TXE_DAGU_LAUNCHD_WAIT_TRIES:-40}" poll="${TXE_DAGU_LAUNCHD_POLL_SECONDS:-0.5}"
  local boots="${TXE_DAGU_LAUNCHD_BOOTSTRAP_TRIES:-3}"
  if out="$(launchctl bootout "$domain/$label" 2>&1)"; then rc=0; else rc=$?; fi
  case "$rc" in
    0 | 3) ;; # 0: launchd has begun removing it; 3: it was not loaded
    *) die "$label: launchctl bootout failed ($rc): $out" ;;
  esac
  rc=0
  for ((i = 0; i < tries; i++)); do
    if out="$(launchctl print "$domain/$label" 2>&1)"; then rc=0; else rc=$?; fi
    case "$rc" in
      113) break ;;       # launchd no longer finds the service
      0) sleep "$poll" ;; # still being removed
      *) die "$label: launchctl print failed ($rc): $out" ;;
    esac
  done
  [ "$rc" = 113 ] || die "$label: still loaded after $tries checks ($poll s apart) following bootout, so it was not bootstrapped; see 'launchctl print $domain/$label', then run the install again"
  for ((i = 1; i <= boots; i++)); do
    if out="$(launchctl bootstrap "$domain" "$plist" 2>&1)"; then return 0; else rc=$?; fi
    [ "$rc" = 5 ] || die "$label: launchctl bootstrap failed ($rc): $out"
    if [ "$i" -lt "$boots" ]; then sleep "$poll"; fi
  done
  die "$label: launchctl bootstrap failed with 5 (Input/output error) $boots times; the agent is not loaded; run the install again"
}

# link_dagu_on_path: make `dagu` resolve to this install by linking
# TXE_DAGU_LINK_DIR/dagu to TXE_DAGU_HOME/bin/dagu, the link install.sh moves to
# each new version. A `dagu` already there that is not that link was put there by
# something else: it is named and left alone, never replaced. Neither case fails
# the install; the binary is always reachable by its full path.
link_dagu_on_path() {
  local target="$TXE_DAGU_HOME/bin/dagu" link="$TXE_DAGU_LINK_DIR/dagu" made
  # A link stores its target as written, and a relative one resolves from the
  # link's own directory, so the target is made absolute first.
  case "$target" in /*) ;; *) target="$PWD/$target" ;; esac
  if [ -L "$link" ] && [ "$(readlink "$link")" = "$target" ]; then
    printf 'path     %s -> %s\n' "$link" "$target"
  else
    # os.symlink creates exactly this pathname or fails: an existing file,
    # symlink or directory there, even one that appeared a moment ago, is never
    # written into or replaced (ln -s would put the link inside a directory).
    made="$(mkdir -p "$TXE_DAGU_LINK_DIR" 2>/dev/null && python3 -I -c '
import os, sys
try:
    os.symlink(sys.argv[1], sys.argv[2])
    print("made")
except FileExistsError:
    print("exists")
except OSError:
    print("failed")' "$target" "$link" 2>/dev/null)" || made=failed
    case "$made" in
      made) printf 'path     %s -> %s\n' "$link" "$target" ;;
      exists) printf 'path     not linked: %s is not this install'"'"'s link; run %s, or remove it and install again\n' \
                "$link" "$target" >&2 ;;
      *) printf 'path     not linked: could not create %s; run %s\n' "$link" "$target" >&2 ;;
    esac
  fi
  case ":$PATH:" in
    *":$TXE_DAGU_LINK_DIR:"*) ;;
    *) printf 'path     %s is not on this shell'"'"'s PATH; add it so dagu resolves by name\n' \
         "$TXE_DAGU_LINK_DIR" >&2 ;;
  esac
}

# worker_credential GIVEN PATH MACHINE_ID: print the machine credential file the
# worker agent is to pass, or nothing. GIVEN is 1 when --credential-file named PATH,
# and "none" for --no-credential: nothing is passed and no file is read, moved or
# removed. Otherwise enrol's default, TXE_DAGU_HOME/worker-credential.json, is used
# when it exists (a dangling link included, so it is refused rather than ignored). A
# file that is not a usable credential for MACHINE_ID fails with the reason on stderr.
worker_credential() {
  local given="$1" path="$2" machine_id="$3" default="$TXE_DAGU_HOME/worker-credential.json"
  [ "$given" != none ] || return 0
  if [ "$given" != 1 ]; then
    if [ -e "$default" ] || [ -L "$default" ]; then path="$default"; else return 0; fi
  fi
  python3 -I "$(dirname "${BASH_SOURCE[0]}")/agents.py" check-credential "$path" "$machine_id" >&2 || return 1
  printf '%s\n' "$path"
}

# json_field FILE KEY: print one top-level string field of a JSON file.
json_field() {
  python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

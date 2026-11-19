#!/usr/bin/env bash
# Write the tunnel's own kubeconfig: a short credential that can do nothing but
# port-forward to the dagu Service (TXE-3727).
#
#   txe/worker/tunnel-credential.sh [--duration 720h]
#
# Run it from your own shell. It uses your interactive context once, checks that it
# reaches the expected cluster by kube-system UID, and asks the API server for a
# token for ServiceAccount dagu/dagu-tunnel (TokenRequest). That account's Role,
# delivered by txehq/txe kubernetes/dagu, grants get on services and pods and create
# on pods/portforward in namespace dagu, nothing else.
#
# Why not the interactive context itself: it renews through a browser OIDC flow,
# which a launchd agent cannot complete, so the tunnel would silently stop at the
# next expiry. This token expires too; status.sh prints when, and rerunning this
# script renews it.
#
# The token is written to $TXE_DAGU_HOME/tunnel/kubeconfig (mode 0600) and is never
# printed. It is a service-issued tunnel credential and stays on this machine; no
# resource credential of yours is involved or copied anywhere.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=txe/worker/lib.sh
. "$here/lib.sh"

duration="720h"
while [ $# -gt 0 ]; do
  case "$1" in
    --duration) duration="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

ctx="$TXE_DAGU_CONTEXT"
uid="$(kubectl --context "$ctx" get ns kube-system -o jsonpath='{.metadata.uid}')"
[ "$uid" = "$TXE_DAGU_CLUSTER_UID" ] || die "context $ctx reaches kube-system UID $uid, not $TXE_DAGU_CLUSTER_UID; refusing"

cluster="$(kubectl config view -o jsonpath="{.contexts[?(@.name==\"$ctx\")].context.cluster}")"
server="$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"$cluster\")].cluster.server}")"
ca="$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"$cluster\")].cluster.certificate-authority-data}")"
[ -n "$server" ] || die "context $ctx has no cluster server"

umask 077
tdir="$TXE_DAGU_HOME/tunnel"
mkdir -p "$tdir"
# The token is written only into a directory this user owns and no other account
# can enter: there, no other account can swap the candidate for a link, or read
# it even if its mode changes. A directory that is a link, not this user's, or
# open to group or others in any way is refused before any token is asked for
# (TXE-7864). The script makes it 0700 itself. What this does not cover: a
# process of this same account, which could read the token directly anyway.
if [ -L "$tdir" ] || [ ! -d "$tdir" ] || [ ! -O "$tdir" ]; then
  die "$tdir is not a directory this user owns (or it is a symbolic link); refusing to write a credential there"
fi
# private PATH: no permission bit for group or others.
private() {
  [ -z "$(find "$1" -maxdepth 0 \( -perm -040 -o -perm -020 -o -perm -010 -o -perm -004 -o -perm -002 -o -perm -001 \) -print)" ]
}
if ! private "$tdir"; then
  die "$tdir is open to group or others; refusing to write a credential there (chmod 700 it)"
fi
# Nor can another account replace the directory itself: every directory above
# it, by its physical path, is this user's or root's, and one that group or
# others can write has the sticky bit, so only its owner can rename what is in
# it (/tmp). Otherwise the tunnel directory could be renamed away and a link
# put in its place, and the candidate and cleanup would follow the link
# (independent review of PR 293). From here on the physical path is used.
tdir="$(cd "$tdir" && pwd -P)" || die "cannot resolve $tdir"
a="$tdir"
while [ "$a" != / ]; do
  a="${a%/*}"
  [ -n "$a" ] || a=/
  if ! { [ -O "$a" ] || [ -n "$(find "$a" -maxdepth 0 -user 0 -print)" ]; }; then
    die "$a, above $tdir, belongs to another account; refusing to write a credential there"
  fi
  if [ -n "$(find "$a" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print)" ] && [ ! -k "$a" ]; then
    die "$a, above $tdir, is writable by group or others without the sticky bit, so the tunnel directory could be replaced; refusing to write a credential there"
  fi
done
out="$tdir/kubeconfig"
# The new credential is written to a private candidate and checked there. Only a
# candidate that passes replaces the live kubeconfig, so a refused renewal leaves
# the tunnel on the credential it already had.
cand="$(mktemp "$out.XXXXXX")"
# The candidate holds a service-account token. Leaving it behind is a defect, not
# a best-effort cleanup (TXE-7864, the rule of txe's TXE-7858): when its removal
# fails, or its absence cannot be proved, the script fails, and an earlier
# failure keeps its own status. Absence is proved, never inferred from rm's
# status: the parent can be searched and holds no entry by that name. A path
# that became a symbolic link or a file of another account is reported too: its
# link is removed, never followed, and the run fails. The candidate and its
# .expires are one pair, checked and reported together. The message names the
# path only, never the token or the file's contents.
cand_absent() {
  [ -d "${1%/*}" ] && [ -x "${1%/*}" ] && [ ! -e "$1" ] && [ ! -L "$1" ]
}
cleanup() {
  local p
  for p in "$cand" "$cand.expires"; do
    if [ -L "$p" ] || { [ -e "$p" ] && [ ! -O "$p" ]; }; then
      printf 'txe-dagu: FATAL: %s (a tunnel credential candidate) was replaced by a symbolic link or a file of another account; it was not written through, and only that entry is removed\n' "$p" >&2
      [ "${RC:-0}" -ne 0 ] || RC=1
    fi
    if ! rm -f -- "$p" || ! cand_absent "$p"; then
      printf 'txe-dagu: FATAL: %s (a token-bearing tunnel credential candidate) may still be on disk: its removal failed or its absence could not be verified (rm'"'"'s error, if any, is above); remove it\n' "$p" >&2
      [ "${RC:-0}" -ne 0 ] || RC=1
    fi
  done
}
trap 'RC=$?; set +e; cleanup; exit "$RC"' EXIT

# The token goes straight from kubectl into the file through python's stdin; it is
# never in an argument, an environment variable or the terminal.
kubectl --context "$ctx" -n "$TXE_DAGU_NAMESPACE" create token "$TXE_DAGU_TUNNEL_SA" --duration "$duration" \
  | python3 -I -c '
import base64, json, os, stat, sys
out, server, ca, ns = sys.argv[1:]
token = sys.stdin.read().strip()
if not token:
    sys.exit("txe-dagu: the API server returned no token")
claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
cluster = {"server": server}
if ca:
    cluster["certificate-authority-data"] = ca
config = {
    "apiVersion": "v1", "kind": "Config",
    "clusters": [{"name": "txe-dagu", "cluster": cluster}],
    "users": [{"name": "dagu-tunnel", "user": {"token": token}}],
    "contexts": [{"name": "txe-dagu-tunnel",
                  "context": {"cluster": "txe-dagu", "user": "dagu-tunnel", "namespace": ns}}],
    "current-context": "txe-dagu-tunnel",
}
# The candidate is the private file mktemp made: never followed if it became a
# link, and refused unless it is a regular file of this user, with one link and
# no access for group or others. Its .expires is created new, never reused.
try:
    fd = os.open(out, os.O_WRONLY | os.O_NOFOLLOW)
except OSError:
    sys.exit("txe-dagu: the credential candidate is not the file this run made; refusing to write the credential")
st = os.fstat(fd)
if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or st.st_mode & 0o077:
    sys.exit("txe-dagu: the credential candidate is not a private file of this user; refusing to write the credential")
os.ftruncate(fd, 0)
with os.fdopen(fd, "w") as f:
    json.dump(config, f)
try:
    efd = os.open(out + ".expires", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except OSError:
    sys.exit("txe-dagu: the credential candidate'"'"'s .expires already exists; refusing to reuse it")
with os.fdopen(efd, "w") as f:
    f.write(str(claims.get("exp", "")) + "\n")
' "$cand" "$server" "$ca" "$TXE_DAGU_NAMESPACE"

# The pair is still the private files the writer made: neither has become a
# link (which kubectl and mv would follow or promote), another account's file,
# or open to others. Checked before each use of the candidate and before it is
# moved; the directory is this user's alone, so no other account can swap it
# in between.
cand_intact() {
  local p
  for p in "$cand" "$cand.expires"; do
    if [ -L "$p" ] || [ ! -f "$p" ] || [ ! -O "$p" ] || ! private "$p"; then
      die "the credential candidate $p is no longer the private file this run wrote; refusing to use it, kept the previous credential"
    fi
  done
}
cand_intact

# Prove the credential does what the tunnel needs, and no more than that.
kubectl --kubeconfig "$cand" -n "$TXE_DAGU_NAMESPACE" auth can-i create pods --subresource=portforward >/dev/null \
  || die "the new credential cannot port-forward in $TXE_DAGU_NAMESPACE; kept the previous one"
cand_intact
if kubectl --kubeconfig "$cand" -n "$TXE_DAGU_NAMESPACE" auth can-i get secrets >/dev/null 2>&1; then
  die "the new credential can read Secrets; the dagu-tunnel Role is wider than intended; kept the previous one"
fi
# The kubeconfig and its .expires are a pair: when the second move fails, the
# live .expires would name the old credential's expiry, so it is removed and
# the run fails. Two renames are not one atomic step: if that removal fails
# too, the pair disagrees, and the FATAL line names the stale file.
cand_intact
mv -f "$cand" "$out"
if ! mv -f "$cand.expires" "$out.expires"; then
  if ! rm -f -- "$out.expires" || [ -e "$out.expires" ] || [ -L "$out.expires" ]; then
    printf 'txe-dagu: FATAL: %s may still hold the previous credential'"'"'s expiry beside the new credential in %s: its removal failed (rm'"'"'s error, if any, is above); remove it\n' "$out.expires" "$out" >&2
    die "the new credential is in $out, but its expiry record could not be moved beside it, and the old one could not be removed; run this script again"
  fi
  die "the new credential is in $out, but its expiry record could not be moved beside it; $out.expires was removed so that status.sh does not report the old expiry; run this script again"
fi
printf 'wrote %s (expires %s)\n' "$out" \
  "$(date -r "$(cat "$out.expires")" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"

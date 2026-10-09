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
mkdir -p "$TXE_DAGU_HOME/tunnel"
out="$TXE_DAGU_HOME/tunnel/kubeconfig"

# The token goes straight from kubectl into the file through python's stdin; it is
# never in an argument, an environment variable or the terminal.
kubectl --context "$ctx" -n "$TXE_DAGU_NAMESPACE" create token "$TXE_DAGU_TUNNEL_SA" --duration "$duration" \
  | python3 -I -c '
import base64, json, os, sys
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
tmp = out + ".tmp"
with open(tmp, "w") as f:
    json.dump(config, f)
os.chmod(tmp, 0o600)
os.replace(tmp, out)
with open(out + ".expires", "w") as f:
    f.write(str(claims.get("exp", "")) + "\n")
' "$out" "$server" "$ca" "$TXE_DAGU_NAMESPACE"

# Prove the credential does what the tunnel needs, and no more than that.
kubectl --kubeconfig "$out" -n "$TXE_DAGU_NAMESPACE" auth can-i create pods --subresource=portforward >/dev/null \
  || die "the new credential cannot port-forward in $TXE_DAGU_NAMESPACE"
if kubectl --kubeconfig "$out" -n "$TXE_DAGU_NAMESPACE" auth can-i get secrets >/dev/null 2>&1; then
  die "the new credential can read Secrets; the dagu-tunnel Role is wider than intended"
fi
printf 'wrote %s (expires %s)\n' "$out" \
  "$(date -r "$(cat "$out.expires")" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"

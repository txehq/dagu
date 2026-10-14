#!/usr/bin/env bash
# Refuse the pass unless every account given is in the allowlist (main's copy).
#
#   authorize.sh <authorized-actors.txt> <login>...
#
# The workflow passes the PR's author, the event's sender, github.actor and
# github.triggering_actor. An empty login is refused: an event that names no actor reviews nothing.
set -euo pipefail
[ "$#" -ge 2 ] || { echo "usage: authorize.sh <authorized-actors.txt> <login>..." >&2; exit 2; }
list="$1"; shift
[ -f "$list" ] || { echo "authorize: $list is missing" >&2; exit 1; }
allowed="$(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$list" | grep -v '^$' || true)"
for login in "$@"; do
  if [ -z "$login" ] || ! grep -Fxq -- "$login" <<<"$allowed"; then
    echo "::error::codex-review: '${login:-<none>}' is not in authorized-actors.txt; nothing is reviewed" >&2
    exit 1
  fi
done
echo "authorize: every actor of this event is authorized ($#)"

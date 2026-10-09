#!/usr/bin/env bash
# Print a new opaque id: <prefix>_<ULID>, for example own_01J9Z3...
# The contract (txe/contract/README.md) allows only these prefixes.
set -euo pipefail

prefix="${1:-}"
case "$prefix" in
  own|prj|mch|job|clm|dec|act) ;;
  *) echo "usage: mint-id.sh own|prj|mch|job|clm|dec|act" >&2; exit 2 ;;
esac

python3 -I - "$prefix" <<'PY'
import os, sys, time
alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
value = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
ulid = "".join(alphabet[(value >> (5 * i)) & 31] for i in reversed(range(26)))
print(f"{sys.argv[1]}_{ulid}")
PY

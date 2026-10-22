#!/bin/sh
# One harmless run: print a result line and publish it as result.json.
set -eu
line="$(printf '{"ok":true,"observed_at":"%s"}' "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
printf '%s\n' "$line" > "$TXE_RUN_OUTPUT_DIR/result.json"
printf '%s\n' "$line"

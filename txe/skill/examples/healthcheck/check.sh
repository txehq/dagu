#!/bin/sh
# Health check: report whether one target is present and fresh.
#
# The target is named by a stable identity, not by a path that could be reused:
# TARGET_PATH must hold a file whose first line is TARGET_ID. A missing file is
# "absent"; a file carrying another id is "replaced". Neither is reported as
# healthy, and neither is treated as the same target.
#
#   TARGET_PATH      file standing in for the monitored resource
#   TARGET_ID        the identity recorded when the job was registered
#   MAX_AGE_SEC      optional; older than this is "stale"
#   TXE_OUTPUT_DIR   durable directory for this job's results
#
# Prints one JSON result line. Exit 0 healthy, 1 unhealthy, 2 misconfigured.
set -eu

: "${TARGET_PATH:?TARGET_PATH is required}"
: "${TARGET_ID:?TARGET_ID is required}"
: "${TXE_OUTPUT_DIR:?TXE_OUTPUT_DIR is required}"

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
state=healthy
detail=""

if [ ! -e "$TARGET_PATH" ]; then
  state=absent
elif [ ! -r "$TARGET_PATH" ]; then
  state=unreadable
  detail="permission denied; this is not evidence the target was deleted"
else
  found="$(head -n 1 "$TARGET_PATH")"
  if [ "$found" != "$TARGET_ID" ]; then
    state=replaced
    detail="found identity $found"
  elif [ -n "${MAX_AGE_SEC:-}" ]; then
    modified="$(stat -f %m "$TARGET_PATH" 2>/dev/null || stat -c %Y "$TARGET_PATH")"
    age=$(( $(date +%s) - modified ))
    if [ "$age" -gt "$MAX_AGE_SEC" ]; then
      state=stale
      detail="last changed ${age}s ago"
    fi
  fi
fi

result="$(printf '{"observed_at":"%s","target_id":"%s","state":"%s","detail":"%s"}' \
  "$now" "$TARGET_ID" "$state" "$detail")"

mkdir -p "$TXE_OUTPUT_DIR"
printf '%s\n' "$result" >> "$TXE_OUTPUT_DIR/observations.jsonl"
printf '%s\n' "$result"

[ "$state" = healthy ]

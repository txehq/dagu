#!/bin/sh
# Post-integration validation: pass until a success condition is met, then say so.
#
# Each run probes once. After REQUIRED_PASSES consecutive passes the job has met
# its completion criterion: it writes the final deliverable and reports
# "complete": true. Deciding to stop the schedule belongs to the job's lifecycle,
# not to this script, so a completed job that runs again only repeats the report.
#
#   PROBE_PATH        file that must contain the word "ok" for a probe to pass
#   REQUIRED_PASSES   consecutive passes needed (default 3)
#   TXE_OUTPUT_DIR    durable directory for this job's state and deliverable
#
# Prints one JSON result line. Exit 0 on a pass, 1 on a failed probe, 2 when
# misconfigured.
set -eu

: "${PROBE_PATH:?PROBE_PATH is required}"
: "${TXE_OUTPUT_DIR:?TXE_OUTPUT_DIR is required}"
required="${REQUIRED_PASSES:-3}"

mkdir -p "$TXE_OUTPUT_DIR"
streak_file="$TXE_OUTPUT_DIR/streak"
deliverable="$TXE_OUTPUT_DIR/validation-report.json"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

streak=0
[ -f "$streak_file" ] && streak="$(cat "$streak_file")"

if [ -r "$PROBE_PATH" ] && grep -qx ok "$PROBE_PATH"; then
  streak=$((streak + 1))
  passed=true
else
  streak=0
  passed=false
fi

printf '%s\n' "$streak" > "$streak_file.partial"
mv "$streak_file.partial" "$streak_file"

complete=false
if [ "$streak" -ge "$required" ]; then
  complete=true
  if [ ! -f "$deliverable" ]; then
    printf '{"completed_at":"%s","consecutive_passes":%s,"required":%s}\n' \
      "$now" "$streak" "$required" > "$deliverable.partial"
    mv "$deliverable.partial" "$deliverable"
  fi
fi

printf '{"observed_at":"%s","passed":%s,"consecutive_passes":%s,"required":%s,"complete":%s}\n' \
  "$now" "$passed" "$streak" "$required" "$complete"

[ "$passed" = true ]

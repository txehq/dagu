#!/bin/bash
# Copyright (C) 2026 TXE
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The I5 harness's fixture job (TXE-7516). Harmless: no network, no shared state.
# One execution:
#   1. counts itself in the rig's control/counter (the one-effect counter, outside
#      the package) and writes control/started-<run>;
#   2. waits for control/go-<run>, written by the harness after it cuts the relay,
#      for at most I5_GO_WAIT_SEC (120) seconds; on timeout it exits 1, so nothing
#      is sealed and the attempt is inconclusive;
#   3. writes result.json, unique to this run;
#   4. exits 0, and the rendered DAG's `artifacts seal` seals result.json.
set -eu
control=${I5_CONTROL_DIR:?the job sets I5_CONTROL_DIR}
run=${DAG_RUN_ID:?dagu sets DAG_RUN_ID}
out=${TXE_RUN_OUTPUT_DIR:?the txe run step sets TXE_RUN_OUTPUT_DIR}
wait_sec=${I5_GO_WAIT_SEC:-120}

n=$(( $(cat "$control/counter" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$control/counter.tmp"
mv "$control/counter.tmp" "$control/counter"
date -u +%FT%TZ > "$control/started-$run"

waited=0
while [ ! -e "$control/go-$run" ]; do
  if [ "$waited" -ge "$wait_sec" ]; then
    echo "no go marker for $run after ${wait_sec}s; exiting without a result" >&2
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done

prev=null
if [ -f "$control/last-result-sha256" ]; then
  prev="\"$(cat "$control/last-result-sha256")\""
fi
printf '{"run_id":"%s","ordinal":%d,"previous_result_sha256":%s,"written_at":"%s"}\n' \
  "$run" "$n" "$prev" "$(date -u +%FT%TZ)" > "$out/result.json"
if command -v shasum >/dev/null; then sum="shasum -a 256"; else sum=sha256sum; fi
$sum "$out/result.json" | cut -d' ' -f1 > "$control/last-result-sha256"
cat "$out/result.json"

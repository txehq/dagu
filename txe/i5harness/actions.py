#!/usr/bin/env python3
# Copyright (C) 2026 TXE
# SPDX-License-Identifier: GPL-3.0-or-later
"""The state of the action a decided proposal created (TXE-7516 harness).

  actions.py <GET /txe/jobs/{job}/actions JSON> <proposal id>

The reply is {"archived": [...], "in_flight": [...]}; each action names its
proposal_id, its state and, once admitted, outcome.admitted_execution. Exit:
  0  the proposal's action succeeded with an admitted execution;
  3  no action yet, or it is still in flight (ask again);
  2  it settled any other way (failed, escalated, uncertain, ...), or more than
     one action names the proposal.
It prints one JSON line with what it found. It only reads.
"""

import json
import sys


def main(argv):
    if len(argv) != 2:
        print((__doc__ or "").strip(), file=sys.stderr)
        return 2
    doc = json.load(open(argv[0]))
    want = argv[1]
    found = []
    for bucket in ("in_flight", "archived"):
        for a in doc.get(bucket) or []:
            if a.get("proposal_id") == want:
                found.append((bucket, a))
    if not found:
        print(json.dumps({"proposal": want, "state": None}))
        return 3
    if len(found) > 1:
        print(json.dumps({"proposal": want, "error": f"{len(found)} actions name this proposal"}))
        return 2
    bucket, a = found[0]
    outcome = a.get("outcome") or {}
    report = {"proposal": want, "action": a.get("action_id"), "bucket": bucket, "state": a.get("state"),
              "admitted_execution": outcome.get("admitted_execution"), "detail": outcome.get("detail")}
    print(json.dumps(report))
    if bucket == "in_flight":
        return 3
    if a.get("state") == "succeeded" and outcome.get("admitted") and outcome.get("admitted_execution"):
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

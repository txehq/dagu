#!/usr/bin/env python3
# Copyright (C) 2026 TXE
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check that a run's sealed files still hash to their seal (TXE-7516 harness).

  check_seal.py <copy of seals.json> <run dir: outputs/<job>/runs/<run>>

The run directory holds seals.json, executions/<execution>/<path> and attempts/.
It prints one line per file and a summary JSON line, and exits 2 when any file is
missing or differs, when there is not exactly one seal and one begun execution,
or when attempts/ is not empty (an interrupted second begin). It only reads.
"""

import hashlib
import json
import os
import sys


def main(argv):
    if len(argv) != 2:
        print((__doc__ or "").strip(), file=sys.stderr)
        return 2
    seals = json.load(open(argv[0]))
    run_dir = argv[1]
    errs = []
    begun, sealed = seals.get("begun", []), seals.get("seals", [])
    if len(begun) != 1:
        errs.append(f"{len(begun)} begun executions, want 1")
    if len(sealed) != 1:
        errs.append(f"{len(sealed)} seals, want 1")
    attempts = os.path.join(run_dir, "attempts")
    left = sorted(os.listdir(attempts)) if os.path.isdir(attempts) else []
    if left:
        errs.append(f"attempts/ holds {left}")
    for s in sealed:
        for f in s.get("files", []):
            p = os.path.join(run_dir, "executions", s["execution"], f["path"])
            if not os.path.isfile(p):
                errs.append(f"{s['execution']}/{f['path']} is missing")
                continue
            got = "sha256:" + hashlib.sha256(open(p, "rb").read()).hexdigest()
            ok = got == f["sha256"]
            print(f"{'OK  ' if ok else 'DIFF'} {s['execution']}/{f['path']} {got}")
            if not ok:
                errs.append(f"{s['execution']}/{f['path']} hashes to {got}, sealed {f['sha256']}")
    print(json.dumps({"ok": not errs, "errors": errs,
                      "execution": sealed[0]["execution"] if len(sealed) == 1 else None}))
    return 2 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

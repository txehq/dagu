#!/usr/bin/env python3
# Copyright (C) 2026 TXE
# SPDX-License-Identifier: GPL-3.0-or-later
"""P8: the publish-only recovery published the sealed bytes, and only that (TXE-7516).

  check_proof.py --run <GET /dag-runs/{job}/{run}> --artifacts <GET /txe/jobs/{job}/runs/{run}/artifacts>
                 --seals <seals.json copied at the loss> --admitted <execution id from the action>
                 --counter-at-loss F --counter-now F

An action that "succeeded" says the retry was dispatched, not that it finished
(the reviewer's observeRetry counts a dispatched execution as applied). So this
checks the run itself:
  - the run's current execution is the admitted one and it has finished;
  - it is a retry of the sealed execution (retryRequest.retryOf);
  - its publish step succeeded and its run step was not executed again;
  - the hub's artifacts record that execution, produced_in = the sealed one,
    and every sealed file with the sealed sha256;
  - the fixture's counter did not move after the loss.
Exit 0 when all hold, 3 while the execution is still queued or running, 2 when
any check fails. One JSON line reports every check. It only reads.
"""

import argparse
import json
import sys

UNFINISHED = {"queued", "running", "not_started", "waiting"}


def main(argv):
    p = argparse.ArgumentParser(prog="check_proof.py")
    for f in ("--run", "--artifacts", "--seals", "--admitted", "--counter-at-loss", "--counter-now"):
        p.add_argument(f, required=True)
    a = p.parse_args(argv)
    run = json.load(open(a.run)).get("dagRunDetails") or {}
    seals = json.load(open(a.seals)).get("seals") or []
    errs = []
    if len(seals) != 1:
        print(json.dumps({"ok": False, "errors": [f"{len(seals)} seals in the loss snapshot, want 1"]}))
        return 2
    seal = seals[0]
    status = run.get("statusLabel")
    if run.get("executionRef") != a.admitted:
        errs.append(f"the run is at execution {run.get('executionRef')!r}, not the admitted {a.admitted!r}")
    elif status in UNFINISHED:
        print(json.dumps({"ok": False, "pending": True, "status": status}))
        return 3
    if status != "succeeded":
        errs.append(f"the admitted execution ended {status!r}")
    retry_of = (run.get("retryRequest") or {}).get("retryOf")
    if retry_of != seal["execution"]:
        errs.append(f"retryRequest.retryOf is {retry_of!r}, not the sealed {seal['execution']!r}")
    nodes = {(n.get("step") or {}).get("name"): n.get("statusLabel") for n in run.get("nodes") or []}
    if nodes.get("publish") != "succeeded":
        errs.append(f"the publish step is {nodes.get('publish')!r}")
    if nodes.get("run") == "succeeded":
        errs.append("the run step succeeded in the recovery: the job ran again")
    try:
        art = json.load(open(a.artifacts))
    except (OSError, ValueError) as err:
        art = {}
        errs.append(f"artifacts unreadable: {err}")
    if art.get("execution") != a.admitted:
        errs.append(f"the artifacts record execution {art.get('execution')!r}, not {a.admitted!r}")
    produced = (art.get("produced_in") or {}).get("execution")
    if produced != seal["execution"]:
        errs.append(f"produced_in is {produced!r}, not the sealed {seal['execution']!r}")
    published = {x.get("path"): x.get("sha256") for x in art.get("artifacts") or []}
    for f in seal.get("files") or []:
        if published.get(f["path"]) != f["sha256"]:
            errs.append(f"{f['path']}: published {published.get(f['path'])!r}, sealed {f['sha256']!r}")
    extra = sorted(set(published) - {f["path"] for f in seal.get("files") or []})
    if extra:
        errs.append(f"published files that were not sealed: {extra}")
    before, now = open(a.counter_at_loss).read().strip(), open(a.counter_now).read().strip()
    if before != now:
        errs.append(f"the fixture counter moved from {before} to {now}: the job ran again")
    print(json.dumps({"ok": not errs, "errors": errs, "status": status, "nodes": nodes,
                      "produced_in": produced, "counter": now}))
    return 2 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

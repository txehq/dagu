#!/usr/bin/env python3
"""Data collector: write one dated snapshot of a source directory.

The job depends on lib/snapshot.py, which sits beside this file. Registering the
job must package both; a package holding only this file fails at import.

    SOURCE_DIR       directory to summarise
    TXE_OUTPUT_DIR   durable directory for this job's snapshots

Prints the snapshot path and a one-line JSON summary. Exit 0 on success, 1 when
the source cannot be read, 2 when misconfigured.
"""

import json
import os
import sys
from datetime import datetime, timezone

from lib.snapshot import summarise


def main() -> int:
    source = os.environ.get("SOURCE_DIR")
    output = os.environ.get("TXE_OUTPUT_DIR")
    if not source or not output:
        print("SOURCE_DIR and TXE_OUTPUT_DIR are required", file=sys.stderr)
        return 2

    try:
        summary = summarise(source)
    except OSError as err:
        print(f"cannot read {source}: {err}", file=sys.stderr)
        return 1

    taken = datetime.now(timezone.utc)
    summary["collected_at"] = taken.strftime("%Y-%m-%dT%H:%M:%SZ")

    os.makedirs(output, exist_ok=True)
    path = os.path.join(output, f"snapshot-{taken.strftime('%Y%m%dT%H%M%SZ')}.json")
    partial = path + ".partial"
    with open(partial, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(partial, path)

    print(path)
    print(json.dumps({k: summary[k] for k in ("collected_at", "files", "bytes")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

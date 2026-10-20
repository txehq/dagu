"""Reduce recorded connector payloads to what codex-review-check.sh reads (TXE-4719).

The recordings come from private repositories (txehq/txe, txehq/sub2api) and this repository is
public, so only structure is kept: ids, SHAs, times, users, labels, events, the connector's state
block, its Code Review row, its receipt lines and each finding's badge. People's logins become
a-person and branch names synthetic-branch; bot logins are kept, the check reads them. Every other line of a body
is dropped, code hunks and URLs are removed, and file paths become synthetic ones.

  python3 -I sanitize.py <file.json>...   # rewrites each file in place; idempotent
"""
import json, re, sys

KEEP = re.compile(r"codex-review-state:v1|\*\*Code Review\*\*|codex-review-receipt:v1|major issues|Reviewed commit")
BADGE = re.compile(r"\b(P[0-3]) Badge\b")
DROP_KEYS = {"diff_hunk", "_links", "node_id", "gravatar_id", "performed_via_github_app", "description"}
paths = {}


def body(text):
    out = []
    for line in (text or "").split("\n"):
        m = BADGE.search(line)
        if m:
            out.append(f"**<sub><sub>![{m.group(1)} Badge](badge)</sub></sub>  Synthetic finding title**")
        elif KEEP.search(line):
            out.append(line)
    return "\n".join(out) if out else "Synthetic comment."


def walk(v, key=None):
    if isinstance(v, dict):
        return {k: walk(x, k) for k, x in v.items()
                if k not in DROP_KEYS and not (k == "url" or k.endswith("_url"))}
    if isinstance(v, list):
        return [walk(x) for x in v]
    if key == "body" and isinstance(v, str):
        return body(v)
    if key == "login" and isinstance(v, str) and not v.endswith("[bot]"):
        return "a-person"
    if key in ("ref", "label") and isinstance(v, str):
        return "synthetic-branch"
    if key == "path" and isinstance(v, str):
        return paths.setdefault(v, v if v.startswith("synthetic/") else f"synthetic/file{len(paths) + 1}.go")
    return v


for name in sys.argv[1:]:
    with open(name) as f:
        data = json.load(f)
    with open(name, "w") as f:
        json.dump(walk(data), f, indent=1, ensure_ascii=False)
        f.write("\n")
for old, new in paths.items():
    print(f"{new}\t{len(old)}")

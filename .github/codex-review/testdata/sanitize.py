"""Reduce recorded connector payloads to what codex-review-check.sh reads (TXE-4719).

The recordings come from private repositories (txehq/txe, txehq/sub2api) and this repository is
public. So every object is rebuilt from an explicit allowlist of fields, and every body is rebuilt
from values parsed out of it, never copied: the connector's state block (re-serialized from its
known keys), its Code Review row (from its datetime and status), its receipt (from the reviewed
commit), and each finding's badge (from its level). Paths become synthetic, people's logins
a-person, branch names synthetic-branch, repository names synthetic/repo; state values and
timestamps are kept only in their known shapes; bot logins are kept, the check reads them.

  python3 -I sanitize.py <file.json>...   # rewrites each file in place; idempotent
"""
import json, re, sys

FIELDS = {"id", "user", "login", "type", "body", "created_at", "updated_at", "submitted_at",
          "commit_id", "original_commit_id", "pull_request_review_id", "in_reply_to_id", "path",
          "line", "original_line", "start_line", "original_start_line", "side", "position",
          "original_position", "subject_type", "event", "actor", "label", "name", "color", "head",
          "sha", "repo", "full_name", "labels", "draft", "state", "number", "ref"}
STATE_KEYS = {"commit_sha", "has_any_findings", "has_unresolved_findings", "status"}
paths = {}


def state_value(k, v):
    """A state value only in its known shape: a 40-hex SHA, a boolean, a short status word, or null."""
    if v is None or isinstance(v, bool):
        return v
    if k == "commit_sha" and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{40}", v):
        return v
    if k == "status" and isinstance(v, str) and re.fullmatch(r"[a-z_]{1,20}", v):
        return v
    return None


def state_line(m):
    block = json.loads(m.group(1))
    clean = {part: {k: state_value(k, v) for k, v in (block.get(part) or {}).items() if k in STATE_KEYS}
             for part in ("code_review", "security_review") if part in block}
    return "<!-- codex-review-state:v1 " + json.dumps(clean, separators=(",", ":")) + " -->"


def body(text):
    out = []
    for line in (text or "").split("\n"):
        if (m := re.search(r"<!-- codex-review-state:v1 (.*?) -->", line)):
            out.append(state_line(m))
        elif "**Code Review**" in line:
            t = re.search(r'datetime="([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]+)?Z)"', line)
            done = "Completed" in line
            out.append("| \U0001F4DD **Code Review** | " + ("✅ **Completed** " if done else "**Running** ")
                       + (f'<relative-time datetime="{t.group(1)}">{t.group(1)}</relative-time>' if t else "") + " |")
        elif "codex-review-receipt:v1" in line:
            out.append("<!-- codex-review-receipt:v1 -->")
        elif "major issues" in line:
            out.append("Codex Review: Didn't find any major issues.")
        elif (m := re.search(r"Reviewed commit:[*]* *`([0-9a-f]{7,40})`", line)):
            out.append(f"**Reviewed commit:** `{m.group(1)}`")
        elif (m := re.search(r"\b(P[0-3]) Badge\b", line)):
            out.append(f"**<sub><sub>![{m.group(1)} Badge](badge)</sub></sub>  Synthetic finding title**")
    return "\n".join(out) if out else "Synthetic comment."


def walk(v, key=None):
    if isinstance(v, dict):
        return {k: walk(x, k) for k, x in v.items() if k in FIELDS}
    if isinstance(v, list):
        return [walk(x) for x in v]
    if not isinstance(v, str):
        return v
    if key == "body":
        return body(v)
    if key == "login":
        return v if v.endswith("[bot]") else "a-person"
    if key in ("ref", "label"):
        return "synthetic-branch"
    if key == "path":
        return paths.setdefault(v, v if v.startswith("synthetic/") else f"synthetic/file{len(paths) + 1}.go")
    if key == "full_name":
        return "synthetic/repo"
    if key in ("name", "state", "event", "type", "side", "subject_type", "color"):
        return v if len(v) <= 40 and "\n" not in v else "synthetic"
    return v


if __name__ == "__main__":
    for name in sys.argv[1:]:
        with open(name) as f:
            data = json.load(f)
        with open(name, "w") as f:
            json.dump(walk(data), f, indent=1, ensure_ascii=False)
            f.write("\n")

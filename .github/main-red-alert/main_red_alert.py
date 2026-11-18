#!/usr/bin/env python3
"""Post to Mattermost #infra-alert when a watched workflow turns red on main (TXE-7846).

A red SecurityScans run on main reached nobody: GitHub mails a failed scheduled run only to
the last person who edited its cron. The 2026-11-16 scheduled run (43798559034) stayed red
until an unrelated PR could not merge two days later, and the 2026-10-12 to 10-26 streak
went three weeks unseen. SecurityScans runs weekly, so the alert fires on the first red run,
not after a streak.

.github/workflows/main-red-alert.yaml runs `notify` on every completed run of the workflows
it lists (`on.workflow_run.workflows`). The rule is stateless; it reads the run's own history:

  * Only a run whose event is schedule or push, on branch main, from this repository, counts.
    A pull request from a fork whose branch is named main reaches workflow_run with
    head_branch "main"; its head repository is the fork, so it is ignored.
  * A conclusion of failure, timed_out or startup_failure is red; success is green. Any other
    conclusion (cancelled, skipped, neutral, ...) neither alerts nor clears.
  * The state before the run is its newest earlier attempt that was red or green (a re-run),
    otherwise the newest earlier counted run of the same workflow on main.
  * Every red run posts, so the first red is never missed: "is red" after green or no counted
    run, "is still red" after red. A previous red is not proof that its post was delivered
    (the notifier may have been installed mid-streak, or that POST failed), and the rule keeps
    no state to prove it, so it repeats rather than goes quiet. A watched workflow fires at
    most daily (SecurityScans: weekly), which bounds the repeats.
  * Green after red: post the clear. Green after green: nothing.
  * The history read fails: a red run posts "is red" anyway; a green run fails this job, since
    it cannot tell whether a clear is due.

The post names the repository, the workflow and the run link, nothing else: this repository
is public and a scan's findings stay in the run.

`check` is the coverage rule: every workflow with `on: schedule` must be listed by name in the
notifier's workflow_run trigger, and every listed name must be a workflow here. It runs on
every pull request that touches a workflow. `replay --run-id N` evaluates a past run through
the same code, read-only, and prints what notify would post; it never posts.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

WORKFLOWS = pathlib.Path(".github") / "workflows"
NOTIFIER = WORKFLOWS / "main-red-alert.yaml"
BRANCH = "main"
EVENTS = ("schedule", "push")
RED = ("failure", "timed_out", "startup_failure")
GREEN = ("success",)
API = "https://api.github.com"
# History pages read before the previous counted run is called unknown (100 runs a page).
MAX_PAGES = 3

# chat.engapp.dev sits behind Cloudflare bot protection that 403s default library
# User-Agents (TXE-6112, measured in txe's scheduled_workflow_watchdog.py).
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


class ReadError(Exception):
    """A GitHub read that did not complete; never treated as an empty history."""


# ---------------------------------------------------------------------------------- the rule


def state_of(conclusion: str | None) -> str | None:
    if conclusion in RED:
        return "red"
    if conclusion in GREEN:
        return "green"
    return None


def counts(run: dict, repo: str) -> bool:
    """Whether a run is one of main's own schedule or push runs."""
    head_repo = (run.get("head_repository") or {}).get("full_name")
    return run.get("event") in EVENTS and run.get("head_branch") == BRANCH and head_repo == repo


def previous_state(run: dict, history: list[dict], repo: str) -> str | None:
    """The state of the newest counted run of the history created before `run`.

    `history` is any list of the workflow's runs; `run` itself and runs created after it are
    skipped. Order is (created_at, id), so two runs created in the same second still order.
    """
    key = (run["created_at"], run["id"])
    best = None
    for h in history:
        if h.get("id") == run["id"] or not counts(h, repo):
            continue
        if h.get("status") != "completed" or state_of(h.get("conclusion")) is None:
            continue
        hk = (h["created_at"], h["id"])
        if hk < key and (best is None or hk > (best["created_at"], best["id"])):
            best = h
    return None if best is None else state_of(best["conclusion"])


def decide(now: str | None, before: str | None, before_known: bool = True) -> str | None:
    """'alert', 'still', 'clear' or None for a run in state `now` after state `before`."""
    if now == "red":
        return "still" if before_known and before == "red" else "alert"
    if now == "green":
        if not before_known:
            raise ReadError("the run is green but the previous run's state could not be read")
        return "clear" if before == "red" else None
    return None


def message(action: str, repo: str, workflow: str, run_url: str) -> str:
    if action == "alert":
        return f":rotating_light: {repo}: workflow `{workflow}` is red on {BRANCH}. Run: {run_url}"
    if action == "still":
        return f":rotating_light: {repo}: workflow `{workflow}` is still red on {BRANCH}. Run: {run_url}"
    return f":white_check_mark: {repo}: workflow `{workflow}` is green again on {BRANCH}. Run: {run_url}"


# ----------------------------------------------------------------------------------- GitHub


def gh_get(path: str, token: str | None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "txehq-dagu-main-red-alert",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise ReadError(f"GET {path}: HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise ReadError(f"GET {path}: {type(e).__name__}") from None


def prior_state(run: dict, repo: str, token: str | None, get=gh_get) -> str | None:
    """The state before `run`, read from GitHub. Raises ReadError when it cannot be read."""
    attempt = int(run.get("run_attempt") or 1)
    # A re-run: its newest earlier attempt that was red or green, walking past cancelled ones.
    for n in range(attempt - 1, 0, -1):
        prev = get(f"/repos/{repo}/actions/runs/{run['id']}/attempts/{n}", token)
        s = state_of(prev.get("conclusion"))
        if s is not None:
            return s
    branch = urllib.parse.quote(BRANCH)
    history: list[dict] = []
    for page in range(1, MAX_PAGES + 1):
        body = get(
            f"/repos/{repo}/actions/workflows/{run['workflow_id']}/runs"
            f"?branch={branch}&status=completed&per_page=100&page={page}",
            token,
        )
        runs = body.get("workflow_runs")
        if not isinstance(runs, list):
            raise ReadError("workflow runs listing has no workflow_runs array")
        history.extend(runs)
        found = previous_state(run, history, repo)
        if found is not None or len(runs) < 100:
            return found
    # MAX_PAGES full pages with no earlier counted run: unknown, not "none".
    raise ReadError(f"no counted run before {run['id']} in the newest {MAX_PAGES * 100} runs")


def evaluate(run: dict, repo: str, token: str | None, get=gh_get) -> tuple[str | None, str]:
    """Decide for one completed run. Returns (action, a one-line reason for the log)."""
    if not counts(run, repo):
        head_repo = (run.get("head_repository") or {}).get("full_name")
        return None, f"not a {BRANCH} schedule/push run of {repo} (event={run.get('event')} branch={run.get('head_branch')} repo={head_repo})"
    now = state_of(run.get("conclusion"))
    if now is None:
        return None, f"conclusion {run.get('conclusion')} neither alerts nor clears"
    try:
        before = prior_state(run, repo, token, get)
        known = True
        why = f"now {now}, before {before or 'no counted run'}"
    except ReadError as e:
        before, known = None, False
        why = f"now {now}, before unknown ({e})"
    return decide(now, before, known), why


def post_mattermost(webhook: str, text: str) -> tuple[bool, str]:
    """POST one message. Nothing derived from `webhook` reaches the detail: the URL is the credential."""
    try:
        payload = json.dumps({"text": text, "username": "dagu-main-red-alert", "icon_emoji": ":alarm_clock:"}).encode()
        req = urllib.request.Request(
            webhook,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": BROWSER_UA},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            return 200 <= r.status < 300, str(r.status)
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except ValueError:
        return False, "webhook URL is malformed (value withheld: it is a credential)"
    except Exception as e:  # noqa: BLE001
        return False, type(e).__name__


# --------------------------------------------------------------------------------- commands


def cmd_notify(args, env=os.environ, get=gh_get, post=post_mattermost) -> int:
    repo = env["GITHUB_REPOSITORY"]
    event = json.loads(pathlib.Path(env["GITHUB_EVENT_PATH"]).read_text())
    run = event.get("workflow_run")
    if not isinstance(run, dict):
        print("::error::the event has no workflow_run")
        return 1
    workflow = run.get("name") or "?"
    try:
        action, why = evaluate(run, repo, env.get("GH_TOKEN"), get)
    except ReadError as e:
        print(f"::error::{workflow} run {run.get('id')}: {e}")
        return 1
    print(f"{workflow} run {run.get('id')} attempt {run.get('run_attempt')}: {why}: {action or 'no post'}")
    if action is None:
        return 0
    text = message(action, repo, workflow, run["html_url"])
    webhook = env.get("MM_WEBHOOK", "")
    if not webhook:
        print(f"would post: {text}")
        print("::error::a post is due but MATTERMOST_WEBHOOK_URL is not set for this repository: nothing was delivered")
        return 1
    ok, detail = post(webhook, text)
    print(f"posted {action}: delivered={ok} ({detail})")
    if not ok:
        print("::error::the #infra-alert post failed")
        return 1
    return 0


def cmd_replay(args, env=os.environ, get=gh_get) -> int:
    repo = args.repo
    token = env.get("GH_TOKEN")
    rc = 0
    for run_id in args.run_id:
        try:
            run = get(f"/repos/{repo}/actions/runs/{run_id}", token)
            action, why = evaluate(run, repo, token, get)
        except ReadError as e:
            print(f"run {run_id}: ERROR {e}")
            rc = 1
            continue
        line = f"run {run_id} ({run.get('event')}, {run.get('conclusion')}, {run.get('created_at')}): {why}: "
        print(line + (f"would post: {message(action, repo, run.get('name') or '?', run['html_url'])}" if action else "no post"))
    return rc


def _on(doc: dict) -> dict:
    # YAML 1.1 reads a bare `on` key as boolean true.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {e: None for e in on}
    return on if isinstance(on, dict) else {}


def coverage_errors(root: pathlib.Path) -> list[str]:
    import yaml  # GitHub's ubuntu images ship python3-yaml; only `check` needs it.

    errors: list[str] = []
    names: dict[str, str] = {}
    scheduled: list[tuple[str, str | None]] = []
    files = sorted(p for p in (root / WORKFLOWS).iterdir() if p.suffix in (".yaml", ".yml"))
    notifier_doc = None
    for p in files:
        doc = yaml.safe_load(p.read_text()) or {}
        name = doc.get("name")
        if isinstance(name, str):
            names[name] = p.name
        on = _on(doc)
        if "schedule" in on:
            scheduled.append((p.name, name if isinstance(name, str) else None))
            for entry in on.get("schedule") or []:
                cron = str((entry or {}).get("cron", "")).split()
                if len(cron) != 5 or not (cron[0].isdigit() and cron[1].isdigit()):
                    errors.append(
                        f"{p.name}: cron {' '.join(cron)!r} may fire more than once a day; every red run "
                        "posts to #infra-alert, so a watched workflow fires at most daily "
                        "(a fixed minute and hour). A faster one needs a deduplicating rule first."
                    )
        if p.name == NOTIFIER.name:
            notifier_doc = doc
    if notifier_doc is None:
        return [f"{NOTIFIER} is missing"]
    wr = _on(notifier_doc).get("workflow_run") or {}
    listed = wr.get("workflows") or []
    if wr.get("types") != ["completed"]:
        errors.append(f"{NOTIFIER.name}: workflow_run.types must be [completed], got {wr.get('types')}")
    if wr.get("branches") != [BRANCH]:
        errors.append(f"{NOTIFIER.name}: workflow_run.branches must be [{BRANCH}], got {wr.get('branches')}")
    for file, name in scheduled:
        if name is None:
            errors.append(f"{file} has `on: schedule` but no `name:`; workflow_run matches a workflow by its name")
        elif name not in listed:
            errors.append(
                f"{file} (`{name}`) has `on: schedule` but is not in {NOTIFIER.name}'s "
                "on.workflow_run.workflows: a red scheduled run would reach nobody (TXE-7846)"
            )
    for name in listed:
        if name not in names:
            errors.append(f"{NOTIFIER.name} lists `{name}`, which is not the name of any workflow here")
    return errors


def cmd_check(args) -> int:
    errors = coverage_errors(pathlib.Path(args.root))
    for e in errors:
        print(f"::error::{e}")
    if not errors:
        print("every scheduled workflow is watched by main-red-alert.yaml")
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Alert #infra-alert when a watched workflow turns red on main.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("notify", help="decide and post for the workflow_run event in GITHUB_EVENT_PATH")
    r = sub.add_parser("replay", help="print what notify would post for past runs; never posts")
    r.add_argument("--repo", default="txehq/dagu")
    r.add_argument("--run-id", action="append", required=True, type=int)
    c = sub.add_parser("check", help="fail when a scheduled workflow is not watched")
    c.add_argument("--root", default=".")
    args = ap.parse_args(argv)
    return {"notify": cmd_notify, "replay": cmd_replay, "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

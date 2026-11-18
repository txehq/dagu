#!/usr/bin/env python3
"""Post to Mattermost #infra-alert when a watched workflow turns red on main (TXE-7846).

A red SecurityScans run on main reached nobody: GitHub mails a failed scheduled run only to
the last person who edited its cron. The 2026-11-16 scheduled run (43798559034) stayed red
until an unrelated PR could not merge two days later, and the 2026-10-12 to 10-26 streak
went three weeks unseen. SecurityScans runs weekly, so the alert fires on the first red run,
not after a streak.

.github/workflows/main-red-alert.yaml runs on every completed run of the workflows it lists
(`on.workflow_run.workflows`). Its `decide` step runs this script's `notify`, which writes the
due post (if any) for its `Post alert` or `Post clear` step; that step runs `post`, which
delivers it or fails. Nothing is cached: the rule reads two histories through the API.

The watched workflow's runs (what is red):
  * Only a run whose event is schedule or push, on branch main, from this repository, counts.
    A pull request from a fork whose branch is named main reaches workflow_run with
    head_branch "main"; its head repository is the fork, so it is ignored.
  * failure, timed_out and startup_failure are red; success is green. Any other conclusion
    (cancelled, skipped, ...) is passed over.
  * Each attempt is its own event, ordered by its run's creation, the run id, then the
    attempt: a run re-run red, green, red is three events and two streaks, and a red run whose
    re-run was cancelled stays red. A streak is the consecutive red events up to the one judged.

The notifier's own runs (what was delivered):
  * Each one is named `notify <workflow id> <run id> <attempt>` (the workflow's run-name), so a
    delivery belongs to one event, and
    only its `workflow_run` runs are read: those always run the default branch's copy of the
    workflow, which a pull request cannot change.
  * An alert or clear counts as delivered only when the `Post alert` or `Post clear` step of
    such a run concluded success. That step fails when the webhook secret is missing or the
    POST gets anything but 2xx, so a missing configuration or a failed delivery never counts
    as sent.

The rule:
  * An event with a newer event after it (a later run, or a later attempt of the same run) is
    superseded: no post (no stale alert or clear; the newer event's notify decides).
  * Red: post the alert unless an alert for this streak was already delivered. That gives one
    recorded delivery per streak; a retry on every later red run while none is recorded
    (activation mid-streak, a failed POST); and no second post for a duplicate or re-run
    delivery whose first post was recorded.
  * Green after a red streak whose alert was delivered: post the clear unless one of the
    greens since the streak delivered it, so a failed clear is retried by the next green.
    Green after a streak whose alert was never delivered: the clear says so, and it is posted
    only for the first green event after the streak.
  * A read fails, or a finished notifier run has no readable notify job: the decision fails
    closed. The job fails with ::error:: and posts nothing; it neither guesses "not
    delivered" (and posts) nor "delivered" (and stays quiet). The next event retries.

Delivery is at-least-once, not exactly-once. Mattermost incoming webhooks have no idempotency
key, so a send whose outcome is uncertain is retried: the webhook accepted the message but the
response was lost (a timeout), or the runner died before the step's success was recorded.
The retry is a duplicate. Every post therefore carries the streak's stable identifier (the
run id of its first red event), so a reader sees that two posts are the same alert. A
duplicate is possible only after such an uncertain send; a recorded delivery is never
repeated.

GitHub's concurrency group keeps one notify running and at most one pending per watched
workflow; a newer pending notify replaces an older one (the replaced run ends cancelled with
its job never started, which counts as nothing delivered). Only main's own schedule and push
runs reach the job (its `if`), so a fork's pull request cannot queue there and replace one. That is safe because no decision
depends on an earlier notify having run: the newer one reads the same history and record, so
a replaced red's alert is posted by the next red of its streak, and a replaced green's clear
by the next green.

The post names the repository, the workflow and run links, nothing else: this repository is
public and a scan's findings stay in the run. Its destination comes only from the
MATTERMOST_WEBHOOK_URL secret, never from the event or the repository.

`check` is the coverage rule: every workflow with `on: schedule` must be listed by name in the
notifier's workflow_run trigger, every listed name must be a workflow here, and the notifier
keeps the trigger shape, run-name and step names this script reads. `replay` evaluates past
runs through the same rule, read-only, with a simulated delivery record; it never posts.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
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
# Pages of 100 read from each history before giving up on finding what is asked.
MAX_PAGES = 3
STEP = {"alert": "Post alert", "clear": "Post clear"}
RUN_NAME = re.compile(r"^notify (\d+) (\d+) (\d+)$")
RUN_NAME_EXPR = (
    "${{ github.event_name == 'workflow_run' && format('notify {0} {1} {2}', "
    "github.event.workflow_run.workflow_id, github.event.workflow_run.id, "
    "github.event.workflow_run.run_attempt) || github.workflow }}"
)
NOTIFY_IF = (
    "github.event_name == 'workflow_run' "
    "&& github.event.workflow_run.head_repository.full_name == github.repository "
    "&& (github.event.workflow_run.event == 'schedule' || github.event.workflow_run.event == 'push')"
)

# chat.engapp.dev sits behind Cloudflare bot protection that 403s default library
# User-Agents (TXE-6112, measured in txe's scheduled_workflow_watchdog.py).
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


class ReadError(Exception):
    """A GitHub read that did not complete; never treated as an empty history."""


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


def key(run: dict, attempt: int | None = None) -> tuple:
    """Order of judged events: the run's creation, its id, then its attempt."""
    return (run["created_at"], run["id"], int(attempt if attempt is not None else run.get("run_attempt") or 1))


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


class Event:
    """One judged attempt of a watched run: (run, attempt, red|green)."""

    __slots__ = ("run", "attempt", "state")

    def __init__(self, run: dict, attempt: int, state: str):
        self.run, self.attempt, self.state = run, attempt, state

    @property
    def key(self) -> tuple:
        return key(self.run, self.attempt)

    @property
    def ident(self) -> tuple[int, int]:
        return (int(self.run["id"]), self.attempt)


def attempt_events(run: dict, upto: int, repo: str, token: str | None, get) -> list[Event]:
    """Red and green events of `run`'s attempts 1..upto. The listing's own conclusion is the
    latest attempt's; earlier attempts are read (only when the run was re-run)."""
    out = []
    latest = int(run.get("run_attempt") or 1)
    for n in range(1, upto + 1):
        if n == latest:
            c = run.get("conclusion")
        else:
            c = get(f"/repos/{repo}/actions/runs/{run['id']}/attempts/{n}", token).get("conclusion")
        s = state_of(c)
        if s is not None:
            out.append(Event(run, n, s))
    return out


class History:
    """The watched workflow's judged events on main, newest first.

    Every attempt of a run is its own event, ordered after the run's earlier attempts: a run
    re-run red, then green, then red is three events, two streaks.
    """

    def __init__(self, run: dict, repo: str, token: str | None, get, as_of: str | None = None):
        self.run, self.repo, self.token, self.get = run, repo, token, get
        self.attempt = int(run.get("run_attempt") or 1)
        # Replay only: read the history as it stood when `run` was created.
        self.as_of = as_of
        self.events: list[Event] = []
        self.complete = False
        self._seen: set[int] = set()
        self._page = 0
        # This run's own earlier attempts come before this attempt.
        self.events.extend(attempt_events(run, self.attempt - 1, repo, token, get) if self.attempt > 1 else [])
        self.later_own = False
        self.oldest_listed: tuple | None = None

    def _more(self) -> bool:
        if self.complete or self._page >= MAX_PAGES:
            return False
        self._page += 1
        branch = urllib.parse.quote(BRANCH)
        created = f"&created={urllib.parse.quote('<=' + self.as_of)}" if self.as_of else ""
        body = self.get(
            f"/repos/{self.repo}/actions/workflows/{self.run['workflow_id']}/runs"
            f"?branch={branch}{created}&per_page=100&page={self._page}",
            self.token,
        )
        runs = body.get("workflow_runs")
        if not isinstance(runs, list):
            raise ReadError("workflow runs listing has no workflow_runs array")
        self.complete = len(runs) < 100
        for r in runs:
            # Every listed run, counted or not, tells how far back the read has reached.
            rk = (r["created_at"], r["id"])
            if self.oldest_listed is None or rk < self.oldest_listed:
                self.oldest_listed = rk
            if r["id"] == self.run["id"]:
                # The listing shows this run by its latest attempt. A later red or green attempt
                # than the one being judged is a newer event.
                latest = int(r.get("run_attempt") or 1)
                if latest > self.attempt and not self.later_own:
                    upto = latest if r.get("status") == "completed" else latest - 1
                    later = attempt_events(r, upto, self.repo, self.token, self.get)
                    self.later_own = any(e.attempt > self.attempt for e in later)
                continue
            if r["id"] in self._seen or not counts(r, self.repo):
                continue
            self._seen.add(r["id"])
            # A run being re-run still has its completed earlier attempts (an alerted red).
            latest = int(r.get("run_attempt") or 1)
            upto = latest if r.get("status") == "completed" else latest - 1
            self.events.extend(attempt_events(r, upto, self.repo, self.token, self.get))
        self.events.sort(key=lambda e: e.key, reverse=True)
        return True

    def newer(self) -> bool:
        """Whether an event comes after this attempt: a later run, or a later attempt of it.

        Reads pages until the listing reaches back past this run (ignored runs, such as fork
        pull requests from a branch named main, can push a newer counted run off page 1), or
        until MAX_PAGES.
        """
        me = (self.run["created_at"], self.run["id"])
        while (self.oldest_listed is None or self.oldest_listed >= me) and self._more():
            pass
        return self.later_own or any(e.key > key(self.run, self.attempt) for e in self.events)

    def before(self):
        """Events before this attempt, newest first, reading pages as needed.

        Stops at MAX_PAGES: history older than that is treated as absent. A streak longer than
        that is judged by its newest part; a red streak further back than that is not cleared.
        A read that fails raises ReadError.
        """
        i = 0
        if not self._page:
            self._more()
        me = key(self.run, self.attempt)
        while True:
            # A later page holds only older runs, so earlier positions never move.
            older = [e for e in self.events if e.key < me]
            while i < len(older):
                yield older[i]
                i += 1
            if not self._more():
                return


class Ledger:
    """What the notifier delivered, read from its own workflow_run runs and their steps."""

    def __init__(self, repo: str, token: str | None, get, self_run_id: str | None, self_attempt: str | None = None):
        self.repo, self.token, self.get = repo, token, get
        # This notify's own attempt is not a record of anything yet. Its earlier attempts are:
        # a re-run of a notifier that already posted keeps the same run id.
        self.self_run_id = int(self_run_id) if self_run_id else None
        self.self_attempt = int(self_attempt or 1)
        self._runs: dict[tuple[int, int, int], list[tuple[int, bool, str | None]]] | None = None
        self._steps: dict[int, set[str]] = {}

    def _index(self) -> dict[tuple[int, int, int], list[tuple[int, bool, str | None]]]:
        """(workflow id, run id, attempt) -> [(notifier run id, finished, its conclusion)]."""
        if self._runs is None:
            idx: dict[tuple[int, int, int], list[tuple[int, bool, str | None]]] = {}
            for page in range(1, MAX_PAGES + 1):
                body = self.get(
                    f"/repos/{self.repo}/actions/workflows/{NOTIFIER.name}/runs"
                    f"?event=workflow_run&per_page=100&page={page}",
                    self.token,
                )
                runs = body.get("workflow_runs")
                if not isinstance(runs, list):
                    raise ReadError("notifier runs listing has no workflow_runs array")
                for r in runs:
                    m = RUN_NAME.match(r.get("display_title") or r.get("name") or "")
                    if r.get("event") != "workflow_run" or not m:
                        continue
                    ident = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
                    idx.setdefault(ident, []).append((r["id"], r.get("status") == "completed", r.get("conclusion")))
                if len(runs) < 100:
                    break
            self._runs = idx
        return self._runs

    def _delivered_steps(self, notifier_run_id: int, finished: bool, conclusion: str | None = None) -> set[str]:
        """Names of the steps that concluded success in a notifier run's notify job.

        A run still queued or running has delivered nothing yet. A finished run cancelled or
        skipped before its notify job started (a pending notify replaced in the concurrency
        group ends this way) delivered nothing. Any other finished run (or an earlier attempt
        of this one) whose jobs listing has no notify job (no `Decide` step) is unreadable,
        not "nothing delivered": ReadError, so the decision fails closed.
        """
        if notifier_run_id not in self._steps:
            body = self.get(f"/repos/{self.repo}/actions/runs/{notifier_run_id}/jobs?filter=all&per_page=100", self.token)
            jobs = body.get("jobs")
            if not isinstance(jobs, list):
                raise ReadError(f"notifier run {notifier_run_id}: jobs listing has no jobs array")
            own = notifier_run_id == self.self_run_id
            if own:
                jobs = [j for j in jobs if int(j.get("run_attempt") or 1) < self.self_attempt]
            # This notify's own run: only its earlier attempts are records, and they finished.
            must_read = self.self_attempt > 1 if own else (finished and conclusion not in ("cancelled", "skipped"))
            if must_read and not any(st.get("name") == "Decide" for j in jobs for st in (j.get("steps") or [])):
                raise ReadError(f"notifier run {notifier_run_id}: no notify job in its jobs listing")
            self._steps[notifier_run_id] = {
                st.get("name") for j in jobs for st in (j.get("steps") or []) if st.get("conclusion") == "success"
            }
        return self._steps[notifier_run_id]

    def delivered(self, action: str, workflow_id: int, idents) -> bool:
        """Whether a notify of any of these (run id, attempt) events delivered `action`."""
        idx = self._index()
        for rid, att in idents:
            for nid, finished, conclusion in idx.get((int(workflow_id), int(rid), int(att)), []):
                if STEP[action] in self._delivered_steps(nid, finished, conclusion):
                    return True
        return False


class SimLedger:
    """A delivery record for replay: what this replay 'delivered', minus the failures it is told of."""

    def __init__(self, fail=()):
        self.fail = {int(f) for f in fail}
        self.sent: set[tuple[str, int, int, int]] = set()

    def delivered(self, action: str, workflow_id: int, idents) -> bool:
        return any((action, int(workflow_id), int(r), int(a)) in self.sent for r, a in idents)

    def record(self, action: str, workflow_id: int, run_id: int, attempt: int) -> bool:
        if int(run_id) in self.fail:
            return False
        self.sent.add((action, int(workflow_id), int(run_id), int(attempt)))
        return True


# --------------------------------------------------------------------------------- the rule


def evaluate(run: dict, repo: str, token: str | None, get, ledger, as_of: str | None = None) -> tuple[str | None, str, list[dict]]:
    """Decide for one completed attempt: (action, a one-line reason, the streak's runs oldest first).

    Raises ReadError when a history or the delivery record cannot be read: fail closed.
    """
    if not counts(run, repo):
        head_repo = (run.get("head_repository") or {}).get("full_name")
        return None, f"not a {BRANCH} schedule/push run of {repo} (event={run.get('event')} branch={run.get('head_branch')} repo={head_repo})", []
    now = state_of(run.get("conclusion"))
    if now is None:
        return None, f"conclusion {run.get('conclusion')} neither alerts nor clears", []
    wf = run["workflow_id"]
    me = Event(run, int(run.get("run_attempt") or 1), now)
    if now == "red":
        hist = History(run, repo, token, get, as_of)
        if hist.newer():
            return None, "red, superseded by a newer event", []
        streak = [me]
        for e in hist.before():
            if e.state != "red":
                break
            streak.append(e)
        streak.reverse()
        if ledger.delivered("alert", wf, [e.ident for e in streak]):
            return None, f"red, streak of {len(streak)}: its alert was delivered", [e.run for e in streak]
        return "alert", f"red, streak of {len(streak)}: no alert delivered for it yet", [e.run for e in streak]
    hist = History(run, repo, token, get, as_of)
    if hist.newer():
        return None, "green, superseded by a newer event", []
    streak: list[Event] = []
    greens = [me]
    for e in hist.before():
        if e.state == "green":
            if streak:
                break
            greens.append(e)
            continue
        streak.append(e)
    if not streak:
        return None, "green, no red streak before it", []
    streak.reverse()
    runs = [e.run for e in streak]
    if ledger.delivered("alert", wf, [e.ident for e in streak]):
        if ledger.delivered("clear", wf, [g.ident for g in greens]):
            return None, f"green after a red streak of {len(streak)}: its clear was delivered", runs
        return "clear", f"green after a red streak of {len(streak)} whose alert was delivered", runs
    if len(greens) > 1:
        return None, "green, an earlier green already followed the undelivered red streak", []
    if ledger.delivered("clear", wf, [me.ident]):
        return None, "green after an undelivered red streak: its clear was delivered", runs
    return "clear-undelivered", f"green after a red streak of {len(streak)} whose alert was never delivered", runs


def message(action: str, repo: str, workflow: str, run_url: str, streak: list[dict]) -> str:
    """The post. `streak {id}` is the run id of the streak's first red event: stable across
    retries and the clear, so a duplicate after an uncertain send reads as the same alert."""
    first = streak[0] if streak else {"id": run_url.rsplit("/", 1)[-1], "html_url": run_url}
    tag = f"streak {first['id']}"
    if action == "alert":
        if len(streak) <= 1:
            return f":rotating_light: {repo}: workflow `{workflow}` is red on {BRANCH} ({tag}). Run: {run_url}"
        return (f":rotating_light: {repo}: workflow `{workflow}` is still red on {BRANCH} ({tag}, red since "
                f"{first['html_url']}). Run: {run_url}")
    text = f":white_check_mark: {repo}: workflow `{workflow}` is green again on {BRANCH} ({tag} ended). Run: {run_url}"
    if action == "clear-undelivered":
        text += " The alert for this red streak was not delivered."
    return text


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


def cmd_notify(args, env=os.environ, get=gh_get) -> int:
    """Decide, and hand the due post to the workflow's Post step through GITHUB_OUTPUT and a file."""
    repo = env["GITHUB_REPOSITORY"]
    event = json.loads(pathlib.Path(env["GITHUB_EVENT_PATH"]).read_text())
    run = event.get("workflow_run")
    if not isinstance(run, dict):
        print("::error::the event has no workflow_run")
        return 1
    workflow = run.get("name") or "?"
    token = env.get("GH_TOKEN")
    ledger = Ledger(repo, token, get, env.get("GITHUB_RUN_ID"), env.get("GITHUB_RUN_ATTEMPT"))
    try:
        action, why, streak = evaluate(run, repo, token, get, ledger)
    except ReadError as e:
        print(f"::error::{workflow} run {run.get('id')}: history or delivery record unreadable, nothing posted (fail closed): {e}")
        return 1
    print(f"{workflow} run {run.get('id')} attempt {run.get('run_attempt')}: {why}: {action or 'no post'}")
    step = None if action is None else ("alert" if action == "alert" else "clear")
    with open(env["GITHUB_OUTPUT"], "a") as out:
        out.write(f"post={step or 'none'}\n")
    if step:
        pathlib.Path(env["POST_FILE"]).write_text(message(action, repo, workflow, run["html_url"], streak))
    return 0


def cmd_post(args, env=os.environ, post=post_mattermost) -> int:
    """Deliver the decided post. Fails, so the step does not count as delivered, unless 2xx."""
    text = pathlib.Path(env["POST_FILE"]).read_text()
    print(f"post: {text}")
    webhook = env.get("MM_WEBHOOK", "")
    if not webhook:
        print("::error::a post is due but the MATTERMOST_WEBHOOK_URL secret is not set: nothing was delivered")
        return 1
    ok, detail = post(webhook, text)
    print(f"delivered={ok} ({detail})")
    if not ok:
        print("::error::the #infra-alert post failed; it does not count as delivered")
        return 1
    return 0


def cmd_replay(args, env=os.environ, get=gh_get) -> int:
    """Evaluate past runs in the order given, against a simulated delivery record."""
    repo = args.repo
    token = env.get("GH_TOKEN")
    ledger = SimLedger(set(args.undelivered))
    rc = 0
    for run_id in args.run_id:
        try:
            run = get(f"/repos/{repo}/actions/runs/{run_id}", token)
            action, why, streak = evaluate(run, repo, token, get, ledger, as_of=run["created_at"])
        except ReadError as e:
            print(f"run {run_id}: ERROR {e}")
            rc = 1
            continue
        line = f"run {run_id} ({run.get('event')}, {run.get('conclusion')}, {run.get('created_at')}): {why}: "
        if not action:
            print(line + "no post")
            continue
        step = "alert" if action == "alert" else "clear"
        ok = ledger.record(step, run["workflow_id"], run_id, int(run.get("run_attempt") or 1))
        text = message(action, repo, run.get("name") or "?", run["html_url"], streak)
        print(line + ("would post: " if ok else "would post, delivery fails (simulated): ") + text)
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
        if "schedule" in _on(doc):
            scheduled.append((p.name, name if isinstance(name, str) else None))
        if p.name == NOTIFIER.name:
            notifier_doc = doc
    if notifier_doc is None:
        return [f"{NOTIFIER} is missing"]
    n = NOTIFIER.name
    wr = _on(notifier_doc).get("workflow_run") or {}
    listed = wr.get("workflows") or []
    if wr.get("types") != ["completed"]:
        errors.append(f"{n}: workflow_run.types must be [completed], got {wr.get('types')}")
    if wr.get("branches") != [BRANCH]:
        errors.append(f"{n}: workflow_run.branches must be [{BRANCH}], got {wr.get('branches')}")
    if notifier_doc.get("run-name") != RUN_NAME_EXPR:
        errors.append(f"{n}: run-name must be {RUN_NAME_EXPR!r}: the delivery record is read by it")
    if notifier_doc.get("permissions") != {"actions": "read", "contents": "read"}:
        errors.append(f"{n}: permissions must be exactly actions: read, contents: read")
    notify = (notifier_doc.get("jobs") or {}).get("notify") or {}
    if str(notify.get("if", "")).strip() != NOTIFY_IF:
        errors.append(f"{n}: the notify job's if must be {NOTIFY_IF!r}: a fork's run must not queue in its concurrency group")
    steps = [st.get("name") for st in notify.get("steps") or []]
    for want in STEP.values():
        if steps.count(want) != 1:
            errors.append(f"{n}: the notify job needs exactly one step named {want!r}: the delivery record is read by it")
    for file, name in scheduled:
        if name is None:
            errors.append(f"{file} has `on: schedule` but no `name:`; workflow_run matches a workflow by its name")
        elif name not in listed:
            errors.append(
                f"{file} (`{name}`) has `on: schedule` but is not in {n}'s "
                "on.workflow_run.workflows: a red scheduled run would reach nobody (TXE-7846)"
            )
    for name in listed:
        if name not in names:
            errors.append(f"{n} lists `{name}`, which is not the name of any workflow here")
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
    sub.add_parser("notify", help="decide for the workflow_run event in GITHUB_EVENT_PATH")
    sub.add_parser("post", help="deliver the post notify wrote to POST_FILE")
    r = sub.add_parser("replay", help="print what notify would post for past runs, in order; never posts")
    r.add_argument("--repo", default="txehq/dagu")
    r.add_argument("--run-id", action="append", required=True, type=int)
    r.add_argument("--undelivered", action="append", default=[], type=int, metavar="RUN_ID",
                   help="simulate a failed delivery for this run's post (the secret missing, a non-2xx)")
    c = sub.add_parser("check", help="fail when a scheduled workflow is not watched")
    c.add_argument("--root", default=".")
    args = ap.parse_args(argv)
    return {"notify": cmd_notify, "post": cmd_post, "replay": cmd_replay, "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

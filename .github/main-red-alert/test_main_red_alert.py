"""Tests for main_red_alert.py (TXE-7846). Offline: GitHub reads and the POST are stand-ins.

Run: python3 -I .github/main-red-alert/test_main_red_alert.py
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import main_red_alert as m  # noqa: E402

REPO = "txehq/dagu"
WF_ID = 4242


def run(id_, conclusion, created, event="schedule", branch="main", repo=REPO, attempt=1):
    return {
        "id": id_,
        "name": "SecurityScans",
        "workflow_id": WF_ID,
        "event": event,
        "head_branch": branch,
        "head_repository": {"full_name": repo},
        "status": "completed",
        "conclusion": conclusion,
        "created_at": created,
        "run_attempt": attempt,
        "html_url": f"https://github.com/{REPO}/actions/runs/{id_}",
    }


class FakeGitHub:
    """The API as the script reads it: watched runs, attempts, notifier runs and their jobs.

    `notified` maps a notifier run id to (judged run id, attempt, {step name: conclusion}).
    """

    def __init__(self, runs, attempts=None, notified=None, fail=False, notifier_event="workflow_run"):
        self.runs = sorted(runs, key=m.key, reverse=True)
        self.attempts = attempts or {}
        self.notified = notified or {}
        self.notifier_event = notifier_event
        self.fail = fail
        self.calls: list[str] = []

    def __call__(self, path, token):
        self.calls.append(path)
        if self.fail:
            raise m.ReadError("HTTP 502")
        if "/attempts/" in path:
            rid, n = path.split("/runs/")[1].split("/attempts/")
            return {"conclusion": self.attempts[(int(rid), int(n))]}
        if f"/workflows/{WF_ID}/runs?" in path:
            assert "branch=main" in path and "status=completed" in path
            page = int(path.rsplit("page=", 1)[1])
            runs = self.runs
            if "&created=" in path:
                bound = urllib.parse.unquote(path.split("&created=")[1].split("&")[0])
                assert bound.startswith("<=")
                runs = [r for r in runs if r["created_at"] <= bound[2:]]
            return {"workflow_runs": runs[(page - 1) * 100 : page * 100]}
        if "/workflows/main-red-alert.yaml/runs?" in path:
            assert "event=workflow_run" in path
            page = int(path.rsplit("page=", 1)[1])
            rows = [
                {"id": nid, "event": self.notifier_event, "display_title": f"notify {WF_ID} {rid} {att}"}
                for nid, (rid, att, _) in sorted(self.notified.items(), reverse=True)
            ]
            return {"workflow_runs": rows[(page - 1) * 100 : page * 100]}
        if path.endswith("/jobs?filter=all&per_page=100"):
            nid = int(path.split("/runs/")[1].split("/")[0])
            steps = [{"name": "Decide", "conclusion": "success"}]
            steps += [{"name": n, "conclusion": c} for n, c in self.notified[nid][2].items()]
            return {"jobs": [{"steps": steps}]}
        rid = int(path.rsplit("/", 1)[1])
        return next(r for r in self.runs if r["id"] == rid)


def evaluate(r, gh):
    return m.evaluate(r, REPO, None, gh, m.Ledger(REPO, None, gh, None))[0]


# The SecurityScans main history as read on 2026-11-18 (gh run list --workflow
# image-security.yaml --branch main), oldest first.
HISTORY = [
    run(38201258145, "failure", "2026-10-12T03:49:11Z"),
    run(39195531596, "failure", "2026-10-19T03:37:01Z"),
    run(40265174723, "failure", "2026-10-26T03:39:49Z"),
    run(41287012982, "success", "2026-11-01T09:00:26Z", event="push"),
    run(41291253865, "success", "2026-11-01T09:01:08Z", event="push"),
    run(41383017458, "success", "2026-11-02T03:25:23Z"),
    run(42420937192, "success", "2026-11-07T22:30:36Z", event="push"),
    run(42556389297, "success", "2026-11-09T03:26:10Z"),
    run(42769738971, "success", "2026-11-10T06:37:20Z", event="push"),
    run(43798559034, "failure", "2026-11-16T03:30:12Z"),
]

OK = {"Post alert": "success"}
FAILED = {"Post alert": "failure"}


class Replay(unittest.TestCase):
    """Each recorded run judged as of its own completion, its notify's outcome then recorded."""

    def replay(self, undelivered=()):
        out = {}
        notified = {}
        for i, r in enumerate(HISTORY):
            gh = FakeGitHub(HISTORY[: i + 1], notified=dict(notified))
            action = evaluate(r, gh)
            out[r["id"]] = action
            if action:
                step = "Post alert" if action == "alert" else "Post clear"
                notified[900 + i] = (r["id"], 1, {step: "failure" if r["id"] in undelivered else "success"})
        return out

    def test_the_recorded_history_alerts_once_per_streak_and_clears(self):
        got = self.replay()
        self.assertEqual(
            {k: v for k, v in got.items() if v},
            {38201258145: "alert", 41287012982: "clear", 43798559034: "alert"},
        )

    def test_activation_mid_streak_alerts_on_the_next_red(self):
        # 2026-10-12's post fails (no secret yet); the secret is added before 2026-10-19.
        got = self.replay(undelivered={38201258145})
        self.assertEqual(
            {k: v for k, v in got.items() if v},
            {38201258145: "alert", 39195531596: "alert", 41287012982: "clear", 43798559034: "alert"},
        )

    def test_a_streak_never_delivered_gets_a_clear_that_says_so(self):
        got = self.replay(undelivered={38201258145, 39195531596, 40265174723})
        self.assertEqual(got[41287012982], "clear-undelivered")
        self.assertIsNone(got[41291253865], "only the first green after an undelivered streak")


class ReplayCommand(unittest.TestCase):
    def replay(self, *undelivered):
        lines = []
        args = type("A", (), {"repo": REPO, "run_id": [r["id"] for r in HISTORY], "undelivered": list(undelivered)})
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = m.cmd_replay(args, env={}, get=FakeGitHub(HISTORY))
        lines = buf.getvalue().splitlines()
        return rc, {int(line.split()[1]): ("would post" in line) for line in lines}, lines

    def test_replay_reads_each_run_as_of_its_creation(self):
        rc, posted, _ = self.replay()
        self.assertEqual(rc, 0)
        self.assertEqual([k for k, v in posted.items() if v], [38201258145, 41287012982, 43798559034])

    def test_replay_of_activation_mid_streak(self):
        rc, posted, lines = self.replay(38201258145)
        self.assertEqual([k for k, v in posted.items() if v], [38201258145, 39195531596, 41287012982, 43798559034])
        self.assertIn("delivery fails (simulated)", lines[0])


class Rule(unittest.TestCase):
    G0 = run(1, "success", "2026-01-01T00:00:00Z")
    R1 = run(2, "failure", "2026-01-02T00:00:00Z")
    R2 = run(3, "failure", "2026-01-03T00:00:00Z")
    G3 = run(4, "success", "2026-01-04T00:00:00Z")

    def test_first_red_alerts(self):
        self.assertEqual(evaluate(self.R1, FakeGitHub([self.G0, self.R1])), "alert")

    def test_red_after_a_delivered_alert_is_quiet(self):
        gh = FakeGitHub([self.G0, self.R1, self.R2], notified={10: (2, 1, OK)})
        self.assertIsNone(evaluate(self.R2, gh))

    def test_missing_secret_or_failed_post_does_not_count_as_sent(self):
        # Both look the same in the record: the Post step concluded failure.
        gh = FakeGitHub([self.G0, self.R1, self.R2], notified={10: (2, 1, FAILED)})
        self.assertEqual(evaluate(self.R2, gh), "alert")
        text = m.message("alert", REPO, "SecurityScans", self.R2["html_url"], [self.R1, self.R2])
        self.assertIn("is still red on main, red since https://github.com/txehq/dagu/actions/runs/2.", text)

    def test_a_skipped_or_cancelled_post_step_does_not_count_as_sent(self):
        for c in ("skipped", "cancelled", None):
            gh = FakeGitHub([self.G0, self.R1, self.R2], notified={10: (2, 1, {"Post alert": c})})
            self.assertEqual(evaluate(self.R2, gh), "alert", c)

    def test_duplicate_delivery_of_the_same_run_posts_once(self):
        gh = FakeGitHub([self.G0, self.R1], notified={10: (2, 1, OK)})
        self.assertIsNone(evaluate(self.R1, gh))
        # A re-run of the same red run (attempt 2) is the same streak.
        r1b = dict(self.R1, run_attempt=2)
        gh = FakeGitHub([self.G0, r1b], attempts={(2, 1): "failure"}, notified={10: (2, 1, OK)})
        self.assertIsNone(evaluate(r1b, gh))

    def test_out_of_order_red_after_a_newer_green_is_superseded(self):
        self.assertIsNone(evaluate(self.R1, FakeGitHub([self.G0, self.R1, self.G3])))

    def test_stale_green_before_a_newer_red_does_not_clear(self):
        gh = FakeGitHub([self.R1, self.G3, run(5, "failure", "2026-01-05T00:00:00Z")], notified={10: (2, 1, OK)})
        self.assertIsNone(evaluate(self.G3, gh))

    def test_clear_only_once(self):
        gh = FakeGitHub([self.R1, self.G3], notified={10: (2, 1, OK)})
        self.assertEqual(evaluate(self.G3, gh), "clear")
        gh = FakeGitHub([self.R1, self.G3], notified={10: (2, 1, OK), 11: (4, 1, {"Post clear": "success"})})
        self.assertIsNone(evaluate(self.G3, gh))

    def test_a_clear_lost_to_a_replaced_notify_is_posted_by_the_next_green(self):
        g5 = run(5, "success", "2026-01-05T00:00:00Z")
        gh = FakeGitHub([self.R1, self.G3, g5], notified={10: (2, 1, OK)})
        self.assertEqual(evaluate(g5, gh), "clear")
        gh = FakeGitHub([self.R1, self.G3, g5], notified={10: (2, 1, OK), 11: (4, 1, {"Post clear": "success"})})
        self.assertIsNone(evaluate(g5, gh))

    def test_a_failed_clear_is_retried_by_the_next_green(self):
        g5 = run(5, "success", "2026-01-05T00:00:00Z")
        gh = FakeGitHub([self.R1, self.G3, g5], notified={10: (2, 1, OK), 11: (4, 1, {"Post clear": "failure"})})
        self.assertEqual(evaluate(g5, gh), "clear")

    def test_green_after_green_is_quiet(self):
        self.assertIsNone(evaluate(self.G3, FakeGitHub([self.G0, self.G3])))

    def test_only_the_notifiers_own_workflow_run_runs_count_as_delivered(self):
        # A pull request's run of a modified notifier could name a step "Post alert": not read.
        gh = FakeGitHub([self.G0, self.R1, self.R2], notified={10: (2, 1, OK)}, notifier_event="pull_request")
        self.assertEqual(evaluate(self.R2, gh), "alert")

    def test_the_running_notifier_is_not_its_own_record(self):
        gh = FakeGitHub([self.G0, self.R1], notified={10: (2, 1, OK)})
        self.assertEqual(m.evaluate(self.R1, REPO, None, gh, m.Ledger(REPO, None, gh, "10"))[0], "alert")

    def test_cancelled_and_skipped_runs_are_passed_over(self):
        hist = [self.R1, run(5, "cancelled", "2026-01-02T01:00:00Z"), run(6, "skipped", "2026-01-02T02:00:00Z"), self.G3]
        gh = FakeGitHub(hist, notified={10: (2, 1, OK)})
        self.assertIsNone(evaluate(hist[1], gh))
        self.assertEqual(evaluate(self.G3, gh), "clear")

    def test_timed_out_and_startup_failure_are_red(self):
        for c in ("timed_out", "startup_failure"):
            r = run(2, c, "2026-01-02T00:00:00Z")
            self.assertEqual(evaluate(r, FakeGitHub([self.G0, r])), "alert", c)

    def test_pull_request_dispatch_other_branch_and_fork_runs_are_ignored(self):
        others = [
            run(12, "failure", "2026-01-02T00:00:00Z", event="pull_request", branch="feature"),
            # A fork's PR from a branch named main reaches workflow_run with head_branch "main".
            run(13, "failure", "2026-01-03T00:00:00Z", event="pull_request", repo="someone/dagu"),
            run(14, "failure", "2026-01-04T00:00:00Z", event="push", repo="someone/dagu"),
            run(15, "failure", "2026-01-05T00:00:00Z", event="workflow_dispatch"),
            run(16, "failure", "2026-01-06T00:00:00Z", branch="maint/txe-v1-1"),
        ]
        gh = FakeGitHub([self.G0, *others])
        for r in others:
            self.assertIsNone(evaluate(r, gh), r["id"])
        self.assertEqual(gh.calls, [], "an ignored run reads nothing")
        r7 = run(17, "failure", "2026-01-07T00:00:00Z")
        self.assertEqual(evaluate(r7, FakeGitHub([self.G0, *others, r7])), "alert")

    def test_an_earlier_red_run_whose_rerun_was_cancelled_is_still_red(self):
        r1 = dict(self.R1, conclusion="cancelled", run_attempt=2)
        gh = FakeGitHub([self.G0, r1, self.G3], attempts={(2, 1): "failure"}, notified={10: (2, 1, OK)})
        self.assertEqual(evaluate(self.G3, gh), "clear")
        # A run cancelled on every attempt is passed over.
        gh = FakeGitHub([self.G0, r1, self.G3], attempts={(2, 1): "cancelled"})
        self.assertIsNone(evaluate(self.G3, gh))

    def test_a_red_run_rerun_green_clears_its_own_alert(self):
        r1g = dict(self.R1, conclusion="success", run_attempt=2)
        gh = FakeGitHub([self.G0, r1g], attempts={(2, 1): "failure"}, notified={10: (2, 1, OK)})
        self.assertEqual(evaluate(r1g, gh), "clear")
        # Its attempt-1 red was never delivered: a clear that says so.
        gh = FakeGitHub([self.G0, r1g], attempts={(2, 1): "failure"}, notified={10: (2, 1, FAILED)})
        self.assertEqual(evaluate(r1g, gh), "clear-undelivered")

    def test_red_green_red_attempts_of_one_run_are_two_streaks(self):
        # Attempt 1 red (alert delivered), attempt 2 green (clear delivered), attempt 3 red.
        r = dict(self.R1, run_attempt=3)
        gh = FakeGitHub([self.G0, r], attempts={(2, 1): "failure", (2, 2): "success"},
                        notified={10: (2, 1, OK), 11: (2, 2, {"Post clear": "success"})})
        self.assertEqual(evaluate(r, gh), "alert")

    def test_a_failed_clear_after_a_green_rerun_is_retried(self):
        # Attempt 1 red (alert delivered), attempt 2 green, its clear POST failed.
        r1g = dict(self.R1, conclusion="success", run_attempt=2)
        notified = {10: (2, 1, OK), 11: (2, 2, {"Post clear": "failure"})}
        gh = FakeGitHub([self.G0, r1g, self.G3], attempts={(2, 1): "failure"}, notified=notified)
        self.assertEqual(evaluate(self.G3, gh), "clear")
        # Or a third, green attempt of the same run.
        r1g3 = dict(self.R1, conclusion="success", run_attempt=3)
        gh = FakeGitHub([self.G0, r1g3], attempts={(2, 1): "failure", (2, 2): "success"}, notified=notified)
        self.assertEqual(evaluate(r1g3, gh), "clear")

    def test_an_earlier_attempt_is_superseded_by_a_later_one_of_the_same_run(self):
        listed = dict(self.R1, conclusion="success", run_attempt=2)
        gh = FakeGitHub([self.G0, listed], attempts={(2, 1): "failure"})
        self.assertIsNone(evaluate(dict(self.R1, run_attempt=1), gh))
        # A later attempt that was cancelled does not supersede.
        listed = dict(self.R1, conclusion="cancelled", run_attempt=2)
        gh = FakeGitHub([self.G0, listed], attempts={(2, 1): "failure"})
        self.assertEqual(evaluate(dict(self.R1, run_attempt=1), gh), "alert")

    def test_unread_history_alerts_a_red_and_fails_a_green(self):
        self.assertEqual(evaluate(self.R1, FakeGitHub([], fail=True)), "alert")
        with self.assertRaises(m.ReadError):
            evaluate(self.G3, FakeGitHub([], fail=True))

    def test_history_beyond_the_first_page(self):
        noise = [run(100 + i, "failure", f"2026-01-02T{i // 3600:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z", event="pull_request", repo="f/dagu") for i in range(150)]
        gh = FakeGitHub([self.R1, *noise, self.G3], notified={10: (2, 1, OK)})
        self.assertEqual(evaluate(self.G3, gh), "clear")

    def test_a_long_green_history_ends_quietly(self):
        greens = [run(100 + i, "success", f"2026-01-02T{i // 3600:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z") for i in range(m.MAX_PAGES * 100 + 5)]
        g = run(9, "success", "2026-02-01T00:00:00Z")
        self.assertIsNone(evaluate(g, FakeGitHub([*greens, g])))

    def test_the_post_carries_repository_workflow_and_links_only(self):
        r = HISTORY[-1]
        self.assertEqual(
            m.message("alert", REPO, r["name"], r["html_url"], [r]),
            ":rotating_light: txehq/dagu: workflow `SecurityScans` is red on main. "
            "Run: https://github.com/txehq/dagu/actions/runs/43798559034",
        )
        self.assertEqual(
            m.message("clear-undelivered", REPO, r["name"], "https://github.com/txehq/dagu/actions/runs/5", [r]),
            ":white_check_mark: txehq/dagu: workflow `SecurityScans` is green again on main. "
            "Run: https://github.com/txehq/dagu/actions/runs/5 The alert for this red streak was not "
            "delivered (red since https://github.com/txehq/dagu/actions/runs/43798559034).",
        )


class Steps(unittest.TestCase):
    """notify writes the decision for the Post step; post delivers it or fails."""

    def notify(self, r, gh):
        with tempfile.TemporaryDirectory() as d:
            ev, out, pf = (pathlib.Path(d) / n for n in ("event.json", "output", "post.txt"))
            ev.write_text(json.dumps({"workflow_run": r}))
            env = {"GITHUB_REPOSITORY": REPO, "GITHUB_EVENT_PATH": str(ev), "GITHUB_OUTPUT": str(out),
                   "POST_FILE": str(pf), "GITHUB_RUN_ID": "77"}
            rc = m.cmd_notify(None, env=env, get=gh)
            return rc, out.read_text() if out.exists() else "", pf.read_text() if pf.exists() else None

    def post(self, webhook, result):
        posts = []

        def fake(url, text):
            posts.append((url, text))
            return result

        with tempfile.TemporaryDirectory() as d:
            pf = pathlib.Path(d) / "post.txt"
            pf.write_text("hello")
            rc = m.cmd_post(None, env={"POST_FILE": str(pf), "MM_WEBHOOK": webhook}, post=fake)
        return rc, posts

    def test_notify_writes_the_alert_for_the_post_alert_step(self):
        rc, out, text = self.notify(HISTORY[-1], FakeGitHub(HISTORY))
        self.assertEqual((rc, out), (0, "post=alert\n"))
        self.assertEqual(text, m.message("alert", REPO, "SecurityScans", HISTORY[-1]["html_url"], [HISTORY[-1]]))

    def test_notify_writes_none_when_nothing_is_due(self):
        rc, out, text = self.notify(HISTORY[-2], FakeGitHub(HISTORY[:-1]))
        self.assertEqual((rc, out, text), (0, "post=none\n", None))

    def test_notify_fails_a_green_it_cannot_judge(self):
        rc, out, _ = self.notify(HISTORY[3], FakeGitHub([], fail=True))
        self.assertEqual((rc, out), (1, ""))

    def test_missing_secret_fails_the_post_step_and_sends_nothing(self):
        self.assertEqual(self.post("", (True, "200")), (1, []))

    def test_webhook_failure_and_rate_limit_fail_the_post_step(self):
        for detail in ("HTTP 500", "HTTP 429", "URLError"):
            rc, posts = self.post("https://hook.example/x", (False, detail))
            self.assertEqual((rc, len(posts)), (1, 1), detail)

    def test_delivered_post_passes_and_goes_only_to_the_secret(self):
        self.assertEqual(self.post("https://hook.example/x", (True, "200")), (0, [("https://hook.example/x", "hello")]))


class Coverage(unittest.TestCase):
    NOTIFIER = f"""name: main-red-alert
run-name: "{m.RUN_NAME_EXPR}"
on:
  workflow_run:
    workflows: [SecurityScans]
    types: [completed]
    branches: [main]
permissions:
  actions: read
  contents: read
jobs:
  notify:
    steps:
      - name: Decide
      - name: Post alert
      - name: Post clear
"""
    SCANS = "name: SecurityScans\non:\n  push:\n  schedule:\n    - cron: '17 3 * * 1'\n"

    def errors(self, files):
        with tempfile.TemporaryDirectory() as d:
            wf = pathlib.Path(d) / ".github" / "workflows"
            wf.mkdir(parents=True)
            for name, body in files.items():
                (wf / name).write_text(body)
            return m.coverage_errors(pathlib.Path(d))

    def test_listed_scheduled_workflow_passes(self):
        self.assertEqual(self.errors({"main-red-alert.yaml": self.NOTIFIER, "image-security.yaml": self.SCANS, "ci.yaml": "name: CI\non: [push]\n"}), [])

    def test_unlisted_scheduled_workflow_fails(self):
        errs = self.errors({
            "main-red-alert.yaml": self.NOTIFIER,
            "image-security.yaml": self.SCANS,
            "nightly.yml": "name: Nightly\n'on':\n  schedule:\n    - cron: '0 0 * * *'\n",
        })
        self.assertEqual(len(errs), 1)
        self.assertIn("nightly.yml (`Nightly`) has `on: schedule` but is not in", errs[0])

    def test_scheduled_workflow_without_a_name_fails(self):
        errs = self.errors({"main-red-alert.yaml": self.NOTIFIER, "image-security.yaml": self.SCANS, "x.yaml": "on:\n  schedule:\n    - cron: '0 0 * * *'\n"})
        self.assertEqual(len(errs), 1)
        self.assertIn("x.yaml has `on: schedule` but no `name:`", errs[0])

    def test_stale_listed_name_fails(self):
        errs = self.errors({"main-red-alert.yaml": self.NOTIFIER})
        self.assertEqual(errs, ["main-red-alert.yaml lists `SecurityScans`, which is not the name of any workflow here"])

    def test_notifier_shape_is_held(self):
        for old, new in [
            ("types: [completed]", "types: [requested]"),
            ("branches: [main]", "branches: [main, dev]"),
            ("format('notify", "format('note"),
            ("actions: read", "actions: write"),
            ("- name: Post alert", "- name: Post"),
            ("- name: Post clear", "- name: Post alert"),
        ]:
            errs = self.errors({"main-red-alert.yaml": self.NOTIFIER.replace(old, new), "image-security.yaml": self.SCANS})
            self.assertGreaterEqual(len(errs), 1, (old, errs))

    def test_the_repository_itself_is_covered(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        self.assertEqual(m.coverage_errors(root), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

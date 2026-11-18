"""Tests for main_red_alert.py (TXE-7846). Offline: GitHub reads and the post are stand-ins.

Run: python3 -I .github/main-red-alert/test_main_red_alert.py
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

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
    """Serves runs listings newest first, 100 a page, like the API; and run attempts."""

    def __init__(self, runs, attempts=None, fail=False):
        self.runs = sorted(runs, key=lambda r: (r["created_at"], r["id"]), reverse=True)
        self.attempts = attempts or {}
        self.fail = fail
        self.calls = []

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
            return {"workflow_runs": self.runs[(page - 1) * 100 : page * 100]}
        rid = int(path.rsplit("/", 1)[1])
        return next(r for r in self.runs if r["id"] == rid)


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


def evaluate(r, gh):
    return m.evaluate(r, REPO, None, gh)[0]


class Rule(unittest.TestCase):
    def test_replay_of_the_recorded_history(self):
        gh = FakeGitHub(HISTORY)
        got = {r["id"]: evaluate(r, gh) for r in HISTORY}
        self.assertEqual(got[38201258145], "alert")  # first red, no earlier counted run
        self.assertEqual(got[39195531596], "still")  # red after red: a reminder, never silence
        self.assertEqual(got[40265174723], "still")
        self.assertEqual(got[41287012982], "clear")  # first green after the streak
        self.assertIsNone(got[41291253865])
        self.assertEqual(got[43798559034], "alert")  # the 2026-11-16 run: alerts on the first red
        self.assertEqual([i for i, a in got.items() if a], [38201258145, 39195531596, 40265174723, 41287012982, 43798559034])

    def test_cancelled_and_skipped_runs_neither_alert_nor_break_a_streak(self):
        hist = [
            run(1, "failure", "2026-01-01T00:00:00Z"),
            run(2, "cancelled", "2026-01-02T00:00:00Z"),
            run(3, "skipped", "2026-01-03T00:00:00Z"),
            run(4, "failure", "2026-01-04T00:00:00Z"),
        ]
        gh = FakeGitHub(hist)
        self.assertIsNone(evaluate(hist[1], gh))
        self.assertIsNone(evaluate(hist[2], gh))
        self.assertEqual(evaluate(hist[3], gh), "still")

    def test_timed_out_and_startup_failure_are_red(self):
        for c in ("timed_out", "startup_failure"):
            hist = [run(1, "success", "2026-01-01T00:00:00Z"), run(2, c, "2026-01-02T00:00:00Z")]
            self.assertEqual(evaluate(hist[1], FakeGitHub(hist)), "alert", c)

    def test_push_red_after_a_green_schedule_alerts(self):
        hist = [run(1, "success", "2026-01-01T00:00:00Z"), run(2, "failure", "2026-01-02T00:00:00Z", event="push")]
        self.assertEqual(evaluate(hist[1], FakeGitHub(hist)), "alert")

    def test_pull_request_dispatch_other_branch_and_fork_runs_are_ignored(self):
        green = run(1, "success", "2026-01-01T00:00:00Z")
        others = [
            run(2, "failure", "2026-01-02T00:00:00Z", event="pull_request", branch="feature"),
            # A fork's PR from a branch named main reaches workflow_run with head_branch "main".
            run(3, "failure", "2026-01-03T00:00:00Z", event="pull_request", repo="someone/dagu"),
            run(4, "failure", "2026-01-04T00:00:00Z", event="push", repo="someone/dagu"),
            run(5, "failure", "2026-01-05T00:00:00Z", event="workflow_dispatch"),
            run(6, "failure", "2026-01-06T00:00:00Z", event="schedule", branch="maint/txe-v1-1"),
        ]
        gh = FakeGitHub([green, *others])
        for r in others:
            self.assertIsNone(evaluate(r, gh), r["id"])
        self.assertEqual(gh.calls, [], "an ignored run must not even read history")
        # And they do not count as history: a red after them is still the first red.
        r7 = run(7, "failure", "2026-01-07T00:00:00Z")
        self.assertEqual(evaluate(r7, FakeGitHub([green, *others, r7])), "alert")
        # Nor does a red fork run hide a green-after-red clear, or fake one.
        r8 = run(8, "success", "2026-01-08T00:00:00Z")
        self.assertEqual(evaluate(r8, FakeGitHub([green, *others, r7, r8])), "clear")

    def test_rerun_judged_against_its_own_previous_attempt(self):
        older_green = run(1, "success", "2026-01-01T00:00:00Z")
        rerun_green = run(2, "success", "2026-01-02T00:00:00Z", attempt=2)
        gh = FakeGitHub([older_green, rerun_green], attempts={(2, 1): "failure"})
        self.assertEqual(evaluate(rerun_green, gh), "clear")
        rerun_red = run(3, "failure", "2026-01-03T00:00:00Z", attempt=2)
        gh = FakeGitHub([older_green, rerun_red], attempts={(3, 1): "failure"})
        self.assertEqual(evaluate(rerun_red, gh), "still")
        # Attempt 1 red (alerted), attempt 2 cancelled, attempt 3 green: walk back to attempt 1.
        third = run(4, "success", "2026-01-04T00:00:00Z", attempt=3)
        gh = FakeGitHub([older_green, third], attempts={(4, 2): "cancelled", (4, 1): "failure"})
        self.assertEqual(evaluate(third, gh), "clear")
        # A cancelled first attempt says nothing: fall back to the earlier run.
        gh = FakeGitHub([older_green, rerun_red], attempts={(3, 1): "cancelled"})
        self.assertEqual(evaluate(rerun_red, gh), "alert")

    def test_a_later_run_is_not_history(self):
        # A run created earlier that finishes after a later one is judged by creation order.
        hist = [run(1, "success", "2026-01-01T00:00:00Z"), run(2, "failure", "2026-01-02T00:00:00Z"), run(3, "failure", "2026-01-03T00:00:00Z")]
        self.assertEqual(evaluate(hist[1], FakeGitHub(hist)), "alert")

    def test_history_beyond_the_first_page(self):
        reds = [run(10 + i, "failure", f"2026-02-01T00:{i // 60:02d}:{i % 60:02d}Z", event="pull_request", branch="main", repo="f/dagu") for i in range(150)]
        old_red = run(1, "failure", "2026-01-01T00:00:00Z")
        new_green = run(2, "success", "2026-03-01T00:00:00Z")
        gh = FakeGitHub([old_red, *reds, new_green])
        self.assertEqual(evaluate(new_green, gh), "clear")
        self.assertEqual(sum("page=" in c for c in gh.calls), 2)

    def test_unread_history_alerts_a_red_and_fails_a_green(self):
        self.assertEqual(evaluate(run(1, "failure", "2026-01-01T00:00:00Z"), FakeGitHub([], fail=True)), "alert")
        with self.assertRaises(m.ReadError):
            evaluate(run(2, "success", "2026-01-02T00:00:00Z"), FakeGitHub([], fail=True))

    def test_a_full_history_with_no_counted_run_is_unknown_not_none(self):
        noise = [run(10 + i, "failure", f"2026-02-01T{i // 3600:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z", event="pull_request", repo="f/dagu") for i in range(m.MAX_PAGES * 100)]
        green = run(1, "success", "2026-03-01T00:00:00Z")
        with self.assertRaises(m.ReadError):
            evaluate(green, FakeGitHub([*noise, green]))

    def test_the_post_carries_repository_workflow_and_link_only(self):
        r = HISTORY[-1]
        text = m.message("alert", REPO, r["name"], r["html_url"])
        self.assertEqual(
            text,
            ":rotating_light: txehq/dagu: workflow `SecurityScans` is red on main. "
            "Run: https://github.com/txehq/dagu/actions/runs/43798559034",
        )


class Notify(unittest.TestCase):
    def notify(self, r, webhook="https://chat.example/hooks/x", post_ok=True, gh=None):
        posts = []

        def post(url, text):
            posts.append(text)
            return post_ok, "200" if post_ok else "HTTP 500"

        with tempfile.TemporaryDirectory() as d:
            ev = pathlib.Path(d) / "event.json"
            ev.write_text(json.dumps({"workflow_run": r}))
            env = {"GITHUB_REPOSITORY": REPO, "GITHUB_EVENT_PATH": str(ev), "MM_WEBHOOK": webhook}
            rc = m.cmd_notify(None, env=env, get=gh or FakeGitHub(HISTORY), post=post)
        return rc, posts

    def test_posts_once_for_the_first_red(self):
        rc, posts = self.notify(HISTORY[-1])
        self.assertEqual(rc, 0)
        self.assertEqual(len(posts), 1)
        self.assertIn("runs/43798559034", posts[0])

    def test_red_after_red_posts_still_red(self):
        # Installed mid-streak, or the first POST failed: a later red must still reach someone.
        rc, posts = self.notify(HISTORY[1])
        self.assertEqual(rc, 0)
        self.assertEqual(len(posts), 1)
        self.assertIn("is still red on main", posts[0])

    def test_no_post_for_green_after_green(self):
        self.assertEqual(self.notify(HISTORY[4]), (0, []))

    def test_missing_webhook_fails_when_a_post_is_due_only(self):
        self.assertEqual(self.notify(HISTORY[-1], webhook=""), (1, []))
        self.assertEqual(self.notify(HISTORY[4], webhook=""), (0, []))

    def test_failed_delivery_fails_the_job(self):
        rc, posts = self.notify(HISTORY[-1], post_ok=False)
        self.assertEqual((rc, len(posts)), (1, 1))

    def test_green_with_unread_history_fails_the_job_and_posts_nothing(self):
        self.assertEqual(self.notify(HISTORY[3], gh=FakeGitHub([], fail=True)), (1, []))


class Coverage(unittest.TestCase):
    NOTIFIER = """name: main-red-alert
on:
  workflow_run:
    workflows: [SecurityScans]
    types: [completed]
    branches: [main]
"""

    def errors(self, files):
        with tempfile.TemporaryDirectory() as d:
            wf = pathlib.Path(d) / ".github" / "workflows"
            wf.mkdir(parents=True)
            for name, body in files.items():
                (wf / name).write_text(body)
            return m.coverage_errors(pathlib.Path(d))

    SCANS = "name: SecurityScans\non:\n  push:\n  schedule:\n    - cron: '17 3 * * 1'\n"

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

    def test_notifier_trigger_shape_is_held(self):
        bad = self.NOTIFIER.replace("types: [completed]", "types: [requested]").replace("branches: [main]", "branches: [main, dev]")
        errs = self.errors({"main-red-alert.yaml": bad, "image-security.yaml": self.SCANS})
        self.assertEqual(len(errs), 2)

    def test_a_cron_that_can_fire_more_than_daily_fails(self):
        for cron in ("*/15 * * * *", "0 */6 * * *", "0 1,13 * * *", "@hourly"):
            body = f"name: SecurityScans\non:\n  schedule:\n    - cron: '{cron}'\n"
            errs = self.errors({"main-red-alert.yaml": self.NOTIFIER, "image-security.yaml": body})
            self.assertEqual(len(errs), 1, cron)
            self.assertIn("may fire more than once a day", errs[0])

    def test_the_repository_itself_is_covered(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        self.assertEqual(m.coverage_errors(root), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

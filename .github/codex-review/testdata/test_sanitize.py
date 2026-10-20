"""sanitize.py keeps only what the check reads, even when private text sits on a marker line (TXE-4719).

  python3 -I .github/codex-review/testdata/test_sanitize.py
"""
import json, os, sys, unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sanitize  # noqa: E402

SECRET = "PRIVATE-services/billing/reconciler.go-https://internal.example/x"


class Sanitize(unittest.TestCase):
    def test_marker_lines_are_rebuilt_not_copied(self):
        body = "\n".join([
            '<!-- codex-review-state:v1 {"code_review":{"commit_sha":"' + "a" * 40 + '","status":"completed","has_any_findings":false,"note":"' + SECRET + '"}} -->',
            '| **Code Review** | Completed <relative-time datetime="2026-10-17T21:09:57.6Z">x</relative-time> | ' + SECRET + ' |',
            "Codex Review: Didn't find any major issues. " + SECRET,
            "**Reviewed commit:** `83822e7ebb` " + SECRET,
            "![P1 Badge](https://img) " + SECRET,
            SECRET,
        ])
        out = sanitize.walk([{"id": 1, "body": body, "user": {"login": "someone", "type": "User"}}])
        text = json.dumps(out)
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn("internal.example", text)
        self.assertIn('"has_any_findings":false', out[0]["body"])
        self.assertIn('datetime="2026-10-17T21:09:57.6Z"', out[0]["body"])
        self.assertIn("major issues", out[0]["body"])
        self.assertIn("`83822e7ebb`", out[0]["body"])
        self.assertIn("P1 Badge", out[0]["body"])
        self.assertEqual(out[0]["user"]["login"], "a-person")

    def test_unknown_fields_urls_and_hunks_are_dropped(self):
        out = sanitize.walk({"id": 2, "diff_hunk": SECRET, "html_url": SECRET, "title": SECRET,
                             "head": {"sha": "b" * 40, "ref": "fix/private-branch", "label": SECRET},
                             "path": "services/private.go", "user": {"login": "chatgpt-codex-connector[bot]"}})
        text = json.dumps(out)
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn("private", text)
        self.assertEqual(out["user"]["login"], "chatgpt-codex-connector[bot]")
        self.assertTrue(out["path"].startswith("synthetic/"))
        self.assertEqual(sanitize.walk({"user": {"login": "private-integration[bot]"}})["user"]["login"], "another-app[bot]")

    def test_account_ids_and_private_labels_are_dropped(self):
        out = sanitize.walk({"id": 7, "user": {"login": "x", "id": 123456789, "type": "User"},
                             "event": "labeled", "actor": {"login": "y", "id": 987654321, "type": "User"},
                             "label": {"name": "customer-acme", "color": "b60205"},
                             "labels": [{"name": "review-override"}, {"name": "secret-project"}]})
        text = json.dumps(out)
        for private in ("123456789", "987654321", "customer-acme", "secret-project"):
            self.assertNotIn(private, text)
        self.assertEqual(out["id"], 7)
        self.assertEqual([l["name"] for l in out["labels"]], ["review-override", "synthetic-label"])

    def test_private_text_inside_kept_values_is_dropped(self):
        body = ('<!-- codex-review-state:v1 {"code_review":{"commit_sha":"' + SECRET + '","status":"' + SECRET
                + '","has_any_findings":"' + SECRET + '"}} -->\n'
                + '| **Code Review** | Completed <relative-time datetime="' + SECRET + '">x</relative-time> |')
        out = sanitize.walk({"body": body, "head": {"repo": {"full_name": "txehq/private-repo"}}})
        text = json.dumps(out)
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn("private-repo", text)
        self.assertIn('"commit_sha":null', out["body"])

    def test_short_private_values_are_dropped(self):
        out = sanitize.walk({"body": '<!-- codex-review-state:v1 {"code_review":{"status":"acquisition_pending"}} -->',
                             "head": {"repo": {"name": "private-project", "full_name": "txehq/private-project"}}})
        text = json.dumps(out)
        self.assertNotIn("acquisition", text)
        self.assertNotIn("private-project", text)


if __name__ == "__main__":
    unittest.main()

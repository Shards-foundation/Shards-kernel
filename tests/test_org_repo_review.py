"""Negative-path regression tests for safe organisation-wide GitHub inventory."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from scripts import org_repo_review as review


class FakeResponse:
    """In-memory HTTP response with a bounded reader interface."""

    def __init__(self, value: object, status: int = 200) -> None:
        self.data = json.dumps(value).encode("utf-8")
        self.status = status

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, maximum: int) -> bytes:
        return self.data[:maximum]


class FakeOpener:
    """Record and return predictable GET responses without network access."""

    def __init__(self, pages: list[object]) -> None:
        self.pages = list(pages)
        self.requests: list[tuple[str, str, float]] = []

    def open(self, request: object, timeout: float) -> FakeResponse:
        self.requests.append((request.full_url, request.get_method(), timeout))
        if not self.pages:
            raise AssertionError("Unexpected extra HTTP request")
        value = self.pages.pop(0)
        if isinstance(value, Exception):
            raise value
        return FakeResponse(value)


def make_repo(name: str = "Shards-kernel", **updates: object) -> dict[str, object]:
    """Provide synthetic GitHub metadata; no actual repositories accessed."""
    result: dict[str, object] = {
        "name": name,
        "full_name": f"Shards-foundation/{name}",
        "archived": False,
        "disabled": False,
        "private": False,
        "fork": False,
        "default_branch": "main",
        "pushed_at": "2026-11-05T10:00:00Z",
        "clone_url": "https://example.invalid/UNTRUSTED-DO-NOT-EXECUTE",
    }
    result.update(updates)
    return result


class TestOrgSafety(unittest.TestCase):
    """Prove non-destructive defaults and fail-closed API handling."""

    def setUp(self) -> None:
        self.settings = review.validate(review.parse_args(["--org", "Shards-foundation"]))

    def test_default_inventory_never_fetches_clone_url(self) -> None:
        opener = FakeOpener([[make_repo()]])
        repos, pages, complete = review.collect_repos(opener, self.settings, None, [])
        self.assertEqual(pages, 1)
        self.assertTrue(complete)
        self.assertEqual(repos[0]["name"], "Shards-kernel")
        self.assertEqual(opener.requests[0][1], "GET")
        self.assertNotIn("example.invalid", opener.requests[0][0])
        self.assertNotIn("clone_url", repos[0])

    def test_malicious_repo_identity_rejected(self) -> None:
        for wrong in ["../../evil", "$(touch file)", "good;rm -rf /", "a/b"]:
            with self.subTest(wrong=wrong):
                with self.assertRaises(review.InventoryError):
                    review.validate_repo(make_repo(name=wrong), "Shards-foundation")
        with self.assertRaisesRegex(review.InventoryError, "identity_mismatch"):
            review.validate_repo(make_repo(full_name="attacker/Shards-kernel"), "Shards-foundation")

    def test_no_token_in_error_logs(self) -> None:
        opener = FakeOpener([urllib.error.HTTPError(
            "https://api.github.com/orgs/Shards-foundation/repos", 401, "secret in reason", {}, None,
        )])
        with self.assertRaisesRegex(review.InventoryError, "github_http_401"):
            review.collect_repos(opener, self.settings, "PRIVATE_TOKEN_123", [])

    def test_503_retry_is_bounded(self) -> None:
        opener = FakeOpener([urllib.error.HTTPError("https://api.github.com", 503, "unavailable", {}, None),
                             [make_repo()]])
        with mock.patch.object(review.time, "sleep", return_value=None), \
                mock.patch.object(review.time, "monotonic", side_effect=[0.0, 9.0]):
            repos, _pages, complete = review.collect_repos(opener, self.settings, None, [])
        self.assertEqual(len(repos), 1)
        self.assertEqual(len(opener.requests), 2)

    def test_auth_failure_does_not_retry(self) -> None:
        opener = FakeOpener([urllib.error.HTTPError("https://api.github.com", 403, "denied", {}, None)])
        with self.assertRaisesRegex(review.InventoryError, "github_http_403"):
            review.collect_repos(opener, self.settings, None, [])
        self.assertEqual(len(opener.requests), 1)

    def test_missing_repo_is_not_success(self) -> None:
        opener = FakeOpener([[]])
        with mock.patch.object(review, "make_opener", return_value=opener):
            with self.assertRaisesRegex(review.InventoryError, "no_repositories_visible"):
                review.report_inventory(self.settings, None, [])

    def test_exactly_full_page_requires_followup(self) -> None:
        limited = review.validate(review.parse_args(["--org", "Shards-foundation", "--max-pages", "1"]))
        opener = FakeOpener([[make_repo(name=f"R{i}") for i in range(100)]])
        with self.assertRaisesRegex(review.InventoryError, "pagination_limit"):
            review.collect_repos(opener, limited, None, [])

    def test_duplicate_repos_fail_closed(self) -> None:
        opener = FakeOpener([[make_repo(name="A"), make_repo(name="a")]])
        with self.assertRaisesRegex(review.InventoryError, "duplicate"):
            review.collect_repos(opener, self.settings, None, [])

    def test_branch_protection_is_status_not_certification(self) -> None:
        repo = review.validate_repo(make_repo(), "Shards-foundation")
        opener = FakeOpener([{"protected": False}])
        review.check_branches([repo], opener, self.settings, None, [])
        self.assertEqual(repo["branch_protected"], "REPORTED_FALSE")
        self.assertIn("default_branch_not_reported_protected", repo["findings"])
        self.assertEqual(opener.requests[0][1], "GET")

    def test_unverified_branch_is_nonzero_even_without_strict(self) -> None:
        settings = review.validate(review.parse_args(["--org", "Shards-foundation", "--check-branches"]))
        api = FakeOpener([[make_repo()], urllib.error.HTTPError(
            "https://api.github.com", 404, "missing", {}, None,
        )])
        with mock.patch.object(review, "make_opener", return_value=api), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            outcome = review.report_inventory(settings, None, [])
        self.assertEqual(outcome, 2)
        self.assertEqual(json.loads(out.getvalue())["assessment"], "NOT_VERIFIED")

    def test_explicit_unprotected_branch_is_nonzero(self) -> None:
        settings = review.validate(review.parse_args(["--org", "Shards-foundation", "--check-branches"]))
        api = FakeOpener([[make_repo()], {"protected": False}])
        with mock.patch.object(review, "make_opener", return_value=api), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            outcome = review.report_inventory(settings, None, [])
        self.assertEqual(outcome, 1)
        self.assertEqual(json.loads(out.getvalue())["assessment"], "UNPROTECTED")

    def test_branch_not_found_stays_not_verified(self) -> None:
        repo = review.validate_repo(make_repo(), "Shards-foundation")
        opener = FakeOpener([urllib.error.HTTPError("https://api.github.com", 404, "missing", {}, None)])
        review.check_branches([repo], opener, self.settings, None, [])
        self.assertEqual(repo["branch_protected"], "NOT_VERIFIED")
        self.assertIn("default_branch_metadata_unavailable", repo["findings"])

    def test_old_repo_yields_advisory(self) -> None:
        repo = review.validate_repo(make_repo(pushed_at="2021-01-01T00:00:00Z"), "Shards-foundation")
        review.add_risk_flags(repo, datetime(2026, 11, 6, tzinfo=timezone.utc), 180)
        self.assertIn("last_push_older_than_threshold", repo["findings"])

    def test_invalid_org_fails_before_network(self) -> None:
        for name in ["Shards-foundation/other", "../../etc", "bad%2Fpath", "a--b"]:
            with self.subTest(name=name):
                with self.assertRaises(review.InventoryError):
                    review.validate(review.parse_args(["--org", name]))

    def test_dry_run_does_not_read_network_or_write_files(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            untouched = root / "important.txt"
            untouched.write_text("DO NOT TOUCH", encoding="utf-8")
            with mock.patch.object(review, "make_opener", side_effect=AssertionError("network")), \
                    mock.patch.object(review, "report_inventory", side_effect=AssertionError("network")):
                self.assertEqual(review.main(["--org", "Shards-foundation", "--dry-run"]), 0)
            self.assertEqual(untouched.read_text(encoding="utf-8"), "DO NOT TOUCH")

    def test_removed_legacy_options_do_not_silently_run(self) -> None:
        with mock.patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as ctx:
                review.parse_args(["--org", "Shards-foundation", "--workspace", "unused-test-directory"])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_github_bad_page_fails_closed(self) -> None:
        opener = FakeOpener([{"untrusted": "not a list"}])
        with self.assertRaisesRegex(review.InventoryError, "github_repo_page_invalid"):
            review.collect_repos(opener, self.settings, None, [])

    def test_repo_limit_reports_partial_and_exit_failure(self) -> None:
        settings = review.validate(review.parse_args(["--org", "Shards-foundation", "--repo-limit", "1"]))
        opener = FakeOpener([[make_repo("A"), make_repo("B")]])
        repos, pages, complete = review.collect_repos(opener, settings, None, [])
        self.assertEqual((len(repos), pages, complete), (1, 1, False))
        with mock.patch.object(review, "make_opener", return_value=FakeOpener([[make_repo("A"), make_repo("B")]])), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            result = review.report_inventory(settings, None, [])
        self.assertEqual(result, 2)
        self.assertFalse(json.loads(out.getvalue())["complete"])

    def test_markdown_safe_schema(self) -> None:
        report = {"organisation": "Shards-foundation", "repositories_checked": 1,
                  "advisory_findings": 0, "repositories": [review.validate_repo(make_repo(), "Shards-foundation")]}
        value = review.render_markdown(report)
        self.assertIn("Shards-kernel", value)
        self.assertNotIn("clone_url", value)


if __name__ == "__main__":
    unittest.main()

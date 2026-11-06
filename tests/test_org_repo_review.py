"""Negative-path regression tests for safe organisation-wide GitHub inventory."""

from __future__ import annotations

import io
import itertools
import json
import tempfile
import unittest
import urllib.error
import signal
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

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
        with patch.object(review.time, "sleep", return_value=None), \
                patch.object(review.time, "monotonic", side_effect=[0.0, 9.0]):
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
        with patch.object(review, "make_opener", return_value=opener):
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
        with patch.object(review, "make_opener", return_value=api), \
                patch("sys.stdout", new_callable=io.StringIO) as out:
            outcome = review.report_inventory(settings, None, [])
        self.assertEqual(outcome, 2)
        self.assertEqual(json.loads(out.getvalue())["assessment"], "NOT_VERIFIED")

    def test_explicit_unprotected_branch_is_nonzero(self) -> None:
        settings = review.validate(review.parse_args(["--org", "Shards-foundation", "--check-branches"]))
        api = FakeOpener([[make_repo()], {"protected": False}])
        with patch.object(review, "make_opener", return_value=api), \
                patch("sys.stdout", new_callable=io.StringIO) as out:
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
            with patch.object(review, "make_opener", side_effect=AssertionError("network")), \
                    patch.object(review, "report_inventory", side_effect=AssertionError("network")):
                self.assertEqual(review.main(["--org", "Shards-foundation", "--dry-run"]), 0)
            self.assertEqual(untouched.read_text(encoding="utf-8"), "DO NOT TOUCH")

    def test_removed_legacy_options_do_not_silently_run(self) -> None:
        with patch("sys.stderr", new_callable=io.StringIO):
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
        with patch.object(review, "make_opener", return_value=FakeOpener([[make_repo("A"), make_repo("B")]])), \
                patch("sys.stdout", new_callable=io.StringIO) as out:
            result = review.report_inventory(settings, None, [])
        self.assertEqual(result, 2)
        self.assertFalse(json.loads(out.getvalue())["complete"])

    def test_markdown_safe_schema(self) -> None:
        report = {"organisation": "Shards-foundation", "repositories_checked": 1,
                  "advisory_findings": 0, "repositories": [review.validate_repo(make_repo(), "Shards-foundation")]}
        value = review.render_markdown(report)
        self.assertIn("Shards-kernel", value)
        self.assertNotIn("clone_url", value)



    def test_exactly_reached_repo_cap_is_always_partial(self) -> None:
        settings = review.validate(review.parse_args(["--org", "Shards-foundation", "--repo-limit", "1"]))
        opener = FakeOpener([[make_repo()]])
        repos, pages, complete = review.collect_repos(opener, settings, None, [])
        self.assertEqual((len(repos), pages, complete), (1, 1, False))

    def test_strict_mode_stale_repo_is_nonzero(self) -> None:
        settings = review.validate(review.parse_args(["--org", "Shards-foundation", "--strict"]))
        opener = FakeOpener([[make_repo(pushed_at="2021-01-01T00:00:00Z")]])
        with patch.object(review, "make_opener", return_value=opener), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            result = review.report_inventory(settings, None, [])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(output.getvalue())["assessment"], "ADVISORY")

    def test_untrusted_description_never_reaches_report(self) -> None:
        untrusted = make_repo(description="DO_NOT_EXPOSE\n|Injected|", clone_url="https://attacker.invalid/evil")
        repo = review.validate_repo(untrusted, "Shards-foundation")
        self.assertNotIn("description", repo)
        self.assertNotIn("clone_url", repo)
        report = {"organisation": "Shards-foundation", "repositories_checked": 1,
                  "advisory_findings": 0, "repositories": [repo]}
        self.assertNotIn("DO_NOT_EXPOSE", review.render_markdown(report))
        with self.assertRaises(review.InventoryError):
            review.validate_repo(make_repo(name="bad\n|row"), "Shards-foundation")

    def test_response_size_limit_and_malformed_json_fail_closed(self) -> None:
        settings = self.settings
        opener = FakeOpener([[make_repo()]])
        with patch.object(review, "MAX_RESPONSE_BYTES", 8):
            with self.assertRaisesRegex(review.InventoryError, "github_response_too_large"):
                review.read_api(opener, "/orgs/Shards-foundation/repos", settings, None, [])
        class InvalidOpener:
            def open(self, request, timeout):
                class InvalidResponse:
                    status = 200
                    def __enter__(self):
                        return self
                    def __exit__(self, *_args):
                        return None
                    def read(self, _maximum):
                        return b"not-json"
                return InvalidResponse()
        with self.assertRaisesRegex(review.InventoryError, "github_invalid_json"):
            review.read_api(InvalidOpener(), "/orgs/Shards-foundation/repos", settings, None, [])

    def test_invalid_token_and_transport_failure_are_redacted(self) -> None:
        with self.assertRaisesRegex(review.InventoryError, "invalid_token_format"):
            review.read_api(FakeOpener([]), "/orgs/Shards-foundation/repos", self.settings,
                            "secret\nheader", [])
        settings = review.validate(review.parse_args(["--org", "Shards-foundation", "--attempts", "1"]))
        opener = FakeOpener([urllib.error.URLError("synthetic disconnected")])
        with self.assertRaisesRegex(review.InventoryError, "github_transport_error"):
            review.collect_repos(opener, settings, None, [])

    def test_no_redirect_handler_is_fail_closed(self) -> None:
        self.assertIsNone(review.NoRedirect().redirect_request(None, None, 302, "move", {},
                                                                  "https://other.invalid/"))

    def test_main_signal_exit_statuses(self) -> None:
        for signum, expected in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
            callbacks = {}
            def capture(sig, callback):
                callbacks[sig] = callback
                return lambda *_args: None
            def run(*_args):
                callbacks[signum](signum, None)
                return 0
            with self.subTest(signum=signum), \
                    patch.object(review.signal, "signal", capture), \
                    patch.object(review, "report_inventory", run):
                self.assertEqual(review.main(["--org", "Shards-foundation"]), expected)

    def test_interruption_during_retry_is_nonzero(self) -> None:
        stopped = []
        opener = FakeOpener([urllib.error.URLError("transient")])
        ticks = itertools.count(0.0, 0.0)
        def stop_on_sleep(_seconds):
            stopped.append(signal.SIGINT)
        with patch.object(review.time, "monotonic", side_effect=lambda: next(ticks)), \
                patch.object(review.time, "sleep", side_effect=stop_on_sleep):
            with self.assertRaisesRegex(review.InventoryError, "interrupted"):
                review.collect_repos(opener, self.settings, None, stopped)

    def test_real_inventory_never_invokes_subprocesses_or_filesystem_writes(self) -> None:
        opener = FakeOpener([[make_repo()]])
        with patch.object(review, "make_opener", return_value=opener), \
                patch("subprocess.run", side_effect=AssertionError("subprocess")), \
                patch("pathlib.Path.write_text", side_effect=AssertionError("filesystem write")), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(review.report_inventory(self.settings, None, []), 0)
        self.assertTrue(json.loads(output.getvalue())["complete"])


    def test_invalid_numeric_ranges_fail_before_network(self) -> None:
        invalid = [
            ("--timeout", "nan"), ("--timeout", "0"),
            ("--attempts", "0"), ("--attempts", "999"),
            ("--max-pages", "0"), ("--max-pages", "999"),
            ("--repo-limit", "-1"), ("--repo-limit", "99999"),
            ("--stale-days", "0"), ("--stale-days", "9999"),
        ]
        for flag, value in invalid:
            with self.subTest(flag=flag, value=value):
                with self.assertRaises(review.InventoryError):
                    review.validate(review.parse_args([
                        "--org", "Shards-foundation", flag, value,
                    ]))

    def test_invalid_datetime_types_formats_and_timezone(self) -> None:
        for value in (None, 123, "this-is-not-a-date", "2026-11-06T09:00:00"):
            with self.subTest(value=value):
                with self.assertRaises(review.InventoryError):
                    review.parse_datetime(value)

    def test_repo_metadata_types_and_defaults_fail_closed(self) -> None:
        bad_values = [
            make_repo(archived="false"),
            make_repo(private=1),
            make_repo(default_branch=""),
            make_repo(default_branch=123),
            make_repo(pushed_at="injected-not-a-date"),
        ]
        for value in bad_values:
            with self.subTest(value=value):
                with self.assertRaises(review.InventoryError):
                    review.validate_repo(value, "Shards-foundation")
        with self.assertRaisesRegex(review.InventoryError, "github_repo_not_object"):
            review.validate_repo(["not-an-object"], "Shards-foundation")

    def test_missing_default_branch_and_push_date_are_advisory(self) -> None:
        repo = review.validate_repo(
            make_repo(default_branch=None, pushed_at=None), "Shards-foundation"
        )
        review.add_risk_flags(repo, datetime(2026, 11, 6, tzinfo=timezone.utc), 180)
        self.assertIn("default_branch_missing", repo["findings"])
        self.assertIn("last_push_unavailable", repo["findings"])

    def test_disabled_repository_is_advisory_but_not_staleness(self) -> None:
        repo = review.validate_repo(
            make_repo(disabled=True, pushed_at="2021-01-01T00:00:00Z"),
            "Shards-foundation",
        )
        review.add_risk_flags(repo, datetime(2026, 11, 6, tzinfo=timezone.utc), 180)
        self.assertIn("repository_disabled", repo["findings"])
        self.assertNotIn("last_push_older_than_threshold", repo["findings"])

    def test_archived_repository_does_not_generate_staleness(self) -> None:
        repo = review.validate_repo(
            make_repo(archived=True, pushed_at="2021-01-01T00:00:00Z"),
            "Shards-foundation",
        )
        review.add_risk_flags(repo, datetime(2026, 11, 6, tzinfo=timezone.utc), 180)
        self.assertNotIn("last_push_older_than_threshold", repo["findings"])

    def test_branch_lookup_errors_and_invalid_data_fail_closed(self) -> None:
        cases = [
            ({"protected": "yes"}, "github_branch_metadata_invalid"),
            ([1, 2], "github_branch_metadata_invalid"),
            (urllib.error.HTTPError("https://api.github.com", 401, "denied", {}, None),
             "github_http_401"),
        ]
        for result, expected in cases:
            repo = review.validate_repo(make_repo(), "Shards-foundation")
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(review.InventoryError, expected):
                    review.check_branches(
                        [repo], FakeOpener([result]), self.settings, None, [],
                    )

    def test_branch_lookup_interruption_fails_closed(self) -> None:
        repo = review.validate_repo(make_repo(), "Shards-foundation")
        with self.assertRaisesRegex(review.InventoryError, "interrupted"):
            review.check_branches(
                [repo], FakeOpener([]), self.settings, None, [signal.SIGTERM],
            )

    def test_missing_branch_is_unknown_not_confirmed_protected(self) -> None:
        settings = review.validate(review.parse_args([
            "--org", "Shards-foundation", "--check-branches",
        ]))
        repo = make_repo(default_branch=None, pushed_at=None)
        with patch.object(review, "make_opener", return_value=FakeOpener([[repo]])), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            code = review.report_inventory(settings, None, [])
        self.assertEqual(code, 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report["assessment"], "NOT_VERIFIED")
        self.assertEqual(report["repositories"][0]["branch_protected"], "NOT_APPLICABLE")

    def test_branch_protected_flag_is_not_rule_certification(self) -> None:
        settings = review.validate(review.parse_args([
            "--org", "Shards-foundation", "--check-branches",
        ]))
        with patch.object(review, "make_opener",
                          return_value=FakeOpener([[make_repo()], {"protected": True}])), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            code = review.report_inventory(settings, None, [])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["repositories"][0]["branch_protected"], "REPORTED_TRUE")
        self.assertEqual(report["scope"], "read_only_github_api_inventory_not_security_certification")

    def test_markdown_mode_outputs_safe_summary(self) -> None:
        settings = review.validate(review.parse_args([
            "--org", "Shards-foundation", "--format", "markdown",
        ]))
        with patch.object(review, "make_opener", return_value=FakeOpener([[make_repo()]])), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            code = review.report_inventory(settings, None, [])
        self.assertEqual(code, 0)
        self.assertIn("| Shards-kernel |", output.getvalue())
        self.assertNotIn("clone_url", output.getvalue())

    def test_none_report_format_has_no_stdout(self) -> None:
        settings = review.validate(review.parse_args([
            "--org", "Shards-foundation", "--format", "none",
        ]))
        with patch.object(review, "make_opener", return_value=FakeOpener([[make_repo()]])), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            code = review.report_inventory(settings, None, [])
        self.assertEqual(code, 0)
        self.assertEqual(output.getvalue(), "")

    def test_main_rejects_invalid_config_and_api_errors(self) -> None:
        with patch.object(review, "report_inventory",
                          side_effect=AssertionError("must not run")):
            self.assertEqual(review.main([
                "--org", "Shards-foundation", "--attempts", "0",
            ]), 2)
        with patch.object(review, "report_inventory",
                          side_effect=review.InventoryError("synthetic_outage")):
            self.assertEqual(review.main(["--org", "Shards-foundation"]), 2)

    def test_oversized_page_rejected(self) -> None:
        page = [make_repo(name=f"R{i}") for i in range(review.PAGE_SIZE + 1)]
        with self.assertRaisesRegex(review.InventoryError, "github_repo_page_oversized"):
            review.collect_repos(FakeOpener([page]), self.settings, None, [])

    def test_api_interruption_before_open(self) -> None:
        with self.assertRaisesRegex(review.InventoryError, "interrupted"):
            review.read_api(FakeOpener([]), "/orgs/Shards-foundation/repos",
                            self.settings, None, [signal.SIGINT])

    def test_api_non_200_response_is_rejected(self) -> None:
        class ErrorOpener:
            def open(self, request, timeout):
                return FakeResponse({}, status=202)
        with self.assertRaisesRegex(review.InventoryError, "github_unexpected_http_status"):
            review.read_api(ErrorOpener(), "/orgs/Shards-foundation/repos",
                            self.settings, None, [])



if __name__ == "__main__":
    unittest.main()

"""Regression tests for the evidence-bundle CLI.

The command must fail closed. ``replay_and_verify([])`` returns ``(True, [])``,
so an empty or missing ``ledger_entries`` list is rejected in the CLI before
``verify_evidence_bundle`` is called.
"""

from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from shards_kernel.audit.replay import replay_and_verify, verify_evidence_bundle
from shards_kernel.cli import verify_evidence, verify_evidence_file
from shards_kernel.cli.verify import main
from shards_kernel.common.types import KernelConfig, KernelRequest, VirtualClock
from shards_kernel.integrations.wire import evidence_to_mapping
from shards_kernel.variants.permissive_kernel import PermissiveKernel

_FORBIDDEN_SUCCESS_WORDS = ("verified", "authentic", "passed")


def _exported_bundle(submits: int) -> dict:
    """Return the JSON object ``export_evidence()`` produces."""
    kernel = PermissiveKernel()
    kernel.boot(
        KernelConfig(
            kernel_id="cli-verify",
            variant="permissive",
            clock=VirtualClock(1000),
        )
    )
    for index in range(submits):
        kernel.submit(
            KernelRequest(
                request_id=f"req-{index}",
                ts_ms=1000 + index,
                actor="alice",
                intent=f"intent {index}",
            )
        )
    return evidence_to_mapping(kernel.export_evidence())


class TestCliEvidenceConsistency(unittest.TestCase):
    """CLI exit status, wording, and fail-closed cases."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.valid = _exported_bundle(3)
        self.assertGreaterEqual(len(self.valid["ledger_entries"]), 2)

    def _write(self, name: str, payload: object | None = None, text: str | None = None) -> str:
        path = Path(self._tmp.name) / name
        if text is None:
            text = json.dumps(payload)
        path.write_text(text, encoding="utf-8")
        return str(path)

    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def _run_payload(self, name: str, payload: object, *flags: str) -> tuple[int, str, str]:
        return self._run([*flags, self._write(name, payload)])

    def _assert_success_wording(self, text: str) -> None:
        self.assertIn("internally consistent (integrity only)", text)
        lowered = text.lower()
        for word in _FORBIDDEN_SUCCESS_WORDS:
            self.assertNotIn(word, lowered)

    def test_valid_exported_bundle_exits_zero_and_says_internally_consistent(self) -> None:
        """A bundle from export_evidence() exits 0 and claims integrity only."""
        path = self._write("valid.json", self.valid)
        code, stdout, _stderr = self._run([path])
        self.assertEqual(code, 0)
        self._assert_success_wording(stdout)

        completed = subprocess.run(
            [sys.executable, "-m", "shards_kernel.cli.verify", path],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0)
        self._assert_success_wording(completed.stdout)

    def test_json_and_detailed_success_use_internal_consistency_wording(self) -> None:
        path = self._write("valid.json", self.valid)
        code, stdout, _stderr = self._run(["--json", "--detailed", path])
        self.assertEqual(code, 0)
        self._assert_success_wording(stdout)
        self.assertIn('"internally_consistent": true', stdout)
        self.assertIn("ledger:", stdout)

    def test_tampered_content_with_stored_hashes_fails(self) -> None:
        """Changing content without recomputing stored hashes must fail."""
        tampered = copy.deepcopy(self.valid)
        tampered["ledger_entries"][0]["intent"] = "tampered intent"
        self.assertEqual(
            tampered["ledger_entries"][0]["entry_hash"],
            self.valid["ledger_entries"][0]["entry_hash"],
        )
        code, stdout, _stderr = self._run_payload("tampered.json", tampered)
        self.assertNotEqual(code, 0)
        self.assertIn("status: inconsistent", stdout)
        self.assertIn("entry_hash mismatch", stdout)

    def test_reordered_entry_fails(self) -> None:
        reordered = copy.deepcopy(self.valid)
        entries = reordered["ledger_entries"]
        entries[0], entries[1] = entries[1], entries[0]
        code, stdout, _stderr = self._run_payload("reordered.json", reordered)
        self.assertNotEqual(code, 0)
        self.assertIn("status: inconsistent", stdout)

    def test_removed_entry_fails(self) -> None:
        removed = copy.deepcopy(self.valid)
        del removed["ledger_entries"][0]
        self.assertGreaterEqual(len(removed["ledger_entries"]), 1)
        code, stdout, _stderr = self._run_payload("removed.json", removed)
        self.assertNotEqual(code, 0)
        self.assertIn("status: inconsistent", stdout)

    def test_empty_bundle_fails(self) -> None:
        """`{}` and an exported ledger with no entries are both failures."""
        code, stdout, _stderr = self._run_payload("empty.json", {})
        self.assertNotEqual(code, 0)
        self.assertIn("empty bundle", stdout)

        empty_export = _exported_bundle(0)
        self.assertEqual(empty_export["ledger_entries"], [])
        code, stdout, _stderr = self._run_payload("empty-export.json", empty_export)
        self.assertNotEqual(code, 0)
        self.assertIn("empty ledger_entries", stdout)

    def test_malformed_bundle_fails(self) -> None:
        path = self._write("broken.json", text="{")
        code, stdout, _stderr = self._run([path])
        self.assertNotEqual(code, 0)
        self.assertIn("malformed JSON", stdout)

        binary = Path(self._tmp.name) / "binary.json"
        binary.write_bytes(b"\xff\xfe not json")
        code, stdout, _stderr = self._run([str(binary)])
        self.assertNotEqual(code, 0)
        self.assertIn("unable to read evidence file", stdout)

    def test_missing_ledger_entries_fails(self) -> None:
        payload = {
            "kernel_id": "cli-verify",
            "variant": "permissive",
            "exported_at_ms": 1,
            "root_hash": self.valid["root_hash"],
        }
        code, stdout, _stderr = self._run_payload("missing.json", payload)
        self.assertNotEqual(code, 0)
        self.assertIn("missing ledger_entries", stdout)

    def test_legacy_entries_key_fails_closed(self) -> None:
        """`entries` is rejected, not read as an alias.

        Exported bundles store ``ledger_entries``. ``verify_evidence_bundle``
        ignores ``entries`` and treats a missing ``ledger_entries`` key as an
        empty list, which replay reports as consistent. Aliasing the legacy
        key would keep a second shape. The CLI fails closed instead.
        """
        legacy = copy.deepcopy(self.valid)
        legacy["entries"] = legacy.pop("ledger_entries")
        self.assertTrue(verify_evidence_bundle(legacy).is_valid)

        with patch("shards_kernel.cli.verify.verify_evidence_bundle") as replay:
            result = verify_evidence(legacy)
        replay.assert_not_called()
        self.assertFalse(result.internally_consistent)
        self.assertFalse(result.delegated)
        self.assertIn("legacy entries key is not accepted", result.errors)

        code, stdout, _stderr = self._run_payload("legacy.json", legacy)
        self.assertNotEqual(code, 0)
        self.assertIn("legacy entries key is not accepted", stdout)

    def test_empty_or_missing_ledger_entries_rejected_before_replay(self) -> None:
        """Empty and missing ledgers fail before delegation.

        ``replay_and_verify([])`` is ``(True, [])``, and
        ``verify_evidence_bundle`` therefore accepts an empty export. The CLI
        check has to run first.
        """
        self.assertEqual(replay_and_verify([]), (True, []))
        empty_export = _exported_bundle(0)
        self.assertEqual(empty_export["ledger_entries"], [])
        self.assertTrue(verify_evidence_bundle(empty_export).is_valid)

        missing = {
            "kernel_id": empty_export["kernel_id"],
            "variant": empty_export["variant"],
            "exported_at_ms": empty_export["exported_at_ms"],
            "root_hash": empty_export["root_hash"],
        }
        self.assertNotIn("ledger_entries", missing)
        self.assertTrue(verify_evidence_bundle(missing).is_valid)

        with patch("shards_kernel.cli.verify.verify_evidence_bundle") as replay:
            empty_result = verify_evidence(empty_export)
            missing_result = verify_evidence(missing)
            blank_result = verify_evidence({})
        replay.assert_not_called()
        self.assertFalse(empty_result.delegated)
        self.assertFalse(missing_result.delegated)
        self.assertFalse(blank_result.delegated)
        self.assertIn("empty ledger_entries", empty_result.errors)
        self.assertIn("missing ledger_entries", missing_result.errors)
        self.assertIn("empty bundle", blank_result.errors)

    def test_unknown_schema_fails_before_replay(self) -> None:
        coded = copy.deepcopy(self.valid)
        coded["schema_version"] = "other.vendor.v9"
        self.assertTrue(verify_evidence_bundle(coded).is_valid)
        with patch("shards_kernel.cli.verify.verify_evidence_bundle") as replay:
            result = verify_evidence(coded)
            listed = verify_evidence([])
            explicit = verify_evidence({"schema": "shards_kernel.evidence.bundle", **self.valid})
        replay.assert_not_called()
        self.assertFalse(result.internally_consistent)
        self.assertIn("unknown schema", result.errors)
        self.assertIn("unknown schema", listed.errors)
        self.assertIn("unknown schema", explicit.errors)

        code, stdout, _stderr = self._run_payload("schema.json", coded)
        self.assertNotEqual(code, 0)
        self.assertIn("unknown schema", stdout)

    def test_unknown_entries_key_fails_before_replay(self) -> None:
        unknown = {
            "audit_entries": copy.deepcopy(self.valid["ledger_entries"]),
            "root_hash": self.valid["root_hash"],
        }
        not_a_list = {"ledger_entries": "nope", "root_hash": self.valid["root_hash"]}
        extra = copy.deepcopy(self.valid)
        extra["audit_entries"] = []
        with patch("shards_kernel.cli.verify.verify_evidence_bundle") as replay:
            unknown_result = verify_evidence(unknown)
            type_result = verify_evidence(not_a_list)
            extra_result = verify_evidence(extra)
        replay.assert_not_called()
        self.assertIn("unknown entries key: audit_entries", unknown_result.errors)
        self.assertIn("unknown entries key: ledger_entries", type_result.errors)
        self.assertIn("unknown entries key: audit_entries", extra_result.errors)

    def test_missing_root_hash_rejected_before_replay(self) -> None:
        """Replay skips the root comparison when root_hash is absent."""
        missing = copy.deepcopy(self.valid)
        del missing["root_hash"]
        self.assertTrue(verify_evidence_bundle(missing).is_valid)
        blank = copy.deepcopy(self.valid)
        blank["root_hash"] = "  "
        wrong_type = copy.deepcopy(self.valid)
        wrong_type["root_hash"] = 0
        with patch("shards_kernel.cli.verify.verify_evidence_bundle") as replay:
            missing_result = verify_evidence(missing)
            blank_result = verify_evidence(blank)
            type_result = verify_evidence(wrong_type)
        replay.assert_not_called()
        self.assertIn("missing root_hash", missing_result.errors)
        self.assertIn("missing root_hash", blank_result.errors)
        self.assertIn("missing root_hash", type_result.errors)

    def test_malformed_entry_rejected_before_replay(self) -> None:
        malformed = copy.deepcopy(self.valid)
        malformed["ledger_entries"][0] = "not-an-entry"
        with patch("shards_kernel.cli.verify.verify_evidence_bundle") as replay:
            result = verify_evidence(malformed)
        replay.assert_not_called()
        self.assertIn("malformed bundle", result.errors)
        code, stdout, _stderr = self._run(
            ["--detailed", self._write("malformed-entry.json", malformed)]
        )
        self.assertNotEqual(code, 0)
        self.assertIn("malformed entry", stdout)

    def test_valid_bundle_delegates_to_verify_evidence_bundle(self) -> None:
        with patch("shards_kernel.cli.verify.verify_evidence_bundle", wraps=verify_evidence_bundle) as replay:
            result = verify_evidence(self.valid)
        replay.assert_called_once_with(self.valid)
        self.assertTrue(result.delegated)
        self.assertTrue(result.internally_consistent)
        self.assertEqual(result.errors, [])

    def test_file_not_found_and_unreadable_path_fail(self) -> None:
        missing = str(Path(self._tmp.name) / "missing.json")
        code, stdout, _stderr = self._run([missing])
        self.assertNotEqual(code, 0)
        self.assertIn("file not found", stdout)
        self.assertFalse(verify_evidence_file(missing).delegated)

        code, stdout, _stderr = self._run([self._tmp.name])
        self.assertNotEqual(code, 0)
        self.assertIn("unable to read evidence file", stdout)

    def test_detailed_skips_ledger_section_when_entries_are_not_a_list(self) -> None:
        payload = {"ledger_entries": "nope", "root_hash": self.valid["root_hash"]}
        code, stdout, _stderr = self._run(
            ["--detailed", self._write("not-a-list.json", payload)]
        )
        self.assertNotEqual(code, 0)
        self.assertNotIn("ledger:", stdout)
        self.assertIn("unknown entries key: ledger_entries", stdout)

    def test_failure_json_does_not_claim_internal_consistency(self) -> None:
        code, stdout, _stderr = self._run(
            ["--json", self._write("empty.json", {"ledger_entries": []})]
        )
        self.assertNotEqual(code, 0)
        self.assertIn('"internally_consistent": false', stdout)
        self.assertNotIn("internally consistent (integrity only)", stdout)

"""Logic-only tests for native Termux probe trust-anchor handling.

Fake verifier receipts intentionally test the *probe interface*, not actual
permit execution. Real signed execution remains in cross-runner CI or on-device.
"""
from __future__ import annotations

from hashlib import sha256
import importlib.util
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


PROBE = Path(__file__).resolve().parents[1] / "scripts" / "acceptance" / "termux_device_probe.py"
spec = importlib.util.spec_from_file_location("native_termux_probe_under_test", PROBE)
assert spec is not None and spec.loader is not None
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TrustAnchorContractTests(unittest.TestCase):
    def test_fingerprint_checked_with_existing_enrollment_and_case_insensitive_hex(self):
        from shards_kernel.api import Decision, ReceiptStatus

        public = bytes(range(32))
        fingerprint = sha256(public).hexdigest()
        calls = []
        stub = ModuleType("agent_verifier_v3")

        def execute(root, proposal, permit):
            calls.append((root, proposal, permit))
            if len(calls) == 1:
                return SimpleNamespace(
                    decision=Decision.ALLOW, status=ReceiptStatus.ACCEPTED,
                    tool_result=42,
                )
            return SimpleNamespace(
                decision=Decision.DENY, status=ReceiptStatus.REJECTED,
                tool_result=None,
            )

        def must_not_enroll(*args):
            raise AssertionError("Already enrolled key must not re-enroll")

        stub.execute = execute
        stub.enroll = must_not_enroll
        with TemporaryDirectory() as directory, patch.dict(
            sys.modules, {"agent_verifier_v3": stub}
        ):
            state = Path(directory)
            (state / "operator-v3.pub").write_bytes(public)
            args = SimpleNamespace(
                state_dir=state, public_key_hex=public.hex().upper(),
                fingerprint=fingerprint.upper(), proposal=Path("p.json"),
                permit=Path("s.json"),
            )
            result = probe.externally_signed_execution(args)
            self.assertEqual(result["external_permit_exact_add"], "PASS")
            self.assertEqual(result["replay_denied"], "PASS")
            self.assertEqual(len(calls), 2)

            # Critically: the same previously enrolled key must not bypass a
            # wrong independent fingerprint supplied by the operator.
            args.fingerprint = "0" * 64
            with self.assertRaisesRegex(RuntimeError, "fingerprint"):
                probe.externally_signed_execution(args)
            self.assertEqual(len(calls), 2)

    def test_no_enrollment_on_mismatched_trust_anchor(self):
        stub = ModuleType("agent_verifier_v3")
        stub.enroll = lambda *a: self.fail("Invalid key was enrolled")
        stub.execute = lambda *a: self.fail("Invalid key executed")
        with TemporaryDirectory() as directory, patch.dict(
            sys.modules, {"agent_verifier_v3": stub}
        ):
            state = Path(directory) / "phone"
            args = SimpleNamespace(
                state_dir=state, public_key_hex=(b"x" * 32).hex(),
                fingerprint="0" * 64, proposal=Path("p.json"),
                permit=Path("s.json"),
            )
            with self.assertRaisesRegex(RuntimeError, "fingerprint"):
                probe.externally_signed_execution(args)
            self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()

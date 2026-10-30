"""
Comprehensive test suite for permit token system.

Tests cover:
- Canonical serialization and hashing
- HMAC signing and verification
- Nonce registry and replay protection
- Full verification pipeline
- Fail-closed behavior (25+ negative tests)
- Constraint enforcement
- Audit linkage
"""

import unittest

from shards_kernel.permits import (
    NonceRegistry,
    PermitBuilder,
    PermitToken,
    canonical_permit_bytes,
    compute_permit_id,
    deterministic_nonce,
    generate_nonce,
    sign_permit,
    verify_permit,
    verify_signature,
)
from shards_kernel.common.types import Decision


class TestCanonicalSerialization(unittest.TestCase):
    """Test deterministic serialization and hashing."""

    def test_canonical_bytes_deterministic(self) -> None:
        """Identical permits produce identical canonical bytes."""
        permit1 = PermitToken(
            permit_id="test-id",
            issuer="operator1",
            subject="worker1",
            jurisdiction="test",
            action="echo",
            params={"text": "hello"},
            constraints={"max_time_ms": 1000},
            max_executions=1,
            valid_from_ms=0,
            valid_until_ms=10000,
            evidence_hash="abc123",
            proposal_hash="def456",
            nonce="nonce12345678901234567890123456789012",
            signature="sig123",
            key_id="key1",
        )

        permit2 = PermitToken(
            permit_id="test-id",
            issuer="operator1",
            subject="worker1",
            jurisdiction="test",
            action="echo",
            params={"text": "hello"},
            constraints={"max_time_ms": 1000},
            max_executions=1,
            valid_from_ms=0,
            valid_until_ms=10000,
            evidence_hash="abc123",
            proposal_hash="def456",
            nonce="nonce12345678901234567890123456789012",
            signature="sig123",
            key_id="key1",
        )

        self.assertEqual(
            canonical_permit_bytes(permit1), canonical_permit_bytes(permit2)
        )

    def test_canonical_bytes_excludes_signature(self) -> None:
        """Canonical bytes exclude signature by default."""
        permit = PermitToken(
            permit_id="test-id",
            issuer="operator1",
            subject="worker1",
            jurisdiction="test",
            action="echo",
            params={},
            constraints={},
            max_executions=1,
            valid_from_ms=0,
            valid_until_ms=10000,
            evidence_hash="",
            proposal_hash="prop123",
            nonce="nonce12345678901234567890123456789012",
            signature="SHOULD_NOT_APPEAR",
            key_id="key1",
        )

        canonical = canonical_permit_bytes(permit, exclude_signature=True)
        self.assertNotIn(b"SHOULD_NOT_APPEAR", canonical)

    def test_canonical_bytes_sorted_keys(self) -> None:
        """Dictionary keys are sorted for determinism."""
        permit = PermitToken(
            permit_id="test-id",
            issuer="operator1",
            subject="worker1",
            jurisdiction="test",
            action="echo",
            params={"z": 1, "a": 2, "m": 3},  # Unsorted
            constraints={"zebra": 1, "apple": 2},  # Unsorted
            max_executions=1,
            valid_from_ms=0,
            valid_until_ms=10000,
            evidence_hash="",
            proposal_hash="prop123",
            nonce="nonce12345678901234567890123456789012",
            signature="sig123",
            key_id="key1",
        )

        canonical = canonical_permit_bytes(permit).decode("utf-8")
        # Check that 'a' appears before 'z' in params (sorted)
        self.assertLess(canonical.find('"a"'), canonical.find('"z"'))
        # Check that 'apple' appears before 'zebra' in constraints
        self.assertLess(canonical.find('"apple"'), canonical.find('"zebra"'))

    def test_compute_permit_id_deterministic(self) -> None:
        """Identical permits produce identical permit IDs."""
        permit1 = PermitToken(
            permit_id="",  # Will be computed
            issuer="operator1",
            subject="worker1",
            jurisdiction="test",
            action="echo",
            params={"text": "hello"},
            constraints={},
            max_executions=1,
            valid_from_ms=0,
            valid_until_ms=10000,
            evidence_hash="",
            proposal_hash="prop123",
            nonce="nonce12345678901234567890123456789012",
            signature="",
            key_id="key1",
        )

        permit2 = PermitToken(
            permit_id="",
            issuer="operator1",
            subject="worker1",
            jurisdiction="test",
            action="echo",
            params={"text": "hello"},
            constraints={},
            max_executions=1,
            valid_from_ms=0,
            valid_until_ms=10000,
            evidence_hash="",
            proposal_hash="prop123",
            nonce="nonce12345678901234567890123456789012",
            signature="",
            key_id="key1",
        )

        self.assertEqual(compute_permit_id(permit1), compute_permit_id(permit2))

    def test_compute_permit_id_length(self) -> None:
        """Permit ID is 64-character hex (SHA-256)."""
        permit = PermitToken(
            permit_id="",
            issuer="operator1",
            subject="worker1",
            jurisdiction="test",
            action="echo",
            params={},
            constraints={},
            max_executions=1,
            valid_from_ms=0,
            valid_until_ms=10000,
            evidence_hash="",
            proposal_hash="prop123",
            nonce="nonce12345678901234567890123456789012",
            signature="",
            key_id="key1",
        )

        permit_id = compute_permit_id(permit)
        self.assertEqual(len(permit_id), 64)
        # Verify it's valid hex
        int(permit_id, 16)


class TestNonceGeneration(unittest.TestCase):
    """Test nonce generation functions."""

    def test_generate_nonce_length(self) -> None:
        """Generated nonce is 32 characters (UUID4 hex)."""
        nonce = generate_nonce()
        self.assertEqual(len(nonce), 32)
        # Verify it's valid hex
        int(nonce, 16)

    def test_generate_nonce_unique(self) -> None:
        """Multiple generations produce different nonces."""
        nonces = [generate_nonce() for _ in range(100)]
        self.assertEqual(len(nonces), len(set(nonces)))  # All unique

    def test_deterministic_nonce_deterministic(self) -> None:
        """Deterministic nonce is reproducible."""
        proposal = "abc123"
        seq = 42

        nonce1 = deterministic_nonce(proposal, seq)
        nonce2 = deterministic_nonce(proposal, seq)

        self.assertEqual(nonce1, nonce2)

    def test_deterministic_nonce_different_sequences(self) -> None:
        """Different sequences produce different nonces."""
        proposal = "abc123"

        nonce1 = deterministic_nonce(proposal, 1)
        nonce2 = deterministic_nonce(proposal, 2)

        self.assertNotEqual(nonce1, nonce2)


class TestHMACSigning(unittest.TestCase):
    """Test HMAC signing and verification."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}

        # Create permit with empty ID first, then compute it
        permit_unsigned = PermitToken(
            permit_id="",
            issuer="operator1",
            subject="worker1",
            jurisdiction="test",
            action="echo",
            params={"text": "hello"},
            constraints={},
            max_executions=1,
            valid_from_ms=0,
            valid_until_ms=10000,
            evidence_hash="",
            proposal_hash="prop123",
            nonce="nonce12345678901234567890123456789012",
            signature="",
            key_id="key1",
        )

        # Compute and set permit ID
        from dataclasses import replace

        permit_id = compute_permit_id(permit_unsigned)
        self.permit = replace(permit_unsigned, permit_id=permit_id)

    def test_sign_permit_deterministic(self) -> None:
        """Same permit + key produces same signature."""
        sig1 = sign_permit(self.permit, self.key, "key1")
        sig2 = sign_permit(self.permit, self.key, "key1")

        self.assertEqual(sig1.signature, sig2.signature)

    def test_sign_permit_signature_length(self) -> None:
        """Signature is 64-character hex (SHA-256 HMAC)."""
        signed = sign_permit(self.permit, self.key, "key1")
        self.assertEqual(len(signed.signature), 64)
        # Verify it's valid hex
        int(signed.signature, 16)

    def test_sign_permit_different_keys(self) -> None:
        """Different keys produce different signatures."""
        key2 = b"different-key-32-bytes-long12345"

        sig1 = sign_permit(self.permit, self.key, "key1")
        sig2 = sign_permit(self.permit, key2, "key2")

        self.assertNotEqual(sig1.signature, sig2.signature)

    def test_verify_signature_valid(self) -> None:
        """Valid signature verifies successfully."""
        signed = sign_permit(self.permit, self.key, "key1")
        result = verify_signature(signed, self.keyring)

        self.assertEqual(result.status, Decision.ALLOW)
        self.assertEqual(len(result.reasons), 0)

    def test_verify_signature_tampered_signature(self) -> None:
        """Tampered signature fails verification."""
        signed = sign_permit(self.permit, self.key, "key1")

        # Tamper with signature
        tampered_sig = "0" * 64
        from dataclasses import replace

        tampered = replace(signed, signature=tampered_sig)

        result = verify_signature(tampered, self.keyring)

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("SIGNATURE_INVALID", result.reasons)

    def test_verify_signature_unknown_key_id(self) -> None:
        """Unknown key ID fails verification."""
        signed = sign_permit(self.permit, self.key, "unknown-key")

        result = verify_signature(signed, self.keyring)

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("UNKNOWN_KEY_ID", result.reasons)

    def test_verify_signature_tampered_permit_id(self) -> None:
        """Tampered permit ID fails verification."""
        signed = sign_permit(self.permit, self.key, "key1")

        # Tamper with permit ID
        from dataclasses import replace

        tampered = replace(signed, permit_id="tampered-id")

        result = verify_signature(tampered, self.keyring)

        self.assertEqual(result.status, Decision.DENY)
        # Either SIGNATURE_INVALID or PERMIT_ID_MISMATCH is acceptable (both indicate tampering)
        self.assertTrue(
            "PERMIT_ID_MISMATCH" in result.reasons
            or "SIGNATURE_INVALID" in result.reasons,
            f"Expected PERMIT_ID_MISMATCH or SIGNATURE_INVALID, got {result.reasons}",
        )


class TestNonceRegistry(unittest.TestCase):
    """Test nonce registry and replay protection."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.registry = NonceRegistry()

    def test_check_and_record_first_use(self) -> None:
        """First use of nonce is allowed."""
        result = self.registry.check_and_record(
            "nonce1",
            "issuer1",
            "subject1",
            "permit1",
            max_executions=1,
            current_time_ms=1000,
        )
        self.assertTrue(result)

    def test_check_and_record_replay_single_use(self) -> None:
        """Replay of single-use nonce is denied."""
        self.registry.check_and_record(
            "nonce1",
            "issuer1",
            "subject1",
            "permit1",
            max_executions=1,
            current_time_ms=1000,
        )

        # Try to use again
        result = self.registry.check_and_record(
            "nonce1",
            "issuer1",
            "subject1",
            "permit1",
            max_executions=1,
            current_time_ms=2000,
        )

        self.assertFalse(result)  # Replay detected

    def test_check_and_record_multi_use_allowed(self) -> None:
        """Multi-use permit allows N executions."""
        max_uses = 3

        # First use
        r1 = self.registry.check_and_record(
            "nonce1",
            "issuer1",
            "subject1",
            "permit1",
            max_executions=max_uses,
            current_time_ms=1000,
        )
        self.assertTrue(r1)

        # Second use
        r2 = self.registry.check_and_record(
            "nonce1",
            "issuer1",
            "subject1",
            "permit1",
            max_executions=max_uses,
            current_time_ms=2000,
        )
        self.assertTrue(r2)

        # Third use
        r3 = self.registry.check_and_record(
            "nonce1",
            "issuer1",
            "subject1",
            "permit1",
            max_executions=max_uses,
            current_time_ms=3000,
        )
        self.assertTrue(r3)

        # Fourth use (exceeds max)
        r4 = self.registry.check_and_record(
            "nonce1",
            "issuer1",
            "subject1",
            "permit1",
            max_executions=max_uses,
            current_time_ms=4000,
        )
        self.assertFalse(r4)

    def test_check_and_record_different_issuers(self) -> None:
        """Same nonce with different issuers are independent."""
        self.registry.check_and_record(
            "nonce1",
            "issuer1",
            "subject1",
            "permit1",
            max_executions=1,
            current_time_ms=1000,
        )
        result = self.registry.check_and_record(
            "nonce1",
            "issuer2",
            "subject1",
            "permit2",
            max_executions=1,
            current_time_ms=2000,
        )

        self.assertTrue(result)  # Different issuer, so allowed

    def test_has_nonce(self) -> None:
        """has_nonce checks if nonce exists."""
        self.assertFalse(self.registry.has_nonce("nonce1", "issuer1", "subject1"))

        self.registry.check_and_record(
            "nonce1",
            "issuer1",
            "subject1",
            "permit1",
            max_executions=1,
            current_time_ms=1000,
        )

        self.assertTrue(self.registry.has_nonce("nonce1", "issuer1", "subject1"))

    def test_get_record(self) -> None:
        """get_record retrieves nonce record."""
        self.assertIsNone(self.registry.get_record("nonce1", "issuer1", "subject1"))

        self.registry.check_and_record(
            "nonce1",
            "issuer1",
            "subject1",
            "permit1",
            max_executions=1,
            current_time_ms=1000,
        )

        record = self.registry.get_record("nonce1", "issuer1", "subject1")
        self.assertIsNotNone(record)
        self.assertEqual(record.nonce, "nonce1")
        self.assertEqual(record.use_count, 1)


class TestPermitVerificationNegative(unittest.TestCase):
    """
    Negative tests for permit verification (25+ tests).

    Each test validates fail-closed behavior on specific violations.
    """

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}
        self.registry = NonceRegistry()

        # Create a valid base permit
        builder = PermitBuilder()
        self.valid_permit = (
            builder.issuer("operator1")
            .subject("worker1")
            .jurisdiction("test-jurisdiction")
            .action("echo")
            .params({"text": "hello"})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(1000)
            .valid_until_ms(10000)
            .evidence_hash("evidence-hash")
            .proposal_hash("proposal-hash")
            .nonce("test-nonce-123456789012345678901234")
            .build(self.keyring, "key1")
        )

    # Test 1: Unknown key ID
    def test_deny_unknown_key_id(self) -> None:
        """Deny permit with unknown key_id."""
        from dataclasses import replace

        permit = replace(self.valid_permit, key_id="unknown-key")

        result = verify_permit(
            permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("UNKNOWN_KEY_ID", result.reasons)

    # Test 2: Invalid signature
    def test_deny_invalid_signature(self) -> None:
        """Deny permit with invalid signature."""
        from dataclasses import replace

        permit = replace(self.valid_permit, signature="0" * 64)

        result = verify_permit(
            permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("SIGNATURE_INVALID", result.reasons)

    # Test 3: Permit ID mismatch
    def test_deny_permit_id_mismatch(self) -> None:
        """Deny permit with mismatched permit_id."""
        from dataclasses import replace

        permit = replace(self.valid_permit, permit_id="wrong-id")

        result = verify_permit(
            permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        # Either SIGNATURE_INVALID or PERMIT_ID_MISMATCH is acceptable (both indicate tampering)
        self.assertTrue(
            "PERMIT_ID_MISMATCH" in result.reasons
            or "SIGNATURE_INVALID" in result.reasons,
            f"Expected PERMIT_ID_MISMATCH or SIGNATURE_INVALID, got {result.reasons}",
        )

    # Test 4: Expired permit
    def test_deny_expired_permit(self) -> None:
        """Deny permit that has expired."""
        result = verify_permit(
            self.valid_permit,
            self.keyring,
            self.registry,
            current_time_ms=20000,  # After valid_until_ms (10000)
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("EXPIRED", result.reasons)

    # Test 5: Not yet valid
    def test_deny_not_yet_valid(self) -> None:
        """Deny permit that is not yet valid."""
        result = verify_permit(
            self.valid_permit,
            self.keyring,
            self.registry,
            current_time_ms=500,  # Before valid_from_ms (1000)
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("NOT_YET_VALID", result.reasons)

    # Test 6: Jurisdiction mismatch
    def test_deny_jurisdiction_mismatch(self) -> None:
        """Deny permit with mismatched jurisdiction."""
        result = verify_permit(
            self.valid_permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="different-jurisdiction",  # Mismatch
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("JURISDICTION_MISMATCH", result.reasons)

    # Test 7: Action not allowed
    def test_deny_action_not_allowed(self) -> None:
        """Deny permit with action not on allowlist."""
        result = verify_permit(
            self.valid_permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["read", "write"]),  # echo not in allowlist
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("ACTION_NOT_ALLOWED", result.reasons)

    # Test 8: Subject mismatch
    def test_deny_subject_mismatch(self) -> None:
        """Deny permit when subject doesn't match request actor."""
        result = verify_permit(
            self.valid_permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="different-worker",  # Mismatch
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("SUBJECT_MISMATCH", result.reasons)

    # Test 9: Params mismatch (extra param in request)
    def test_deny_params_mismatch_extra(self) -> None:
        """Deny when request has params not in permit."""
        result = verify_permit(
            self.valid_permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello", "extra": "not-allowed"},  # Extra param
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("PARAMS_MISMATCH", result.reasons)

    # Test 10: Params mismatch (value difference)
    def test_deny_params_mismatch_value(self) -> None:
        """Deny when request param value differs from permit."""
        result = verify_permit(
            self.valid_permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "different"},  # Different value
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("PARAMS_MISMATCH", result.reasons)

    # Test 11: Replay detected (single-use)
    def test_deny_replay_detected(self) -> None:
        """Deny replay of single-use permit."""
        # First use
        result1 = verify_permit(
            self.valid_permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )
        self.assertEqual(result1.status, Decision.ALLOW)

        # Second use (replay)
        result2 = verify_permit(
            self.valid_permit,
            self.keyring,
            self.registry,
            current_time_ms=6000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result2.status, Decision.DENY)
        self.assertIn("REPLAY_DETECTED", result2.reasons)

    # Test 12: Forbidden param detected
    def test_deny_forbidden_param(self) -> None:
        """Deny when request contains forbidden parameter."""
        from dataclasses import replace

        permit_with_constraint = replace(
            self.valid_permit, constraints={"forbidden_params": ["--unsafe"]}
        )

        # Re-sign permit
        from shards_kernel.permits import sign_permit

        permit_with_constraint = replace(permit_with_constraint, signature="")
        permit_id = compute_permit_id(permit_with_constraint)
        permit_with_constraint = replace(permit_with_constraint, permit_id=permit_id)
        permit_with_constraint = sign_permit(permit_with_constraint, self.key, "key1")

        result = verify_permit(
            permit_with_constraint,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello", "--unsafe": "true"},  # Forbidden param
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertTrue(
            any("FORBIDDEN_PARAM_DETECTED" in reason for reason in result.reasons)
        )

    # Test 13: Missing issuer
    def test_deny_missing_issuer(self) -> None:
        """Deny permit with empty issuer."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="",  # Empty
                subject="worker1",
                jurisdiction="test",
                action="echo",
                params={},
                constraints={},
                max_executions=1,
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("issuer", str(cm.exception))

    # Test 14: Missing subject
    def test_deny_missing_subject(self) -> None:
        """Deny permit with empty subject."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="",  # Empty
                jurisdiction="test",
                action="echo",
                params={},
                constraints={},
                max_executions=1,
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("subject", str(cm.exception))

    # Test 15: Missing jurisdiction
    def test_deny_missing_jurisdiction(self) -> None:
        """Deny permit with empty jurisdiction."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="",  # Empty
                action="echo",
                params={},
                constraints={},
                max_executions=1,
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("jurisdiction", str(cm.exception))

    # Test 16: Missing action
    def test_deny_missing_action(self) -> None:
        """Deny permit with empty action."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="test",
                action="",  # Empty
                params={},
                constraints={},
                max_executions=1,
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("action", str(cm.exception))

    # Test 17: Missing nonce
    def test_deny_short_nonce(self) -> None:
        """Deny permit with nonce < 32 chars."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="test",
                action="echo",
                params={},
                constraints={},
                max_executions=1,
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="short",  # Too short
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("nonce", str(cm.exception))

    # Test 18: Negative max_executions
    def test_deny_negative_max_executions(self) -> None:
        """Deny permit with negative max_executions."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="test",
                action="echo",
                params={},
                constraints={},
                max_executions=-1,  # Negative
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("max_executions", str(cm.exception))

    # Test 19: Zero max_executions
    def test_deny_zero_max_executions(self) -> None:
        """Deny permit with zero max_executions."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="test",
                action="echo",
                params={},
                constraints={},
                max_executions=0,  # Zero
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("max_executions", str(cm.exception))

    # Test 20: valid_until <= valid_from
    def test_deny_invalid_time_window(self) -> None:
        """Deny permit with valid_until <= valid_from."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="test",
                action="echo",
                params={},
                constraints={},
                max_executions=1,
                valid_from_ms=10000,
                valid_until_ms=10000,  # Equal
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("valid_until_ms", str(cm.exception))

    # Test 21: Non-dict params
    def test_deny_non_dict_params(self) -> None:
        """Deny permit with non-dict params."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="test",
                action="echo",
                params="not-a-dict",  # type: ignore
                constraints={},
                max_executions=1,
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("params", str(cm.exception))

    # Test 22: Non-dict constraints
    def test_deny_non_dict_constraints(self) -> None:
        """Deny permit with non-dict constraints."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="test",
                action="echo",
                params={},
                constraints="not-a-dict",  # type: ignore
                max_executions=1,
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("constraints", str(cm.exception))

    # Test 23: Empty proposal_hash
    def test_deny_empty_proposal_hash(self) -> None:
        """Deny permit with empty proposal_hash."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="test",
                action="echo",
                params={},
                constraints={},
                max_executions=1,
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="",  # Empty
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("proposal_hash", str(cm.exception))

    # Test 24: Empty key_id
    def test_deny_empty_key_id(self) -> None:
        """Deny permit with empty key_id."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="test",
                action="echo",
                params={},
                constraints={},
                max_executions=1,
                valid_from_ms=0,
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="",  # Empty
            )
        self.assertIn("key_id", str(cm.exception))

    # Test 25: Malformed forbidden_params constraint
    def test_deny_malformed_forbidden_params(self) -> None:
        """Deny when forbidden_params constraint is not a list."""
        from dataclasses import replace

        permit_bad_constraint = replace(
            self.valid_permit, constraints={"forbidden_params": "not-a-list"}
        )

        # Re-sign
        from shards_kernel.permits import sign_permit

        permit_bad_constraint = replace(permit_bad_constraint, signature="")
        permit_id = compute_permit_id(permit_bad_constraint)
        permit_bad_constraint = replace(permit_bad_constraint, permit_id=permit_id)
        permit_bad_constraint = sign_permit(permit_bad_constraint, self.key, "key1")

        result = verify_permit(
            permit_bad_constraint,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        self.assertIn("CONSTRAINT_MALFORMED_FORBIDDEN_PARAMS", result.reasons)

    # Test 26: Tampered issuer
    def test_deny_tampered_issuer(self) -> None:
        """Deny permit with tampered issuer field."""
        from dataclasses import replace

        tampered = replace(self.valid_permit, issuer="malicious-operator")

        result = verify_permit(
            tampered,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        # Should fail signature verification since issuer changed
        self.assertIn("SIGNATURE_INVALID", result.reasons)

    # Test 27: Tampered action
    def test_deny_tampered_action(self) -> None:
        """Deny permit with tampered action field."""
        from dataclasses import replace

        tampered = replace(self.valid_permit, action="malicious-action")

        result = verify_permit(
            tampered,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo", "malicious-action"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.DENY)
        # Should fail signature verification since action changed
        self.assertIn("SIGNATURE_INVALID", result.reasons)

    # Test 28: Negative valid_from_ms
    def test_deny_negative_valid_from(self) -> None:
        """Deny permit with negative valid_from_ms."""
        with self.assertRaises(ValueError) as cm:
            PermitToken(
                permit_id="test-id",
                issuer="operator1",
                subject="worker1",
                jurisdiction="test",
                action="echo",
                params={},
                constraints={},
                max_executions=1,
                valid_from_ms=-1,  # Negative
                valid_until_ms=10000,
                evidence_hash="",
                proposal_hash="prop123",
                nonce="nonce12345678901234567890123456789012456789012345678901234",
                signature="sig123",
                key_id="key1",
            )
        self.assertIn("valid_from_ms", str(cm.exception))


class TestPermitBuilder(unittest.TestCase):
    """Test PermitBuilder convenience class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}

    def test_builder_fluent_interface(self) -> None:
        """Builder supports fluent method chaining."""
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("worker1")
            .jurisdiction("test")
            .action("echo")
            .params({"text": "hello"})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("evidence")
            .proposal_hash("proposal")
            .nonce("nonce12345678901234567890123456789012456789012345678901234")
            .build(self.keyring, "key1")
        )

        self.assertEqual(permit.issuer, "operator1")
        self.assertEqual(permit.subject, "worker1")
        self.assertEqual(permit.action, "echo")

    def test_builder_auto_generates_nonce(self) -> None:
        """Builder auto-generates nonce if not set."""
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("worker1")
            .jurisdiction("test")
            .action("echo")
            .params({})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("")
            .proposal_hash("proposal")
            # Note: nonce() NOT called
            .build(self.keyring, "key1")
        )

        self.assertEqual(len(permit.nonce), 32)

    def test_builder_computes_permit_id(self) -> None:
        """Builder computes permit_id automatically."""
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("worker1")
            .jurisdiction("test")
            .action("echo")
            .params({})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("")
            .proposal_hash("proposal")
            .nonce("nonce12345678901234567890123456789012456789012345678901234")
            .build(self.keyring, "key1")
        )

        self.assertEqual(len(permit.permit_id), 64)
        # Verify it matches computed ID
        self.assertEqual(permit.permit_id, compute_permit_id(permit))

    def test_builder_signs_permit(self) -> None:
        """Builder signs permit automatically."""
        builder = PermitBuilder()
        permit = (
            builder.issuer("operator1")
            .subject("worker1")
            .jurisdiction("test")
            .action("echo")
            .params({})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(0)
            .valid_until_ms(10000)
            .evidence_hash("")
            .proposal_hash("proposal")
            .nonce("nonce12345678901234567890123456789012456789012345678901234")
            .build(self.keyring, "key1")
        )

        self.assertEqual(len(permit.signature), 64)
        # Verify signature is valid
        result = verify_signature(permit, self.keyring)
        self.assertEqual(result.status, Decision.ALLOW)

    def test_builder_unknown_key_id(self) -> None:
        """Builder raises error for unknown key_id."""
        builder = PermitBuilder()
        with self.assertRaises(ValueError) as cm:
            (
                builder.issuer("operator1")
                .subject("worker1")
                .jurisdiction("test")
                .action("echo")
                .params({})
                .constraints({})
                .max_executions(1)
                .valid_from_ms(0)
                .valid_until_ms(10000)
                .evidence_hash("")
                .proposal_hash("proposal")
                .nonce("nonce12345678901234567890123456789012456789012345678901234")
                .build(self.keyring, "unknown-key")
            )
        self.assertIn("key_id", str(cm.exception))


class TestPermitVerificationPositive(unittest.TestCase):
    """Positive tests for permit verification."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.key = b"test-secret-key-32-bytes-long123"
        self.keyring = {"key1": self.key}
        self.registry = NonceRegistry()

        builder = PermitBuilder()
        self.valid_permit = (
            builder.issuer("operator1")
            .subject("worker1")
            .jurisdiction("test-jurisdiction")
            .action("echo")
            .params({"text": "hello"})
            .constraints({})
            .max_executions(1)
            .valid_from_ms(1000)
            .valid_until_ms(10000)
            .evidence_hash("evidence-hash")
            .proposal_hash("proposal-hash")
            .nonce("test-nonce-123456789012345678901234")
            .build(self.keyring, "key1")
        )

    def test_allow_valid_permit(self) -> None:
        """Allow valid permit that satisfies all checks."""
        result = verify_permit(
            self.valid_permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )

        self.assertEqual(result.status, Decision.ALLOW)
        self.assertEqual(len(result.reasons), 0)

    def test_allow_subset_params(self) -> None:
        """Allow request with subset of permit params."""
        from dataclasses import replace

        permit = replace(
            self.valid_permit, params={"text": "hello", "extra": "allowed"}
        )
        # Re-sign
        from shards_kernel.permits import sign_permit

        permit = replace(permit, signature="")
        permit_id = compute_permit_id(permit)
        permit = replace(permit, permit_id=permit_id)
        permit = sign_permit(permit, self.key, "key1")

        result = verify_permit(
            permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},  # Subset of permit params
        )

        self.assertEqual(result.status, Decision.ALLOW)

    def test_allow_multi_use_permit(self) -> None:
        """Allow multi-use permit for multiple executions."""
        from dataclasses import replace

        multi_permit = replace(self.valid_permit, max_executions=3)
        # Re-sign
        from shards_kernel.permits import sign_permit

        multi_permit = replace(
            multi_permit, signature="", nonce="multi-nonce-123456789012345678901234"
        )
        permit_id = compute_permit_id(multi_permit)
        multi_permit = replace(multi_permit, permit_id=permit_id)
        multi_permit = sign_permit(multi_permit, self.key, "key1")

        # First use
        r1 = verify_permit(
            multi_permit,
            self.keyring,
            self.registry,
            current_time_ms=5000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )
        self.assertEqual(r1.status, Decision.ALLOW)

        # Second use
        r2 = verify_permit(
            multi_permit,
            self.keyring,
            self.registry,
            current_time_ms=6000,
            current_jurisdiction="test-jurisdiction",
            allowed_actions=frozenset(["echo"]),
            request_actor="worker1",
            request_params={"text": "hello"},
        )
        self.assertEqual(r2.status, Decision.ALLOW)


if __name__ == "__main__":
    unittest.main()

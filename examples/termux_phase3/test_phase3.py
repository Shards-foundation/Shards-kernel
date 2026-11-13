"""Offline tests for the shared proposal protocol (no kernel/network required)."""
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from phase3_protocol import (
    canonical, make_proposal, proposal_hash,
    read_json_file, validate_proposal, validate_tool, write_new_file,
)


class ProtocolTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(validate_tool('add', {'a': 17, 'b': 25}), ('add', {'a': 17, 'b': 25}))

    def test_float_denied(self):
        with self.assertRaises(ValueError):
            validate_tool('add', {'a': 1.0, 'b': 2})

    def test_bool_denied(self):
        with self.assertRaises(ValueError):
            validate_tool('add', {'a': True, 'b': 2})

    def test_extra_arg_denied(self):
        with self.assertRaises(ValueError):
            validate_tool('add', {'a': 1, 'b': 2, 'x': 3})

    def test_arbitrary_tool_denied(self):
        with self.assertRaises(ValueError):
            validate_tool('shell', {'command': 'id'})

    def test_note_traversal_denied(self):
        with self.assertRaises(ValueError):
            validate_tool('read_note', {'name': '../operator.key'})

    def test_mismatched_memory_key(self):
        with self.assertRaises(ValueError):
            validate_tool('remember', {'key': '../secret', 'value': 'x'})

    def test_memory_value_bounds(self):
        with self.assertRaises(ValueError):
            validate_tool('remember', {'key': 'foo', 'value': 'x' * 501})

    def test_no_nan(self):
        with self.assertRaises(ValueError):
            validate_tool('add', {'a': float('nan'), 'b': 1})

    def test_proposal_roundtrip(self):
        n = time.time_ns() // 1_000_000
        p = make_proposal('echo', {'text': 'hello'}, now=n)
        self.assertEqual(validate_proposal(p, now=n), p)
        self.assertEqual(len(proposal_hash(p)), 64)

    def test_proposal_canonical_order(self):
        a = {'a': 1, 'b': 2}
        b = {'b': 2, 'a': 1}
        self.assertEqual(canonical(a), canonical(b))

    def test_proposal_identity_denied(self):
        n = time.time_ns() // 1_000_000
        p = make_proposal('echo', {'text': 'hello'}, now=n)
        p['actor'] = 'attacker'
        with self.assertRaises(ValueError):
            validate_proposal(p, now=n)

    def test_proposal_age_denied(self):
        n = time.time_ns() // 1_000_000
        p = make_proposal('echo', {'text': 'hello'}, now=n - 1_000_000)
        with self.assertRaises(ValueError):
            validate_proposal(p, now=n)

    def test_proposal_future_denied(self):
        n = time.time_ns() // 1_000_000
        p = make_proposal('echo', {'text': 'hello'}, now=n + 60_000)
        with self.assertRaises(ValueError):
            validate_proposal(p, now=n)

    def test_proposal_added_fields_denied(self):
        n = time.time_ns() // 1_000_000
        p = make_proposal('echo', {'text': 'hello'}, now=n)
        p['authorization'] = 'allow'
        with self.assertRaises(ValueError):
            validate_proposal(p, now=n)


    def test_execution_validation_uses_signed_permit_lifetime_not_proposal_age(self):
        # Operator issuance still rejects stale proposals. After approval the
        # signed permit's 5-minute expiry is authoritative at execution.
        n = time.time_ns() // 1_000_000
        proposal = make_proposal('echo', {'text': 'hello'}, now=n - 16 * 60_000)
        with self.assertRaises(ValueError):
            validate_proposal(proposal, now=n)
        self.assertEqual(validate_proposal(proposal, now=n, check_age=False), proposal)

    def test_fifo_json_input_is_rejected_without_hanging(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'proposal.json'
            os.mkfifo(p)
            outcome = []

            def read():
                try:
                    read_json_file(p)
                except Exception as exc:
                    outcome.append(exc)

            worker = threading.Thread(target=read, daemon=True)
            worker.start()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive(), 'read_json_file blocked on FIFO')
            self.assertEqual(len(outcome), 1)
            self.assertIsInstance(outcome[0], ValueError)

    def test_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'proposal.json'
            write_new_file(p, canonical({'test': 7}))
            self.assertEqual(read_json_file(p), {'test': 7})
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_symlink_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'proposal.json'
            q = Path(d) / 'alias.json'
            write_new_file(p, b'{}')
            q.symlink_to(p)
            with self.assertRaises(OSError):
                read_json_file(q)

    def test_create_existing_file_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'proposal.json'
            write_new_file(p, b'{}')
            with self.assertRaises(FileExistsError):
                write_new_file(p, b'{}')

    def test_oversized_file_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'proposal.json'
            write_new_file(p, b' ' * 20000)
            with self.assertRaises(ValueError):
                read_json_file(p)


if __name__ == '__main__':
    unittest.main(verbosity=2)

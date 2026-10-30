"""Tests for hashing utilities."""

import unittest

from shards_kernel.common.hashing import (
    compute_hash,
    compute_hash_str,
    compute_hash_dict,
    compute_chain_hash,
    genesis_hash,
)


class TestHashing(unittest.TestCase):
    """Test cases for hashing functions."""

    def test_compute_hash_deterministic(self) -> None:
        """Hash of same input produces same output."""
        data = b"test data"
        hash1 = compute_hash(data)
        hash2 = compute_hash(data)
        self.assertEqual(hash1, hash2)

    def test_compute_hash_different_inputs(self) -> None:
        """Different inputs produce different hashes."""
        hash1 = compute_hash(b"data1")
        hash2 = compute_hash(b"data2")
        self.assertNotEqual(hash1, hash2)

    def test_compute_hash_str(self) -> None:
        """String hashing works correctly."""
        text = "hello world"
        hash_result = compute_hash_str(text)
        self.assertEqual(len(hash_result), 64)  # SHA-256 hex length

    def test_compute_hash_dict_sorted_keys(self) -> None:
        """Dict hashing is order-independent."""
        dict1 = {"b": 2, "a": 1}
        dict2 = {"a": 1, "b": 2}
        hash1 = compute_hash_dict(dict1)
        hash2 = compute_hash_dict(dict2)
        self.assertEqual(hash1, hash2)

    def test_compute_chain_hash(self) -> None:
        """Chain hash combines prev_hash and entry_data."""
        prev = genesis_hash()
        entry = "entry data"
        chain_hash = compute_chain_hash(prev, entry)
        self.assertEqual(len(chain_hash), 64)
        self.assertNotEqual(chain_hash, prev)

    def test_genesis_hash(self) -> None:
        """Genesis hash is 64 zeros."""
        gen = genesis_hash()
        self.assertEqual(gen, "0" * 64)
        self.assertEqual(len(gen), 64)

    def test_unsupported_algorithm(self) -> None:
        """Unsupported algorithm raises ValueError."""
        with self.assertRaises(ValueError):
            compute_hash(b"data", algorithm="md5")


if __name__ == "__main__":
    unittest.main()

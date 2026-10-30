"""Hashing utilities for Kernels.

All hashing is deterministic and uses SHA-256 by default. The hash functions
produce consistent outputs for identical inputs across all platforms.
"""

import hashlib
from typing import Any

from shards_kernel.common.codec import serialize_deterministic


def compute_hash(data: bytes, algorithm: str = "sha256") -> str:
    """Compute hash of raw bytes.

    Args:
        data: Raw bytes to hash.
        algorithm: Hash algorithm to use. Only "sha256" is supported.

    Returns:
        Hexadecimal string representation of the hash.

    Raises:
        ValueError: If unsupported algorithm is specified.
    """
    if algorithm != "sha256":
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    return hashlib.sha256(data).hexdigest()


def compute_hash_str(text: str, algorithm: str = "sha256") -> str:
    """Compute hash of a string.

    Args:
        text: String to hash.
        algorithm: Hash algorithm to use.

    Returns:
        Hexadecimal string representation of the hash.
    """
    return compute_hash(text.encode("utf-8"), algorithm)


def compute_hash_dict(data: dict[str, Any], algorithm: str = "sha256") -> str:
    """Compute hash of a dictionary with deterministic serialization.

    The dictionary is serialized with sorted keys to ensure consistent
    hashing across different Python implementations and versions.

    Args:
        data: Dictionary to hash.
        algorithm: Hash algorithm to use.

    Returns:
        Hexadecimal string representation of the hash.
    """
    serialized = serialize_deterministic(data)
    return compute_hash(serialized.encode("utf-8"), algorithm)


def compute_chain_hash(
    prev_hash: str, entry_data: str, algorithm: str = "sha256"
) -> str:
    """Compute hash for a chain entry.

    Combines the previous hash with entry data to create a chain link.

    Args:
        prev_hash: Hash of the previous entry in the chain.
        entry_data: Serialized data for the current entry.
        algorithm: Hash algorithm to use.

    Returns:
        Hexadecimal string representation of the chained hash.
    """
    combined = f"{prev_hash}:{entry_data}"
    return compute_hash_str(combined, algorithm)


def genesis_hash() -> str:
    """Return the genesis hash for the start of a chain.

    Returns:
        A fixed hash value representing the start of the chain.
    """
    return "0" * 64

"""
Shards-Kernel CLI Tools

Command-line utilities for working with Shards-Kernel evidence and audit trails.
"""

from shards_kernel.cli.verify import verify_evidence, verify_evidence_file

__all__ = [
    "verify_evidence",
    "verify_evidence_file",
]

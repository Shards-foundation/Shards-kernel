"""In-memory idempotency record store."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class IdempotencyRecord:
    """Stored idempotency execution record."""

    key: str
    input_hash: str
    output_hash: str
    tool_name: str
    ts_ms: int


class IdempotencyStore:
    """Record store for execution idempotency tracking."""

    def __init__(self) -> None:
        self._records: dict[str, IdempotencyRecord] = {}

    def put(self, record: IdempotencyRecord) -> None:
        """Store an idempotency record."""
        self._records[record.key] = record

    def get(self, key: str) -> Optional[IdempotencyRecord]:
        """Get record by key."""
        return self._records.get(key)

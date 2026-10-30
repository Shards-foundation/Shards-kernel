"""Thread-safe nonce registry implementation for permit replay protection."""

from __future__ import annotations

from dataclasses import replace
from threading import RLock

from shards_kernel.permits import NonceRecord


class ThreadSafeNonceRegistry:
    """Thread-safe nonce registry with optional TTL cleanup for long-running services."""

    def __init__(self, ttl_ms: int | None = None) -> None:
        self._registry: dict[tuple[str, str, str], NonceRecord] = {}
        self._ttl_ms = ttl_ms
        self._lock = RLock()
        self._cleanup_runs = 0
        self._cleaned_records = 0

    def check_and_record(
        self,
        nonce: str,
        issuer: str,
        subject: str,
        permit_id: str,
        max_executions: int,
        current_time_ms: int,
    ) -> bool:
        """Atomically check replay status and record nonce usage."""
        key = (nonce, issuer, subject)
        with self._lock:
            self._cleanup_locked(current_time_ms)

            record = self._registry.get(key)
            if record is None:
                self._registry[key] = NonceRecord(
                    nonce=nonce,
                    issuer=issuer,
                    subject=subject,
                    first_seen_ms=current_time_ms,
                    use_count=1,
                    permit_id=permit_id,
                )
                return True

            if record.use_count >= max_executions:
                return False

            self._registry[key] = replace(record, use_count=record.use_count + 1)
            return True

    def get_record(self, nonce: str, issuer: str, subject: str) -> NonceRecord | None:
        """Retrieve a nonce record if present."""
        with self._lock:
            return self._registry.get((nonce, issuer, subject))

    def has_nonce(self, nonce: str, issuer: str, subject: str) -> bool:
        """Check whether a nonce has been seen before."""
        with self._lock:
            return (nonce, issuer, subject) in self._registry

    def size(self) -> int:
        """Return number of tracked nonce records."""
        with self._lock:
            return len(self._registry)

    def cleanup(self, current_time_ms: int) -> int:
        """Cleanup expired records and return number removed."""
        with self._lock:
            return self._cleanup_locked(current_time_ms)

    def stats(self) -> dict[str, int | None]:
        """Return simple observability metrics for registry operations."""
        with self._lock:
            return {
                "size": len(self._registry),
                "ttl_ms": self._ttl_ms,
                "cleanup_runs": self._cleanup_runs,
                "cleaned_records": self._cleaned_records,
            }

    def _cleanup_locked(self, current_time_ms: int) -> int:
        if self._ttl_ms is None:
            return 0

        self._cleanup_runs += 1
        stale_keys = [
            key
            for key, record in self._registry.items()
            if current_time_ms - record.first_seen_ms > self._ttl_ms
        ]
        for key in stale_keys:
            del self._registry[key]

        removed_count = len(stale_keys)
        self._cleaned_records += removed_count
        return removed_count

"""Time utilities for Kernels.

Provides deterministic time handling through VirtualClock and utilities
for timestamp validation.
"""

import threading
import time
from typing import Callable, Optional

from shards_kernel.common.types import VirtualClock


class ClockRollbackError(RuntimeError):
    """A real-time clock became unsafe for permit expiry verification."""


class SystemClock:
    """UTC wall clock with fail-closed process-local rollback detection.

    Unlike a deterministic VirtualClock, this clock advances with real time.
    If time moves backwards (or produces a malformed sample) this clock
    permanently refuses further reads for the life of the process. This
    cannot detect rollback across separate process restarts; production
    deployments require trusted time and persistent safeguards as well.
    """

    def __init__(self, source_ns: Optional[Callable[[], int]] = None) -> None:
        self._source_ns = source_ns if source_ns is not None else time.time_ns
        self._lock = threading.Lock()
        self._last_ms: Optional[int] = None
        self._failed = False

    def now_ms(self) -> int:
        with self._lock:
            if self._failed:
                raise ClockRollbackError("System clock was previously declared unsafe")
            try:
                sample = self._source_ns()
                if not isinstance(sample, int) or isinstance(sample, bool) or sample < 0:
                    raise ValueError("System clock returned an invalid timestamp")
                now = sample // 1_000_000
            except Exception as exc:
                self._failed = True
                raise ClockRollbackError("System clock is unavailable or invalid") from exc
            if self._last_ms is not None and now < self._last_ms:
                self._failed = True
                raise ClockRollbackError("System clock moved backwards; permit checks halted")
            self._last_ms = now
            return now



def create_clock(initial_ms: int = 0) -> VirtualClock:
    """Create a new virtual clock.

    Args:
        initial_ms: Starting time in milliseconds. Defaults to 0.

    Returns:
        A new VirtualClock instance.
    """
    return VirtualClock(initial_ms)


def validate_timestamp(ts_ms: int, clock: VirtualClock) -> bool:
    """Validate that a timestamp is not in the future.

    Args:
        ts_ms: Timestamp to validate in milliseconds.
        clock: Clock to compare against.

    Returns:
        True if timestamp is valid (not in the future), False otherwise.
    """
    return ts_ms <= clock.now_ms()


def timestamp_to_iso(ts_ms: int) -> str:
    """Convert millisecond timestamp to ISO 8601 string.

    Args:
        ts_ms: Timestamp in milliseconds since epoch.

    Returns:
        ISO 8601 formatted string.
    """
    import datetime

    dt = datetime.datetime.fromtimestamp(ts_ms / 1000, tz=datetime.timezone.utc)
    return dt.isoformat()


def iso_to_timestamp(iso_str: str) -> int:
    """Convert ISO 8601 string to millisecond timestamp.

    Args:
        iso_str: ISO 8601 formatted string.

    Returns:
        Timestamp in milliseconds since epoch.
    """
    import datetime

    dt = datetime.datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def monotonic_ms() -> int:
    """Get monotonic time in milliseconds.

    Returns:
        Current monotonic time in milliseconds.
    """
    import time

    return int(time.monotonic() * 1000)


def now_ms() -> int:
    """Get current wall clock time in milliseconds.

    Returns:
        Current time in milliseconds since epoch.
    """
    import time

    return int(time.time() * 1000)

"""Time utilities for Kernels.

Provides deterministic time handling through VirtualClock and utilities
for timestamp validation.
"""

from shards_kernel.common.types import VirtualClock


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

"""Tests for shards_kernel.common.time utilities."""

import datetime
import time

import pytest

from shards_kernel.common.time import (
    create_clock,
    iso_to_timestamp,
    monotonic_ms,
    now_ms,
    timestamp_to_iso,
    validate_timestamp,
)


def test_create_clock_uses_initial_value() -> None:
    clock = create_clock(1234)
    assert clock.now_ms() == 1234


def test_validate_timestamp_rejects_future_values() -> None:
    clock = create_clock(1000)
    assert validate_timestamp(1000, clock) is True
    assert validate_timestamp(999, clock) is True
    assert validate_timestamp(1001, clock) is False


def test_timestamp_to_iso_uses_utc_offset() -> None:
    iso = timestamp_to_iso(0)
    assert iso == "1970-01-01T00:00:00+00:00"


def test_iso_to_timestamp_supports_z_suffix() -> None:
    assert iso_to_timestamp("1970-01-01T00:00:00Z") == 0


@pytest.mark.parametrize(
    ("iso", "expected"),
    [
        ("1970-01-01T00:00:01.001000Z", 1001),
        ("1970-01-01T00:00:01.003000+00:00", 1003),
        ("1970-01-01T01:00:01.001000+01:00", 1001),
        ("1969-12-31T23:59:58.999000+00:00", -1001),
    ],
)
def test_iso_to_timestamp_preserves_exact_milliseconds(iso: str, expected: int) -> None:
    assert iso_to_timestamp(iso) == expected


@pytest.mark.parametrize(
    ("iso", "expected"),
    [
        ("1970-01-01T00:00:00.000999Z", 0),
        ("1970-01-01T00:00:00.001999Z", 1),
        ("1969-12-31T23:59:59.999001Z", 0),
        ("1969-12-31T23:59:59.998001Z", -1),
    ],
)
def test_iso_to_timestamp_truncates_sub_milliseconds_toward_zero(
    iso: str, expected: int,
) -> None:
    assert iso_to_timestamp(iso) == expected


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="requires local timezone control")
@pytest.mark.parametrize(("timezone", "expected"), [("UTC0", 1001), ("EST5", 18001001)])
def test_iso_to_timestamp_preserves_naive_local_timezone(
    monkeypatch: pytest.MonkeyPatch, timezone: str, expected: int,
) -> None:
    try:
        with monkeypatch.context() as context:
            context.setenv("TZ", timezone)
            time.tzset()
            assert iso_to_timestamp("1970-01-01T00:00:01.001000") == expected
    finally:
        time.tzset()


def test_iso_to_timestamp_rejects_invalid_input() -> None:
    with pytest.raises(ValueError):
        iso_to_timestamp("not-a-timestamp")


def test_timestamp_round_trip_preserves_milliseconds() -> None:
    dt = datetime.datetime(2026, 4, 23, 12, 34, 56, 789000, tzinfo=datetime.timezone.utc)
    timestamp_ms = int(dt.timestamp() * 1000)

    assert iso_to_timestamp(timestamp_to_iso(timestamp_ms)) == timestamp_ms


def test_monotonic_ms_reads_time_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.monotonic", lambda: 12.345)
    assert monotonic_ms() == 12345


def test_now_ms_reads_time_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.time", lambda: 9.876)
    assert now_ms() == 9876

"""Tests for shards_kernel.common.time utilities."""

import datetime

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

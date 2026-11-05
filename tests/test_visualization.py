"""Tests for optional chart data and PNG visualization helpers."""

from datetime import datetime, timedelta

import pytest

from src.incidents import analyze_events
from src.models import EventType, LogEvent
from src.visualization import build_event_frame, write_analysis_charts


def make_event(
    offset_seconds: int,
    event_type: EventType,
    ip_address: str = "45.122.10.8",
    username: str = "admin",
) -> LogEvent:
    """Create a test authentication event."""

    timestamp = datetime(2026, 3, 18, 12, 0, 0) + timedelta(
        seconds=offset_seconds,
    )
    return LogEvent(
        timestamp=timestamp,
        ip_address=ip_address,
        username=username,
        event_type=event_type,
        raw_line="test log line",
    )


def test_build_event_frame_contains_expected_columns() -> None:
    pytest.importorskip("pandas")

    events = (
        make_event(0, EventType.FAILED_LOGIN),
        make_event(10, EventType.SUCCESSFUL_LOGIN),
    )

    frame = build_event_frame(events)

    assert list(frame.columns) == [
        "timestamp",
        "ip_address",
        "username",
        "event_type",
        "line_number",
    ]
    assert frame["event_type"].tolist() == [
        "failed_login",
        "successful_login",
    ]


def test_write_analysis_charts_creates_png_files(tmp_path) -> None:
    pytest.importorskip("matplotlib")

    events = (
        make_event(0, EventType.FAILED_LOGIN),
        make_event(15, EventType.FAILED_LOGIN),
        make_event(30, EventType.FAILED_LOGIN),
        make_event(45, EventType.SUCCESSFUL_LOGIN),
    )
    result = analyze_events(events, threshold=3, window_seconds=120)

    paths = write_analysis_charts(result, tmp_path, top_limit=5)

    assert {path.name for path in paths} == {
        "event_timeline.png",
        "top_ip_addresses.png",
        "severity_distribution.png",
    }
    assert all(path.exists() for path in paths)

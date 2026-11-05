"""Tests for incident building and analysis orchestration."""

from datetime import datetime, timedelta

from src.incidents import analyze_events
from src.models import EventType, IncidentType, LogEvent


def make_event(
    offset_seconds: int,
    event_type: EventType,
) -> LogEvent:
    timestamp = datetime(2026, 3, 18, 12, 0, 0) + timedelta(
        seconds=offset_seconds,
    )
    action = "Failed" if event_type == EventType.FAILED_LOGIN else "Accepted"
    return LogEvent(
        timestamp=timestamp,
        ip_address="45.122.10.8",
        username="admin",
        event_type=event_type,
        raw_line=(
            f"{timestamp:%Y-%m-%d %H:%M:%S} "
            f"{action} password for admin from 45.122.10.8"
        ),
    )


def test_analyze_events_groups_matches_into_incidents() -> None:
    events = [
        make_event(0, EventType.FAILED_LOGIN),
        make_event(20, EventType.FAILED_LOGIN),
        make_event(40, EventType.FAILED_LOGIN),
        make_event(60, EventType.SUCCESSFUL_LOGIN),
    ]

    result = analyze_events(events, threshold=3, window_seconds=120)

    assert result.statistics.total_events == 4
    assert result.statistics.incidents_count >= 1
    assert result.incidents[0].incident_id == "INC-0001"
    assert result.incidents[0].risk_score > 0
    assert any(
        incident.incident_type == IncidentType.SUCCESS_AFTER_FAILURES
        for incident in result.incidents
    )

"""Tests for dashboard report rendering."""

from datetime import datetime, timedelta

from src.incidents import analyze_events
from src.models import EventType, LogEvent
from src.report import render_report


def make_event(
    offset_seconds: int,
    event_type: EventType,
    ip_address: str = "45.122.10.8",
    username: str = "admin",
) -> LogEvent:
    timestamp = datetime(2026, 3, 18, 12, 0, 0) + timedelta(
        seconds=offset_seconds,
    )
    action = "Failed" if event_type == EventType.FAILED_LOGIN else "Accepted"
    return LogEvent(
        timestamp=timestamp,
        ip_address=ip_address,
        username=username,
        event_type=event_type,
        raw_line=(
            f"{timestamp:%Y-%m-%d %H:%M:%S} "
            f"{action} password for {username} from {ip_address}"
        ),
    )


def test_render_html_dashboard_contains_visual_sections() -> None:
    events = [
        make_event(0, EventType.FAILED_LOGIN),
        make_event(10, EventType.FAILED_LOGIN),
        make_event(20, EventType.FAILED_LOGIN),
        make_event(30, EventType.SUCCESSFUL_LOGIN),
    ]
    result = analyze_events(events, threshold=3, window_seconds=120)

    html = render_report(result, "html")

    assert "<!doctype html>" in html
    assert "Authentication Threat Dashboard" in html
    assert "Event Timeline" in html
    assert "Security Incidents" in html
    assert "Search incidents" in html

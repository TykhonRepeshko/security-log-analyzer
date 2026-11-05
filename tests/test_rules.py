"""Tests for detection rules."""

from datetime import datetime, timedelta

from src.models import EventType, IncidentType, LogEvent
from src.rules import (
    detect_account_takeover_signal,
    detect_brute_force_by_ip,
    detect_low_and_slow_brute_force,
    detect_success_after_failures,
)


BASE_TIME = datetime(2026, 3, 18, 12, 0, 0)


def make_event(
    offset_seconds: int,
    event_type: EventType,
    ip_address: str = "45.122.10.8",
    username: str = "admin",
) -> LogEvent:
    timestamp = BASE_TIME + timedelta(seconds=offset_seconds)
    action = "Failed" if event_type == EventType.FAILED_LOGIN else "Accepted"
    raw_line = (
        f"{timestamp:%Y-%m-%d %H:%M:%S} "
        f"{action} password for {username} from {ip_address}"
    )
    return LogEvent(
        timestamp=timestamp,
        ip_address=ip_address,
        username=username,
        event_type=event_type,
        raw_line=raw_line,
    )


def test_detect_brute_force_by_time_window() -> None:
    events = [
        make_event(index * 10, EventType.FAILED_LOGIN)
        for index in range(5)
    ]

    matches = detect_brute_force_by_ip(
        events,
        threshold=5,
        window_seconds=120,
    )

    assert len(matches) == 1
    assert matches[0].incident_type == IncidentType.BRUTE_FORCE_IP
    assert matches[0].metadata["failed_count"] == 5


def test_do_not_detect_brute_force_outside_window() -> None:
    events = [
        make_event(index * 60, EventType.FAILED_LOGIN)
        for index in range(5)
    ]

    matches = detect_brute_force_by_ip(
        events,
        threshold=5,
        window_seconds=120,
    )

    assert not matches


def test_detect_successful_login_after_failed_logins() -> None:
    events = [
        make_event(0, EventType.FAILED_LOGIN),
        make_event(20, EventType.FAILED_LOGIN),
        make_event(40, EventType.FAILED_LOGIN),
        make_event(60, EventType.SUCCESSFUL_LOGIN),
    ]

    matches = detect_success_after_failures(
        events,
        threshold=3,
        window_seconds=120,
    )

    assert len(matches) == 1
    assert matches[0].incident_type == IncidentType.SUCCESS_AFTER_FAILURES
    assert matches[0].metadata["username"] == "admin"


def test_detect_account_takeover_signal_after_distributed_failures() -> None:
    events = [
        make_event(
            0,
            EventType.FAILED_LOGIN,
            ip_address="45.122.10.8",
            username="deploy",
        ),
        make_event(
            40,
            EventType.FAILED_LOGIN,
            ip_address="203.0.113.77",
            username="deploy",
        ),
        make_event(
            80,
            EventType.SUCCESSFUL_LOGIN,
            ip_address="203.0.113.77",
            username="deploy",
        ),
    ]

    matches = detect_account_takeover_signal(
        events,
        threshold=5,
        window_seconds=120,
    )

    assert len(matches) == 1
    assert matches[0].incident_type == IncidentType.ACCOUNT_TAKEOVER_SIGNAL
    assert matches[0].metadata["unique_failure_ips"] == 2


def test_detect_low_and_slow_brute_force() -> None:
    events = [
        make_event(
            index * 600,
            EventType.FAILED_LOGIN,
            ip_address="88.88.88.88",
            username="service",
        )
        for index in range(6)
    ]

    matches = detect_low_and_slow_brute_force(
        events,
        threshold=5,
        window_seconds=120,
    )

    assert len(matches) == 1
    assert matches[0].incident_type == IncidentType.LOW_AND_SLOW_BRUTE_FORCE
    assert matches[0].metadata["average_gap_seconds"] == 600.0

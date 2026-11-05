"""Tests for risk scoring."""

from datetime import datetime, timedelta

from src.models import EventType, IncidentType, LogEvent, RuleMatch, Severity
from src.risk import calculate_risk_score, severity_from_score


def make_failed_event(index: int) -> LogEvent:
    timestamp = datetime(2026, 3, 18, 12, 0, 0) + timedelta(
        seconds=index * 10,
    )
    return LogEvent(
        timestamp=timestamp,
        ip_address="45.122.10.8",
        username="admin",
        event_type=EventType.FAILED_LOGIN,
        raw_line=(
            f"{timestamp:%Y-%m-%d %H:%M:%S} "
            "Failed password for admin from 45.122.10.8"
        ),
    )


def test_calculate_risk_score_for_brute_force() -> None:
    events = tuple(make_failed_event(index) for index in range(5))
    match = RuleMatch(
        incident_type=IncidentType.BRUTE_FORCE_IP,
        events=events,
        reason="test",
        metadata={},
    )

    score = calculate_risk_score(match)

    assert 60 <= score <= 100


def test_sensitive_account_adds_risk_factor() -> None:
    events = tuple(make_failed_event(index) for index in range(2))
    match = RuleMatch(
        incident_type=IncidentType.ACCOUNT_TAKEOVER_SIGNAL,
        events=events,
        reason="test",
        metadata={},
    )

    score = calculate_risk_score(match)

    assert score >= 70


def test_severity_from_score() -> None:
    assert severity_from_score(15) == Severity.LOW
    assert severity_from_score(45) == Severity.MEDIUM
    assert severity_from_score(70) == Severity.HIGH
    assert severity_from_score(90) == Severity.CRITICAL

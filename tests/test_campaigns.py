"""Tests for attack campaign correlation."""

from datetime import datetime, timedelta

from src.campaigns import build_campaigns
from src.models import EventType, IncidentType, LogEvent, SecurityIncident
from src.models import Severity


BASE_TIME = datetime(2026, 3, 18, 12, 0, 0)


def make_incident(
    incident_id: str,
    incident_type: IncidentType,
    offset_seconds: int,
    ip_address: str,
    username: str,
    risk_score: int,
) -> SecurityIncident:
    timestamp = BASE_TIME + timedelta(seconds=offset_seconds)
    event = LogEvent(
        timestamp=timestamp,
        ip_address=ip_address,
        username=username,
        event_type=EventType.FAILED_LOGIN,
        raw_line=(
            f"{timestamp:%Y-%m-%d %H:%M:%S} "
            f"Failed password for {username} from {ip_address}"
        ),
    )
    return SecurityIncident(
        incident_id=incident_id,
        incident_type=incident_type,
        title="Test incident",
        description="Synthetic incident for campaign tests.",
        events=(event,),
        risk_score=risk_score,
        severity=Severity.HIGH,
        metadata={"ip_address": ip_address, "username": username},
    )


def test_build_campaigns_correlates_related_incidents() -> None:
    first = make_incident(
        "INC-0001",
        IncidentType.BRUTE_FORCE_IP,
        0,
        "45.122.10.8",
        "admin",
        72,
    )
    second = make_incident(
        "INC-0002",
        IncidentType.SUCCESS_AFTER_FAILURES,
        120,
        "45.122.10.8",
        "admin",
        88,
    )
    unrelated = make_incident(
        "INC-0003",
        IncidentType.USER_ENUMERATION,
        5000,
        "198.51.100.77",
        "guest",
        62,
    )

    campaigns = build_campaigns([first, second, unrelated], gap_seconds=600)

    assert len(campaigns) == 1
    assert campaigns[0].incident_ids == ("INC-0001", "INC-0002")
    assert campaigns[0].source_ips == ("45.122.10.8",)
    assert campaigns[0].usernames == ("admin",)
    assert campaigns[0].risk_score > second.risk_score

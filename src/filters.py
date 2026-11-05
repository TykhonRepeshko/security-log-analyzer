"""Reusable filters for event collections."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from src.models import EventType, LogEvent, SecurityIncident, Severity


def filter_events(
    events: Iterable[LogEvent],
    start: datetime | None = None,
    end: datetime | None = None,
    usernames: set[str] | None = None,
    ip_addresses: set[str] | None = None,
    event_types: set[EventType] | None = None,
) -> tuple[LogEvent, ...]:
    """Filter events by time, user, IP, and event type."""

    filtered_events = []

    for event in events:
        if start is not None and event.timestamp < start:
            continue
        if end is not None and event.timestamp > end:
            continue
        if usernames is not None and event.username not in usernames:
            continue
        if ip_addresses is not None and event.ip_address not in ip_addresses:
            continue
        if event_types is not None and event.event_type not in event_types:
            continue
        filtered_events.append(event)

    return tuple(filtered_events)


def filter_incidents_by_severity(
    incidents: Iterable[SecurityIncident],
    minimum_severity: Severity | None = None,
) -> tuple[SecurityIncident, ...]:
    """Return incidents with severity greater than or equal to a level."""

    if minimum_severity is None:
        return tuple(incidents)

    minimum_rank = _severity_rank(minimum_severity)
    return tuple(
        incident
        for incident in incidents
        if _severity_rank(incident.severity) >= minimum_rank
    )


def parse_datetime(value: str | None) -> datetime | None:
    """Parse a CLI datetime value in a forgiving ISO-like format."""

    if value is None:
        return None

    normalized_value = value.replace("T", " ")
    accepted_formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    )
    for date_format in accepted_formats:
        try:
            return datetime.strptime(normalized_value, date_format)
        except ValueError:
            continue
    raise ValueError(
        "datetime must use YYYY-MM-DD, YYYY-MM-DD HH:MM, "
        "or YYYY-MM-DD HH:MM:SS"
    )


def parse_csv_set(value: str | None) -> set[str] | None:
    """Parse comma-separated CLI values into a set."""

    if not value:
        return None
    return {
        item.strip()
        for item in value.split(",")
        if item.strip()
    }


def _severity_rank(severity: Severity) -> int:
    ranks = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return ranks[severity]

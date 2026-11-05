"""Aggregation helpers for dashboards and reports."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta

from src.models import CounterItem, EventType, LogEvent, SecurityIncident
from src.models import Severity, TimeBucket


def build_timeline(
    events: Iterable[LogEvent],
    incidents: Iterable[SecurityIncident],
    bucket_seconds: int,
) -> tuple[TimeBucket, ...]:
    """Group events into fixed-size time buckets."""

    event_list = sorted(events, key=lambda event: event.timestamp)
    if not event_list:
        return ()

    first_seen = event_list[0].timestamp
    bucket_map: dict[datetime, list[LogEvent]] = defaultdict(list)
    for event in event_list:
        bucket_start = _bucket_start(
            first_seen,
            event.timestamp,
            bucket_seconds,
        )
        bucket_map[bucket_start].append(event)

    incidents_by_bucket = _incidents_by_bucket(
        incidents,
        first_seen,
        bucket_seconds,
    )
    buckets = []
    for start, bucket_events in sorted(bucket_map.items()):
        failed_logins = sum(1 for event in bucket_events if event.is_failed)
        successful_logins = len(bucket_events) - failed_logins
        bucket_incidents = incidents_by_bucket.get(start, [])
        max_risk_score = 0
        if bucket_incidents:
            max_risk_score = max(
                incident.risk_score for incident in bucket_incidents
            )
        buckets.append(
            TimeBucket(
                start=start,
                end=start + timedelta(seconds=bucket_seconds),
                total_events=len(bucket_events),
                failed_logins=failed_logins,
                successful_logins=successful_logins,
                incident_count=len(bucket_incidents),
                max_risk_score=max_risk_score,
            )
        )

    return tuple(buckets)


def top_ip_activity(
    events: Iterable[LogEvent],
    limit: int = 10,
) -> tuple[CounterItem, ...]:
    """Return top IP addresses by event count."""

    groups: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        groups[event.ip_address].append(event)

    return _top_items(groups, limit=limit, label_mode="ip")


def top_user_activity(
    events: Iterable[LogEvent],
    limit: int = 10,
) -> tuple[CounterItem, ...]:
    """Return top usernames by event count."""

    groups: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        groups[event.username].append(event)

    return _top_items(groups, limit=limit, label_mode="user")


def severity_counts(
    incidents: Iterable[SecurityIncident],
) -> dict[str, int]:
    """Count incidents by severity."""

    counter = Counter(incident.severity.value for incident in incidents)
    return {
        severity.value: counter.get(severity.value, 0)
        for severity in Severity
    }


def event_type_counts(events: Iterable[LogEvent]) -> dict[str, int]:
    """Count parsed events by event type."""

    counter = Counter(event.event_type.value for event in events)
    return {
        EventType.FAILED_LOGIN.value: counter.get(
            EventType.FAILED_LOGIN.value,
            0,
        ),
        EventType.SUCCESSFUL_LOGIN.value: counter.get(
            EventType.SUCCESSFUL_LOGIN.value,
            0,
        ),
    }


def _top_items(
    groups: dict[str, list[LogEvent]],
    limit: int,
    label_mode: str,
) -> tuple[CounterItem, ...]:
    items = []

    for label, grouped_events in groups.items():
        failed_logins = sum(1 for event in grouped_events if event.is_failed)
        successful_logins = len(grouped_events) - failed_logins
        unique_ips = len({event.ip_address for event in grouped_events})
        unique_users = len({event.username for event in grouped_events})

        if label_mode == "ip":
            unique_ips = 1
        if label_mode == "user":
            unique_users = 1

        items.append(
            CounterItem(
                label=label,
                total_events=len(grouped_events),
                failed_logins=failed_logins,
                successful_logins=successful_logins,
                unique_ips=unique_ips,
                unique_users=unique_users,
            )
        )

    return tuple(
        sorted(
            items,
            key=lambda item: (-item.total_events, -item.failed_logins),
        )[:limit]
    )


def _bucket_start(
    first_seen: datetime,
    timestamp: datetime,
    bucket_seconds: int,
) -> datetime:
    offset_seconds = int((timestamp - first_seen).total_seconds())
    bucket_index = offset_seconds // bucket_seconds
    return first_seen + timedelta(seconds=bucket_index * bucket_seconds)


def _incidents_by_bucket(
    incidents: Iterable[SecurityIncident],
    first_seen: datetime,
    bucket_seconds: int,
) -> dict[datetime, list[SecurityIncident]]:
    result: dict[datetime, list[SecurityIncident]] = defaultdict(list)

    for incident in incidents:
        bucket_start = _bucket_start(
            first_seen,
            incident.first_seen,
            bucket_seconds,
        )
        result[bucket_start].append(incident)

    return result

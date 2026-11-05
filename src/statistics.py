"""Summary statistics for parsed events and detected incidents."""

from __future__ import annotations

from collections.abc import Iterable

from src.models import AnalysisStatistics, EventType, LogEvent
from src.models import ParseIssue, SecurityIncident
from src.timeline import severity_counts


def calculate_statistics(
    events: Iterable[LogEvent],
    incidents: Iterable[SecurityIncident],
    parse_issues: Iterable[ParseIssue] = (),
) -> AnalysisStatistics:
    """Calculate high-level numbers for the analysis report."""

    event_list = list(events)
    incident_list = list(incidents)
    issue_list = list(parse_issues)
    failed_logins = _count_events(event_list, EventType.FAILED_LOGIN)
    successful_logins = _count_events(
        event_list,
        EventType.SUCCESSFUL_LOGIN,
    )
    suspicious_ips = sorted(
        {
            event.ip_address
            for incident in incident_list
            for event in incident.events
        }
    )

    return AnalysisStatistics(
        total_events=len(event_list),
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        suspicious_ips=tuple(suspicious_ips),
        incidents_count=len(incident_list),
        unique_ips=len({event.ip_address for event in event_list}),
        unique_users=len({event.username for event in event_list}),
        skipped_lines=len(issue_list),
        first_seen=_first_seen(event_list),
        last_seen=_last_seen(event_list),
        severity_counts=severity_counts(incident_list),
    )


def _count_events(events: list[LogEvent], event_type: EventType) -> int:
    return sum(1 for event in events if event.event_type == event_type)


def _first_seen(events: list[LogEvent]):
    if not events:
        return None
    return min(event.timestamp for event in events)


def _last_seen(events: list[LogEvent]):
    if not events:
        return None
    return max(event.timestamp for event in events)

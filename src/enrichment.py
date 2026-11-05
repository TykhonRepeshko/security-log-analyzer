"""Local enrichment helpers for IP addresses and incident context."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable

from src.models import IpProfile, IpScope, LogEvent, SecurityIncident


def build_ip_profiles(
    events: Iterable[LogEvent],
    incidents: Iterable[SecurityIncident],
) -> tuple[IpProfile, ...]:
    """Build local IP profiles from events and incident references."""

    event_list = list(events)
    incidents_by_ip = _incident_ids_by_ip(incidents)
    events_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for event in event_list:
        events_by_ip[event.ip_address].append(event)

    profiles = []
    for ip_address, ip_events in events_by_ip.items():
        profile = _profile_ip(
            ip_address,
            ip_events,
            incidents_by_ip.get(ip_address, ()),
        )
        profiles.append(profile)

    return tuple(
        sorted(
            profiles,
            key=lambda item: (
                -len(item.incident_ids),
                -item.failed_logins,
                item.ip_address,
            ),
        )
    )


def classify_ip_scope(ip_address: str) -> IpScope:
    """Classify an IP address without external threat-intel services."""

    parsed_ip = ipaddress.ip_address(ip_address)
    scope = IpScope.PUBLIC

    if parsed_ip.is_loopback:
        scope = IpScope.LOOPBACK
    elif parsed_ip.is_link_local:
        scope = IpScope.LINK_LOCAL
    elif parsed_ip.is_multicast:
        scope = IpScope.MULTICAST
    elif parsed_ip.is_unspecified:
        scope = IpScope.UNSPECIFIED
    elif parsed_ip.is_private:
        scope = IpScope.PRIVATE
    elif parsed_ip.is_reserved:
        scope = IpScope.RESERVED

    return scope


def describe_ip_profile(profile: IpProfile) -> str:
    """Return a short readable description for reports."""

    tags = ", ".join(profile.risk_tags) if profile.risk_tags else "no tags"
    return (
        f"{profile.ip_address} ({profile.scope.value}) "
        f"events={profile.total_events}, failed={profile.failed_logins}, "
        f"users={len(profile.usernames)}, tags={tags}"
    )


def _profile_ip(
    ip_address: str,
    events: list[LogEvent],
    incident_ids: tuple[str, ...],
) -> IpProfile:
    failed_logins = sum(1 for event in events if event.is_failed)
    successful_logins = sum(1 for event in events if event.is_successful)
    usernames = tuple(sorted({event.username for event in events}))
    first_seen = min(event.timestamp for event in events)
    last_seen = max(event.timestamp for event in events)
    parsed_ip = ipaddress.ip_address(ip_address)
    scope = classify_ip_scope(ip_address)

    return IpProfile(
        ip_address=ip_address,
        version=parsed_ip.version,
        scope=scope,
        total_events=len(events),
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        usernames=usernames,
        first_seen=first_seen,
        last_seen=last_seen,
        incident_ids=incident_ids,
        risk_tags=_risk_tags(
            scope=scope,
            failed_logins=failed_logins,
            successful_logins=successful_logins,
            unique_users=len(usernames),
            incident_count=len(incident_ids),
        ),
    )


def _risk_tags(
    scope: IpScope,
    failed_logins: int,
    successful_logins: int,
    unique_users: int,
    incident_count: int,
) -> tuple[str, ...]:
    tags = []

    if incident_count:
        tags.append("linked_to_incident")
    if scope == IpScope.PUBLIC and failed_logins >= 5:
        tags.append("public_bruteforce_source")
    if unique_users >= 5:
        tags.append("many_usernames")
    if failed_logins >= 10:
        tags.append("high_failure_volume")
    if failed_logins and successful_logins:
        tags.append("mixed_failed_and_success")

    return tuple(tags)


def _incident_ids_by_ip(
    incidents: Iterable[SecurityIncident],
) -> dict[str, tuple[str, ...]]:
    ids_by_ip: dict[str, set[str]] = defaultdict(set)

    for incident in incidents:
        for event in incident.events:
            ids_by_ip[event.ip_address].add(incident.incident_id)

    return {
        ip_address: tuple(sorted(incident_ids))
        for ip_address, incident_ids in ids_by_ip.items()
    }

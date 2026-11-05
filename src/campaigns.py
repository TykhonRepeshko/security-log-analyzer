"""Incident correlation into higher level attack campaigns."""

from __future__ import annotations

from collections.abc import Iterable

from src.models import AttackCampaign, SecurityIncident
from src.risk import severity_from_score


DEFAULT_CAMPAIGN_GAP_SECONDS = 600


def build_campaigns(
    incidents: Iterable[SecurityIncident],
    gap_seconds: int = DEFAULT_CAMPAIGN_GAP_SECONDS,
) -> tuple[AttackCampaign, ...]:
    """Group related incidents into broader attack campaigns."""

    ordered_incidents = sorted(
        incidents,
        key=lambda incident: (incident.first_seen, incident.incident_id),
    )
    if len(ordered_incidents) < 2:
        return ()

    graph = _build_relation_graph(ordered_incidents, gap_seconds)
    campaigns = []
    for index, component in enumerate(
        _connected_components(ordered_incidents, graph),
        start=1,
    ):
        if len(component) < 2:
            continue
        campaigns.append(_make_campaign(index, component))

    return tuple(campaigns)


def _build_relation_graph(
    incidents: list[SecurityIncident],
    gap_seconds: int,
) -> dict[int, set[int]]:
    graph = {index: set() for index in range(len(incidents))}

    for left_index, left_incident in enumerate(incidents):
        for right_index in range(left_index + 1, len(incidents)):
            right_incident = incidents[right_index]
            if not _incidents_are_related(
                left_incident,
                right_incident,
                gap_seconds,
            ):
                continue
            graph[left_index].add(right_index)
            graph[right_index].add(left_index)

    return graph


def _connected_components(
    incidents: list[SecurityIncident],
    graph: dict[int, set[int]],
) -> list[list[SecurityIncident]]:
    visited: set[int] = set()
    components: list[list[SecurityIncident]] = []

    for start_index in range(len(incidents)):
        if start_index in visited:
            continue
        stack = [start_index]
        component_indices = []
        visited.add(start_index)

        while stack:
            current_index = stack.pop()
            component_indices.append(current_index)
            for next_index in graph[current_index]:
                if next_index in visited:
                    continue
                visited.add(next_index)
                stack.append(next_index)

        components.append([incidents[index] for index in component_indices])

    return components


def _incidents_are_related(
    first: SecurityIncident,
    second: SecurityIncident,
    gap_seconds: int,
) -> bool:
    if _time_gap_seconds(first, second) > gap_seconds:
        return False

    first_ips, first_users = _incident_entities(first)
    second_ips, second_users = _incident_entities(second)
    return bool(
        first_ips.intersection(second_ips)
        or first_users.intersection(second_users)
    )


def _make_campaign(
    index: int,
    incidents: list[SecurityIncident],
) -> AttackCampaign:
    ordered = sorted(
        incidents,
        key=lambda incident: (incident.first_seen, incident.incident_id),
    )
    source_ips, usernames = _component_entities(ordered)
    first_seen = min(incident.first_seen for incident in ordered)
    last_seen = max(incident.last_seen for incident in ordered)
    risk_score = _campaign_risk_score(ordered, source_ips, usernames)
    incident_ids = tuple(incident.incident_id for incident in ordered)
    title = _campaign_title(source_ips, usernames)
    summary = (
        f"{len(ordered)} related incident(s), "
        f"{len(source_ips)} source IP(s), "
        f"{len(usernames)} target user(s)."
    )
    return AttackCampaign(
        campaign_id=f"CMP-{index:04d}",
        title=title,
        incident_ids=incident_ids,
        source_ips=source_ips,
        usernames=usernames,
        first_seen=first_seen,
        last_seen=last_seen,
        risk_score=risk_score,
        severity=severity_from_score(risk_score),
        summary=summary,
    )


def _component_entities(
    incidents: list[SecurityIncident],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    source_ips: set[str] = set()
    usernames: set[str] = set()

    for incident in incidents:
        incident_ips, incident_users = _incident_entities(incident)
        source_ips.update(incident_ips)
        usernames.update(incident_users)

    return tuple(sorted(source_ips)), tuple(sorted(usernames))


def _incident_entities(
    incident: SecurityIncident,
) -> tuple[set[str], set[str]]:
    source_ips = {event.ip_address for event in incident.events}
    usernames = {event.username for event in incident.events}
    metadata = incident.metadata

    _add_string(source_ips, metadata.get("ip_address"))
    _add_string(source_ips, metadata.get("success_ip_address"))
    _add_many(source_ips, metadata.get("ip_addresses"))
    _add_many(source_ips, metadata.get("failure_ip_addresses"))
    _add_string(usernames, metadata.get("username"))
    _add_many(usernames, metadata.get("users"))

    return source_ips, usernames


def _add_string(target: set[str], value) -> None:
    if isinstance(value, str) and value:
        target.add(value)


def _add_many(target: set[str], value) -> None:
    if not isinstance(value, (list, tuple, set)):
        return
    for item in value:
        _add_string(target, item)


def _time_gap_seconds(
    first: SecurityIncident,
    second: SecurityIncident,
) -> float:
    if first.last_seen < second.first_seen:
        return (second.first_seen - first.last_seen).total_seconds()
    if second.last_seen < first.first_seen:
        return (first.first_seen - second.last_seen).total_seconds()
    return 0.0


def _campaign_risk_score(
    incidents: list[SecurityIncident],
    source_ips: tuple[str, ...],
    usernames: tuple[str, ...],
) -> int:
    base_score = max(incident.risk_score for incident in incidents)
    relation_bonus = min((len(incidents) - 1) * 5, 20)
    spread_bonus = min(len(source_ips) * 2, 10)
    target_bonus = min(len(usernames) * 2, 10)
    return min(base_score + relation_bonus + spread_bonus + target_bonus, 100)


def _campaign_title(
    source_ips: tuple[str, ...],
    usernames: tuple[str, ...],
) -> str:
    if len(source_ips) == 1 and usernames:
        return f"Correlated activity from {source_ips[0]}"
    if len(usernames) == 1 and source_ips:
        return f"Correlated attack against {usernames[0]}"
    if source_ips:
        return "Multi-incident source campaign"
    if usernames:
        return "Multi-incident account campaign"
    return "Correlated authentication campaign"

"""Incident building and full analysis orchestration."""

from __future__ import annotations

from dataclasses import replace
from collections.abc import Iterable
from pathlib import Path

from src.campaigns import build_campaigns
from src.config import AnalyzerConfig
from src.config import build_config
from src.models import AnalysisResult, IncidentType, LogEvent, ParseIssue
from src.models import ParseResult, RuleMatch, SecurityIncident
from src.parser import parse_log_file_with_diagnostics
from src.remediation import recommended_actions_for_incident
from src.risk import calculate_risk_score, explain_risk, severity_from_score
from src.rules import detect_suspicious_activity
from src.statistics import calculate_statistics


def analyze_events(
    events: Iterable[LogEvent],
    threshold: int = 5,
    window_seconds: int = 120,
    config: AnalyzerConfig | None = None,
    parse_issues: Iterable[ParseIssue] = (),
    source_path: str | None = None,
) -> AnalysisResult:
    """Analyze parsed events and return incidents with statistics."""

    active_config = config or build_config(
        threshold=threshold,
        window_seconds=window_seconds,
    )
    sorted_events = tuple(sorted(events, key=lambda event: event.timestamp))
    rule_matches = detect_suspicious_activity(
        sorted_events,
        active_config,
    )
    incidents = build_incidents(rule_matches, active_config)
    campaigns = build_campaigns(incidents)
    parse_issue_tuple = tuple(parse_issues)
    statistics = calculate_statistics(
        sorted_events,
        incidents,
        parse_issue_tuple,
    )

    return AnalysisResult(
        events=sorted_events,
        incidents=tuple(incidents),
        statistics=statistics,
        campaigns=campaigns,
        parse_issues=parse_issue_tuple,
        source_path=source_path,
        config_summary=active_config.to_dict(),
    )


def analyze_file(
    file_path: str | Path,
    config: AnalyzerConfig,
    default_year: int | None = None,
) -> AnalysisResult:
    """Parse and analyze a log file in one call."""

    parse_result = parse_log_file_with_diagnostics(
        file_path,
        default_year=default_year,
    )
    return analyze_parse_result(
        parse_result,
        config=config,
        source_path=str(file_path),
    )


def analyze_parse_result(
    parse_result: ParseResult,
    config: AnalyzerConfig,
    source_path: str | None = None,
) -> AnalysisResult:
    """Analyze an already parsed file result."""

    return analyze_events(
        parse_result.events,
        config=config,
        parse_issues=parse_result.issues,
        source_path=source_path,
    )


def build_incidents(
    matches: Iterable[RuleMatch],
    config: AnalyzerConfig | None = None,
) -> list[SecurityIncident]:
    """Convert rule matches into reportable security incidents."""

    active_config = config or build_config()
    incidents: list[SecurityIncident] = []
    grouped_matches = _group_related_matches(matches)

    for index, match_group in enumerate(grouped_matches, start=1):
        primary_match = match_group[0]
        merged_match = _merge_match_group(match_group)
        risk_score = calculate_risk_score(merged_match)
        severity = severity_from_score(risk_score)
        incident_type = primary_match.incident_type
        events = _limit_events(
            merged_match.events,
            active_config.max_events_per_incident,
        )
        metadata = dict(merged_match.metadata)
        metadata["risk_factors"] = explain_risk(merged_match)
        metadata["recommended_actions"] = recommended_actions_for_incident(
            incident_type,
            metadata,
        )
        metadata["event_count"] = len(merged_match.events)
        metadata["displayed_event_count"] = len(events)
        incidents.append(
            SecurityIncident(
                incident_id=f"INC-{index:04d}",
                incident_type=incident_type,
                title=_title_for_incident(incident_type),
                description=merged_match.reason,
                events=events,
                risk_score=risk_score,
                severity=severity,
                metadata=metadata,
            )
        )

    return incidents


def _title_for_incident(incident_type: IncidentType) -> str:
    titles = {
        IncidentType.BRUTE_FORCE_IP: "Possible brute-force attack",
        IncidentType.USER_ENUMERATION: "Possible username enumeration",
        IncidentType.SUCCESS_AFTER_FAILURES: (
            "Successful login after failures"
        ),
        IncidentType.DISTRIBUTED_USER_ATTACK: (
            "Distributed attack on user"
        ),
        IncidentType.ACCOUNT_TAKEOVER_SIGNAL: (
            "Possible account takeover signal"
        ),
        IncidentType.LOW_AND_SLOW_BRUTE_FORCE: (
            "Low-and-slow brute-force pattern"
        ),
    }
    return titles[incident_type]


def _group_related_matches(
    matches: Iterable[RuleMatch],
) -> list[list[RuleMatch]]:
    groups: list[list[RuleMatch]] = []

    for match in sorted(matches, key=lambda item: item.first_seen):
        fingerprint = _fingerprint_for_match(match)
        placed = False
        for group in groups:
            group_fingerprint = _fingerprint_for_match(group[0])
            if fingerprint != group_fingerprint:
                continue
            if _matches_overlap(match, group[-1]):
                group.append(match)
                placed = True
                break
        if not placed:
            groups.append([match])

    return groups


def _fingerprint_for_match(match: RuleMatch) -> tuple[str, str]:
    incident_type = match.incident_type.value
    metadata = match.metadata

    if "ip_address" in metadata:
        return incident_type, f"ip:{metadata['ip_address']}"
    if "username" in metadata:
        return incident_type, f"user:{metadata['username']}"

    first_event = match.events[0]
    return incident_type, f"{first_event.ip_address}:{first_event.username}"


def _matches_overlap(first: RuleMatch, second: RuleMatch) -> bool:
    first_event_ids = _event_identity_set(first.events)
    second_event_ids = _event_identity_set(second.events)
    return bool(first_event_ids.intersection(second_event_ids))


def _merge_match_group(matches: list[RuleMatch]) -> RuleMatch:
    primary_match = matches[0]
    if len(matches) == 1:
        return primary_match

    events = _unique_events(
        event
        for match in matches
        for event in match.events
    )
    reasons = "; ".join(match.reason for match in matches)
    metadata = _merge_metadata(matches)
    return replace(
        primary_match,
        events=events,
        reason=reasons,
        metadata=metadata,
    )


def _merge_metadata(matches: list[RuleMatch]) -> dict:
    merged: dict = {"merged_rule_matches": len(matches)}
    for match in matches:
        for key, value in match.metadata.items():
            if key not in merged:
                merged[key] = value
                continue
            if merged[key] == value:
                continue
            merged[f"{key}_{len(merged)}"] = value
    return merged


def _unique_events(events: Iterable[LogEvent]) -> tuple[LogEvent, ...]:
    seen = set()
    unique_events = []

    for event in sorted(events, key=lambda item: item.timestamp):
        identity = _event_identity(event)
        if identity in seen:
            continue
        seen.add(identity)
        unique_events.append(event)

    return tuple(unique_events)


def _event_identity_set(events: tuple[LogEvent, ...]) -> set[tuple]:
    return {_event_identity(event) for event in events}


def _event_identity(event: LogEvent) -> tuple:
    return (
        event.timestamp,
        event.ip_address,
        event.username,
        event.event_type,
        event.raw_line,
    )


def _limit_events(
    events: tuple[LogEvent, ...],
    max_events: int,
) -> tuple[LogEvent, ...]:
    if len(events) <= max_events:
        return events
    return events[:max_events]

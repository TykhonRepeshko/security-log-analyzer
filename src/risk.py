"""Risk scoring for detected security incidents."""

from __future__ import annotations

from src.models import EventType, IncidentType, LogEvent, RuleMatch, Severity


BASE_SCORES = {
    IncidentType.BRUTE_FORCE_IP: 40,
    IncidentType.USER_ENUMERATION: 35,
    IncidentType.SUCCESS_AFTER_FAILURES: 60,
    IncidentType.DISTRIBUTED_USER_ATTACK: 45,
    IncidentType.ACCOUNT_TAKEOVER_SIGNAL: 58,
    IncidentType.LOW_AND_SLOW_BRUTE_FORCE: 38,
}

SENSITIVE_USERNAMES = {
    "admin",
    "administrator",
    "api",
    "backup",
    "deploy",
    "mysql",
    "oracle",
    "postgres",
    "root",
    "service",
    "svc",
}


def calculate_risk_score(match: RuleMatch) -> int:
    """Calculate a 0-100 risk score for a rule match."""

    score = BASE_SCORES[match.incident_type]
    failed_count = _count_events(match.events, EventType.FAILED_LOGIN)
    success_count = _count_events(match.events, EventType.SUCCESSFUL_LOGIN)
    unique_ips = len({event.ip_address for event in match.events})
    unique_users = len({event.username for event in match.events})

    score += min(failed_count * 4, 25)
    score += min(unique_ips * 4, 20)
    score += min(unique_users * 4, 20)
    score += success_count * 12
    score += _speed_bonus(match.events)
    score += _sensitive_account_bonus(match.events)

    return min(score, 100)


def explain_risk(match: RuleMatch) -> tuple[str, ...]:
    """Return short explanations for the assigned risk."""

    factors = [f"base:{match.incident_type.value}"]
    failed_count = _count_events(match.events, EventType.FAILED_LOGIN)
    success_count = _count_events(match.events, EventType.SUCCESSFUL_LOGIN)
    unique_ips = len({event.ip_address for event in match.events})
    unique_users = len({event.username for event in match.events})

    if failed_count >= 5:
        factors.append(f"{failed_count}_failed_logins")
    if success_count:
        factors.append("successful_login_present")
    if unique_ips >= 3:
        factors.append(f"{unique_ips}_source_ips")
    if unique_users >= 3:
        factors.append(f"{unique_users}_target_users")
    if _speed_bonus(match.events) >= 10:
        factors.append("short_time_span")
    if _sensitive_account_bonus(match.events):
        factors.append("sensitive_account_targeted")
    if match.incident_type == IncidentType.ACCOUNT_TAKEOVER_SIGNAL:
        factors.append("success_after_distributed_failures")
    if match.incident_type == IncidentType.LOW_AND_SLOW_BRUTE_FORCE:
        factors.append("slow_repeated_failures")

    return tuple(factors)


def severity_from_score(score: int) -> Severity:
    """Convert numeric risk score to a severity label."""

    if score >= 85:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 30:
        return Severity.MEDIUM
    return Severity.LOW


def _count_events(events: tuple[LogEvent, ...], event_type: EventType) -> int:
    return sum(1 for event in events if event.event_type == event_type)


def _speed_bonus(events: tuple[LogEvent, ...]) -> int:
    if len(events) < 2:
        return 0

    first_seen = min(event.timestamp for event in events)
    last_seen = max(event.timestamp for event in events)
    span_seconds = (last_seen - first_seen).total_seconds()

    if span_seconds <= 30:
        return 15
    if span_seconds <= 120:
        return 10
    if span_seconds <= 300:
        return 5
    return 0


def _sensitive_account_bonus(events: tuple[LogEvent, ...]) -> int:
    usernames = {event.username.lower() for event in events}
    if usernames.intersection(SENSITIVE_USERNAMES):
        return 8
    return 0

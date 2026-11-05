"""Core data models for the security log analyzer.

The application keeps most data in small immutable dataclasses. This makes
the analyzer easier to test and keeps the business logic separated from the
CLI and report rendering code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class EventType(str, Enum):
    """Supported authentication event types."""

    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"


class IncidentType(str, Enum):
    """Security incident categories detected by the analyzer."""

    BRUTE_FORCE_IP = "brute_force_ip"
    USER_ENUMERATION = "user_enumeration"
    SUCCESS_AFTER_FAILURES = "success_after_failures"
    DISTRIBUTED_USER_ATTACK = "distributed_user_attack"
    ACCOUNT_TAKEOVER_SIGNAL = "account_takeover_signal"
    LOW_AND_SLOW_BRUTE_FORCE = "low_and_slow_brute_force"


class Severity(str, Enum):
    """Human readable risk levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IpScope(str, Enum):
    """Network scope for an IP address."""

    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    RESERVED = "reserved"
    MULTICAST = "multicast"
    UNSPECIFIED = "unspecified"


@dataclass(frozen=True)
class LogEvent:
    """One parsed authentication event from a log file."""

    timestamp: datetime
    ip_address: str
    username: str
    event_type: EventType
    raw_line: str
    line_number: int | None = None
    source_format: str = "simple"
    service: str = "auth"
    auth_method: str = "password"

    @property
    def is_failed(self) -> bool:
        """Return ``True`` when the event is a failed authentication."""

        return self.event_type == EventType.FAILED_LOGIN

    @property
    def is_successful(self) -> bool:
        """Return ``True`` when the event is a successful authentication."""

        return self.event_type == EventType.SUCCESSFUL_LOGIN


@dataclass(frozen=True)
class ParseIssue:
    """Information about a log line that could not be parsed."""

    line_number: int
    raw_line: str
    reason: str


@dataclass(frozen=True)
class ParseResult:
    """Events and diagnostics collected while reading a log file."""

    events: tuple[LogEvent, ...]
    issues: tuple[ParseIssue, ...]
    total_lines: int

    @property
    def parsed_lines(self) -> int:
        """Return the number of lines parsed as authentication events."""

        return len(self.events)

    @property
    def skipped_lines(self) -> int:
        """Return the number of ignored or invalid lines."""

        return len(self.issues)


@dataclass(frozen=True)
class RuleMatch:
    """Suspicious pattern produced by one detection rule."""

    incident_type: IncidentType
    events: tuple[LogEvent, ...]
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def first_seen(self) -> datetime:
        """Return the timestamp of the first event in the match."""

        return min(event.timestamp for event in self.events)

    @property
    def last_seen(self) -> datetime:
        """Return the timestamp of the last event in the match."""

        return max(event.timestamp for event in self.events)


@dataclass(frozen=True)
class SecurityIncident:
    """Grouped incident with assigned risk information."""

    incident_id: str
    incident_type: IncidentType
    title: str
    description: str
    events: tuple[LogEvent, ...]
    risk_score: int
    severity: Severity
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def first_seen(self) -> datetime:
        """Return the first event timestamp in this incident."""

        return min(event.timestamp for event in self.events)

    @property
    def last_seen(self) -> datetime:
        """Return the last event timestamp in this incident."""

        return max(event.timestamp for event in self.events)


@dataclass(frozen=True)
class AttackCampaign:
    """Correlated set of incidents that likely belong together."""

    campaign_id: str
    title: str
    incident_ids: tuple[str, ...]
    source_ips: tuple[str, ...]
    usernames: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    severity: Severity
    summary: str


@dataclass(frozen=True)
class CounterItem:
    """One row in a top-N activity table."""

    label: str
    total_events: int
    failed_logins: int
    successful_logins: int
    unique_ips: int = 0
    unique_users: int = 0


@dataclass(frozen=True)
class TimeBucket:
    """Aggregated authentication activity for a time interval."""

    start: datetime
    end: datetime
    total_events: int
    failed_logins: int
    successful_logins: int
    incident_count: int
    max_risk_score: int


@dataclass(frozen=True)
class IpProfile:
    """Local profile of an IP address based on the analyzed log file."""

    ip_address: str
    version: int
    scope: IpScope
    total_events: int
    failed_logins: int
    successful_logins: int
    usernames: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    incident_ids: tuple[str, ...] = ()
    risk_tags: tuple[str, ...] = ()

    @property
    def is_suspicious(self) -> bool:
        """Return ``True`` when this IP is connected to incidents."""

        return bool(self.incident_ids or self.risk_tags)


@dataclass(frozen=True)
class AnalysisStatistics:
    """Summary numbers shown in CLI and reports."""

    total_events: int
    failed_logins: int
    successful_logins: int
    suspicious_ips: tuple[str, ...]
    incidents_count: int
    unique_ips: int = 0
    unique_users: int = 0
    skipped_lines: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    severity_counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalysisResult:
    """Full result of analyzing a parsed log file."""

    events: tuple[LogEvent, ...]
    incidents: tuple[SecurityIncident, ...]
    statistics: AnalysisStatistics
    campaigns: tuple[AttackCampaign, ...] = ()
    parse_issues: tuple[ParseIssue, ...] = ()
    source_path: str | None = None
    config_summary: dict[str, Any] = field(default_factory=dict)

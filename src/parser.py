"""Parsing functions for authentication logs.

The parser accepts a small set of common authentication-log shapes:

* the simple course example with an ISO timestamp;
* OpenSSH/syslog-style lines from Linux auth logs;
* key-value lines often produced by custom services.

Unsupported lines are ignored, but the diagnostic parser records why a line
was skipped. The CLI uses those diagnostics in reports so the user can see
how much of the input file was actually analyzed.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from pathlib import Path

from src.models import EventType, LogEvent, ParseIssue, ParseResult


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
SYSLOG_TIMESTAMP_WITH_YEAR_FORMAT = "%Y %b %d %H:%M:%S"
DEFAULT_SERVICE = "ssh"

ISO_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<action>Failed|Accepted) "
    r"(?P<method>[A-Za-z0-9_-]+) for "
    r"(?:(?:invalid user) )?"
    r"(?P<username>[A-Za-z0-9._@+-]+) from "
    r"(?P<ip>[^\s:]+)"
)

SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>[A-Za-z0-9_.-]+) "
    r"(?P<service>[A-Za-z0-9_.-]+)(?:\[\d+\])?: "
    r"(?P<message>.+)$"
)

SSH_MESSAGE_PATTERN = re.compile(
    r"(?P<action>Failed|Accepted) "
    r"(?P<method>[A-Za-z0-9_-]+) for "
    r"(?:(?:invalid user) )?"
    r"(?P<username>[A-Za-z0-9._@+-]+) from "
    r"(?P<ip>[^\s:]+)"
)

INVALID_USER_PATTERN = re.compile(
    r"Invalid user (?P<username>[A-Za-z0-9._@+-]+) from "
    r"(?P<ip>[^\s:]+)"
)

KEY_VALUE_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r".*?\buser=(?P<username>[A-Za-z0-9._@+-]+)"
    r".*?\bip=(?P<ip>[^\s]+)"
    r".*?\bstatus=(?P<status>failed|success|accepted)"
    r"(?:.*?\bservice=(?P<service>[A-Za-z0-9_.-]+))?"
    r"(?:.*?\bmethod=(?P<method>[A-Za-z0-9_-]+))?",
    re.IGNORECASE,
)


def parse_log_line(
    line: str,
    line_number: int | None = None,
    default_year: int | None = None,
) -> LogEvent | None:
    """Parse one log line and return ``None`` when it is unsupported."""

    event, _reason = _parse_log_line_with_reason(
        line,
        line_number=line_number,
        default_year=default_year,
    )
    return event


def parse_log_file(file_path: str | Path) -> list[LogEvent]:
    """Read and parse a log file, skipping unsupported lines."""

    return list(parse_log_file_with_diagnostics(file_path).events)


def parse_log_file_with_diagnostics(
    file_path: str | Path,
    default_year: int | None = None,
) -> ParseResult:
    """Read a log file and return parsed events plus skipped-line details."""

    path = Path(file_path)
    events: list[LogEvent] = []
    issues: list[ParseIssue] = []
    total_lines = 0

    with path.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            total_lines = line_number
            event, reason = _parse_log_line_with_reason(
                line,
                line_number=line_number,
                default_year=default_year,
            )
            if event is not None:
                events.append(event)
            elif reason is not None:
                issues.append(
                    ParseIssue(
                        line_number=line_number,
                        raw_line=line.rstrip("\n"),
                        reason=reason,
                    )
                )

    return ParseResult(
        events=tuple(events),
        issues=tuple(issues),
        total_lines=total_lines,
    )


def _parse_log_line_with_reason(
    line: str,
    line_number: int | None,
    default_year: int | None,
) -> tuple[LogEvent | None, str | None]:
    clean_line = line.strip()
    if not clean_line:
        return None, "empty line"

    parsers = (
        _parse_iso_ssh_line,
        _parse_syslog_line,
        _parse_key_value_line,
    )
    for parser in parsers:
        event, reason = parser(clean_line, line_number, default_year)
        if event is not None:
            return event, None
        if reason != "pattern did not match":
            return None, reason

    return None, "unsupported authentication log format"


def _parse_iso_ssh_line(
    line: str,
    line_number: int | None,
    _default_year: int | None,
) -> tuple[LogEvent | None, str]:
    match = ISO_SSH_PATTERN.match(line)
    if match is None:
        return None, "pattern did not match"

    timestamp = _parse_timestamp(match.group("timestamp"))
    if timestamp is None:
        return None, "invalid timestamp"

    return _event_from_fields(
        timestamp=timestamp,
        ip_value=match.group("ip"),
        username=match.group("username"),
        event_type=_parse_action(match.group("action")),
        raw_line=line,
        line_number=line_number,
        source_format="iso_ssh",
        service=DEFAULT_SERVICE,
        auth_method=match.group("method"),
    )


def _parse_syslog_line(
    line: str,
    line_number: int | None,
    default_year: int | None,
) -> tuple[LogEvent | None, str]:
    match = SYSLOG_PATTERN.match(line)
    if match is None:
        return None, "pattern did not match"

    timestamp = _parse_syslog_timestamp(
        match.group("timestamp"),
        default_year=default_year,
    )
    if timestamp is None:
        return None, "invalid syslog timestamp"

    message = match.group("message")
    ssh_match = SSH_MESSAGE_PATTERN.search(message)
    if ssh_match is not None:
        return _event_from_fields(
            timestamp=timestamp,
            ip_value=ssh_match.group("ip"),
            username=ssh_match.group("username"),
            event_type=_parse_action(ssh_match.group("action")),
            raw_line=line,
            line_number=line_number,
            source_format="syslog_ssh",
            service=match.group("service"),
            auth_method=ssh_match.group("method"),
        )

    invalid_user_match = INVALID_USER_PATTERN.search(message)
    if invalid_user_match is None:
        return None, "unsupported syslog authentication message"

    return _event_from_fields(
        timestamp=timestamp,
        ip_value=invalid_user_match.group("ip"),
        username=invalid_user_match.group("username"),
        event_type=EventType.FAILED_LOGIN,
        raw_line=line,
        line_number=line_number,
        source_format="syslog_invalid_user",
        service=match.group("service"),
        auth_method="unknown",
    )


def _parse_key_value_line(
    line: str,
    line_number: int | None,
    _default_year: int | None,
) -> tuple[LogEvent | None, str]:
    match = KEY_VALUE_PATTERN.match(line)
    if match is None:
        return None, "pattern did not match"

    timestamp = _parse_timestamp(match.group("timestamp"))
    if timestamp is None:
        return None, "invalid timestamp"

    status = match.group("status").lower()
    event_type = EventType.SUCCESSFUL_LOGIN
    if status == "failed":
        event_type = EventType.FAILED_LOGIN

    return _event_from_fields(
        timestamp=timestamp,
        ip_value=match.group("ip"),
        username=match.group("username"),
        event_type=event_type,
        raw_line=line,
        line_number=line_number,
        source_format="key_value",
        service=match.group("service") or "application",
        auth_method=match.group("method") or "unknown",
    )


def _event_from_fields(
    timestamp: datetime,
    ip_value: str,
    username: str,
    event_type: EventType,
    raw_line: str,
    line_number: int | None,
    source_format: str,
    service: str,
    auth_method: str,
) -> tuple[LogEvent | None, str]:
    ip_address = _parse_ip_address(ip_value)
    if ip_address is None:
        return None, "invalid IP address"

    return (
        LogEvent(
            timestamp=timestamp,
            ip_address=ip_address,
            username=username,
            event_type=event_type,
            raw_line=raw_line,
            line_number=line_number,
            source_format=source_format,
            service=service,
            auth_method=auth_method,
        ),
        "",
    )


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError:
        return None


def _parse_syslog_timestamp(
    value: str,
    default_year: int | None,
) -> datetime | None:
    year = default_year or datetime.now().year
    try:
        return datetime.strptime(
            f"{year} {value}",
            SYSLOG_TIMESTAMP_WITH_YEAR_FORMAT,
        )
    except ValueError:
        return None


def _parse_ip_address(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _parse_action(action: str) -> EventType:
    if action == "Failed":
        return EventType.FAILED_LOGIN
    return EventType.SUCCESSFUL_LOGIN

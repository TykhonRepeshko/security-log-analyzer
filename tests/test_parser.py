"""Tests for log parsing."""

from pathlib import Path

from src.models import EventType
from src.parser import parse_log_file_with_diagnostics, parse_log_line


def test_parse_valid_failed_login_line() -> None:
    line = "2026-03-18 12:01:10 Failed password for admin from 45.122.10.8"

    event = parse_log_line(line)

    assert event is not None
    assert event.username == "admin"
    assert event.ip_address == "45.122.10.8"
    assert event.event_type == EventType.FAILED_LOGIN
    assert event.timestamp.year == 2026


def test_parse_valid_successful_login_line() -> None:
    line = "2026-03-18 12:02:20 Accepted password for admin from 45.122.10.8"

    event = parse_log_line(line)

    assert event is not None
    assert event.username == "admin"
    assert event.event_type == EventType.SUCCESSFUL_LOGIN


def test_ignore_invalid_line() -> None:
    line = "This is not an authentication log line"

    assert parse_log_line(line) is None


def test_ignore_invalid_ip_address() -> None:
    line = "2026-03-18 12:01:10 Failed password for admin from 999.1.1.1"

    assert parse_log_line(line) is None


def test_parse_syslog_ssh_line() -> None:
    line = (
        "Mar 18 12:08:00 lab-host sshd[4121]: Failed password for "
        "invalid user test from 203.0.113.77 port 43122 ssh2"
    )

    event = parse_log_line(line, default_year=2026)

    assert event is not None
    assert event.timestamp.year == 2026
    assert event.username == "test"
    assert event.ip_address == "203.0.113.77"
    assert event.source_format == "syslog_ssh"


def test_parse_key_value_auth_line() -> None:
    line = (
        "2026-03-18 12:13:00 auth service=web user=api "
        "ip=198.51.100.45 status=failed method=token"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event.username == "api"
    assert event.auth_method == "token"
    assert event.event_type == EventType.FAILED_LOGIN


def test_parse_file_with_diagnostics(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "\n".join(
            [
                "2026-03-18 12:01:10 Failed password for admin "
                "from 45.122.10.8",
                "noise line",
            ]
        ),
        encoding="utf-8",
    )

    result = parse_log_file_with_diagnostics(log_path)

    assert result.parsed_lines == 1
    assert result.skipped_lines == 1
    assert result.issues[0].line_number == 2

"""Report generation in text, JSON, and HTML formats."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from src.dashboard import generate_html_dashboard
from src.enrichment import build_ip_profiles
from src.models import AnalysisResult, AttackCampaign, LogEvent
from src.models import SecurityIncident
from src.timeline import build_timeline, top_ip_activity, top_user_activity


SUPPORTED_FORMATS = {"txt", "json", "html"}


def render_report(result: AnalysisResult, report_format: str) -> str:
    """Render an analysis result in the selected format."""

    normalized_format = report_format.lower()
    if normalized_format == "json":
        return json.dumps(result_to_dict(result), indent=4)
    if normalized_format == "txt":
        return generate_text_report(result)
    if normalized_format == "html":
        return generate_html_dashboard(result)
    raise ValueError(f"Unsupported report format: {report_format}")


def write_report(
    result: AnalysisResult,
    output_path: str | Path,
    report_format: str,
) -> None:
    """Write an analysis report to a file."""

    path = Path(output_path)
    path.write_text(render_report(result, report_format), encoding="utf-8")


def result_to_dict(result: AnalysisResult) -> dict[str, Any]:
    """Convert analysis result to JSON-friendly data."""

    statistics = result.statistics
    bucket_seconds = int(
        result.config_summary.get("timeline_bucket_seconds", 300)
    )
    top_limit = int(result.config_summary.get("top_limit", 10))
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_path": result.source_path,
        "config": result.config_summary,
        "statistics": {
            "total_events": statistics.total_events,
            "failed_logins": statistics.failed_logins,
            "successful_logins": statistics.successful_logins,
            "suspicious_ips": list(statistics.suspicious_ips),
            "incidents_count": statistics.incidents_count,
            "unique_ips": statistics.unique_ips,
            "unique_users": statistics.unique_users,
            "skipped_lines": statistics.skipped_lines,
            "first_seen": _datetime_to_string(statistics.first_seen),
            "last_seen": _datetime_to_string(statistics.last_seen),
            "severity_counts": statistics.severity_counts,
        },
        "top_ips": [
            _counter_item_to_dict(item)
            for item in top_ip_activity(result.events, limit=top_limit)
        ],
        "top_users": [
            _counter_item_to_dict(item)
            for item in top_user_activity(result.events, limit=top_limit)
        ],
        "ip_profiles": [
            _ip_profile_to_dict(profile)
            for profile in build_ip_profiles(result.events, result.incidents)
        ],
        "timeline": [
            _bucket_to_dict(bucket)
            for bucket in build_timeline(
                result.events,
                result.incidents,
                bucket_seconds=bucket_seconds,
            )
        ],
        "parse_issues": [
            {
                "line_number": issue.line_number,
                "reason": issue.reason,
                "raw_line": issue.raw_line,
            }
            for issue in result.parse_issues
        ],
        "campaigns": [
            _campaign_to_dict(campaign) for campaign in result.campaigns
        ],
        "incidents": [
            _incident_to_dict(incident) for incident in result.incidents
        ],
    }


def generate_text_report(result: AnalysisResult) -> str:
    """Create a readable plain text report."""

    statistics = result.statistics
    lines = [
        "Security Log Analyzer Report",
        f"Generated at: {datetime.now().isoformat(timespec='seconds')}",
        "",
        "Summary",
        f"- Total events: {statistics.total_events}",
        f"- Failed logins: {statistics.failed_logins}",
        f"- Successful logins: {statistics.successful_logins}",
        f"- Unique IPs: {statistics.unique_ips}",
        f"- Unique users: {statistics.unique_users}",
        f"- Skipped lines: {statistics.skipped_lines}",
        f"- Suspicious IPs: {', '.join(statistics.suspicious_ips) or 'none'}",
        f"- Incidents found: {statistics.incidents_count}",
        f"- Attack campaigns: {len(result.campaigns)}",
    ]
    if statistics.first_seen and statistics.last_seen:
        lines.append(
            f"- Time range: {statistics.first_seen} - {statistics.last_seen}"
        )
    if statistics.severity_counts:
        lines.append(f"- Severity counts: {statistics.severity_counts}")

    lines.extend(_format_top_activity(result))
    lines.extend(_format_parser_diagnostics(result))
    lines.extend(_format_campaigns_text(result.campaigns))
    lines.append("")
    lines.append("Incidents")

    if not result.incidents:
        lines.append("- No suspicious incidents found.")
        return "\n".join(lines)

    for incident in result.incidents:
        lines.extend(_format_incident_text(incident))

    return "\n".join(lines)


def _campaign_to_dict(campaign: AttackCampaign) -> dict[str, Any]:
    return {
        "id": campaign.campaign_id,
        "title": campaign.title,
        "incident_ids": list(campaign.incident_ids),
        "source_ips": list(campaign.source_ips),
        "usernames": list(campaign.usernames),
        "first_seen": campaign.first_seen.isoformat(sep=" "),
        "last_seen": campaign.last_seen.isoformat(sep=" "),
        "risk_score": campaign.risk_score,
        "severity": campaign.severity.value,
        "summary": campaign.summary,
    }


def _incident_to_dict(incident: SecurityIncident) -> dict[str, Any]:
    return {
        "id": incident.incident_id,
        "type": incident.incident_type.value,
        "title": incident.title,
        "description": incident.description,
        "first_seen": incident.first_seen.isoformat(sep=" "),
        "last_seen": incident.last_seen.isoformat(sep=" "),
        "risk_score": incident.risk_score,
        "severity": incident.severity.value,
        "metadata": incident.metadata,
        "events": [_event_to_dict(event) for event in incident.events],
    }


def _event_to_dict(event: LogEvent) -> dict[str, str]:
    return {
        "timestamp": event.timestamp.isoformat(sep=" "),
        "ip_address": event.ip_address,
        "username": event.username,
        "event_type": event.event_type.value,
        "raw_line": event.raw_line,
        "line_number": str(event.line_number or ""),
        "source_format": event.source_format,
        "service": event.service,
        "auth_method": event.auth_method,
    }


def _format_incident_text(incident: SecurityIncident) -> list[str]:
    lines = [
        "",
        f"{incident.incident_id}: {incident.title}",
        f"  Type: {incident.incident_type.value}",
        f"  Severity: {incident.severity.value}",
        f"  Risk score: {incident.risk_score}/100",
        f"  Time range: {incident.first_seen} - {incident.last_seen}",
        f"  Description: {incident.description}",
        f"  Risk factors: {incident.metadata.get('risk_factors', ())}",
    ]
    recommended_actions = incident.metadata.get("recommended_actions", ())
    if recommended_actions:
        lines.append("  Recommended actions:")
        for action in recommended_actions:
            lines.append(f"    - {action}")
    lines.append("  Events:")

    for event in incident.events:
        lines.append(
            "    "
            f"{event.timestamp} | {event.event_type.value} | "
            f"{event.username} | {event.ip_address}"
        )

    return lines


def _format_campaigns_text(
    campaigns: tuple[AttackCampaign, ...],
) -> list[str]:
    lines = ["", "Attack Campaigns"]

    if not campaigns:
        lines.append("- No correlated attack campaigns found.")
        return lines

    for campaign in campaigns:
        source_ips = ", ".join(campaign.source_ips) or "none"
        usernames = ", ".join(campaign.usernames) or "none"
        incident_ids = ", ".join(campaign.incident_ids)
        lines.extend(
            [
                "",
                f"{campaign.campaign_id}: {campaign.title}",
                f"  Severity: {campaign.severity.value}",
                f"  Risk score: {campaign.risk_score}/100",
                f"  Time range: {campaign.first_seen} - "
                f"{campaign.last_seen}",
                f"  Incidents: {incident_ids}",
                f"  Source IPs: {source_ips}",
                f"  Users: {usernames}",
                f"  Summary: {campaign.summary}",
            ]
        )

    return lines


def _format_top_activity(result: AnalysisResult) -> list[str]:
    top_limit = int(result.config_summary.get("top_limit", 10))
    top_ips = top_ip_activity(result.events, limit=top_limit)
    top_users = top_user_activity(result.events, limit=top_limit)
    lines = ["", "Top Source IPs"]

    if not top_ips:
        lines.append("- none")
    for item in top_ips:
        lines.append(
            f"- {item.label}: {item.total_events} event(s), "
            f"{item.failed_logins} failed"
        )

    lines.append("")
    lines.append("Top Usernames")
    if not top_users:
        lines.append("- none")
    for item in top_users:
        lines.append(
            f"- {item.label}: {item.total_events} event(s), "
            f"{item.failed_logins} failed"
        )

    return lines


def _format_parser_diagnostics(result: AnalysisResult) -> list[str]:
    lines = ["", "Parser Diagnostics"]

    if not result.parse_issues:
        lines.append("- No skipped lines.")
        return lines

    for issue in result.parse_issues[:10]:
        lines.append(
            f"- line {issue.line_number}: {issue.reason} "
            f"({issue.raw_line})"
        )
    if len(result.parse_issues) > 10:
        lines.append(f"- ... {len(result.parse_issues) - 10} more")

    return lines


def _counter_item_to_dict(item) -> dict[str, Any]:
    return {
        "label": item.label,
        "total_events": item.total_events,
        "failed_logins": item.failed_logins,
        "successful_logins": item.successful_logins,
        "unique_ips": item.unique_ips,
        "unique_users": item.unique_users,
    }


def _ip_profile_to_dict(profile) -> dict[str, Any]:
    return {
        "ip_address": profile.ip_address,
        "version": profile.version,
        "scope": profile.scope.value,
        "total_events": profile.total_events,
        "failed_logins": profile.failed_logins,
        "successful_logins": profile.successful_logins,
        "usernames": list(profile.usernames),
        "first_seen": profile.first_seen.isoformat(sep=" "),
        "last_seen": profile.last_seen.isoformat(sep=" "),
        "incident_ids": list(profile.incident_ids),
        "risk_tags": list(profile.risk_tags),
    }


def _bucket_to_dict(bucket) -> dict[str, Any]:
    return {
        "start": bucket.start.isoformat(sep=" "),
        "end": bucket.end.isoformat(sep=" "),
        "total_events": bucket.total_events,
        "failed_logins": bucket.failed_logins,
        "successful_logins": bucket.successful_logins,
        "incident_count": bucket.incident_count,
        "max_risk_score": bucket.max_risk_score,
    }


def _datetime_to_string(value) -> str | None:
    if value is None:
        return None
    return value.isoformat(sep=" ")

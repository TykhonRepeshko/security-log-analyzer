"""HTML dashboard rendering for visual log analysis."""

from __future__ import annotations

from html import escape

from src.enrichment import build_ip_profiles
from src.models import AnalysisResult, AttackCampaign, CounterItem, IpProfile
from src.models import SecurityIncident, TimeBucket
from src.timeline import build_timeline, severity_counts, top_ip_activity
from src.timeline import top_user_activity


def generate_html_dashboard(result: AnalysisResult) -> str:
    """Render the analysis result as a self-contained HTML dashboard."""

    bucket_seconds = int(
        result.config_summary.get("timeline_bucket_seconds", 300)
    )
    top_limit = int(result.config_summary.get("top_limit", 10))
    timeline = build_timeline(
        result.events,
        result.incidents,
        bucket_seconds=bucket_seconds,
    )
    top_ips = top_ip_activity(result.events, limit=top_limit)
    top_users = top_user_activity(result.events, limit=top_limit)
    profiles = build_ip_profiles(result.events, result.incidents)

    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" '
            'content="width=device-width, initial-scale=1">',
            "<title>Security Log Analyzer Dashboard</title>",
            f"<style>{_dashboard_css()}</style>",
            "</head>",
            "<body>",
            '<main class="page">',
            _hero(result),
            _summary_grid(result),
            _chart_section(result, timeline, top_ips, top_users),
            _campaign_section(result.campaigns),
            _ip_profile_section(profiles),
            _incident_section(result.incidents),
            _parse_issue_section(result),
            "</main>",
            f"<script>{_dashboard_javascript()}</script>",
            "</body>",
            "</html>",
        ]
    )


def _hero(result: AnalysisResult) -> str:
    source_path = result.source_path or "in-memory events"
    profile = result.config_summary.get("profile", "balanced")
    return "\n".join(
        [
            '<section class="hero">',
            '<div class="hero-copy">',
            "<p>Security Log Analyzer</p>",
            "<h1>Authentication Threat Dashboard</h1>",
            "<span>Source: "
            f"{escape(source_path)} | profile: {escape(str(profile))}</span>",
            "</div>",
            '<div class="hero-score">',
            f"<strong>{_highest_risk(result.incidents)}</strong>",
            "<span>highest risk</span>",
            "</div>",
            "</section>",
        ]
    )


def _summary_grid(result: AnalysisResult) -> str:
    stats = result.statistics
    cards = [
        ("Parsed events", stats.total_events),
        ("Failed logins", stats.failed_logins),
        ("Successful logins", stats.successful_logins),
        ("Unique IPs", stats.unique_ips),
        ("Unique users", stats.unique_users),
        ("Incidents", stats.incidents_count),
        ("Campaigns", len(result.campaigns)),
        ("Skipped lines", stats.skipped_lines),
        ("Suspicious IPs", len(stats.suspicious_ips)),
    ]
    body = "\n".join(
        f'<article class="metric"><span>{escape(label)}</span>'
        f"<strong>{value}</strong></article>"
        for label, value in cards
    )
    return f'<section class="metrics">{body}</section>'


def _chart_section(
    result: AnalysisResult,
    timeline: tuple[TimeBucket, ...],
    top_ips: tuple[CounterItem, ...],
    top_users: tuple[CounterItem, ...],
) -> str:
    return "\n".join(
        [
            '<section class="grid two-columns">',
            _panel(
                "Event Timeline",
                _timeline_svg(timeline),
                "Wide blocks show failed and successful logins over time.",
            ),
            _panel(
                "Incident Severity",
                _severity_chart(severity_counts(result.incidents)),
                "Distribution of detected incident severities.",
            ),
            _panel(
                "Top Source IPs",
                _counter_bars(top_ips, "IP address"),
                "Sources sorted by authentication event volume.",
            ),
            _panel(
                "Top Usernames",
                _counter_bars(top_users, "Username"),
                "Accounts most frequently seen in the log.",
            ),
            "</section>",
        ]
    )


def _ip_profile_section(profiles: tuple[IpProfile, ...]) -> str:
    if not profiles:
        content = '<p class="empty">No IP addresses were parsed.</p>'
    else:
        rows = "\n".join(_ip_profile_row(profile) for profile in profiles[:20])
        content = (
            '<div class="table-wrap"><table>'
            "<thead><tr>"
            "<th>IP address</th><th>Scope</th><th>Events</th>"
            "<th>Failed</th><th>Users</th><th>Risk tags</th>"
            "</tr></thead>"
            f"<tbody>{rows}</tbody></table></div>"
        )
    return _section("IP Profiles", content)


def _campaign_section(campaigns: tuple[AttackCampaign, ...]) -> str:
    if not campaigns:
        return _section(
            "Attack Campaigns",
            '<p class="empty">No correlated campaigns were found.</p>',
        )

    rows = "\n".join(_campaign_row(campaign) for campaign in campaigns)
    content = (
        '<div class="table-wrap"><table>'
        "<thead><tr>"
        "<th>ID</th><th>Severity</th><th>Risk</th><th>Incidents</th>"
        "<th>Source IPs</th><th>Users</th><th>Summary</th>"
        "</tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
    )
    return _section("Attack Campaigns", content)


def _incident_section(incidents: tuple[SecurityIncident, ...]) -> str:
    if not incidents:
        return _section(
            "Security Incidents",
            '<p class="empty">No suspicious incidents were detected.</p>',
        )

    toolbar = (
        '<div class="toolbar">'
        '<input id="incidentFilter" type="search" '
        'placeholder="Search incidents">'
        '<select id="severityFilter">'
        '<option value="">all severities</option>'
        '<option value="CRITICAL">CRITICAL</option>'
        '<option value="HIGH">HIGH</option>'
        '<option value="MEDIUM">MEDIUM</option>'
        '<option value="LOW">LOW</option>'
        "</select>"
        "</div>"
    )
    cards = "\n".join(_incident_card(incident) for incident in incidents)
    return _section(
        "Security Incidents",
        f'{toolbar}<div class="incidents">{cards}</div>',
    )


def _parse_issue_section(result: AnalysisResult) -> str:
    if not result.parse_issues:
        return _section(
            "Parser Diagnostics",
            '<p class="empty">No skipped lines were recorded.</p>',
        )

    rows = "\n".join(
        "<tr>"
        f"<td>{issue.line_number}</td>"
        f"<td>{escape(issue.reason)}</td>"
        f"<td><code>{escape(issue.raw_line)}</code></td>"
        "</tr>"
        for issue in result.parse_issues[:30]
    )
    content = (
        '<div class="table-wrap"><table>'
        "<thead><tr><th>Line</th><th>Reason</th><th>Raw line</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
    )
    return _section("Parser Diagnostics", content)


def _timeline_svg(timeline: tuple[TimeBucket, ...]) -> str:
    if not timeline:
        return '<p class="empty">No event timeline is available.</p>'

    width = 760
    height = 260
    padding = 34
    chart_width = width - padding * 2
    chart_height = height - padding * 2
    max_count = max(bucket.total_events for bucket in timeline) or 1
    bar_width = max(chart_width / len(timeline) - 4, 8)
    failed_rects = []
    success_rects = []
    incident_markers = []

    for index, bucket in enumerate(timeline):
        x = padding + index * (chart_width / len(timeline))
        failed_height = chart_height * bucket.failed_logins / max_count
        success_height = chart_height * bucket.successful_logins / max_count
        failed_y = padding + chart_height - failed_height
        success_y = failed_y - success_height
        label = escape(bucket.start.strftime("%H:%M:%S"))
        failed_rects.append(
            f'<rect x="{x:.1f}" y="{failed_y:.1f}" '
            f'width="{bar_width:.1f}" height="{failed_height:.1f}" '
            f'class="failed"><title>{label}: '
            f"{bucket.failed_logins} failed</title></rect>"
        )
        success_rects.append(
            f'<rect x="{x:.1f}" y="{success_y:.1f}" '
            f'width="{bar_width:.1f}" height="{success_height:.1f}" '
            f'class="success"><title>{label}: '
            f"{bucket.successful_logins} successful</title></rect>"
        )
        if bucket.incident_count:
            marker_y = max(success_y - 10, 12)
            incident_markers.append(
                f'<circle cx="{x + bar_width / 2:.1f}" '
                f'cy="{marker_y:.1f}" r="5" class="incident-dot">'
                f"<title>{bucket.incident_count} incident(s)</title></circle>"
            )

    return "\n".join(
        [
            f'<svg viewBox="0 0 {width} {height}" '
            'role="img" aria-label="Authentication event timeline">',
            f'<line x1="{padding}" y1="{padding + chart_height}" '
            f'x2="{width - padding}" y2="{padding + chart_height}" '
            'class="axis"/>',
            *failed_rects,
            *success_rects,
            *incident_markers,
            '<text x="34" y="22" class="axis-label">events per bucket</text>',
            "</svg>",
        ]
    )


def _severity_chart(counts: dict[str, int]) -> str:
    total = sum(counts.values()) or 1
    rows = []
    for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        count = counts.get(severity, 0)
        width = max(4, int(count / total * 100)) if count else 0
        rows.append(
            '<div class="bar-row">'
            f'<span>{severity}</span>'
            '<div class="bar-track">'
            f'<div class="bar severity-{severity.lower()}" '
            f'style="width:{width}%"></div>'
            "</div>"
            f"<strong>{count}</strong>"
            "</div>"
        )
    return "\n".join(rows)


def _counter_bars(items: tuple[CounterItem, ...], heading: str) -> str:
    if not items:
        return '<p class="empty">No data available.</p>'

    max_count = max(item.total_events for item in items) or 1
    rows = []
    for item in items:
        width = max(5, int(item.total_events / max_count * 100))
        rows.append(
            '<div class="counter-row">'
            f'<span title="{escape(item.label)}">{escape(item.label)}</span>'
            '<div class="bar-track">'
            f'<div class="bar neutral" style="width:{width}%"></div>'
            "</div>"
            f"<strong>{item.total_events}</strong>"
            "</div>"
        )

    return f'<p class="mini-heading">{escape(heading)}</p>' + "\n".join(rows)


def _incident_card(incident: SecurityIncident) -> str:
    event_rows = "\n".join(
        "<tr>"
        f"<td>{event.timestamp}</td>"
        f"<td>{escape(event.event_type.value)}</td>"
        f"<td>{escape(event.username)}</td>"
        f"<td>{escape(event.ip_address)}</td>"
        "</tr>"
        for event in incident.events
    )
    risk_factors = incident.metadata.get("risk_factors", ())
    factors = " ".join(
        f"<span>{escape(str(factor))}</span>" for factor in risk_factors
    )
    recommended_actions = incident.metadata.get("recommended_actions", ())
    action_items = "".join(
        f"<li>{escape(str(action))}</li>" for action in recommended_actions
    )
    actions = ""
    if action_items:
        actions = (
            '<div class="actions"><strong>Recommended actions</strong>'
            f"<ul>{action_items}</ul></div>"
        )
    return "\n".join(
        [
            '<article class="incident '
            f'severity-{incident.severity.value.lower()}" '
            f'data-severity="{escape(incident.severity.value)}" '
            f'data-search="{_incident_search_text(incident)}">',
            '<div class="incident-head">',
            "<div>",
            f"<h3>{escape(incident.incident_id)}: "
            f"{escape(incident.title)}</h3>",
            f"<p>{escape(incident.description)}</p>",
            "</div>",
            '<div class="risk-pill">',
            f"<strong>{incident.risk_score}</strong>",
            f"<span>{escape(incident.severity.value)}</span>",
            "</div>",
            "</div>",
            f'<div class="factors">{factors}</div>',
            actions,
            '<div class="table-wrap"><table>',
            "<thead><tr><th>Time</th><th>Type</th>"
            "<th>User</th><th>IP</th></tr></thead>",
            f"<tbody>{event_rows}</tbody></table></div>",
            "</article>",
        ]
    )


def _campaign_row(campaign: AttackCampaign) -> str:
    incident_ids = ", ".join(campaign.incident_ids)
    source_ips = ", ".join(campaign.source_ips) or "none"
    usernames = ", ".join(campaign.usernames) or "none"
    return (
        "<tr>"
        f"<td><code>{escape(campaign.campaign_id)}</code></td>"
        f"<td>{escape(campaign.severity.value)}</td>"
        f"<td>{campaign.risk_score}</td>"
        f"<td>{escape(incident_ids)}</td>"
        f"<td>{escape(source_ips)}</td>"
        f"<td>{escape(usernames)}</td>"
        f"<td>{escape(campaign.summary)}</td>"
        "</tr>"
    )


def _ip_profile_row(profile: IpProfile) -> str:
    tags = " ".join(
        f"<span>{escape(tag)}</span>" for tag in profile.risk_tags
    )
    users = ", ".join(profile.usernames[:5])
    if len(profile.usernames) > 5:
        users += ", ..."
    return (
        "<tr>"
        f"<td><code>{escape(profile.ip_address)}</code></td>"
        f"<td>{escape(profile.scope.value)}</td>"
        f"<td>{profile.total_events}</td>"
        f"<td>{profile.failed_logins}</td>"
        f'<td title="{escape(", ".join(profile.usernames))}">'
        f"{escape(users)}</td>"
        f'<td><div class="factors">{tags}</div></td>'
        "</tr>"
    )


def _panel(title: str, body: str, caption: str) -> str:
    return (
        '<article class="panel">'
        f"<h2>{escape(title)}</h2>"
        f'<p class="caption">{escape(caption)}</p>'
        f"{body}"
        "</article>"
    )


def _section(title: str, body: str) -> str:
    return (
        '<section class="section">'
        f"<h2>{escape(title)}</h2>"
        f"{body}"
        "</section>"
    )


def _highest_risk(incidents: tuple[SecurityIncident, ...]) -> int:
    if not incidents:
        return 0
    return max(incident.risk_score for incident in incidents)


def _incident_search_text(incident: SecurityIncident) -> str:
    values = [
        incident.incident_id,
        incident.title,
        incident.description,
        incident.severity.value,
        incident.incident_type.value,
    ]
    for event in incident.events:
        values.extend(
            [
                event.ip_address,
                event.username,
                event.event_type.value,
            ]
        )
    values.extend(
        str(action)
        for action in incident.metadata.get("recommended_actions", ())
    )
    return escape(" ".join(values).lower(), quote=True)


def _dashboard_javascript() -> str:
    return """
const incidentFilter = document.getElementById("incidentFilter");
const severityFilter = document.getElementById("severityFilter");

function filterIncidents() {
  if (!incidentFilter || !severityFilter) {
    return;
  }
  const query = incidentFilter.value.trim().toLowerCase();
  const severity = severityFilter.value;
  document.querySelectorAll(".incident").forEach((card) => {
    const text = card.dataset.search || "";
    const severityOk = !severity || card.dataset.severity === severity;
    card.hidden = !(severityOk && text.includes(query));
  });
}

if (incidentFilter && severityFilter) {
  incidentFilter.addEventListener("input", filterIncidents);
  severityFilter.addEventListener("change", filterIncidents);
}
"""


def _dashboard_css() -> str:
    return """
    :root {
        color-scheme: light;
        --bg: #f5f7fb;
        --surface: #ffffff;
        --text: #17202a;
        --muted: #5d6b7a;
        --line: #d9e2ec;
        --accent: #1f7a8c;
        --failed: #c24135;
        --success: #2f855a;
        --warning: #c0841a;
        --critical: #8f1d2c;
        --shadow: 0 12px 32px rgba(20, 33, 43, 0.08);
    }
    * { box-sizing: border-box; }
    body {
        margin: 0;
        font-family: Arial, Helvetica, sans-serif;
        background: var(--bg);
        color: var(--text);
    }
    .page {
        width: min(1180px, calc(100% - 32px));
        margin: 0 auto;
        padding: 28px 0 48px;
    }
    .hero {
        min-height: 210px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 24px;
        padding: 30px;
        color: #ffffff;
        background:
            linear-gradient(120deg, rgba(12, 31, 48, 0.95),
            rgba(31, 122, 140, 0.88)),
            repeating-linear-gradient(45deg, #102a43 0 12px,
            #173b56 12px 24px);
        border: 1px solid #24485a;
    }
    .hero p, .hero span {
        margin: 0;
        color: #d8edf2;
    }
    .hero h1 {
        margin: 8px 0 12px;
        font-size: clamp(2rem, 5vw, 4.4rem);
        line-height: 1;
        letter-spacing: 0;
    }
    .hero-score {
        min-width: 160px;
        padding: 18px;
        border: 1px solid rgba(255, 255, 255, 0.32);
        text-align: center;
    }
    .hero-score strong {
        display: block;
        font-size: 3.5rem;
        line-height: 1;
    }
    .metrics {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 12px;
        margin: 18px 0;
    }
    .metric, .panel, .section, .incident {
        background: var(--surface);
        border: 1px solid var(--line);
        box-shadow: var(--shadow);
    }
    .metric {
        padding: 16px;
    }
    .metric span, .caption, .empty {
        color: var(--muted);
    }
    .metric strong {
        display: block;
        margin-top: 8px;
        font-size: 2rem;
    }
    .grid {
        display: grid;
        gap: 18px;
    }
    .two-columns {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .panel, .section {
        margin-top: 18px;
        padding: 18px;
    }
    h2, h3 {
        margin: 0 0 10px;
        letter-spacing: 0;
    }
    svg {
        width: 100%;
        height: auto;
        display: block;
    }
    .axis {
        stroke: var(--line);
        stroke-width: 2;
    }
    .axis-label {
        fill: var(--muted);
        font-size: 13px;
    }
    .failed { fill: var(--failed); }
    .success { fill: var(--success); }
    .incident-dot { fill: var(--critical); }
    .bar-row, .counter-row {
        display: grid;
        grid-template-columns: 100px 1fr 44px;
        align-items: center;
        gap: 10px;
        margin: 10px 0;
    }
    .counter-row {
        grid-template-columns: minmax(100px, 180px) 1fr 44px;
    }
    .bar-track {
        height: 12px;
        background: #edf2f7;
        border-radius: 999px;
        overflow: hidden;
    }
    .bar {
        height: 100%;
        border-radius: inherit;
    }
    .neutral { background: var(--accent); }
    .severity-low { background: #64748b; }
    .severity-medium { background: var(--warning); }
    .severity-high { background: #d65f2b; }
    .severity-critical { background: var(--critical); }
    .mini-heading {
        margin: 0 0 12px;
        color: var(--muted);
        font-size: 0.9rem;
    }
    .table-wrap {
        width: 100%;
        overflow-x: auto;
    }
    table {
        width: 100%;
        border-collapse: collapse;
    }
    th, td {
        padding: 9px 10px;
        border-bottom: 1px solid var(--line);
        text-align: left;
        vertical-align: top;
        white-space: nowrap;
    }
    th {
        color: var(--muted);
        font-size: 0.85rem;
        text-transform: uppercase;
    }
    code {
        font-family: Consolas, Monaco, monospace;
        white-space: pre-wrap;
    }
    .incidents {
        display: grid;
        gap: 14px;
    }
    .incident {
        padding: 16px;
        border-left-width: 5px;
        transition: opacity 0.15s ease, transform 0.15s ease;
    }
    .incident[hidden] {
        display: none;
    }
    .incident-head {
        display: flex;
        justify-content: space-between;
        gap: 18px;
    }
    .incident p {
        margin: 4px 0 0;
        color: var(--muted);
    }
    .risk-pill {
        min-width: 84px;
        padding: 10px;
        border: 1px solid var(--line);
        text-align: center;
    }
    .risk-pill strong {
        display: block;
        font-size: 1.8rem;
    }
    .risk-pill span {
        color: var(--muted);
        font-size: 0.78rem;
    }
    .factors {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin: 12px 0;
    }
    .factors span {
        padding: 4px 8px;
        border: 1px solid var(--line);
        color: var(--muted);
        font-size: 0.78rem;
        background: #f8fafc;
    }
    .actions {
        margin: 10px 0 12px;
        padding: 10px 12px;
        background: #f8fafc;
        border: 1px solid var(--line);
    }
    .actions strong {
        display: block;
        margin-bottom: 6px;
        color: var(--text);
        font-size: 0.82rem;
        text-transform: uppercase;
    }
    .actions ul {
        margin: 0;
        padding-left: 18px;
        color: var(--muted);
    }
    .toolbar {
        display: grid;
        grid-template-columns: minmax(0, 1fr) 180px;
        gap: 10px;
        margin-bottom: 14px;
    }
    input, select {
        min-height: 38px;
        border: 1px solid var(--line);
        padding: 8px 10px;
        color: var(--text);
        background: #ffffff;
        font: inherit;
    }
    @media (max-width: 820px) {
        .hero, .incident-head {
            flex-direction: column;
            align-items: stretch;
        }
        .metrics, .two-columns, .toolbar {
            grid-template-columns: 1fr;
        }
        .bar-row, .counter-row {
            grid-template-columns: 88px 1fr 36px;
        }
    }
    """

"""Small local web application for interactive log analysis."""

from __future__ import annotations

import json
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from src.config import AnalyzerConfig, build_config
from src.incidents import analyze_file
from src.report import result_to_dict


# @generated [partially] OpenAI ChatGPT/Codex 2026-05-23:
# local web interface layout, CSS structure, and short UI wording drafts.
# Final logic, checks, edits, and project integration were reviewed by author.

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


def run_app(
    file_path: str,
    config: AnalyzerConfig,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    default_year: int | None = None,
    open_browser: bool = False,
) -> int:
    """Start the local analyzer web application."""

    handler_class = _make_handler(
        default_file=file_path,
        default_config=config,
        default_year=default_year,
    )
    server = ThreadingHTTPServer((host, port), handler_class)
    url = f"http://{host}:{server.server_port}"

    print(f"Security Log Analyzer app running at {url}")
    print("Press Ctrl+C to stop the server.")

    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()

    return 0


def analyze_for_app(
    file_path: str,
    config: AnalyzerConfig,
    default_year: int | None = None,
) -> dict[str, Any]:
    """Analyze a file and return JSON-friendly web-app data."""

    result = analyze_file(
        file_path,
        config=config,
        default_year=default_year,
    )
    payload = result_to_dict(result)
    payload["ok"] = True
    return payload


def _make_handler(
    default_file: str,
    default_config: AnalyzerConfig,
    default_year: int | None,
):
    class AnalyzerRequestHandler(BaseHTTPRequestHandler):
        """HTTP handler for the local analyzer application."""

        server_version = "SecurityLogAnalyzer/1.0"

        def do_GET(self) -> None:
            if self.path in {"/", "/index.html"}:
                self._send_html(
                    _app_shell(
                        default_file=default_file,
                        default_config=default_config,
                        default_year=default_year,
                    )
                )
                return

            if self.path == "/health":
                self._send_json({"ok": True})
                return

            self._send_json(
                {"ok": False, "error": "not found"},
                status=HTTPStatus.NOT_FOUND,
            )

        def do_POST(self) -> None:
            if self.path != "/api/analyze":
                self._send_json(
                    {"ok": False, "error": "not found"},
                    status=HTTPStatus.NOT_FOUND,
                )
                return

            try:
                request = self._read_json_body()
                file_path = str(request.get("file_path") or default_file)
                config = _config_from_payload(request, default_config)
                year = request.get("default_year", default_year)
                year = _optional_int(year)
                response = analyze_for_app(
                    file_path=file_path,
                    config=config,
                    default_year=year,
                )
            except (OSError, ValueError) as error:
                self._send_json(
                    {"ok": False, "error": str(error)},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            self._send_json(response)

        # pylint: disable-next=redefined-builtin
        def log_message(self, format, *args):
            # Keep the parent signature and silence access logs.
            return

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length).decode("utf-8")
            if not raw_body:
                return {}
            loaded = json.loads(raw_body)
            if not isinstance(loaded, dict):
                raise ValueError("JSON request body must be an object")
            return loaded

        def _send_html(self, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.end_headers()
            self.wfile.write(encoded)

        def _send_json(
            self,
            body: dict[str, Any],
            status: HTTPStatus = HTTPStatus.OK,
        ) -> None:
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.end_headers()
            self.wfile.write(encoded)

    return AnalyzerRequestHandler


def _config_from_payload(
    payload: dict[str, Any],
    default_config: AnalyzerConfig,
) -> AnalyzerConfig:
    return build_config(
        profile=str(payload.get("profile") or default_config.profile),
        threshold=_optional_int(payload.get("threshold")),
        window_seconds=_optional_int(payload.get("window_seconds")),
        user_threshold=_optional_int(payload.get("user_threshold")),
        distributed_threshold=_optional_int(
            payload.get("distributed_threshold")
        ),
        success_threshold=_optional_int(payload.get("success_threshold")),
        timeline_bucket_seconds=_optional_int(
            payload.get("timeline_bucket_seconds")
        ),
        top_limit=_optional_int(payload.get("top_limit")),
        max_events_per_incident=_optional_int(
            payload.get("max_events_per_incident")
        ),
    )


def _optional_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    number = int(value)
    if number <= 0:
        raise ValueError("numeric settings must be greater than zero")
    return number


def _app_shell(
    default_file: str,
    default_config: AnalyzerConfig,
    default_year: int | None,
) -> str:
    app_state = {
        "filePath": str(Path(default_file)),
        "profile": default_config.profile,
        "threshold": default_config.threshold,
        "windowSeconds": default_config.window_seconds,
        "topLimit": default_config.top_limit,
        "bucketSeconds": default_config.timeline_bucket_seconds,
        "defaultYear": default_year or "",
    }
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" '
            'content="width=device-width, initial-scale=1">',
            "<title>Security Log Analyzer App</title>",
            f"<style>{_app_css()}</style>",
            "</head>",
            "<body>",
            '<main class="shell">',
            _app_markup(),
            "</main>",
            "<script>",
            f"const DEFAULT_STATE = {json.dumps(app_state)};",
            _app_javascript(),
            "</script>",
            "</body>",
            "</html>",
        ]
    )


# @generated [partially] OpenAI ChatGPT/Codex 2026-05-23:
# initial HTML layout idea for the local analysis console.
def _app_markup() -> str:
    return """
<section class="topbar">
  <div class="topbar-main">
    <p class="eyebrow">Security Log Analyzer</p>
    <h1>Authentication Log Analysis</h1>
    <p class="subtitle">Local parsing, detection, and risk scoring.</p>
  </div>
  <div class="status-wrap" aria-label="Analyzer status">
    <span class="status-dot"></span>
    <span>Status:</span>
    <span class="status-text" id="status">Ready</span>
  </div>
</section>

<section class="workspace">
  <aside class="controls">
    <label>
      Log file
      <input id="filePath" type="text" autocomplete="off">
    </label>
    <div class="control-grid">
      <label>
        Profile
        <select id="profile">
          <option value="strict">strict</option>
          <option value="balanced">balanced</option>
          <option value="relaxed">relaxed</option>
        </select>
      </label>
      <label>
        Threshold
        <input id="threshold" type="number" min="1">
      </label>
      <label>
        Window
        <input id="windowSeconds" type="number" min="1">
      </label>
      <label>
        Top
        <input id="topLimit" type="number" min="1">
      </label>
      <label>
        Bucket
        <input id="bucketSeconds" type="number" min="1">
      </label>
      <label>
        Syslog year
        <input id="defaultYear" type="number" min="1970">
      </label>
    </div>
    <button class="primary" id="analyzeButton">Analyze</button>
    <button class="secondary" id="downloadJsonButton">Export JSON</button>
  </aside>

  <section class="content">
    <nav class="tabs" aria-label="Dashboard views">
      <button class="tab active" data-tab="overview">Overview</button>
      <button class="tab" data-tab="incidents">Incidents</button>
      <button class="tab" data-tab="ips">IP Profiles</button>
      <button class="tab" data-tab="diagnostics">Diagnostics</button>
    </nav>
    <section class="view active" id="view-overview">
      <div class="overview-focus">
        <article class="summary-panel" id="overviewSummary"></article>
        <article class="panel priority-panel">
          <h2>Priority Signals</h2>
          <div id="prioritySignals"></div>
        </article>
      </div>
      <div class="section-head">
        <h2>Key Metrics</h2>
        <span id="analysisRange"></span>
      </div>
      <div class="metrics" id="metrics"></div>
      <div class="grid overview-grid">
        <article class="panel timeline-panel">
          <h2>Timeline</h2>
          <div id="timeline"></div>
        </article>
        <article class="panel">
          <h2>Severity</h2>
          <div id="severity"></div>
        </article>
        <article class="panel">
          <h2>Top Source IPs</h2>
          <div id="topIps"></div>
        </article>
        <article class="panel">
          <h2>Top Users</h2>
          <div id="topUsers"></div>
        </article>
      </div>
    </section>
    <section class="view" id="view-incidents">
      <div class="toolbar">
        <input id="incidentSearch" type="search" placeholder="Search">
        <select id="severityFilter">
          <option value="">all severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
      </div>
      <div class="incident-list" id="incidents"></div>
    </section>
    <section class="view" id="view-ips">
      <div id="ipProfiles"></div>
    </section>
    <section class="view" id="view-diagnostics">
      <div id="diagnostics"></div>
    </section>
  </section>
</section>
"""


# @generated [partially] OpenAI ChatGPT/Codex 2026-05-23:
# visual style draft for the local dashboard, later adjusted manually.
def _app_css() -> str:
    return """
:root {
  color-scheme: light;
  --bg: #f3f6f8;
  --surface: #ffffff;
  --surface-2: #f7fafc;
  --text: #14212b;
  --muted: #607080;
  --line: #d7e1ea;
  --accent: #1f7a8c;
  --accent-dark: #15586a;
  --failed: #bf3b32;
  --success: #2f855a;
  --warn: #c0841a;
  --critical: #8f1d2c;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  font-family: Arial, Helvetica, sans-serif;
  color: var(--text);
  background: var(--bg);
}
button, input, select {
  font: inherit;
}
.shell {
  width: min(1180px, calc(100% - 28px));
  margin: 0 auto;
  padding: 18px 0 36px;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 18px 22px;
  background: var(--surface);
  border: 1px solid var(--line);
}
.topbar-main {
  display: grid;
  gap: 6px;
}
.eyebrow {
  margin: 0;
  color: var(--accent-dark);
  font-size: 0.88rem;
  font-weight: 700;
  text-transform: uppercase;
}
h1, h2, h3, p {
  margin-top: 0;
}
h1 {
  margin-bottom: 2px;
  font-size: 2.1rem;
  line-height: 1.12;
  letter-spacing: 0;
}
h2 {
  margin-bottom: 14px;
  letter-spacing: 0;
}
.subtitle {
  margin: 0;
  color: var(--muted);
  font-size: 0.95rem;
}
.status-wrap {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 8px 10px;
  color: var(--text);
  background: var(--surface-2);
  border: 1px solid var(--line);
  font-size: 0.86rem;
  white-space: nowrap;
}
.status-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: #7ee787;
  box-shadow: 0 0 0 4px rgba(126, 231, 135, 0.16);
}
.workspace {
  display: grid;
  grid-template-columns: 280px minmax(0, 1fr);
  gap: 16px;
  margin-top: 16px;
}
.controls, .content, .panel, .metric, .incident-card {
  background: var(--surface);
  border: 1px solid var(--line);
}
.controls {
  position: sticky;
  top: 16px;
  align-self: start;
  padding: 16px;
}
label {
  display: grid;
  gap: 7px;
  margin-bottom: 12px;
  color: var(--muted);
  font-size: 0.9rem;
}
input, select {
  width: 100%;
  min-height: 38px;
  border: 1px solid var(--line);
  padding: 8px 10px;
  color: var(--text);
  background: #ffffff;
}
.control-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}
button {
  min-height: 40px;
  border: 1px solid transparent;
  padding: 9px 12px;
  cursor: pointer;
}
.primary {
  width: 100%;
  margin-top: 4px;
  color: #ffffff;
  background: var(--accent);
}
.primary:hover {
  background: var(--accent-dark);
}
.secondary {
  width: 100%;
  margin-top: 10px;
  color: var(--accent-dark);
  background: #e8f3f5;
  border-color: #b9d9df;
}
.content {
  min-width: 0;
  padding: 14px;
}
.overview-focus {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(280px, 0.75fr);
  gap: 14px;
  margin-bottom: 14px;
}
.summary-panel {
  display: grid;
  grid-template-columns: minmax(250px, 0.72fr) minmax(0, 1.28fr);
  min-width: 0;
  background: var(--surface);
  border: 1px solid var(--line);
}
.posture-card {
  min-height: 184px;
  display: grid;
  align-content: space-between;
  gap: 18px;
  padding: 22px;
  color: var(--text);
  background: var(--surface);
  border-left: 5px solid var(--accent);
}
.posture-kicker,
.summary-facts span {
  display: block;
  margin-bottom: 7px;
  font-size: 0.78rem;
  text-transform: uppercase;
  color: var(--muted);
}
.posture-title-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}
.posture-title-row strong {
  display: inline-block;
  padding: 7px 12px 9px;
  color: var(--text);
  border: 1px solid var(--line);
  background: var(--surface-2);
  font-size: clamp(1.55rem, 2.3vw, 2.25rem);
  line-height: 1;
}
.posture-title-row span {
  color: var(--muted);
  font-size: 0.95rem;
}
.posture-card p {
  max-width: 30rem;
  margin-bottom: 0;
  font-size: 1rem;
  line-height: 1.35;
  color: var(--muted);
}
.posture-critical { border-left-color: var(--critical); }
.posture-high { border-left-color: #b9472f; }
.posture-medium { border-left-color: var(--warn); }
.posture-low { border-left-color: var(--success); }
.summary-facts {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.summary-facts div {
  min-width: 0;
  padding: 16px;
  border-left: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
  background:
    linear-gradient(180deg, rgba(247, 250, 252, 0.7), #ffffff);
}
.summary-facts span {
  color: var(--muted);
}
.summary-facts strong {
  display: block;
  overflow: hidden;
  font-size: 1.25rem;
  line-height: 1.15;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.section-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 14px;
  margin: 2px 0 10px;
}
.section-head h2 {
  margin-bottom: 0;
}
.section-head span {
  color: var(--muted);
  font-size: 0.9rem;
}
.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 14px;
  overflow-x: auto;
}
.tab {
  color: var(--muted);
  background: var(--surface-2);
  border-color: var(--line);
}
.tab.active {
  color: #ffffff;
  background: var(--text);
}
.view {
  display: none;
}
.view.active {
  display: block;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}
.metric {
  padding: 14px;
}
.metric span {
  color: var(--muted);
}
.metric strong {
  display: block;
  margin-top: 8px;
  font-size: 2rem;
  line-height: 1;
}
.grid {
  display: grid;
  gap: 14px;
}
.two {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.overview-grid {
  grid-template-columns: minmax(0, 1.2fr) minmax(280px, 0.8fr);
}
.timeline-panel {
  grid-row: span 2;
}
.panel {
  min-width: 0;
  padding: 16px;
}
.priority-panel {
  display: grid;
  align-content: start;
  border-top: 4px solid var(--accent);
}
.signal {
  padding: 11px 0;
  border-bottom: 1px solid var(--line);
}
.signal:last-child {
  border-bottom: 0;
}
.signal span {
  display: block;
  margin-bottom: 5px;
  color: var(--muted);
  font-size: 0.82rem;
  text-transform: uppercase;
}
.signal strong {
  display: block;
  line-height: 1.25;
  font-size: 0.98rem;
}
.bar-row, .counter-row {
  display: grid;
  grid-template-columns: minmax(86px, 140px) 1fr 46px;
  gap: 10px;
  align-items: center;
  margin: 10px 0;
}
.bar-track {
  height: 12px;
  overflow: hidden;
  background: #edf2f7;
  border-radius: 999px;
}
.bar {
  height: 100%;
  border-radius: inherit;
  background: var(--accent);
}
.sev-low { background: #64748b; }
.sev-medium { background: var(--warn); }
.sev-high { background: #d65f2b; }
.sev-critical { background: var(--critical); }
svg {
  width: 100%;
  height: auto;
  display: block;
}
.axis {
  stroke: var(--line);
  stroke-width: 2;
}
.failed {
  fill: var(--failed);
}
.success {
  fill: var(--success);
}
.dot {
  fill: var(--critical);
}
.toolbar {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 180px;
  gap: 10px;
  margin-bottom: 14px;
}
.incident-list {
  display: grid;
  gap: 12px;
}
.incident-card {
  padding: 14px;
  border-left: 5px solid var(--accent);
}
.incident-head {
  display: flex;
  justify-content: space-between;
  gap: 14px;
}
.incident-head p {
  color: var(--muted);
  margin-bottom: 0;
}
.risk {
  min-width: 76px;
  padding: 8px;
  border: 1px solid var(--line);
  text-align: center;
}
.risk strong {
  display: block;
  font-size: 1.7rem;
  line-height: 1;
}
.tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin: 12px 0;
}
.tags span {
  padding: 4px 8px;
  color: var(--muted);
  background: var(--surface-2);
  border: 1px solid var(--line);
  font-size: 0.78rem;
}
.actions {
  margin: 10px 0 12px;
  padding: 10px 12px;
  background: var(--surface-2);
  border: 1px solid var(--line);
}
.actions strong {
  display: block;
  margin-bottom: 6px;
  font-size: 0.78rem;
  text-transform: uppercase;
}
.actions ul {
  margin: 0;
  padding-left: 18px;
  color: var(--muted);
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
  white-space: nowrap;
}
th {
  color: var(--muted);
  font-size: 0.78rem;
  text-transform: uppercase;
}
code {
  font-family: Consolas, Monaco, monospace;
}
.empty {
  color: var(--muted);
}
@media (max-width: 980px) {
  .workspace,
  .two,
  .metrics,
  .overview-focus,
  .overview-grid,
  .summary-panel {
    grid-template-columns: 1fr;
  }
  .controls {
    position: static;
  }
  .topbar {
    flex-direction: column;
    align-items: flex-start;
  }
  .toolbar {
    grid-template-columns: 1fr;
  }
}
"""


# @generated [partially] OpenAI ChatGPT/Codex 2026-05-23:
# small UI rendering helpers for overview cards, tables, and filters.
def _app_javascript() -> str:
    return """
const state = { data: null };

const $ = (id) => document.getElementById(id);

function setStatus(text) {
  $("status").textContent = text;
}

function readPayload() {
  return {
    file_path: $("filePath").value.trim(),
    profile: $("profile").value,
    threshold: $("threshold").value,
    window_seconds: $("windowSeconds").value,
    top_limit: $("topLimit").value,
    timeline_bucket_seconds: $("bucketSeconds").value,
    default_year: $("defaultYear").value
  };
}

async function analyze() {
  setStatus("Analyzing");
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(readPayload())
    });
    const payload = await response.json();
    if (!payload.ok) {
      throw new Error(payload.error || "analysis failed");
    }
    state.data = payload;
    render(payload);
    setStatus("Ready");
  } catch (error) {
    setStatus("Error");
    alert(error.message);
  }
}

function render(data) {
  renderOverviewSummary(data);
  renderPrioritySignals(data);
  renderMetrics(data);
  renderTimeline(data.timeline);
  renderSeverity(data.statistics.severity_counts);
  renderBars("topIps", data.top_ips);
  renderBars("topUsers", data.top_users);
  renderIncidents();
  renderIpProfiles(data.ip_profiles);
  renderDiagnostics(data.parse_issues);
}

function renderOverviewSummary(data) {
  const stats = data.statistics;
  const highestRisk = highestIncidentRisk(data.incidents);
  const posture = postureFromRisk(highestRisk);
  const critical = stats.severity_counts.CRITICAL || 0;
  const high = stats.severity_counts.HIGH || 0;
  const topIp = data.top_ips[0]?.label || "no source";
  const topUser = data.top_users[0]?.label || "no user";
  const failedRatio = stats.total_events
    ? Math.round(stats.failed_logins / stats.total_events * 100)
    : 0;
  $("overviewSummary").innerHTML = `
    <div class="posture-card ${posture.className}">
      <span class="posture-kicker">Threat posture</span>
      <div class="posture-title-row">
        <strong>${posture.label}</strong>
        <span>${highestRisk}/100</span>
      </div>
      <p>${posture.description}</p>
    </div>
    <div class="summary-facts">
      <div>
        <span>Highest risk</span>
        <strong>${highestRisk}/100</strong>
      </div>
      <div>
        <span>Critical + high</span>
        <strong>${critical + high}</strong>
      </div>
      <div>
        <span>Main source</span>
        <strong>${escapeHtml(topIp)}</strong>
      </div>
      <div>
        <span>Main target</span>
        <strong>${escapeHtml(topUser)}</strong>
      </div>
      <div>
        <span>Failed ratio</span>
        <strong>${failedRatio}%</strong>
      </div>
      <div>
        <span>Skipped lines</span>
        <strong>${stats.skipped_lines}</strong>
      </div>
    </div>
  `;
  $("analysisRange").textContent = formatRange(
    stats.first_seen,
    stats.last_seen
  );
}

function renderPrioritySignals(data) {
  const stats = data.statistics;
  const incidents = data.incidents;
  const firstCritical = incidents.find((item) => item.severity === "CRITICAL");
  const successAfterFailures = incidents.find(
    (item) => item.type === "success_after_failures"
  );
  const firstCampaign = data.campaigns[0];
  const topIp = data.top_ips[0];
  const signals = [];

  if (firstCritical) {
    signals.push([
      "Investigate first",
      `${firstCritical.id}: ${firstCritical.title}`
    ]);
  }
  if (successAfterFailures) {
    signals.push([
      "Possible account compromise",
      `${successAfterFailures.metadata.username || "user"} after failures`
    ]);
  }
  if (firstCampaign) {
    signals.push([
      "Correlated campaign",
      `${firstCampaign.id}: ${firstCampaign.summary}`
    ]);
  }
  if (topIp) {
    signals.push([
      "Noisiest source",
      `${topIp.label} with ${topIp.failed_logins} failed login(s)`
    ]);
  }
  if (stats.skipped_lines) {
    signals.push([
      "Parser check",
      `${stats.skipped_lines} skipped line(s) need format review`
    ]);
  }
  if (!signals.length) {
    signals.push(["Status", "No suspicious priority signal was detected"]);
  }

  $("prioritySignals").innerHTML = signals.map(([title, body]) => `
    <div class="signal">
      <span>${escapeHtml(title)}</span>
      <strong>${escapeHtml(body)}</strong>
    </div>
  `).join("");
}

function renderMetrics(data) {
  const stats = data.statistics;
  const items = [
    ["Parsed events", stats.total_events],
    ["Failed logins", stats.failed_logins],
    ["Successful", stats.successful_logins],
    ["Incidents", stats.incidents_count],
    ["Campaigns", data.campaigns.length],
    ["Unique IPs", stats.unique_ips],
    ["Unique users", stats.unique_users],
    ["Suspicious IPs", stats.suspicious_ips.length],
    ["Skipped lines", stats.skipped_lines]
  ];
  $("metrics").innerHTML = items.map(([label, value]) => `
    <article class="metric">
      <span>${escapeHtml(label)}</span>
      <strong>${value}</strong>
    </article>
  `).join("");
}

function highestIncidentRisk(incidents) {
  if (!incidents.length) {
    return 0;
  }
  return Math.max(...incidents.map((incident) => incident.risk_score));
}

function postureFromRisk(score) {
  if (score >= 85) {
    return {
      label: "Critical",
      className: "posture-critical",
      description: "Immediate review is recommended before normal operation."
    };
  }
  if (score >= 60) {
    return {
      label: "High",
      className: "posture-high",
      description: "Several suspicious patterns deserve analyst attention."
    };
  }
  if (score >= 30) {
    return {
      label: "Medium",
      className: "posture-medium",
      description: "Some unusual authentication behavior was detected."
    };
  }
  return {
    label: "Low",
    className: "posture-low",
    description: "No strong incident pattern was detected in this log."
  };
}

function formatRange(firstSeen, lastSeen) {
  if (!firstSeen || !lastSeen) {
    return "No parsed event range";
  }
  return `${firstSeen} to ${lastSeen}`;
}

function renderTimeline(timeline) {
  if (!timeline.length) {
    $("timeline").innerHTML = `<p class="empty">No events.</p>`;
    return;
  }
  const width = 760;
  const height = 250;
  const pad = 30;
  const chartW = width - pad * 2;
  const chartH = height - pad * 2;
  const maxCount = Math.max(...timeline.map((item) => item.total_events), 1);
  const step = chartW / timeline.length;
  const barW = Math.max(step - 4, 8);
  const bars = timeline.map((bucket, index) => {
    const x = pad + index * step;
    const failedH = chartH * bucket.failed_logins / maxCount;
    const successH = chartH * bucket.successful_logins / maxCount;
    const failedY = pad + chartH - failedH;
    const successY = failedY - successH;
    const dot = bucket.incident_count
      ? `<circle class="dot" cx="${x + barW / 2}" cy="${successY - 8}" r="5"/>`
      : "";
    return `
      <rect class="failed" x="${x}" y="${failedY}" width="${barW}"
        height="${failedH}"></rect>
      <rect class="success" x="${x}" y="${successY}" width="${barW}"
        height="${successH}"></rect>
      ${dot}
    `;
  }).join("");
  $("timeline").innerHTML = `
    <svg viewBox="0 0 ${width} ${height}">
      <line class="axis" x1="${pad}" y1="${pad + chartH}"
        x2="${width - pad}" y2="${pad + chartH}"></line>
      ${bars}
    </svg>
  `;
}

function renderSeverity(counts) {
  const names = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const total = names.reduce((sum, name) => sum + (counts[name] || 0), 0) || 1;
  $("severity").innerHTML = names.map((name) => {
    const count = counts[name] || 0;
    const width = count ? Math.max(4, Math.round(count / total * 100)) : 0;
    return `
      <div class="bar-row">
        <span>${name}</span>
        <div class="bar-track">
          <div class="bar sev-${name.toLowerCase()}"
            style="width:${width}%"></div>
        </div>
        <strong>${count}</strong>
      </div>
    `;
  }).join("");
}

function renderBars(targetId, items) {
  if (!items.length) {
    $(targetId).innerHTML = `<p class="empty">No data.</p>`;
    return;
  }
  const maxValue = Math.max(...items.map((item) => item.total_events), 1);
  $(targetId).innerHTML = items.map((item) => {
    const width = Math.max(5, Math.round(item.total_events / maxValue * 100));
    const label = escapeHtml(item.label);
    return `
      <div class="counter-row">
        <span title="${label}">${label}</span>
        <div class="bar-track">
          <div class="bar" style="width:${width}%"></div>
        </div>
        <strong>${item.total_events}</strong>
      </div>
    `;
  }).join("");
}

function renderIncidents() {
  if (!state.data) {
    return;
  }
  const search = $("incidentSearch").value.toLowerCase();
  const severity = $("severityFilter").value;
  const incidents = state.data.incidents.filter((incident) => {
    const text = JSON.stringify(incident).toLowerCase();
    const severityOk = !severity || incident.severity === severity;
    return severityOk && text.includes(search);
  });
  if (!incidents.length) {
    $("incidents").innerHTML = `<p class="empty">No matching incidents.</p>`;
    return;
  }
  $("incidents").innerHTML = incidents.map((incident) => {
    const tags = (incident.metadata.risk_factors || [])
      .map((tag) => `<span>${escapeHtml(String(tag))}</span>`)
      .join("");
    const actions = (incident.metadata.recommended_actions || [])
      .map((action) => `<li>${escapeHtml(String(action))}</li>`)
      .join("");
    const actionBlock = actions
      ? `<div class="actions"><strong>Recommended actions</strong>
          <ul>${actions}</ul></div>`
      : "";
    const rows = incident.events.map((event) => `
      <tr>
        <td>${escapeHtml(event.timestamp)}</td>
        <td>${escapeHtml(event.event_type)}</td>
        <td>${escapeHtml(event.username)}</td>
        <td>${escapeHtml(event.ip_address)}</td>
      </tr>
    `).join("");
    return `
      <article class="incident-card">
        <div class="incident-head">
          <div>
            <h3>${escapeHtml(incident.id)}: ${escapeHtml(incident.title)}</h3>
            <p>${escapeHtml(incident.description)}</p>
          </div>
          <div class="risk">
            <strong>${incident.risk_score}</strong>
            <span>${escapeHtml(incident.severity)}</span>
          </div>
        </div>
        <div class="tags">${tags}</div>
        ${actionBlock}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th><th>Type</th><th>User</th><th>IP</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </article>
    `;
  }).join("");
}

function renderIpProfiles(profiles) {
  if (!profiles.length) {
    $("ipProfiles").innerHTML = `<p class="empty">No IP profiles.</p>`;
    return;
  }
  const rows = profiles.map((profile) => {
    const tags = profile.risk_tags
      .map((tag) => `<span>${escapeHtml(tag)}</span>`)
      .join("");
    return `
      <tr>
        <td><code>${escapeHtml(profile.ip_address)}</code></td>
        <td>${escapeHtml(profile.scope)}</td>
        <td>${profile.total_events}</td>
        <td>${profile.failed_logins}</td>
        <td>${escapeHtml(profile.usernames.join(", "))}</td>
        <td><div class="tags">${tags}</div></td>
      </tr>
    `;
  }).join("");
  $("ipProfiles").innerHTML = `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>IP</th><th>Scope</th><th>Events</th>
            <th>Failed</th><th>Users</th><th>Tags</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderDiagnostics(issues) {
  if (!issues.length) {
    $("diagnostics").innerHTML = `<p class="empty">No skipped lines.</p>`;
    return;
  }
  const rows = issues.map((issue) => `
    <tr>
      <td>${issue.line_number}</td>
      <td>${escapeHtml(issue.reason)}</td>
      <td><code>${escapeHtml(issue.raw_line)}</code></td>
    </tr>
  `).join("");
  $("diagnostics").innerHTML = `
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Line</th><th>Reason</th><th>Raw line</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function downloadJson() {
  if (!state.data) {
    return;
  }
  const blob = new Blob(
    [JSON.stringify(state.data, null, 2)],
    { type: "application/json" }
  );
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "security-log-analysis.json";
  link.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setup() {
  $("filePath").value = DEFAULT_STATE.filePath;
  $("profile").value = DEFAULT_STATE.profile;
  $("threshold").value = DEFAULT_STATE.threshold;
  $("windowSeconds").value = DEFAULT_STATE.windowSeconds;
  $("topLimit").value = DEFAULT_STATE.topLimit;
  $("bucketSeconds").value = DEFAULT_STATE.bucketSeconds;
  $("defaultYear").value = DEFAULT_STATE.defaultYear;
  $("analyzeButton").addEventListener("click", analyze);
  $("downloadJsonButton").addEventListener("click", downloadJson);
  $("incidentSearch").addEventListener("input", renderIncidents);
  $("severityFilter").addEventListener("change", renderIncidents);
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((item) => {
        item.classList.remove("active");
      });
      document.querySelectorAll(".view").forEach((item) => {
        item.classList.remove("active");
      });
      tab.classList.add("active");
      $(`view-${tab.dataset.tab}`).classList.add("active");
    });
  });
  analyze();
}

setup();
"""

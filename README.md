# Security Log Analyzer

A Python tool for investigating suspicious authentication activity. It parses
login logs, detects brute-force and account-takeover patterns, correlates
incidents into attack campaigns, and presents the results through a CLI,
an interactive local web app, and TXT, JSON, or HTML reports.

Developed as a semester project for the Python programming course (BI-PYT)
at the Faculty of Information Technology, Czech Technical University in Prague.

**Stack:** Python, pytest, pandas, NumPy, Matplotlib, and a local web interface
built with the Python standard library.

## Features

- CLI interface with `app`, `analyze`, `charts`, `dashboard`, and `stats`
  commands.
- Backward-compatible simple launch: `python main.py --file ...`.
- Parsing of several authentication log formats:
  - simple ISO timestamp format from the assignment;
  - Linux/OpenSSH syslog-like lines;
  - key-value application authentication lines.
- Skipped-line diagnostics instead of crashing on invalid input.
- Detection rules:
  - brute-force attempts from one IP address;
  - username enumeration from one IP address;
  - successful login after repeated failures;
  - distributed attack against one username;
  - possible account takeover after distributed failures;
  - low-and-slow brute force spread across a longer period.
- Incident grouping, risk scoring, severity labels, risk factors, and
  recommended response actions.
- Campaign correlation: related incidents are linked into higher-level
  attack campaigns when they share source IPs, usernames, and time context.
- Local IP profiling: public/private scope, failed/success counts, users,
  incident links, and risk tags.
- Timeline, top IPs, top usernames, parser diagnostics, and severity
  statistics.
- Local web application on `localhost` without Flask/Django dependencies.
- Optional self-contained HTML dashboard export with visual charts and
  incident filtering.
- Optional PNG chart export using `pandas`, `numpy`, and `matplotlib`.

## Project Structure

```text
src/
    main.py
    cli.py
    config.py
    models.py
    parser.py
    rules.py
    incidents.py
    campaigns.py
    risk.py
    remediation.py
    statistics.py
    timeline.py
    enrichment.py
    filters.py
    dashboard.py
    webapp.py
    visualization.py
    report.py
tests/
    test_parser.py
    test_rules.py
    test_risk.py
    test_incidents.py
    test_campaigns.py
    test_dashboard.py
    test_webapp.py
    test_visualization.py
data/
    sample_auth.log
README.md
requirements.txt
repestyk.pdf
```

## Installation

Tested with Python 3.14. Run the following commands from the project root:

```bash
git clone https://github.com/TykhonRepeshko/security-log-analyzer.git
cd security-log-analyzer
python -m venv .venv
```

Activate the virtual environment on Windows (PowerShell):

```powershell
.\.venv\Scripts\Activate.ps1
```

Or on Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

The analyzer, local web app, and HTML export use only the standard library.
pandas, NumPy, and Matplotlib are used for PNG chart export; pytest and the
lint tools are development dependencies.

## Usage

Recommended way to try the project is the local app:

```bash
python main.py app --file data/sample_auth.log --default-year 2026
```

Then open `http://127.0.0.1:8000` in a browser. The app lets you change the
profile, threshold, time window, top-N size, file path, and export JSON.

The CLI analyzer is still the core of the project and can be used without
the browser:

```bash
python main.py analyze --file data/sample_auth.log --format txt
```

The included sample produces 35 parsed authentication events, 9 incidents,
and 2 correlated attack campaigns with the default balanced profile and
`--default-year 2026`. Two unsupported lines are reported as parser diagnostics.

The old short form also works:

```bash
python main.py --file data/sample_auth.log --threshold 5 --window 120
```

Generate a JSON report:

```bash
python main.py --file data/sample_auth.log --threshold 5 --window 120 \
    --output report.json --format json
```

Generate the visual HTML dashboard:

```bash
python main.py dashboard --file data/sample_auth.log --output dashboard.html
```

Open `dashboard.html` in a browser to inspect charts, top IPs, IP profiles,
incidents, and parser diagnostics.

Generate PNG charts with pandas, numpy, and matplotlib:

```bash
python main.py charts --file data/sample_auth.log --output charts
```

This creates timeline, top-IP, and severity-distribution images in the
selected output directory.

Use a stricter profile:

```bash
python main.py analyze --file data/sample_auth.log --profile strict
```

The same application can also be started as a module:

```bash
python -m src.main --file data/sample_auth.log --format txt
```

## CLI Parameters

- `--file`: path to the log file, required.
- `--profile`: detection profile, `strict`, `balanced`, or `relaxed`.
- `--threshold`: override the default repeated-activity threshold.
- `--window`: override the detection time window in seconds.
- `--user-threshold`: override username enumeration threshold.
- `--distributed-threshold`: override distributed attack threshold.
- `--success-threshold`: override success-after-failures threshold.
- `--bucket`: timeline bucket size in seconds for charts.
- `--top`: number of top IPs/users shown in reports.
- `--output`: optional path where the report will be saved.
- `--format`: report format, `txt`, `json`, or `html`, default `txt`.
- `--from` and `--to`: optional time filters.
- `--users` and `--ips`: optional comma-separated filters.
- `--default-year`: year used for syslog lines that do not contain a year.
- `--host` and `--port`: app server address for the `app` command.

## Interface Field Guide

The local web app uses the same settings as the CLI:

- `Profile`: predefined sensitivity preset. `strict` finds smaller patterns,
  `balanced` is the default, and `relaxed` needs more evidence before raising
  incidents.
- `Threshold`: main count limit for repeated suspicious activity. For example,
  threshold `5` means five related failed logins can trigger a rule.
- `Window`: detection time window in seconds. For example, `120` means the
  rule looks for repeated attempts inside two minutes.
- `Top`: how many top IP addresses and usernames are shown in summaries.
- `Bucket`: timeline aggregation size in seconds. For example, `300` groups
  events into five-minute blocks for charts and dashboards.
- `Syslog year`: year added to Linux syslog lines such as
  `Mar 18 12:08:00 ...`, because this format usually does not include a year.

## Supported Log Format

The parser supports lines like:

```text
2026-03-18 12:01:10 Failed password for admin from 45.122.10.8
2026-03-18 12:02:20 Accepted password for admin from 45.122.10.8
Mar 18 12:08:00 lab sshd[4121]: Failed password for test from 203.0.113.77
2026-03-18 12:13:00 auth user=api ip=198.51.100.45 status=failed
```

Unsupported lines are skipped.

## Running Tests

```bash
python -m pytest
```

The test suite covers parsing, invalid-line handling, brute-force detection,
successful login after failed attempts, account-takeover correlation,
low-and-slow brute force, incident creation, attack-campaign correlation,
risk scoring, and HTML dashboard rendering.

## Semester Report

The original Czech accompanying report is included as
[repestyk.pdf](repestyk.pdf).

## Codestyle Check

The project follows PEP 8. You can verify it with:

```bash
python -m pycodestyle src tests main.py
python -m pylint --disable=C0301,C0103 src tests main.py
```

The repository includes `.pylintrc` for project-specific lint settings.

## Design Notes

The project is split into small modules:

- `parser.py` reads log lines and creates `LogEvent` objects.
- `config.py` stores named analysis profiles.
- `rules.py` contains independent detection rules.
- `incidents.py` turns rule matches into `SecurityIncident` objects.
- `campaigns.py` correlates related incidents into attack campaigns.
- `risk.py` assigns risk scores and severity levels.
- `remediation.py` adds recommended analyst response actions.
- `statistics.py` calculates summary numbers.
- `timeline.py` prepares chart data and top-N tables.
- `enrichment.py` builds local IP profiles.
- `dashboard.py` renders the HTML visualization.
- `webapp.py` runs the local interactive browser application.
- `visualization.py` creates optional PNG charts with pandas/matplotlib.
- `report.py` renders TXT, JSON, and HTML reports.
- `cli.py` handles command line arguments.

Parsing, detection, scoring, correlation, and presentation are separate modules,
so the same analysis pipeline serves the CLI, web app, and exported reports.

## Sources and AI Assistance

- PEP 8, Style Guide for Python Code:
  <https://peps.python.org/pep-0008/>
- Python documentation for `argparse`, `dataclasses`, `enum`, `ipaddress`,
  `json`, and `pathlib`: <https://docs.python.org/3/>
- NumPy documentation: <https://numpy.org/doc/stable/>
- pandas documentation: <https://pandas.pydata.org/docs/>
- Matplotlib documentation: <https://matplotlib.org/stable/>
- Pytest documentation: <https://docs.pytest.org/>
- Generative AI assistance: OpenAI ChatGPT/Codex was used only briefly as a
  supporting tool, mainly for a few wording suggestions, codestyle command
  reminders, and a small first draft of selected web-interface elements. The
  project design, final implementation, tests, debugging, and documentation
  were reviewed and adjusted by the author.

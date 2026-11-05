"""Command line interface for Security Log Analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.config import PROFILE_CONFIGS, AnalyzerConfig, build_config
from src.filters import filter_events, parse_csv_set, parse_datetime
from src.incidents import analyze_parse_result
from src.models import ParseResult
from src.parser import parse_log_file_with_diagnostics
from src.report import SUPPORTED_FORMATS, render_report, write_report
from src.visualization import write_analysis_charts
from src.webapp import DEFAULT_HOST, DEFAULT_PORT, run_app


COMMANDS = {"analyze", "app", "charts", "dashboard", "stats"}


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Analyze authentication logs, detect suspicious activity, "
            "and generate security reports."
        )
    )
    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a log file and create txt/json/html report.",
    )
    _add_common_arguments(analyze_parser)
    analyze_parser.add_argument(
        "--format",
        choices=sorted(SUPPORTED_FORMATS),
        default="txt",
        dest="report_format",
        help="Report format. Default: txt.",
    )

    app_parser = subparsers.add_parser(
        "app",
        help="Start a local interactive web application.",
    )
    _add_common_arguments(app_parser, include_output=False)
    app_parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Host for the local app. Default: {DEFAULT_HOST}.",
    )
    app_parser.add_argument(
        "--port",
        type=_positive_int,
        default=DEFAULT_PORT,
        help=f"Port for the local app. Default: {DEFAULT_PORT}.",
    )
    app_parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open the app in the default browser after startup.",
    )

    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="Generate a self-contained HTML dashboard.",
    )
    _add_common_arguments(dashboard_parser, include_output=False)
    dashboard_parser.add_argument(
        "--output",
        default="dashboard.html",
        help="Output HTML path. Default: dashboard.html.",
    )
    dashboard_parser.set_defaults(report_format="html")

    charts_parser = subparsers.add_parser(
        "charts",
        help="Generate PNG charts with pandas, numpy, and matplotlib.",
    )
    _add_common_arguments(charts_parser, include_output=False)
    charts_parser.add_argument(
        "--output",
        default="charts",
        help="Output directory for PNG charts. Default: charts.",
    )
    charts_parser.set_defaults(report_format="charts")

    stats_parser = subparsers.add_parser(
        "stats",
        help="Print text summary without writing a report file.",
    )
    _add_common_arguments(stats_parser, include_output=False)
    stats_parser.set_defaults(report_format="txt", output=None)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the command line application."""

    parser = build_arg_parser()
    normalized_argv = _normalize_argv(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(normalized_argv)

    try:
        config = _config_from_args(args)
        if args.command == "app":
            return run_app(
                file_path=args.file,
                config=config,
                host=args.host,
                port=args.port,
                default_year=args.default_year,
                open_browser=args.open_browser,
            )
        parse_result = parse_log_file_with_diagnostics(
            Path(args.file),
            default_year=args.default_year,
        )
        filtered_parse_result = _apply_event_filters(parse_result, args)
    except OSError as error:
        parser.error(f"Cannot read log file: {error}")
    except ValueError as error:
        parser.error(str(error))

    result = analyze_parse_result(
        filtered_parse_result,
        config=config,
        source_path=args.file,
    )

    if args.command == "charts":
        try:
            paths = write_analysis_charts(
                result,
                output_dir=args.output,
                top_limit=config.top_limit,
            )
        except RuntimeError as error:
            parser.error(str(error))
        print(f"Charts saved to {args.output}")
        for path in paths:
            print(f"- {path}")
        return 0

    if args.output:
        write_report(result, args.output, args.report_format)
        print(f"Report saved to {args.output}")
        print(
            _summary_line(
                result.statistics.incidents_count,
                len(result.events),
            )
        )
    else:
        print(render_report(result, args.report_format))

    return 0


def _add_common_arguments(
    parser: argparse.ArgumentParser,
    include_output: bool = True,
) -> None:
    parser.add_argument(
        "--file",
        required=True,
        help="Path to the authentication log file.",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILE_CONFIGS),
        default="balanced",
        help="Detection profile. Default: balanced.",
    )
    parser.add_argument(
        "--threshold",
        type=_positive_int,
        help="Override default threshold for repeated activity.",
    )
    parser.add_argument(
        "--window",
        type=_positive_int,
        help="Override detection time window in seconds.",
    )
    parser.add_argument(
        "--user-threshold",
        type=_positive_int,
        help="Threshold for many usernames from one IP.",
    )
    parser.add_argument(
        "--distributed-threshold",
        type=_positive_int,
        help="Threshold for many IPs attacking one username.",
    )
    parser.add_argument(
        "--success-threshold",
        type=_positive_int,
        help="Failed attempts needed before success-after-failures alert.",
    )
    parser.add_argument(
        "--bucket",
        type=_positive_int,
        dest="timeline_bucket_seconds",
        help="Timeline bucket size in seconds for dashboard/report charts.",
    )
    parser.add_argument(
        "--top",
        type=_positive_int,
        dest="top_limit",
        help="Number of top IPs/users shown in reports.",
    )
    parser.add_argument(
        "--max-events-per-incident",
        type=_positive_int,
        help="Limit displayed raw events inside each incident.",
    )
    if include_output:
        parser.add_argument(
            "--output",
            help="Optional output report path.",
        )
    parser.add_argument(
        "--from",
        dest="start_time",
        help="Analyze only events at or after this datetime.",
    )
    parser.add_argument(
        "--to",
        dest="end_time",
        help="Analyze only events at or before this datetime.",
    )
    parser.add_argument(
        "--users",
        help="Comma-separated usernames to include.",
    )
    parser.add_argument(
        "--ips",
        help="Comma-separated IP addresses to include.",
    )
    parser.add_argument(
        "--default-year",
        type=_positive_int,
        help="Year used for syslog lines without an explicit year.",
    )


def _normalize_argv(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    if argv[0] in {"-h", "--help"}:
        return argv
    if argv[0] in COMMANDS:
        return argv
    if argv[0].startswith("-"):
        return ["analyze", *argv]
    return argv


def _config_from_args(args: argparse.Namespace) -> AnalyzerConfig:
    return build_config(
        profile=args.profile,
        threshold=args.threshold,
        window_seconds=args.window,
        user_threshold=args.user_threshold,
        distributed_threshold=args.distributed_threshold,
        success_threshold=args.success_threshold,
        timeline_bucket_seconds=args.timeline_bucket_seconds,
        top_limit=args.top_limit,
        max_events_per_incident=args.max_events_per_incident,
    )


def _apply_event_filters(
    parse_result: ParseResult,
    args: argparse.Namespace,
) -> ParseResult:
    start_time = parse_datetime(args.start_time)
    end_time = parse_datetime(args.end_time)
    usernames = parse_csv_set(args.users)
    ip_addresses = parse_csv_set(args.ips)
    events = filter_events(
        parse_result.events,
        start=start_time,
        end=end_time,
        usernames=usernames,
        ip_addresses=ip_addresses,
    )
    return ParseResult(
        events=events,
        issues=parse_result.issues,
        total_lines=parse_result.total_lines,
    )


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error

    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def _summary_line(incidents_count: int, events_count: int) -> str:
    return (
        f"Analyzed {events_count} events, "
        f"found {incidents_count} incident(s)."
    )

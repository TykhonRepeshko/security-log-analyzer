"""PNG chart generation based on pandas and matplotlib."""

from __future__ import annotations

from pathlib import Path

from src.models import AnalysisResult, LogEvent, Severity


def build_event_frame(events: tuple[LogEvent, ...]):
    """Return a pandas DataFrame with normalized event data."""

    pandas = _import_pandas()
    rows = [
        {
            "timestamp": event.timestamp,
            "ip_address": event.ip_address,
            "username": event.username,
            "event_type": event.event_type.value,
            "line_number": event.line_number,
        }
        for event in events
    ]
    frame = pandas.DataFrame(rows)
    if not frame.empty:
        frame["timestamp"] = pandas.to_datetime(frame["timestamp"])
    return frame


def write_analysis_charts(
    result: AnalysisResult,
    output_dir: str | Path,
    top_limit: int = 10,
) -> tuple[Path, ...]:
    """Write PNG charts for an analysis result and return their paths."""

    pyplot, numpy = _import_matplotlib()
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    event_frame = build_event_frame(result.events)
    created_paths = [
        _write_event_timeline(event_frame, result, output_path, pyplot),
        _write_top_ip_chart(event_frame, output_path, pyplot, top_limit),
        _write_severity_chart(result, output_path, pyplot, numpy),
    ]
    return tuple(path for path in created_paths if path is not None)


def _write_event_timeline(event_frame, result, output_dir, pyplot):
    if event_frame.empty:
        return None

    bucket_seconds = int(
        result.config_summary.get("timeline_bucket_seconds", 300),
    )
    frame = event_frame.copy()
    frame["bucket"] = frame["timestamp"].dt.floor(f"{bucket_seconds}s")
    grouped = (
        frame.groupby(["bucket", "event_type"])
        .size()
        .unstack(fill_value=0)
        .sort_index()
    )

    figure, axis = pyplot.subplots(figsize=(9, 4.6))
    grouped.plot(
        kind="bar",
        stacked=True,
        ax=axis,
        color=["#9E1B32", "#247BA0"],
    )
    axis.set_title("Authentication Events Over Time")
    axis.set_xlabel("Time bucket")
    axis.set_ylabel("Events")
    axis.legend(title="Event type")
    axis.tick_params(axis="x", labelrotation=35)
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()

    path = output_dir / "event_timeline.png"
    figure.savefig(path, dpi=140)
    pyplot.close(figure)
    return path


def _write_top_ip_chart(event_frame, output_dir, pyplot, top_limit):
    if event_frame.empty:
        return None

    grouped = (
        event_frame.groupby(["ip_address", "event_type"])
        .size()
        .unstack(fill_value=0)
    )
    grouped["total"] = grouped.sum(axis=1)
    grouped = grouped.sort_values("total", ascending=False).head(top_limit)
    grouped = grouped.drop(columns=["total"])

    figure, axis = pyplot.subplots(figsize=(8, 4.8))
    grouped.plot(
        kind="barh",
        stacked=True,
        ax=axis,
        color=["#9E1B32", "#247BA0"],
    )
    axis.invert_yaxis()
    axis.set_title("Top Source IP Addresses")
    axis.set_xlabel("Events")
    axis.set_ylabel("IP address")
    axis.legend(title="Event type")
    axis.grid(axis="x", alpha=0.25)
    figure.tight_layout()

    path = output_dir / "top_ip_addresses.png"
    figure.savefig(path, dpi=140)
    pyplot.close(figure)
    return path


def _write_severity_chart(result, output_dir, pyplot, numpy):
    labels = [severity.value for severity in Severity]
    counts = [
        result.statistics.severity_counts.get(severity.value, 0)
        for severity in Severity
    ]
    positions = numpy.arange(len(labels))

    figure, axis = pyplot.subplots(figsize=(7, 4.2))
    axis.bar(
        positions,
        counts,
        color=["#5C7C89", "#F4B942", "#E68A00", "#9E1B32"],
    )
    axis.set_title("Incident Severity Distribution")
    axis.set_xlabel("Severity")
    axis.set_ylabel("Incidents")
    axis.set_xticks(positions, labels)
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()

    path = output_dir / "severity_distribution.png"
    figure.savefig(path, dpi=140)
    pyplot.close(figure)
    return path


def _import_pandas():
    try:
        # pylint: disable-next=import-outside-toplevel
        import pandas
    except ImportError as error:
        raise RuntimeError(
            "pandas is required for chart data preparation. "
            "Install dependencies with: "
            "python -m pip install -r requirements.txt"
        ) from error

    return pandas


def _import_matplotlib():
    try:
        # pylint: disable-next=import-outside-toplevel
        import matplotlib
        # pylint: disable-next=import-outside-toplevel
        import numpy

        matplotlib.use("Agg")
        # pylint: disable-next=import-outside-toplevel
        from matplotlib import pyplot
    except ImportError as error:
        raise RuntimeError(
            "numpy and matplotlib are required for PNG chart generation. "
            "Install dependencies with: "
            "python -m pip install -r requirements.txt"
        ) from error

    return pyplot, numpy

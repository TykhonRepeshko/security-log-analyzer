"""Tests for the local web app helpers."""

from pathlib import Path

from src.config import build_config
from src.webapp import _app_shell, analyze_for_app


def test_analyze_for_app_returns_json_payload(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "\n".join(
            [
                "2026-03-18 12:01:10 Failed password for admin "
                "from 45.122.10.8",
                "2026-03-18 12:01:20 Failed password for admin "
                "from 45.122.10.8",
                "2026-03-18 12:01:30 Failed password for admin "
                "from 45.122.10.8",
            ]
        ),
        encoding="utf-8",
    )

    payload = analyze_for_app(
        str(log_path),
        config=build_config(threshold=3, window_seconds=120),
    )

    assert payload["ok"] is True
    assert payload["statistics"]["total_events"] == 3
    assert payload["statistics"]["incidents_count"] == 1


def test_app_shell_contains_redesigned_overview() -> None:
    html = _app_shell(
        "data/sample_auth.log",
        build_config(),
        default_year=2026,
    )

    assert "overviewSummary" in html
    assert "Priority Signals" in html
    assert "Key Metrics" in html

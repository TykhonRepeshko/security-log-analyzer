"""Configuration profiles for the analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace


@dataclass(frozen=True)
class AnalyzerConfig:
    """Runtime settings used by detection rules and reports."""

    profile: str = "balanced"
    threshold: int = 5
    window_seconds: int = 120
    user_threshold: int | None = None
    distributed_threshold: int | None = None
    success_threshold: int | None = None
    timeline_bucket_seconds: int = 300
    top_limit: int = 10
    max_events_per_incident: int = 12

    @property
    def brute_force_threshold(self) -> int:
        """Return threshold for many failures from one IP."""

        return self.threshold

    @property
    def username_threshold(self) -> int:
        """Return threshold for many usernames from one IP."""

        if self.user_threshold is not None:
            return self.user_threshold
        return self.threshold

    @property
    def distributed_attack_threshold(self) -> int:
        """Return threshold for many IPs attacking one user."""

        if self.distributed_threshold is not None:
            return self.distributed_threshold
        return self.threshold

    @property
    def success_after_failures_threshold(self) -> int:
        """Return threshold for failures before a successful login."""

        if self.success_threshold is not None:
            return self.success_threshold
        return self.threshold

    def to_dict(self) -> dict[str, int | str | None]:
        """Return a JSON-friendly configuration summary."""

        return asdict(self)


PROFILE_CONFIGS = {
    "strict": AnalyzerConfig(
        profile="strict",
        threshold=3,
        window_seconds=180,
        user_threshold=3,
        distributed_threshold=3,
        success_threshold=3,
        timeline_bucket_seconds=180,
    ),
    "balanced": AnalyzerConfig(),
    "relaxed": AnalyzerConfig(
        profile="relaxed",
        threshold=8,
        window_seconds=300,
        user_threshold=6,
        distributed_threshold=6,
        success_threshold=5,
        timeline_bucket_seconds=600,
    ),
}


def build_config(
    profile: str = "balanced",
    threshold: int | None = None,
    window_seconds: int | None = None,
    user_threshold: int | None = None,
    distributed_threshold: int | None = None,
    success_threshold: int | None = None,
    timeline_bucket_seconds: int | None = None,
    top_limit: int | None = None,
    max_events_per_incident: int | None = None,
) -> AnalyzerConfig:
    """Build a config from a named profile and optional overrides."""

    if profile not in PROFILE_CONFIGS:
        known_profiles = ", ".join(sorted(PROFILE_CONFIGS))
        raise ValueError(f"Unknown profile '{profile}'. Use: {known_profiles}")

    config = PROFILE_CONFIGS[profile]
    overrides: dict[str, int | str | None] = {"profile": profile}

    if threshold is not None:
        overrides["threshold"] = threshold
    if window_seconds is not None:
        overrides["window_seconds"] = window_seconds
    if user_threshold is not None:
        overrides["user_threshold"] = user_threshold
    if distributed_threshold is not None:
        overrides["distributed_threshold"] = distributed_threshold
    if success_threshold is not None:
        overrides["success_threshold"] = success_threshold
    if timeline_bucket_seconds is not None:
        overrides["timeline_bucket_seconds"] = timeline_bucket_seconds
    if top_limit is not None:
        overrides["top_limit"] = top_limit
    if max_events_per_incident is not None:
        overrides["max_events_per_incident"] = max_events_per_incident

    return replace(config, **overrides)

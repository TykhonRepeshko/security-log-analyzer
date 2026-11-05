"""Detection rules for suspicious authentication activity."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from src.config import AnalyzerConfig
from src.models import EventType, IncidentType, LogEvent, RuleMatch


def detect_suspicious_activity(
    events: Iterable[LogEvent],
    threshold: int | AnalyzerConfig,
    window_seconds: int | None = None,
) -> list[RuleMatch]:
    """Run all supported detection rules."""

    config = _coerce_config(threshold, window_seconds)
    sorted_events = sorted(events, key=lambda event: event.timestamp)
    matches: list[RuleMatch] = []
    matches.extend(
        detect_brute_force_by_ip(
            sorted_events,
            config.brute_force_threshold,
            config.window_seconds,
        )
    )
    matches.extend(
        detect_user_enumeration(
            sorted_events,
            config.username_threshold,
            config.window_seconds,
        )
    )
    matches.extend(
        detect_success_after_failures(
            sorted_events,
            config.success_after_failures_threshold,
            config.window_seconds,
        )
    )
    matches.extend(
        detect_distributed_user_attack(
            sorted_events,
            config.distributed_attack_threshold,
            config.window_seconds,
        )
    )
    matches.extend(
        detect_account_takeover_signal(
            sorted_events,
            config.success_after_failures_threshold,
            config.window_seconds,
        )
    )
    matches.extend(
        detect_low_and_slow_brute_force(
            sorted_events,
            config.brute_force_threshold,
            config.window_seconds,
        )
    )
    return sorted(matches, key=lambda match: match.first_seen)


def detect_brute_force_by_ip(
    events: Iterable[LogEvent],
    threshold: int,
    window_seconds: int,
) -> list[RuleMatch]:
    """Detect many failed logins from one IP in a time window."""

    failed_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == EventType.FAILED_LOGIN:
            failed_by_ip[event.ip_address].append(event)

    matches: list[RuleMatch] = []
    for ip_address, ip_events in failed_by_ip.items():
        for event_window in _find_count_windows(
            ip_events,
            threshold,
            window_seconds,
        ):
            users = sorted({event.username for event in event_window})
            reason = (
                f"{len(event_window)} failed logins from {ip_address} "
                f"within {window_seconds} seconds."
            )
            matches.append(
                RuleMatch(
                    incident_type=IncidentType.BRUTE_FORCE_IP,
                    events=event_window,
                    reason=reason,
                    metadata={
                        "ip_address": ip_address,
                        "failed_count": len(event_window),
                        "unique_users": len(users),
                        "users": users,
                    },
                )
            )

    return matches


def detect_user_enumeration(
    events: Iterable[LogEvent],
    threshold: int,
    window_seconds: int,
) -> list[RuleMatch]:
    """Detect one IP trying many different usernames."""

    failed_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == EventType.FAILED_LOGIN:
            failed_by_ip[event.ip_address].append(event)

    matches: list[RuleMatch] = []
    for ip_address, ip_events in failed_by_ip.items():
        start_index = 0
        ordered_events = sorted(ip_events, key=lambda event: event.timestamp)

        while start_index < len(ordered_events):
            event_window = _collect_window(
                ordered_events,
                start_index,
                window_seconds,
            )
            users = sorted({event.username for event in event_window})
            if len(users) >= threshold:
                reason = (
                    f"{ip_address} tried {len(users)} different users "
                    f"within {window_seconds} seconds."
                )
                matches.append(
                    RuleMatch(
                        incident_type=IncidentType.USER_ENUMERATION,
                        events=event_window,
                        reason=reason,
                        metadata={
                            "ip_address": ip_address,
                            "unique_users": len(users),
                            "users": users,
                        },
                    )
                )
                start_index += len(event_window)
            else:
                start_index += 1

    return matches


def detect_success_after_failures(
    events: Iterable[LogEvent],
    threshold: int,
    window_seconds: int,
) -> list[RuleMatch]:
    """Detect a successful login after repeated failures."""

    failed_by_account: dict[tuple[str, str], list[LogEvent]]
    failed_by_account = defaultdict(list)
    matches: list[RuleMatch] = []

    for event in sorted(events, key=lambda item: item.timestamp):
        account_key = (event.ip_address, event.username)

        if event.event_type == EventType.FAILED_LOGIN:
            failed_by_account[account_key].append(event)
            continue

        recent_failures = [
            failed_event
            for failed_event in failed_by_account[account_key]
            if _seconds_between(failed_event, event) <= window_seconds
        ]
        if len(recent_failures) < threshold:
            continue

        incident_events = tuple(recent_failures + [event])
        reason = (
            f"Successful login for {event.username} from {event.ip_address} "
            f"after {len(recent_failures)} failed attempts."
        )
        matches.append(
            RuleMatch(
                incident_type=IncidentType.SUCCESS_AFTER_FAILURES,
                events=incident_events,
                reason=reason,
                metadata={
                    "ip_address": event.ip_address,
                    "username": event.username,
                    "failed_count": len(recent_failures),
                    "success_count": 1,
                },
            )
        )

    return matches


def detect_distributed_user_attack(
    events: Iterable[LogEvent],
    threshold: int,
    window_seconds: int,
) -> list[RuleMatch]:
    """Detect many IP addresses attacking one username."""

    failed_by_user: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == EventType.FAILED_LOGIN:
            failed_by_user[event.username].append(event)

    matches: list[RuleMatch] = []
    for username, user_events in failed_by_user.items():
        start_index = 0
        ordered_events = sorted(
            user_events,
            key=lambda event: event.timestamp,
        )

        while start_index < len(ordered_events):
            event_window = _collect_window(
                ordered_events,
                start_index,
                window_seconds,
            )
            ip_addresses = sorted(
                {event.ip_address for event in event_window}
            )
            if len(ip_addresses) >= threshold:
                reason = (
                    f"{username} was attacked from {len(ip_addresses)} "
                    f"different IP addresses within {window_seconds} "
                    "seconds."
                )
                matches.append(
                    RuleMatch(
                        incident_type=IncidentType.DISTRIBUTED_USER_ATTACK,
                        events=event_window,
                        reason=reason,
                        metadata={
                            "username": username,
                            "unique_ips": len(ip_addresses),
                            "ip_addresses": ip_addresses,
                        },
                    )
                )
                start_index += len(event_window)
            else:
                start_index += 1

    return matches


def detect_account_takeover_signal(
    events: Iterable[LogEvent],
    threshold: int,
    window_seconds: int,
) -> list[RuleMatch]:
    """Detect a success after failures against one user from several IPs."""

    ordered_events = sorted(events, key=lambda event: event.timestamp)
    failures_by_user: dict[str, list[LogEvent]] = defaultdict(list)
    matches: list[RuleMatch] = []
    takeover_window_seconds = window_seconds * 4
    minimum_failures = max(2, threshold // 2)

    for event in ordered_events:
        if event.event_type == EventType.FAILED_LOGIN:
            failures_by_user[event.username].append(event)
            continue

        recent_failures = [
            failed_event
            for failed_event in failures_by_user[event.username]
            if 0 <= _seconds_between(failed_event, event)
            <= takeover_window_seconds
        ]
        failed_ips = sorted(
            {failed_event.ip_address for failed_event in recent_failures}
        )
        if len(recent_failures) < minimum_failures or len(failed_ips) < 2:
            continue

        incident_events = tuple(recent_failures + [event])
        reason = (
            f"{event.username} had a successful login from "
            f"{event.ip_address} after {len(recent_failures)} failed "
            f"attempts from {len(failed_ips)} IP addresses within "
            f"{takeover_window_seconds} seconds."
        )
        matches.append(
            RuleMatch(
                incident_type=IncidentType.ACCOUNT_TAKEOVER_SIGNAL,
                events=incident_events,
                reason=reason,
                metadata={
                    "username": event.username,
                    "success_ip_address": event.ip_address,
                    "failed_count": len(recent_failures),
                    "success_count": 1,
                    "unique_failure_ips": len(failed_ips),
                    "failure_ip_addresses": failed_ips,
                    "correlation_window_seconds": takeover_window_seconds,
                },
            )
        )

    return matches


def detect_low_and_slow_brute_force(
    events: Iterable[LogEvent],
    threshold: int,
    window_seconds: int,
) -> list[RuleMatch]:
    """Detect repeated failures spread across a longer time window."""

    failed_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == EventType.FAILED_LOGIN:
            failed_by_ip[event.ip_address].append(event)

    matches: list[RuleMatch] = []
    long_window_seconds = max(window_seconds * 30, 3600)
    long_threshold = max(threshold + 1, 3)

    for ip_address, ip_events in failed_by_ip.items():
        ordered_events = sorted(ip_events, key=lambda event: event.timestamp)
        if len(ordered_events) < long_threshold:
            continue
        if _find_count_windows(ordered_events, threshold, window_seconds):
            continue

        event_window = _collect_window(
            ordered_events,
            0,
            long_window_seconds,
        )
        if len(event_window) < long_threshold:
            continue

        span_seconds = _span_seconds(event_window)
        if span_seconds < window_seconds * 4:
            continue

        users = sorted({event.username for event in event_window})
        average_gap = round(span_seconds / (len(event_window) - 1), 1)
        reason = (
            f"{ip_address} produced {len(event_window)} failed logins over "
            f"{int(span_seconds)} seconds without crossing the short "
            f"{window_seconds}-second brute-force threshold."
        )
        matches.append(
            RuleMatch(
                incident_type=IncidentType.LOW_AND_SLOW_BRUTE_FORCE,
                events=event_window,
                reason=reason,
                metadata={
                    "ip_address": ip_address,
                    "failed_count": len(event_window),
                    "unique_users": len(users),
                    "users": users,
                    "long_window_seconds": long_window_seconds,
                    "average_gap_seconds": average_gap,
                },
            )
        )

    return matches


def _find_count_windows(
    events: list[LogEvent],
    threshold: int,
    window_seconds: int,
) -> list[tuple[LogEvent, ...]]:
    windows: list[tuple[LogEvent, ...]] = []
    ordered_events = sorted(events, key=lambda event: event.timestamp)
    start_index = 0

    while start_index <= len(ordered_events) - threshold:
        event_window = _collect_window(
            ordered_events,
            start_index,
            window_seconds,
        )
        if len(event_window) >= threshold:
            windows.append(event_window)
            start_index += len(event_window)
        else:
            start_index += 1

    return windows


def _collect_window(
    events: list[LogEvent],
    start_index: int,
    window_seconds: int,
) -> tuple[LogEvent, ...]:
    start_event = events[start_index]
    collected: list[LogEvent] = []

    for event in events[start_index:]:
        if _seconds_between(start_event, event) > window_seconds:
            break
        collected.append(event)

    return tuple(collected)


def _seconds_between(first_event: LogEvent, second_event: LogEvent) -> float:
    return (second_event.timestamp - first_event.timestamp).total_seconds()


def _span_seconds(events: tuple[LogEvent, ...]) -> float:
    first_seen = min(event.timestamp for event in events)
    last_seen = max(event.timestamp for event in events)
    return (last_seen - first_seen).total_seconds()


def _coerce_config(
    threshold: int | AnalyzerConfig,
    window_seconds: int | None,
) -> AnalyzerConfig:
    if isinstance(threshold, AnalyzerConfig):
        return threshold
    if window_seconds is None:
        raise ValueError("window_seconds is required when threshold is int")
    return AnalyzerConfig(threshold=threshold, window_seconds=window_seconds)

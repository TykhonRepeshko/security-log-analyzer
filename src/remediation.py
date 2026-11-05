"""Recommended response actions for detected incidents."""

from __future__ import annotations

from src.models import IncidentType


def recommended_actions_for_incident(
    incident_type: IncidentType,
    metadata: dict,
) -> tuple[str, ...]:
    """Return concise analyst actions for an incident type."""

    ip_address = metadata.get("ip_address") or metadata.get(
        "success_ip_address",
        "source IP",
    )
    username = metadata.get("username", "affected account")

    actions = {
        IncidentType.BRUTE_FORCE_IP: (
            f"Temporarily block or rate-limit {ip_address}.",
            "Review firewall, SSH, and authentication throttling settings.",
            "Check whether the targeted account was later accessed.",
        ),
        IncidentType.USER_ENUMERATION: (
            f"Investigate username discovery activity from {ip_address}.",
            "Avoid detailed login error messages that reveal valid users.",
            "Review exposed services and account naming patterns.",
        ),
        IncidentType.SUCCESS_AFTER_FAILURES: (
            f"Verify the successful login for {username}.",
            "Reset credentials or rotate tokens if the login is unexpected.",
            "Review activity after the successful login timestamp.",
        ),
        IncidentType.DISTRIBUTED_USER_ATTACK: (
            f"Protect {username} with MFA or temporary lockout.",
            "Check whether the account appears in credential leaks.",
            "Review source IP diversity and upstream rate limits.",
        ),
        IncidentType.ACCOUNT_TAKEOVER_SIGNAL: (
            f"Treat {username} as possibly compromised until verified.",
            "Compare the successful source IP with normal user behavior.",
            "Reset credentials and inspect post-login actions if suspicious.",
        ),
        IncidentType.LOW_AND_SLOW_BRUTE_FORCE: (
            f"Review long-term activity from {ip_address}.",
            "Use longer detection windows in addition to burst thresholds.",
            "Consider rate limits that track failures across hours.",
        ),
    }
    return actions[incident_type]

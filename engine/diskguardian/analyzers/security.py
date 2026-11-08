"""Security posture analysis: what is off, stale, or unsupported.

Reports conditions with an explicit recommended action; never changes a setting.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from . import common

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
UNKNOWN = "unknown"


def _finding(target: str, risk: str, evidence: list[str], reasons: list[str], action: str, details: dict | None = None):
    return {
        "target": target,
        "category": "security",
        "risk_level": risk,
        "confidence": common.confidence(len(evidence) + len(reasons), base=0.6, step=0.08),
        "evidence": evidence,
        "reasons": reasons,
        "recommended_action": action,
        **({"details": details} if details else {}),
    }


def _signature_age_days(value: str | None) -> float | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - moment).total_seconds() / 86400


def analyze_security_status(data: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    defender = data.get("defender") or {}
    firewall = data.get("firewall") or []
    services = data.get("services") or []
    lifecycle = data.get("lifecycle") or {}

    if not defender.get("available"):
        findings.append(
            _finding(
                "Microsoft Defender status",
                UNKNOWN,
                [f"Status query unavailable: {defender.get('error') or 'unknown reason'}"],
                ["protection state cannot be confirmed from this session"],
                common.RECOMMEND_INVESTIGATE,
                {"service_state": defender.get("service_state"), "fallback": defender.get("fallback")},
            )
        )
    else:
        if defender.get("antivirus_enabled") is False:
            findings.append(
                _finding(
                    "Microsoft Defender antivirus",
                    HIGH,
                    ["AntivirusEnabled=false"],
                    ["real-time protection is reported off"],
                    common.RECOMMEND_INVESTIGATE,
                )
            )
        if defender.get("realtime_enabled") is False:
            findings.append(
                _finding(
                    "real-time protection",
                    HIGH,
                    ["RealTimeProtectionEnabled=false"],
                    ["new files are not scanned as they are written"],
                    common.RECOMMEND_INVESTIGATE,
                )
            )
        if defender.get("tamper_protection") is False:
            findings.append(
                _finding(
                    "tamper protection",
                    MEDIUM,
                    ["IsTamperProtected=false"],
                    ["security settings can be changed by other software"],
                    common.RECOMMEND_REVIEW,
                )
            )
        age = _signature_age_days(defender.get("signature_updated"))
        if age is not None and age > 7:
            findings.append(
                _finding(
                    "virus definitions",
                    MEDIUM,
                    [f"Definitions last updated {age:.1f} days ago"],
                    ["outdated definitions reduce detection coverage"],
                    common.RECOMMEND_REVIEW,
                    {"signature_version": defender.get("signature_version")},
                )
            )

    for profile in firewall:
        if profile.get("enabled") is False:
            findings.append(
                _finding(
                    f"firewall profile: {profile.get('name')}",
                    HIGH,
                    ["EnableFirewall=false"],
                    ["this network profile has no firewall filtering"],
                    common.RECOMMEND_INVESTIGATE,
                )
            )
        elif profile.get("enabled") is None:
            findings.append(
                _finding(
                    f"firewall profile: {profile.get('name')}",
                    UNKNOWN,
                    ["firewall policy key could not be read"],
                    ["state is unknown rather than confirmed on"],
                    common.RECOMMEND_REVIEW,
                )
            )

    for service in services:
        if service.get("state") not in {"running", "unknown"}:
            findings.append(
                _finding(
                    f"security service: {service.get('name')}",
                    HIGH,
                    [f"state={service.get('state')}"],
                    ["a security service that should run is not running"],
                    common.RECOMMEND_INVESTIGATE,
                )
            )

    if lifecycle.get("windows_generation") == "windows-10":
        findings.append(
            _finding(
                "Windows lifecycle",
                MEDIUM,
                [lifecycle.get("support_note") or "Windows 10 is past mainstream support"],
                ["running DiskGuardian does not mean the operating system is still supported"],
                common.RECOMMEND_REVIEW,
                {"build": lifecycle.get("build")},
            )
        )

    by_risk: dict[str, int] = {}
    for finding in findings:
        by_risk[finding["risk_level"]] = by_risk.get(finding["risk_level"], 0) + 1

    return {
        "summary": {"total": len(findings), "by_risk": by_risk},
        "findings": findings,
        "coverage": data.get("coverage") or {},
        "note": (
            "DiskGuardian reports and explains; it never disables a protection feature. "
            "For an actual threat, use the security product that reported it."
        ),
        "errors": data.get("errors") or [],
    }

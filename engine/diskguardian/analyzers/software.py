"""Software risk analysis over the installed-software inventory."""

from __future__ import annotations

from typing import Any

from . import common

_USER_WRITABLE_MARKERS = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\", "\\programdata\\")
_SYSTEM_MARKERS = ("\\program files\\", "\\program files (x86)\\", "\\windows\\")


def _user_writable(install_location: str | None) -> bool:
    if not install_location:
        return False
    lowered = install_location.casefold()
    return any(marker in lowered for marker in _USER_WRITABLE_MARKERS)


def _in_system_location(install_location: str | None) -> bool:
    if not install_location:
        return False
    lowered = install_location.casefold()
    return any(marker in lowered for marker in _SYSTEM_MARKERS)


def assess_software(entry: dict[str, Any]) -> dict[str, Any]:
    score = 0.5
    evidence: list[str] = []
    reasons: list[str] = []

    signature = entry.get("signature")
    if signature == "valid":
        score += 0.3
        evidence.append("Authenticode signature is valid")
    elif signature is not None:
        score -= 0.2
        evidence.append(f"Authenticode result: {signature}")

    publisher = entry.get("publisher")
    if publisher:
        score += 0.1
        evidence.append(f"Publisher recorded: {publisher}")
    else:
        score -= 0.2
        evidence.append("No publisher recorded")

    location = entry.get("install_location")
    if _user_writable(location):
        score -= 0.25
        evidence.append(f"Installed under a user-writable location: {location}")
        reasons.append("install location is unusual for a system-wide application")
    elif _in_system_location(location):
        score += 0.1
        evidence.append(f"Installed under a system location: {location}")
    elif not location:
        score -= 0.1
        evidence.append("No install location recorded")

    if not entry.get("uninstall_string"):
        score -= 0.1
        evidence.append("No uninstall command recorded")
    if not entry.get("version"):
        score -= 0.05
        evidence.append("No version recorded")

    if not evidence:
        evidence.append("No identifying metadata was available")

    risk = common.risk_from_score(score)
    if risk == common.RISK_SUSPICIOUS:
        action = common.RECOMMEND_VERIFY_PUBLISHER
        reasons.append("weak or missing trust signals; verify the publisher before keeping it")
    elif risk == common.RISK_UNKNOWN:
        action = common.RECOMMEND_REVIEW
    else:
        action = common.RECOMMEND_NO_ACTION

    return common.make_finding(
        target=entry.get("name") or "(unnamed)",
        category="software",
        risk_level=risk,
        evidence=evidence,
        reasons=reasons,
        recommended_action=action,
        details={
            "version": entry.get("version"),
            "publisher": publisher,
            "install_location": location,
            "source": entry.get("source"),
            "registry_key": entry.get("registry_key"),
        },
    )


def analyze_software(software: list[dict[str, Any]], coverage: dict[str, Any] | None = None) -> dict[str, Any]:
    findings = [assess_software(entry) for entry in software]
    return {
        "summary": common.summarize(findings),
        "findings": findings,
        "coverage": coverage or {},
        "note": (
            "This build has no threat-intelligence feed. It reports trust signals and can reach "
            "'suspicious', never a malware verdict; treat findings as questions to verify."
        ),
        "errors": [],
    }

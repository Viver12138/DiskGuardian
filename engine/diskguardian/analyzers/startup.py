"""Startup-entry risk analysis.

Signals are structural: missing executable, unsigned binary, user-writable
location, or a command interpreter. None of them proves malicious intent; the
output is framed as questions to verify.
"""

from __future__ import annotations

from typing import Any

from . import common

_COMMAND_HOSTS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
}
_USER_WRITABLE_MARKERS = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\")
_HIDDEN_FLAGS = ("-enc", "-encodedcommand", "-windowstyle hidden", "-w hidden", "frombase64string")


def _basename(path: str | None) -> str:
    if not path:
        return ""
    return path.replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def assess_startup_entry(entry: dict[str, Any]) -> dict[str, Any]:
    score = 0.55
    evidence: list[str] = []
    reasons: list[str] = []

    executable = entry.get("executable")
    exists = entry.get("executable_exists")
    if executable and exists is False:
        score -= 0.25
        evidence.append(f"Executable is missing: {executable}")
        reasons.append("a startup entry that points at a missing file is broken or was tampered with")
    elif executable:
        evidence.append(f"Executable: {executable}")

    signature = entry.get("signature")
    if signature == "valid":
        score += 0.25
        evidence.append("Authenticode signature is valid")
    elif signature is not None:
        score -= 0.2
        evidence.append(f"Authenticode result: {signature}")

    lowered = (executable or "").casefold()
    if any(marker in lowered for marker in _USER_WRITABLE_MARKERS):
        score -= 0.2
        evidence.append("Executable lives in a user-writable location")

    if _basename(executable) in _COMMAND_HOSTS:
        score -= 0.2
        evidence.append("Entry runs through a command interpreter instead of a direct binary")
        reasons.append("interpreter-based startup entries can hide their real payload")
        command_line = str(entry.get("command") or "").casefold()
        if any(flag in command_line for flag in _HIDDEN_FLAGS):
            score -= 0.25
            evidence.append("Interpreter arguments look obfuscated or hidden")
            reasons.append("encoded or hidden interpreter arguments have no legitimate reason at startup")

    if entry.get("state") == "disabled":
        score += 0.1
        evidence.append("Entry is currently disabled")

    risk = common.risk_from_score(score)
    if risk == common.RISK_SUSPICIOUS:
        action = common.RECOMMEND_INVESTIGATE
    elif risk == common.RISK_UNKNOWN:
        action = common.RECOMMEND_REVIEW
    else:
        action = common.RECOMMEND_NO_ACTION

    return common.make_finding(
        target=f"{entry.get('name') or '(unnamed)'} [{entry.get('source') or 'unknown'}]",
        category="startup",
        risk_level=risk,
        evidence=evidence or ["No command metadata was available"],
        reasons=reasons,
        recommended_action=action,
        details={
            "source": entry.get("source"),
            "scope": entry.get("scope"),
            "location": entry.get("location"),
            "command": entry.get("command"),
            "state": entry.get("state"),
        },
    )


def analyze_startup(entries: list[dict[str, Any]], coverage: dict[str, Any] | None = None) -> dict[str, Any]:
    findings = [assess_startup_entry(entry) for entry in entries]
    return {
        "summary": common.summarize(findings),
        "findings": findings,
        "coverage": coverage or {},
        "note": (
            "Signals describe structure, not intent. A missing signature on a legitimate "
            "tool is common; combine this with the user's own knowledge of the software."
        ),
        "errors": [],
    }

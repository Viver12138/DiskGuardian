"""Windows security posture without WMI.

Sources: Defender status through its own cmdlet (no WMI dependency), firewall
state from the policy registry keys, service state from the SCM, and OS identity
from the registry. DiskGuardian reports; it never changes a security setting.
"""

from __future__ import annotations

import json
import winreg
from typing import Any

from ..util import clamp_text
from . import powershell
from .services import service_states

_CURRENT_VERSION = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_FIREWALL_PROFILES = (
    ("domain", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"),
    ("private", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),
    ("public", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"),
)

DEFENDER_QUERY = r"""
$ErrorActionPreference = 'Stop'
$status = Get-MpComputerStatus
[pscustomobject]@{
  available = $true
  antivirus_enabled = [bool]$status.AntivirusEnabled
  realtime_enabled = [bool]$status.RealTimeProtectionEnabled
  signature_version = [string]$status.AntivirusSignatureVersion
  signature_updated = if ($status.AntivirusSignatureLastUpdated) { $status.AntivirusSignatureLastUpdated.ToString('o') } else { $null }
  tamper_protection = [bool]$status.IsTamperProtected
} | ConvertTo-Json -Compress
"""


def _os_identity() -> dict[str, Any]:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CURRENT_VERSION) as key:
            def value(name: str) -> Any:
                try:
                    data, _ = winreg.QueryValueEx(key, name)
                    return data
                except OSError:
                    return None

            build_text = str(value("CurrentBuildNumber") or value("CurrentBuild") or "")
            revision = value("UBR")
            try:
                build = int(build_text) if build_text.isdigit() else None
            except ValueError:
                build = None
            return {
                "product_name": clamp_text(value("ProductName"), 200),
                "display_version": clamp_text(value("DisplayVersion"), 60),
                "build": build,
                "revision": int(revision) if isinstance(revision, int) else None,
                "edition": clamp_text(value("EditionID"), 80),
                "installation_type": clamp_text(value("InstallationType"), 80),
            }
    except OSError:
        return {"product_name": None, "display_version": None, "build": None, "revision": None, "edition": None}


def _lifecycle(build: int | None) -> dict[str, Any]:
    if build is None:
        return {"windows_generation": "unknown", "support_note": "The Windows build could not be determined."}
    generation = "windows-11" if build >= 22000 else "windows-10"
    note = (
        "Windows 11 is within its support lifecycle; feature updates still expire, so check the installed version."
        if generation == "windows-11"
        else "Windows 10 mainstream support ended 2025-10-14; ESU or LTSC terms decide whether security updates continue."
    )
    return {"windows_generation": generation, "build": build, "support_note": note}


def _firewall() -> list[dict[str, Any]]:
    profiles: list[dict[str, Any]] = []
    for name, path in _FIREWALL_PROFILES:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                try:
                    enabled, _ = winreg.QueryValueEx(key, "EnableFirewall")
                    profiles.append({"name": name, "enabled": bool(enabled)})
                except OSError:
                    profiles.append({"name": name, "enabled": None})
        except OSError:
            profiles.append({"name": name, "enabled": None})
    return profiles


def _defender(states: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    fallback_state = states.get("windefend", "unknown")
    try:
        payload = powershell.run_json(DEFENDER_QUERY, timeout=60)
        if isinstance(payload, dict):
            return payload, {"query": "ok"}
        return {"available": False, "error": "unexpected Defender response"}, {"query": "invalid-response"}
    except powershell.PowerShellUnavailable as error:
        return (
            {
                "available": False,
                "error": clamp_text(str(error), 300),
                "service_state": fallback_state,
                "fallback": "service-state-only",
            },
            {"query": "unavailable"},
        )
    except (ValueError, json.JSONDecodeError):
        return (
            {
                "available": False,
                "error": "Defender query returned invalid JSON",
                "service_state": fallback_state,
                "fallback": "service-state-only",
            },
            {"query": "invalid-json"},
        )


def _security_services(states: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, label in (
        ("WinDefend", "Microsoft Defender Antivirus Service"),
        ("MpsSvc", "Windows Defender Firewall"),
        ("SecurityHealthService", "Windows Security Service"),
        ("Sense", "Microsoft Defender for Endpoint"),
        ("WdNisSvc", "Network Inspection Service"),
    ):
        if name in states or name in {"WinDefend", "MpsSvc", "SecurityHealthService"}:
            rows.append({"name": name, "label": label, "state": states.get(name.casefold(), "unknown")})
    return rows


def inspect_security_status() -> dict[str, Any]:
    states = service_states()
    defender, defender_coverage = _defender(states)
    os_identity = _os_identity()
    build = os_identity.get("build")
    return {
        "defender": defender,
        "firewall": _firewall(),
        "services": _security_services(states),
        "os": os_identity,
        "lifecycle": _lifecycle(build if isinstance(build, int) else None),
        "coverage": {
            "defender": defender_coverage,
            "services_queried": bool(states),
        },
        "errors": [],
    }

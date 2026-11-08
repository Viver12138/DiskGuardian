"""Chrome and Edge inspection from their public profile files (read-only).

Boundary enforced here and in the tests: only extension metadata and
browser-level settings are read. Passwords, cookies, autofill data, history, and
credentials are never opened — the module does not contain their file names.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ..util import clamp_text

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_EXTENSIONS = 500

BROWSERS = (
    ("chrome", "Google Chrome", Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data"),
    ("edge", "Microsoft Edge", Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data"),
)

POLICY_KEYS = {
    "chrome": (r"SOFTWARE\Policies\Google\Chrome",),
    "edge": (r"SOFTWARE\Policies\Microsoft\Edge",),
}


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
            return None
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def _profiles(user_data: Path) -> list[str]:
    local_state = _read_json(user_data / "Local State") or {}
    cache = local_state.get("profile", {}).get("info_cache", {})
    if isinstance(cache, dict) and cache:
        return sorted(name for name in cache if isinstance(name, str))
    return [item.name for item in user_data.iterdir() if item.is_dir() and item.name in {"Default", "Profile 1", "Profile 2", "Profile 3"}] if user_data.is_dir() else []


def _install_policy(browser_id: str) -> dict[str, Any]:
    try:
        import winreg
    except ImportError:  # pragma: no cover - non-Windows
        return {"present": False, "keys": []}
    found: list[str] = []
    for path in POLICY_KEYS.get(browser_id, ()):  # machine policy only; user policy is separate
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path):
                found.append(path)
        except OSError:
            continue
    return {"present": bool(found), "keys": found}


def _manifest(profile_dir: Path, extension_id: str) -> dict[str, Any] | None:
    versions_dir = profile_dir / "Extensions" / extension_id
    if not versions_dir.is_dir():
        return None
    candidates = sorted((item for item in versions_dir.iterdir() if item.is_dir()), reverse=True)
    for candidate in candidates:
        manifest = _read_json(candidate / "manifest.json")
        if manifest:
            return manifest
    return None


def inspect_browser_extensions(*, limit: int = MAX_EXTENSIONS) -> dict[str, Any]:
    browsers: list[dict[str, Any]] = []
    coverage = {"browsers_present": 0, "profiles_examined": 0, "profiles_unreadable": 0, "extensions_found": 0}

    for browser_id, display_name, user_data in BROWSERS:
        if not user_data.is_dir():
            browsers.append({"id": browser_id, "name": display_name, "installed": False, "profiles": []})
            continue
        coverage["browsers_present"] += 1
        profiles: list[dict[str, Any]] = []
        for profile_name in _profiles(user_data):
            profile_dir = user_data / profile_name
            preferences = _read_json(profile_dir / "Preferences") or {}
            secure = _read_json(profile_dir / "Secure Preferences") or {}
            settings = {}
            for source in (preferences, secure):
                candidate = source.get("extensions", {}).get("settings", {})
                if isinstance(candidate, dict):
                    settings.update(candidate)
            coverage["profiles_examined"] += 1
            extensions: list[dict[str, Any]] = []
            for extension_id, state in sorted(settings.items()):
                if not isinstance(state, dict):
                    continue
                manifest = _manifest(profile_dir, extension_id)
                if manifest is None and not state.get("path"):
                    coverage["profiles_unreadable"] += 1
                    continue
                manifest = manifest or {}
                permissions = manifest.get("permissions") or []
                host_permissions = manifest.get("host_permissions") or []
                extensions.append(
                    {
                        "id": extension_id,
                        "name": clamp_text(manifest.get("name") or state.get("manifest", {}).get("name"), 200),
                        "version": clamp_text(manifest.get("version") or state.get("manifest", {}).get("version"), 60),
                        "enabled": state.get("state") == 1,
                        "location": clamp_text(state.get("location"), 20),
                        "from_webstore": bool(state.get("from_webstore")),
                        "permissions": [str(item) for item in permissions][:64],
                        "host_permissions": [str(item) for item in host_permissions][:64],
                        "update_url": clamp_text(manifest.get("update_url"), 300),
                        "has_background": bool(manifest.get("background")),
                        "content_scripts": len(manifest.get("content_scripts") or []),
                    }
                )
                if len(extensions) >= limit:
                    coverage["extensions_truncated"] = True
                    break
            coverage["extensions_found"] += len(extensions)
            profiles.append({"profile": profile_name, "extensions": extensions})
        browsers.append(
            {
                "id": browser_id,
                "name": display_name,
                "installed": True,
                "user_data_path": str(user_data),
                "managed_by_policy": _install_policy(browser_id),
                "profiles": profiles,
            }
        )

    return {"browsers": browsers, "coverage": coverage, "errors": []}


def _search_provider(preferences: dict[str, Any]) -> dict[str, Any] | None:
    provider = preferences.get("default_search_provider_data", {}).get("template_url_data", {})
    if not isinstance(provider, dict) or not provider:
        return None
    return {
        "name": clamp_text(provider.get("short_name"), 120),
        "keyword": clamp_text(provider.get("keyword"), 60),
        "url": clamp_text(provider.get("url"), 300),
    }


def inspect_browser_settings() -> dict[str, Any]:
    browsers: list[dict[str, Any]] = []
    coverage = {"browsers_present": 0, "profiles_examined": 0, "profiles_unreadable": 0}

    for browser_id, display_name, user_data in BROWSERS:
        if not user_data.is_dir():
            browsers.append({"id": browser_id, "name": display_name, "installed": False, "profiles": []})
            continue
        coverage["browsers_present"] += 1
        profiles: list[dict[str, Any]] = []
        for profile_name in _profiles(user_data):
            preferences = _read_json(user_data / profile_name / "Preferences")
            if preferences is None:
                coverage["profiles_unreadable"] += 1
                continue
            coverage["profiles_examined"] += 1
            session = preferences.get("session", {}) if isinstance(preferences.get("session"), dict) else {}
            startup_urls = session.get("startup_urls") if isinstance(session.get("startup_urls"), list) else []
            profiles.append(
                {
                    "profile": profile_name,
                    "homepage": clamp_text(preferences.get("homepage"), 500),
                    "homepage_is_new_tab": preferences.get("homepage_is_newtabpage"),
                    "restore_on_startup": session.get("restore_on_startup"),
                    "startup_urls": [str(url)[:500] for url in startup_urls][:20],
                    "default_search_provider": _search_provider(preferences),
                    "default_search_provider_enabled": preferences.get("default_search_provider", {}).get("enabled")
                    if isinstance(preferences.get("default_search_provider"), dict)
                    else None,
                }
            )
        browsers.append(
            {
                "id": browser_id,
                "name": display_name,
                "installed": True,
                "managed_by_policy": _install_policy(browser_id),
                "profiles": profiles,
            }
        )

    return {"browsers": browsers, "coverage": coverage, "errors": []}

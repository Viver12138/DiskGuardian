"""Browser extension and settings risk analysis.

Signals: side-loaded extensions, broad host access, high-impact permissions, and
a default search provider that is not among the widely known ones. A managed
policy is reported as context, never as hijacking.
"""

from __future__ import annotations

from typing import Any

from . import common

_KNOWN_SEARCH_KEYWORDS = {
    "google",
    "bing",
    "baidu",
    "yandex",
    "duckduckgo",
    "sogou",
    "so.com",
    "360",
    "ecosia",
    "brave",
    "qwant",
    "startpage",
}

_HIGH_IMPACT_PERMISSIONS = {
    "proxy",
    "management",
    "nativeMessaging",
    "debugger",
    "webRequestBlocking",
    "privacy",
    "cookies",
    "declarativeNetRequest",
}

_BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def assess_extension(browser: str, profile: str, extension: dict[str, Any]) -> dict[str, Any]:
    score = 0.5
    evidence: list[str] = []
    reasons: list[str] = []

    if extension.get("from_webstore") is True:
        score += 0.15
        evidence.append("Installed from the browser store")
    elif extension.get("from_webstore") is False:
        score -= 0.2
        evidence.append("Extension was not installed from the browser store")
        reasons.append("side-loaded extensions bypass store review")
    if extension.get("location") not in (None, "1", 1):
        evidence.append(f"Install location code: {extension.get('location')}")

    hosts = [str(item) for item in extension.get("host_permissions") or []]
    if any(item in _BROAD_HOSTS for item in hosts):
        score -= 0.25
        evidence.append("Requests access to all sites")

    permissions = {str(item) for item in extension.get("permissions") or []}
    impactful = sorted(permissions & _HIGH_IMPACT_PERMISSIONS)
    if impactful:
        score -= 0.05 * min(len(impactful), 3)
        evidence.append(f"High-impact permissions: {', '.join(impactful)}")
        reasons.append("these permissions can change traffic, settings, or other extensions")

    if extension.get("enabled") is False:
        score += 0.1
        evidence.append("Extension is disabled")
    elif extension.get("enabled") is True:
        score += 0.1
        evidence.append("Extension is enabled")

    risk = common.risk_from_score(score)
    if risk == common.RISK_SUSPICIOUS:
        action = common.RECOMMEND_INVESTIGATE
    elif risk == common.RISK_UNKNOWN:
        action = common.RECOMMEND_REVIEW
    else:
        action = common.RECOMMEND_NO_ACTION

    return common.make_finding(
        target=f"{extension.get('name') or extension.get('id')} [{browser}/{profile}]",
        category="browser-extension",
        risk_level=risk,
        evidence=evidence or ["No permission metadata was available"],
        reasons=reasons,
        recommended_action=action,
        details={
            "extension_id": extension.get("id"),
            "version": extension.get("version"),
            "browser": browser,
            "profile": profile,
            "enabled": extension.get("enabled"),
        },
    )


def assess_search_provider(browser: str, profile: str, provider: dict[str, Any] | None) -> dict[str, Any] | None:
    if not provider:
        return None
    keyword = str(provider.get("keyword") or "").casefold()
    name = str(provider.get("name") or "").casefold()
    if any(known in keyword or known in name for known in _KNOWN_SEARCH_KEYWORDS):
        return None
    return common.make_finding(
        target=f"default search provider [{browser}/{profile}]",
        category="browser-setting",
        risk_level=common.RISK_UNKNOWN,
        evidence=[f"Search provider: {provider.get('name') or provider.get('keyword')}"],
        reasons=["the provider is not among the widely known search engines"],
        recommended_action=common.RECOMMEND_REVIEW,
        details={"provider": provider},
    )


def analyze_browser(
    extensions_data: dict[str, Any] | None,
    settings_data: dict[str, Any] | None,
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []

    for browser in (extensions_data or {}).get("browsers") or []:
        if not browser.get("installed"):
            continue
        for profile in browser.get("profiles") or []:
            for extension in profile.get("extensions") or []:
                findings.append(assess_extension(browser.get("name") or browser.get("id"), profile.get("profile"), extension))

    for browser in (settings_data or {}).get("browsers") or []:
        if not browser.get("installed"):
            continue
        policy = browser.get("managed_by_policy") or {}
        for profile in browser.get("profiles") or []:
            finding = assess_search_provider(
                browser.get("name") or browser.get("id"), profile.get("profile"), profile.get("default_search_provider")
            )
            if finding is not None:
                if policy.get("present"):
                    finding["reasons"].append("machine policy is present; confirm with the organization before changing")
                findings.append(finding)

    return {
        "summary": common.summarize(findings),
        "findings": findings,
        "coverage": coverage or {},
        "note": (
            "Store extensions frequently request broad access for legitimate reasons. "
            "Treat these findings as review prompts, not accusations."
        ),
        "errors": [],
    }

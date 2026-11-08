"""Evidence-based analyzers.

Each analyzer consumes scanner output (never touches the disk itself) and returns
findings with risk level, confidence, evidence, reasoning, and a recommended
action. The vocabulary is deliberately conservative: without a threat-intelligence
source this engine can reach `suspicious` at most, and never `confirmed-threat`.
"""

from __future__ import annotations

RISK_TRUSTED = "trusted"
RISK_UNKNOWN = "unknown"
RISK_SUSPICIOUS = "suspicious"

RISK_ORDER = {RISK_TRUSTED: 0, RISK_UNKNOWN: 1, RISK_SUSPICIOUS: 2}

RECOMMEND_NO_ACTION = "no-action"
RECOMMEND_REVIEW = "review"
RECOMMEND_VERIFY_PUBLISHER = "verify-publisher"
RECOMMEND_INVESTIGATE = "investigate"


def confidence(evidence_count: int, base: float = 0.45, step: float = 0.1) -> float:
    return round(min(0.95, base + step * max(evidence_count, 0)), 2)


def risk_from_score(score: float) -> str:
    if score >= 0.7:
        return RISK_TRUSTED
    if score >= 0.4:
        return RISK_UNKNOWN
    return RISK_SUSPICIOUS


def make_finding(
    *,
    target: str,
    category: str,
    risk_level: str,
    evidence: list[str],
    reasons: list[str],
    recommended_action: str,
    details: dict | None = None,
) -> dict:
    return {
        "target": target,
        "category": category,
        "risk_level": risk_level,
        "confidence": confidence(len(evidence) + len(reasons)),
        "evidence": evidence,
        "reasons": reasons,
        "recommended_action": recommended_action,
        **({"details": details} if details else {}),
    }


def summarize(findings: list[dict]) -> dict:
    by_risk: dict[str, int] = {}
    for finding in findings:
        by_risk[finding["risk_level"]] = by_risk.get(finding["risk_level"], 0) + 1
    ordered = sorted(findings, key=lambda item: RISK_ORDER.get(item["risk_level"], 0), reverse=True)
    return {
        "total": len(findings),
        "by_risk": by_risk,
        "highlights": [
            {
                "target": item["target"],
                "risk_level": item["risk_level"],
                "recommended_action": item["recommended_action"],
                "evidence": item["evidence"][:4],
            }
            for item in ordered
            if item["risk_level"] == RISK_SUSPICIOUS
        ][:20],
    }

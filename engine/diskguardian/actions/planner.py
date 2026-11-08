"""Action plans: durable, hash-bound, and reviewable before anything moves.

A plan is a proposal. Creating one changes nothing on disk. The engine records
each item's identity (path, size, mtime, file index) so a later execution can
prove the targets did not change after the user saw the preview.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import config
from ..permissions import rules
from ..protocol import E_INVALID_PARAMS, E_PLAN_EMPTY, EngineError
from ..storage import db


def _now() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso_in(seconds: int) -> str:
    return (_now() + timedelta(seconds=seconds)).isoformat(timespec="seconds").replace("+00:00", "Z")


def item_identity(target: str, size: int | None, mtime_ns: int | None, file_index: int | None) -> str:
    payload = f"{target.casefold()}|{size}|{mtime_ns}|{file_index}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_plan_hash(plan_type: str, items: list[dict[str, Any]]) -> str:
    canonical = json.dumps(
        {
            "plan_type": plan_type,
            "items": sorted(
                (
                    {
                        "target": item["target"].casefold(),
                        "action_type": item["action_type"],
                        "target_hash": item["target_hash"],
                    }
                    for item in items
                ),
                key=lambda entry: entry["target"],
            ),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_manifest_hash(items: list[dict[str, Any]]) -> str:
    """Hash of the exact on-disk targets the approval is bound to."""
    canonical = "\n".join(
        sorted(
            f"{item['action_type']}|{item['target'].casefold()}|{item.get('size_bytes')}|"
            f"{item.get('mtime_ns')}|{item.get('file_index')}"
            for item in items
        )
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_REVERSIBLE = {
    "cleanup": (True, "Eligible items are moved to the DiskGuardian quarantine and can be restored until it is emptied."),
    "startup": (True, "The original startup value is stored before the change and can be written back."),
    "removal": (False, "The vendor uninstaller removes the software; DiskGuardian cannot restore it."),
}


def _plan_view(connection, plan_row) -> dict[str, Any]:
    items = connection.execute(
        "SELECT * FROM action_items WHERE plan_id = ? ORDER BY order_index", (plan_row["plan_id"],)
    ).fetchall()
    summary = json.loads(plan_row["summary_json"] or "{}")
    reversible, reversible_note = _REVERSIBLE.get(plan_row["plan_type"], (False, "This action is not reversible."))
    return {
        "plan_id": plan_row["plan_id"],
        "plan_type": plan_row["plan_type"],
        "status": plan_row["status"],
        "risk_level": plan_row["risk_level"],
        "plan_hash": plan_row["plan_hash"],
        "requires_approval": bool(plan_row["requires_approval"]),
        "created_at": plan_row["created_at"],
        "expires_at": summary.get("expires_at"),
        "items": [
            {
                "action_id": row["item_id"],
                "action_type": row["action_type"],
                "target": row["target"],
                "target_hash": row["target_hash"],
                **json.loads(row["metadata_json"] or "{}"),
            }
            for row in items
        ],
        "excluded": summary.get("excluded", []),
        "summary": summary.get("counts", {}),
        "reversible": reversible,
        "reversible_note": reversible_note,
    }


def create_cleanup_plan(connection, paths: list[str], max_items: int = config.MAX_PLAN_ITEMS) -> dict[str, Any]:
    classifications = rules.classify_many(paths)
    eligible = [item for item in classifications if item.eligible][:max_items]
    excluded = [
        {
            "path": item.path,
            "category": item.category,
            "risk_level": item.risk_level,
            "reasons": item.reasons,
        }
        for item in classifications
        if not item.eligible
    ]
    if not eligible:
        raise EngineError(
            E_PLAN_EMPTY,
            "no eligible cleanup targets were found; every path was excluded",
            {"excluded": excluded[:50]},
        )

    plan_id = db.new_id("plan")
    items: list[dict[str, Any]] = []
    for order, classification in enumerate(eligible):
        target_hash = item_identity(
            classification.path, classification.size_bytes, classification.mtime_ns, classification.file_index
        )
        items.append(
            {
                "item_id": db.new_id("act"),
                "action_type": "quarantine-file",
                "target": classification.path,
                "target_hash": target_hash,
                "size_bytes": classification.size_bytes,
                "mtime_ns": classification.mtime_ns,
                "file_index": classification.file_index,
                "order_index": order,
                "category": classification.category,
                "risk_level": classification.risk_level,
                "root": classification.root,
            }
        )

    plan_hash = compute_plan_hash("cleanup", items)
    total_bytes = sum(int(item["size_bytes"] or 0) for item in items)
    summary = {
        "expires_at": iso_in(config.PLAN_TTL_SECONDS),
        "counts": {
            "requested": len(paths),
            "items": len(items),
            "excluded": len(excluded),
            "bytes": total_bytes,
        },
        "excluded": excluded[:100],
        "risk_levels": sorted({item["risk_level"] for item in items}),
    }

    with db.transaction(connection):
        connection.execute(
            "INSERT INTO action_plans (plan_id, plan_type, created_at, status, risk_level, plan_hash, requires_approval, summary_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                plan_id,
                "cleanup",
                db.utc_now(),
                "pending",
                ",".join(summary["risk_levels"]),
                plan_hash,
                1,
                json.dumps(summary, ensure_ascii=False),
            ),
        )
        for item in items:
            connection.execute(
                "INSERT INTO action_items (item_id, plan_id, action_type, target, target_hash, metadata_json, order_index)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    item["item_id"],
                    plan_id,
                    item["action_type"],
                    item["target"],
                    item["target_hash"],
                    json.dumps(
                        {
                            "category": item["category"],
                            "risk_level": item["risk_level"],
                            "root": item["root"],
                            "size_bytes": item["size_bytes"],
                            "mtime_ns": item["mtime_ns"],
                            "file_index": item["file_index"],
                        },
                        ensure_ascii=False,
                    ),
                    item["order_index"],
                ),
            )

    row = connection.execute("SELECT * FROM action_plans WHERE plan_id = ?", (plan_id,)).fetchone()
    return _plan_view(connection, row)


def load_plan(connection, plan_id: str) -> dict[str, Any]:
    row = connection.execute("SELECT * FROM action_plans WHERE plan_id = ?", (plan_id,)).fetchone()
    if row is None:
        raise EngineError("E_PLAN_NOT_FOUND", f"unknown plan: {plan_id}")
    return _plan_view(connection, row)


def load_plan_items(connection, plan_id: str) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM action_items WHERE plan_id = ? ORDER BY order_index", (plan_id,)
    ).fetchall()
    items = []
    for row in rows:
        metadata = json.loads(row["metadata_json"] or "{}")
        items.append(
            {
                "item_id": row["item_id"],
                "action_type": row["action_type"],
                "target": row["target"],
                "target_hash": row["target_hash"],
                **metadata,
            }
        )
    return items


def plan_expired(plan_view: dict[str, Any]) -> bool:
    expires_at = plan_view.get("expires_at")
    if not expires_at:
        return False
    return parse_time(expires_at) <= _now()


__all__ = [
    "E_INVALID_PARAMS",
    "compute_manifest_hash",
    "compute_plan_hash",
    "create_cleanup_plan",
    "item_identity",
    "load_plan",
    "load_plan_items",
    "parse_time",
    "plan_expired",
]

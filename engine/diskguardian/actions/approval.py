"""Approval records: issued only after a real user confirmation, consumed once.

The model cannot call this module: the plugin issues an approval only after the
Harness user-question tool returned an explicit confirmation for this exact
plan hash. The engine then owns the record; execution carries an opaque
approval_id, never a boolean.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .. import config
from ..protocol import (
    E_APPROVAL_EXPIRED,
    E_APPROVAL_NOT_FOUND,
    E_APPROVAL_STALE,
    E_APPROVAL_USED,
    E_PLAN_EXPIRED,
    EngineError,
)
from ..storage import db
from . import planner


def issue_approval(connection, plan_id: str, source: str = "harness-user-question") -> dict[str, Any]:
    plan = planner.load_plan(connection, plan_id)
    if plan["status"] != "pending":
        raise EngineError("E_INVALID_STATE", f"plan state is {plan['status']}, not pending")
    if planner.plan_expired(plan):
        raise EngineError(E_PLAN_EXPIRED, "the plan expired; create a new plan")

    items = planner.load_plan_items(connection, plan_id)
    if not items:
        raise EngineError("E_INVALID_STATE", "the plan has no items")
    manifest = planner.compute_manifest_hash(items)
    approval_id = db.new_id("approval")
    expires_at = planner.iso_in(config.APPROVAL_TTL_SECONDS)
    with db.transaction(connection):
        connection.execute(
            "INSERT INTO approval_records"
            " (approval_id, plan_id, plan_hash, target_manifest_hash, approved_at, expires_at, used, approval_source)"
            " VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
            (approval_id, plan_id, plan["plan_hash"], manifest, db.utc_now(), expires_at, source),
        )
    db.record_audit(
        connection,
        operation="approval.issue",
        result="completed",
        plan_id=plan_id,
        detail={"approval_id": approval_id, "source": source, "expires_at": expires_at},
    )
    return {
        "approval_id": approval_id,
        "plan_id": plan_id,
        "plan_hash": plan["plan_hash"],
        "expires_at": expires_at,
        "item_count": len(items),
        "bytes": sum(int(item.get("size_bytes") or 0) for item in items),
    }


def validate(connection, *, approval_id: str, plan_id: str) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM approval_records WHERE approval_id = ? AND plan_id = ?", (approval_id, plan_id)
    ).fetchone()
    if row is None:
        raise EngineError(E_APPROVAL_NOT_FOUND, "no approval matches this plan")
    if int(row["used"]) == 1:
        raise EngineError(E_APPROVAL_USED, "this approval was already used; confirm a new plan")
    try:
        expired = planner.parse_time(row["expires_at"]) <= datetime.now(timezone.utc)
    except ValueError:
        expired = True
    if expired:
        raise EngineError(E_APPROVAL_EXPIRED, "the approval expired; confirm a new plan")

    plan = planner.load_plan(connection, plan_id)
    if plan["plan_hash"] != row["plan_hash"]:
        raise EngineError(E_APPROVAL_STALE, "the plan changed after approval")

    items = planner.load_plan_items(connection, plan_id)
    if planner.compute_manifest_hash(items) != row["target_manifest_hash"]:
        raise EngineError(E_APPROVAL_STALE, "the approved target list no longer matches the plan")
    return dict(row)


def consume(connection, approval_id: str) -> None:
    with db.transaction(connection):
        cursor = connection.execute(
            "UPDATE approval_records SET used = 1, used_at = ? WHERE approval_id = ? AND used = 0",
            (db.utc_now(), approval_id),
        )
    if cursor.rowcount != 1:
        raise EngineError(E_APPROVAL_USED, "this approval was already used")


def find_for_plan(connection, plan_id: str) -> list[dict[str, Any]]:
    rows = connection.execute("SELECT * FROM approval_records WHERE plan_id = ?", (plan_id,)).fetchall()
    return [dict(row) for row in rows]

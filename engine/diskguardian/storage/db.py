"""SQLite storage for scans, plans, approvals, audit, and quarantine."""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import config

SCHEMA_VERSION = 3
SCHEMA_FILE = Path(__file__).with_name("schema.sql")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open (and if needed create) the local database, then migrate it."""
    target = path or config.database_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(target), timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    migrate(connection)
    return connection


def migrate(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    current = connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0]
    if current >= SCHEMA_VERSION:
        return
    connection.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
    if current < 3:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(quarantine_records)")}
        if "purged_at" not in columns:
            connection.execute("ALTER TABLE quarantine_records ADD COLUMN purged_at TEXT")
    connection.execute("DELETE FROM schema_migrations")
    connection.execute(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
        (SCHEMA_VERSION, utc_now()),
    )


@contextmanager
def transaction(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
    except BaseException:
        connection.execute("ROLLBACK")
        raise
    else:
        connection.execute("COMMIT")


def record_scan(
    connection: sqlite3.Connection,
    *,
    scan_type: str,
    started_at: str,
    completed_at: str,
    status: str,
    summary: dict[str, Any],
) -> str:
    scan_id = new_id("scan")
    connection.execute(
        "INSERT INTO scan_sessions (scan_id, scan_type, started_at, completed_at, status, summary_json)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, scan_type, started_at, completed_at, status, _json(summary)),
    )
    return scan_id


def record_audit(
    connection: sqlite3.Connection,
    *,
    operation: str,
    result: str,
    target: str | None = None,
    plan_id: str | None = None,
    action_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> str:
    audit_id = new_id("audit")
    connection.execute(
        "INSERT INTO action_logs (audit_id, plan_id, action_id, operation, target, result, detail_json, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (audit_id, plan_id, action_id, operation, target, result, _json(detail or {}), utc_now()),
    )
    return audit_id


def _json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

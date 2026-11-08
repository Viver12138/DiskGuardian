"""Headless acceptance run for the DiskGuardian engine.

Runs the real engine over its real JSONL wire in a throwaway sandbox under the
workspace, so the full read-only surface and the plan/approval/quarantine flow
can be validated without a Harness session. It never touches user data: TEMP,
LOCALAPPDATA and USERPROFILE all point into the sandbox.

Usage:  python tools/acceptance.py
Exit:   0 when every scenario passes, 1 otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "engine" / "run.py"
SANDBOX_ROOT = ROOT / ".tmp-tests"


class Session:
    def __init__(self) -> None:
        SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
        self.base = SANDBOX_ROOT / f"accept-{int(time.time())}"
        self.temp = self.base / "Temp"
        self.local = self.base / "Local"
        self.profile = self.base / "Profile"
        for directory in (self.temp, self.local, self.profile):
            directory.mkdir(parents=True, exist_ok=True)
        self.env = os.environ.copy()
        self.env.update(
            {
                "TEMP": str(self.temp),
                "TMP": str(self.temp),
                "LOCALAPPDATA": str(self.local),
                "USERPROFILE": str(self.profile),
            }
        )
        self.counter = 0
        self.results: list[tuple[str, bool, str]] = []

    def call(self, operation: str, params: dict | None = None) -> dict:
        self.counter += 1
        request = {"request_id": f"acc_{self.counter}", "operation": operation, "params": params or {}}
        completed = subprocess.run(
            [sys.executable, "-I", str(ENGINE)],
            input=json.dumps(request).encode("utf-8"),
            capture_output=True,
            cwd=str(ROOT),
            env=self.env,
            timeout=300,
        )
        text = completed.stdout.decode("utf-8", "replace").strip()
        if not text:
            raise RuntimeError(f"{operation}: engine returned nothing (stderr: {completed.stderr.decode('utf-8', 'replace')[:400]})")
        return json.loads(text.splitlines()[0])

    def expect(self, label: str, condition: bool, detail: str = "") -> None:
        self.results.append((label, condition, detail))

    def step(self, label: str, operation: str, params: dict | None, check, expected_error: str | None = None) -> dict | None:
        try:
            response = self.call(operation, params)
        except Exception as error:  # noqa: BLE001 - report, do not abort the run
            self.expect(label, False, f"call failed: {error}")
            return None
        if not response.get("success"):
            error = response.get("error") or {}
            if expected_error is not None:
                self.expect(label, error.get("code") == expected_error, f"rejected with {error.get('code')}")
                return None
            self.expect(label, False, f"{error.get('code')}: {error.get('message')}")
            return None
        if expected_error is not None:
            self.expect(label, False, f"expected {expected_error} but the call succeeded")
            return None
        data = response.get("data")
        try:
            ok, detail = check(data)
        except Exception as error:  # noqa: BLE001
            ok, detail = False, f"check raised: {error}"
        self.expect(label, ok, detail)
        return data


def scenario(session: Session) -> None:
    fixture = session.temp / "old-fixture.tmp"
    fixture.write_bytes(b"x" * 4096)
    stamp = time.time() - 3 * 86400
    os.utime(fixture, (stamp, stamp))

    session.step("self_check", "self_check", None, lambda d: (len(d["operations"]) >= 25, f"{len(d['operations'])} operations"))
    session.step("scan_disk", "scan_disk", None, lambda d: (len(d["disks"]) >= 1, f"{len(d['disks'])} disks"))
    session.step(
        "scan_directories",
        "scan_directories",
        {"paths": [str(session.temp)]},
        lambda d: (d["analysis"][0]["bytes"] >= 4096, f"{d['analysis'][0]['bytes']} bytes"),
    )
    session.step(
        "find_large_files",
        "find_large_files",
        {"roots": [str(session.temp)], "min_bytes": 1024},
        lambda d: (len(d["files"]) >= 1, f"{len(d['files'])} files"),
    )
    session.step("list_installed_software", "list_installed_software", {"limit": 5}, lambda d: (d["total"] > 0, f"{d['total']} installed"))
    session.step(
        "inspect_startup_entries",
        "inspect_startup_entries",
        {"include_tasks": False},
        lambda d: ("entries" in d, f"{len(d['entries'])} entries"),
    )
    session.step(
        "inspect_services",
        "inspect_services",
        {"running_only": True},
        lambda d: (d["total"] > 0, f"{d['total']} running services"),
    )
    session.step("inspect_browser_extensions", "inspect_browser_extensions", None, lambda d: (len(d["browsers"]) >= 1, f"{len(d['browsers'])} browsers"))
    session.step("inspect_browser_settings", "inspect_browser_settings", None, lambda d: ("coverage" in d, "coverage reported"))
    session.step("inspect_security_status", "inspect_security_status", None, lambda d: ("defender" in d, "defender block present"))
    session.step("analyze_software", "analyze_software", {"limit": 5}, lambda d: (d["summary"]["total"] == 5, f"{d['summary']['total']} findings"))
    session.step("analyze_startup", "analyze_startup", {"include_tasks": False}, lambda d: ("findings" in d, f"{len(d['findings'])} findings"))
    session.step("analyze_browser", "analyze_browser", None, lambda d: ("findings" in d, f"{len(d['findings'])} findings"))
    session.step("analyze_security_status", "analyze_security_status", None, lambda d: ("summary" in d, f"{len(d['findings'])} findings"))
    session.step(
        "classify_files",
        "classify_files",
        {"paths": [str(fixture)]},
        lambda d: (d["files"][0]["category"] == "temporary-file" and d["files"][0]["eligible"], d["files"][0]["category"]),
    )
    session.step(
        "list_cleanup_candidates",
        "list_cleanup_candidates",
        {},
        lambda d: (d["eligible"] >= 1, f"{d['eligible']} eligible, {d['returned']} returned"),
    )

    plan = session.step(
        "create_cleanup_plan",
        "create_cleanup_plan",
        {"paths": [str(fixture)]},
        lambda d: (d["plan_type"] == "cleanup" and len(d["items"]) == 1, d["plan_type"]),
    )
    if plan:
        session.step("preview_action_plan", "preview_action_plan", {"plan_id": plan["plan_id"]}, lambda d: (d["status"] == "pending", d["status"]))
        issued = session.step(
            "issue_approval",
            "issue_approval",
            {"plan_id": plan["plan_id"]},
            lambda d: (bool(d.get("approval_id")), "approval issued"),
        )
        if issued:
            session.step(
                "execute_cleanup_plan",
                "execute_cleanup_plan",
                {"plan_id": plan["plan_id"], "approval_id": issued["approval_id"]},
                lambda d: (d["success"] and d["verification"]["verified"], d["status"]),
            )
            session.step("list_quarantine", "list_quarantine", None, lambda d: (d["total"] == 1, f"{d['total']} quarantined"))
            quarantined = session.call("list_quarantine")["data"]["items"][0]["quarantine_id"]
            session.step(
                "restore_quarantined_item",
                "restore_quarantined_item",
                {"quarantine_id": quarantined},
                lambda d: (d["verified"], "restored"),
            )
            session.step(
                "replay_rejected",
                "execute_cleanup_plan",
                {"plan_id": plan["plan_id"], "approval_id": issued["approval_id"]},
                lambda d: (False, "should not succeed"),
                expected_error="E_APPROVAL_USED",
            )

    purged_fixture = session.temp / "purge-fixture.tmp"
    purged_fixture.write_bytes(b"y" * 1024)
    old_stamp = time.time() - 3 * 86400
    os.utime(purged_fixture, (old_stamp, old_stamp))
    purge_plan = session.step(
        "create_cleanup_plan_purge",
        "create_cleanup_plan",
        {"paths": [str(purged_fixture)]},
        lambda d: (d["plan_type"] == "cleanup", d["plan_type"]),
    )
    if purge_plan:
        purge_issued = session.step(
            "issue_approval_purge",
            "issue_approval",
            {"plan_id": purge_plan["plan_id"]},
            lambda d: (bool(d.get("approval_id")), "approval issued"),
        )
        if purge_issued:
            session.step(
                "execute_cleanup_plan_purge",
                "execute_cleanup_plan",
                {"plan_id": purge_plan["plan_id"], "approval_id": purge_issued["approval_id"]},
                lambda d: (d["verification"]["verified"], d["status"]),
            )
            session.step(
                "purge_dry_run",
                "purge_quarantine",
                {"all": True, "dry_run": True},
                lambda d: (d["count"] >= 1, f"{d['count']} would be deleted"),
            )
            session.step(
                "purge_quarantine",
                "purge_quarantine",
                {"all": True},
                lambda d: (d["purged"] >= 1 and d["bytes_freed"] >= 1024, f"{d['purged']} purged, {d['bytes_freed']} bytes"),
            )

    session.step("get_audit_log", "get_audit_log", {"limit": 20}, lambda d: (len(d["entries"]) >= 4, f"{len(d['entries'])} entries"))
    session.step(
        "create_removal_plan_unknown",
        "create_removal_plan",
        {"software": [{"name": "DiskGuardian No Such App"}]},
        lambda d: (False, "should not succeed"),
        expected_error="E_PLAN_EMPTY",
    )
    session.step(
        "create_startup_plan_unknown",
        "create_startup_plan",
        {"name": "DiskGuardianNoSuchEntry", "action": "disable"},
        lambda d: (False, "should not succeed"),
        expected_error="E_NOT_FOUND",
    )
    session.step(
        "inspect_removal_residue",
        "inspect_removal_residue",
        {"software": "DiskGuardian No Such App"},
        lambda d: (d["registered"] is False, "not registered"),
    )
    session.step(
        "unknown_operation",
        "no_such_operation",
        None,
        lambda d: (False, "should not succeed"),
        expected_error="E_UNKNOWN_OPERATION",
    )


def main() -> int:
    session = Session()
    scenario(session)
    failures = 0
    print(f"{'scenario':34} {'result':6} detail")
    print("-" * 78)
    for label, ok, detail in session.results:
        if not ok:
            failures += 1
        print(f"{label:34} {'PASS' if ok else 'FAIL':6} {detail}")
    print("-" * 78)
    print(f"{len(session.results) - failures}/{len(session.results)} scenarios passed; sandbox: {session.base}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

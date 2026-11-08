import os
import time
import unittest
from unittest import mock

from diskguardian import config
from diskguardian.actions import approval as approvals
from diskguardian.actions import cleaner, planner
from diskguardian.permissions import rules
from diskguardian.protocol import EngineError
from diskguardian.storage import db
from tests.support import cleanup, unique_dir


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.root = unique_dir("actions")
        self.temp = self.root / "Temp"
        self.temp.mkdir()
        self.local = self.root / "Local"
        self.local.mkdir()
        self.env = mock.patch.dict(
            os.environ, {"TEMP": str(self.temp), "TMP": str(self.temp), "LOCALAPPDATA": str(self.local)}
        )
        self.env.start()
        # The fixture lives under a user-content directory, which the real rules
        # would classify as personal; tests focus on the cleanup policy itself.
        self.personal = mock.patch.object(config, "personal_roots", return_value=[])
        self.personal.start()
        self.addCleanup(self.personal.stop)
        self.addCleanup(self.env.stop)
        self.connection = db.connect()
        self.addCleanup(self.connection.close)
        self.addCleanup(cleanup, self.root)

    def make_file(self, name: str = "old.tmp", content: bytes = b"x" * 2048, age_days: float = 2) -> os.PathLike:
        path = self.temp / name
        path.write_bytes(content)
        stamp = time.time() - age_days * 86400
        os.utime(path, (stamp, stamp))
        return path

    def test_plan_execute_verify_and_restore(self):
        target = self.make_file()
        plan = planner.create_cleanup_plan(self.connection, [str(target)])
        self.assertEqual(plan["items"][0]["category"], "temporary-file")
        self.assertEqual(plan["risk_level"], "L1")
        self.assertTrue(plan["reversible"])

        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        result = cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        self.assertTrue(result["success"])
        self.assertTrue(result["verification"]["verified"])
        self.assertFalse(os.path.exists(target))
        self.assertEqual(len(result["affected_items"]), 1)

        quarantine_id = result["affected_items"][0]["quarantine_id"]
        restored = cleaner.restore_quarantined_item(self.connection, quarantine_id)
        self.assertTrue(restored["verified"])
        self.assertTrue(os.path.exists(target))

    def test_fabricated_approval_is_rejected(self):
        target = self.make_file()
        plan = planner.create_cleanup_plan(self.connection, [str(target)])
        with self.assertRaises(EngineError) as caught:
            cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], "approval_fake")
        self.assertEqual(caught.exception.code, "E_APPROVAL_NOT_FOUND")
        self.assertTrue(os.path.exists(target))

    def test_approval_is_single_use(self):
        target = self.make_file()
        plan = planner.create_cleanup_plan(self.connection, [str(target)])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        with self.assertRaises(EngineError) as caught:
            cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        self.assertIn(caught.exception.code, {"E_APPROVAL_USED", "E_TARGET_CHANGED"})

    def test_expired_approval_is_rejected(self):
        target = self.make_file()
        plan = planner.create_cleanup_plan(self.connection, [str(target)])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        self.connection.execute(
            "UPDATE approval_records SET expires_at = ? WHERE approval_id = ?",
            ("2000-01-01T00:00:00Z", issued["approval_id"]),
        )
        with self.assertRaises(EngineError) as caught:
            cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        self.assertEqual(caught.exception.code, "E_APPROVAL_EXPIRED")

    def test_plan_change_invalidates_approval(self):
        target = self.make_file()
        other = self.make_file("second.tmp")
        plan = planner.create_cleanup_plan(self.connection, [str(target)])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        self.connection.execute(
            "UPDATE action_items SET target = ? WHERE plan_id = ?",
            (str(other), plan["plan_id"]),
        )
        with self.assertRaises(EngineError) as caught:
            cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        self.assertIn(caught.exception.code, {"E_APPROVAL_STALE", "E_TARGET_CHANGED"})

    def test_target_change_invalidates_approval(self):
        target = self.make_file()
        plan = planner.create_cleanup_plan(self.connection, [str(target)])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        target.write_bytes(b"changed after approval")
        with self.assertRaises(EngineError) as caught:
            cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        self.assertEqual(caught.exception.code, "E_TARGET_CHANGED")

    def test_unknown_and_system_paths_are_not_eligible(self):
        unknown = self.root / "plain.bin"
        unknown.write_bytes(b"data")
        result = rules.classify(str(unknown))
        self.assertFalse(result.eligible)
        self.assertIn(result.category, {"unknown", "system"})
        with self.assertRaises(EngineError) as caught:
            planner.create_cleanup_plan(self.connection, [str(unknown)])
        self.assertEqual(caught.exception.code, "E_PLAN_EMPTY")

    def test_personal_document_is_prohibited(self):
        personal_dir = self.root / "Documents"
        personal_dir.mkdir()
        target = personal_dir / "thesis.docx"
        target.write_bytes(b"content")
        with mock.patch.object(config, "personal_roots", return_value=[personal_dir]):
            result = rules.classify(str(target))
        self.assertEqual(result.category, "personal-document")
        self.assertEqual(result.risk_level, "L4")
        self.assertFalse(result.eligible)

    def test_young_temp_file_is_excluded(self):
        target = self.make_file("fresh.tmp", age_days=0)
        result = rules.classify(str(target))
        self.assertFalse(result.eligible)
        self.assertIn("safety window", " ".join(result.reasons))

    def test_quarantine_capacity_is_enforced(self):
        target = self.make_file("big.tmp", content=b"x" * 4096)
        plan = planner.create_cleanup_plan(self.connection, [str(target)])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        with mock.patch.object(config, "QUARANTINE_MAX_BYTES", 1024):
            with self.assertRaises(EngineError) as caught:
                cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        self.assertEqual(caught.exception.code, "E_QUARANTINE_FULL")
        self.assertTrue(os.path.exists(target))
        # The approval is not consumed by a refused execution, so it can be retried.
        result = cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        self.assertTrue(result["success"])

    def test_quarantine_listing_reports_capacity_and_expiry(self):
        target = self.make_file()
        plan = planner.create_cleanup_plan(self.connection, [str(target)])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        listing = cleaner.list_quarantine(self.connection)
        self.assertEqual(listing["usage"]["bytes"], 2048)
        self.assertEqual(listing["retention_days"], config.QUARANTINE_RETENTION_DAYS)
        self.assertFalse(listing["items"][0]["expired"])
        self.assertIsNotNone(listing["items"][0]["expires_at"])

    def test_audit_log_records_execution(self):
        target = self.make_file()
        plan = planner.create_cleanup_plan(self.connection, [str(target)])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        log = cleaner.get_audit_log(self.connection, limit=20)
        operations = {entry["operation"] for entry in log["entries"]}
        self.assertIn("approval.issue", operations)
        self.assertIn("cleanup.quarantine", operations)
        self.assertIn("cleanup.execute", operations)


if __name__ == "__main__":
    unittest.main()

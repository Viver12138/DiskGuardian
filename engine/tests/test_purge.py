import os
import time
import unittest
from unittest import mock

from diskguardian import config
from diskguardian.actions import approval as approvals
from diskguardian.actions import cleaner, planner
from diskguardian.protocol import EngineError
from diskguardian.storage import db
from tests.support import cleanup, unique_dir


class PurgeTests(unittest.TestCase):
    def setUp(self):
        self.root = unique_dir("purge")
        self.temp = self.root / "Temp"
        self.temp.mkdir()
        self.local = self.root / "Local"
        self.local.mkdir()
        self.env = mock.patch.dict(
            os.environ, {"TEMP": str(self.temp), "TMP": str(self.temp), "LOCALAPPDATA": str(self.local)}
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.personal = mock.patch.object(config, "personal_roots", return_value=[])
        self.personal.start()
        self.addCleanup(self.personal.stop)
        self.connection = db.connect()
        self.addCleanup(self.connection.close)
        self.addCleanup(cleanup, self.root)

    def quarantine(self, name: str, size: int = 1024) -> str:
        path = self.temp / name
        path.write_bytes(b"x" * size)
        stamp = time.time() - 3 * 86400
        os.utime(path, (stamp, stamp))
        plan = planner.create_cleanup_plan(self.connection, [str(path)])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        result = cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        return result["affected_items"][0]["quarantine_id"]

    def purge_row(self, quarantine_id: str) -> dict:
        return dict(
            self.connection.execute(
                "SELECT * FROM quarantine_records WHERE quarantine_id = ?", (quarantine_id,)
            ).fetchone()
        )

    def test_dry_run_does_not_delete(self):
        quarantine_id = self.quarantine("a.tmp")
        preview = cleaner.purge_quarantine(self.connection, purge_all=True, dry_run=True)
        self.assertEqual(preview["count"], 1)
        self.assertEqual(preview["bytes"], 1024)
        row = self.purge_row(quarantine_id)
        self.assertTrue(os.path.isfile(row["quarantine_path"]))
        self.assertEqual(row["status"], "quarantined")

    def test_purge_deletes_and_marks_records(self):
        first = self.quarantine("a.tmp", 1024)
        second = self.quarantine("b.tmp", 2048)
        result = cleaner.purge_quarantine(self.connection, purge_all=True)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["purged"], 2)
        self.assertEqual(result["bytes_freed"], 3072)
        for quarantine_id in (first, second):
            row = self.purge_row(quarantine_id)
            self.assertEqual(row["status"], "purged")
            self.assertIsNotNone(row["purged_at"])
            self.assertFalse(os.path.exists(row["quarantine_path"]))
        log = cleaner.get_audit_log(self.connection, limit=50)
        operations = {entry["operation"] for entry in log["entries"]}
        self.assertIn("quarantine.purge", operations)
        self.assertIn("quarantine.purge_all", operations)

    def test_restore_after_purge_is_rejected(self):
        quarantine_id = self.quarantine("a.tmp")
        cleaner.purge_quarantine(self.connection, purge_all=True)
        with self.assertRaises(EngineError) as caught:
            cleaner.restore_quarantined_item(self.connection, quarantine_id)
        self.assertEqual(caught.exception.code, "E_INVALID_STATE")

    def test_tampered_copy_is_not_deleted(self):
        quarantine_id = self.quarantine("a.tmp")
        row = self.purge_row(quarantine_id)
        with open(row["quarantine_path"], "wb") as handle:
            handle.write(b"tampered")
        result = cleaner.purge_quarantine(self.connection, purge_all=True)
        self.assertEqual(result["failed"][0]["code"], "E_VERIFY_FAILED")
        self.assertTrue(os.path.isfile(row["quarantine_path"]))
        self.assertEqual(self.purge_row(quarantine_id)["status"], "quarantined")

    def test_older_than_days_filter(self):
        old = self.quarantine("old.tmp")
        fresh = self.quarantine("fresh.tmp")
        self.connection.execute(
            "UPDATE quarantine_records SET quarantined_at = ? WHERE quarantine_id = ?",
            ("2020-01-01T00:00:00Z", old),
        )
        result = cleaner.purge_quarantine(self.connection, older_than_days=30)
        self.assertEqual(result["purged"], 1)
        self.assertEqual(self.purge_row(old)["status"], "purged")
        self.assertEqual(self.purge_row(fresh)["status"], "quarantined")

    def test_requires_a_filter(self):
        with self.assertRaises(EngineError) as caught:
            cleaner.purge_quarantine(self.connection)
        self.assertEqual(caught.exception.code, "E_INVALID_PARAMS")


if __name__ == "__main__":
    unittest.main()

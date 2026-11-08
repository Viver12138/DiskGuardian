import os
import unittest
from unittest import mock

from diskguardian.actions import approval as approvals
from diskguardian.actions import cleaner, startup as startup_actions
from diskguardian.protocol import EngineError
from diskguardian.storage import db
from tests.support import cleanup, unique_dir

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
ENTRY_NAME = "DiskGuardianTestUpdater"
ENTRY_DATA = r"C:\Program Files\Test\updater.exe --silent"


class FakeRegistry:
    def __init__(self, entries=None):
        self.data = entries or {}

    def _bucket(self, hive, path, view):
        return self.data.setdefault((hive, path, view), {})

    def list_values(self, hive, path, view):
        return list(self.data.get((hive, path, view), {}).items())

    def read_value(self, hive, path, view, name):
        return self.data.get((hive, path, view), {}).get(name)

    def write_value(self, hive, path, view, name, data):
        self._bucket(hive, path, view)[name] = data

    def delete_value(self, hive, path, view, name):
        self.data.get((hive, path, view), {}).pop(name, None)


class StartupActionTests(unittest.TestCase):
    def setUp(self):
        self.root = unique_dir("startup")
        self.local = self.root / "Local"
        self.local.mkdir()
        self.env = mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.local)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.connection = db.connect()
        self.addCleanup(self.connection.close)
        self.addCleanup(cleanup, self.root)
        self.registry = FakeRegistry({("HKCU", RUN_KEY, 0): {ENTRY_NAME: ENTRY_DATA}})

    def _disable(self):
        plan = startup_actions.create_startup_plan(
            self.connection, name=ENTRY_NAME, action="disable", registry=self.registry
        )
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        return plan, issued

    def test_disable_removes_value_and_records_it(self):
        plan, issued = self._disable()
        self.assertEqual(plan["plan_type"], "startup")
        self.assertEqual(plan["risk_level"], "L3")

        result = startup_actions.execute_startup_plan(
            self.connection, plan["plan_id"], issued["approval_id"], registry=self.registry
        )
        self.assertTrue(result["success"])
        self.assertIsNone(self.registry.read_value("HKCU", RUN_KEY, 0, ENTRY_NAME))

        rows = self.connection.execute("SELECT * FROM startup_changes").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["value_data"], ENTRY_DATA)
        self.assertEqual(rows[0]["status"], "disabled")

    def test_enable_restores_exact_value(self):
        plan, issued = self._disable()
        startup_actions.execute_startup_plan(self.connection, plan["plan_id"], issued["approval_id"], registry=self.registry)

        restore_plan = startup_actions.create_startup_plan(
            self.connection, name=ENTRY_NAME, action="enable", registry=self.registry
        )
        restore_issued = approvals.issue_approval(self.connection, restore_plan["plan_id"])
        result = startup_actions.execute_startup_plan(
            self.connection, restore_plan["plan_id"], restore_issued["approval_id"], registry=self.registry
        )
        self.assertTrue(result["success"])
        self.assertEqual(self.registry.read_value("HKCU", RUN_KEY, 0, ENTRY_NAME), ENTRY_DATA)
        row = self.connection.execute("SELECT * FROM startup_changes").fetchone()
        self.assertEqual(row["status"], "restored")

    def test_changed_value_is_rejected(self):
        plan, issued = self._disable()
        self.registry.write_value("HKCU", RUN_KEY, 0, ENTRY_NAME, r"C:\Other\payload.exe")
        with self.assertRaises(EngineError) as caught:
            startup_actions.execute_startup_plan(
                self.connection, plan["plan_id"], issued["approval_id"], registry=self.registry
            )
        self.assertEqual(caught.exception.code, "E_TARGET_CHANGED")
        self.assertEqual(self.registry.read_value("HKCU", RUN_KEY, 0, ENTRY_NAME), r"C:\Other\payload.exe")

    def test_unknown_entry_is_rejected(self):
        with self.assertRaises(EngineError) as caught:
            startup_actions.create_startup_plan(self.connection, name="NoSuchEntry", action="disable", registry=self.registry)
        self.assertEqual(caught.exception.code, "E_NOT_FOUND")

    def test_enable_without_record_is_rejected(self):
        with self.assertRaises(EngineError) as caught:
            startup_actions.create_startup_plan(self.connection, name=ENTRY_NAME, action="enable", registry=self.registry)
        self.assertEqual(caught.exception.code, "E_NOT_FOUND")

    def test_execution_requires_approval(self):
        plan, _issued = self._disable()
        with self.assertRaises(EngineError) as caught:
            startup_actions.execute_startup_plan(self.connection, plan["plan_id"], "approval_fake", registry=self.registry)
        self.assertEqual(caught.exception.code, "E_APPROVAL_NOT_FOUND")
        self.assertEqual(self.registry.read_value("HKCU", RUN_KEY, 0, ENTRY_NAME), ENTRY_DATA)

    def test_changes_are_listed(self):
        plan, issued = self._disable()
        startup_actions.execute_startup_plan(self.connection, plan["plan_id"], issued["approval_id"], registry=self.registry)
        listing = startup_actions.list_startup_changes(self.connection)
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["value_name"], ENTRY_NAME)

    def test_startup_plan_cannot_be_executed_as_cleanup(self):
        plan, issued = self._disable()
        with self.assertRaises(EngineError) as caught:
            cleaner.execute_cleanup_plan(self.connection, plan["plan_id"], issued["approval_id"])
        self.assertEqual(caught.exception.code, "E_INVALID_PARAMS")
        self.assertEqual(self.registry.read_value("HKCU", RUN_KEY, 0, ENTRY_NAME), ENTRY_DATA)


if __name__ == "__main__":
    unittest.main()

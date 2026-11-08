import os
import unittest
from unittest import mock

from diskguardian.actions import approval as approvals
from diskguardian.actions import removal
from diskguardian.protocol import EngineError
from diskguardian.storage import db
from tests.support import cleanup, unique_dir

NOTEPAD = r"C:\Windows\System32\notepad.exe"
TEST_ENTRY = {
    "hive": "HKCU",
    "key_path": r"Software\Microsoft\Windows\CurrentVersion\Uninstall\DiskGuardianTestApp",
    "name": "DiskGuardian Test App",
    "version": "1.0",
    "publisher": "DiskGuardian",
    "uninstall_string": f'"{NOTEPAD}" /S',
    "quiet_uninstall_string": None,
}


class RemovalValidationTests(unittest.TestCase):
    def test_accepts_plain_vendor_uninstaller(self):
        executable, arguments = removal.validate_uninstaller({"uninstall_string": f'"{NOTEPAD}" /S'})
        self.assertEqual(executable, NOTEPAD)
        self.assertEqual(arguments, ["/S"])

    def test_rejects_command_interpreter(self):
        with self.assertRaises(EngineError):
            removal.validate_uninstaller({"uninstall_string": r"C:\Windows\System32\cmd.exe /c del x"})

    def test_rejects_temp_directory_uninstaller(self):
        with self.assertRaises(EngineError):
            removal.validate_uninstaller({"uninstall_string": r"C:\Users\a\AppData\Local\Temp\uninst.exe"})

    def test_msiexec_requires_remove_argument(self):
        executable = r"C:\Windows\System32\msiexec.exe"
        with self.assertRaises(EngineError):
            removal.validate_uninstaller({"uninstall_string": executable})
        path, arguments = removal.validate_uninstaller(
            {"uninstall_string": f"{executable} /X{{11111111-2222-3333-4444-555555555555}}"}
        )
        self.assertTrue(path.endswith("msiexec.exe"))
        self.assertTrue(any(argument.casefold().startswith("/x") for argument in arguments))


class RemovalPlanTests(unittest.TestCase):
    def setUp(self):
        self.root = unique_dir("removal")
        self.local = self.root / "Local"
        self.local.mkdir()
        self.env = mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.local)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.connection = db.connect()
        self.addCleanup(self.connection.close)
        self.addCleanup(cleanup, self.root)

        self.entries = mock.patch.object(
            removal, "_iter_uninstall_entries", side_effect=lambda: iter([dict(TEST_ENTRY)])
        )
        self.entries.start()
        self.addCleanup(self.entries.stop)

    def test_plan_contains_vendor_uninstaller(self):
        plan = removal.create_removal_plan(self.connection, [{"name": "DiskGuardian Test App"}])
        self.assertEqual(plan["plan_type"], "removal")
        self.assertEqual(plan["risk_level"], "L3")
        self.assertEqual(plan["items"][0]["uninstaller"], NOTEPAD)
        self.assertEqual(plan["items"][0]["software"], "DiskGuardian Test App")
        self.assertFalse(plan["reversible"])

    def test_unknown_software_is_rejected(self):
        with self.assertRaises(EngineError) as caught:
            removal.create_removal_plan(self.connection, [{"name": "No Such App 9000"}])
        self.assertEqual(caught.exception.code, "E_PLAN_EMPTY")

    def test_execution_requires_approval(self):
        plan = removal.create_removal_plan(self.connection, [{"name": "DiskGuardian Test App"}])
        with self.assertRaises(EngineError) as caught:
            removal.execute_removal_plan(self.connection, plan["plan_id"], "approval_fake")
        self.assertEqual(caught.exception.code, "E_APPROVAL_NOT_FOUND")

    def test_successful_removal_is_verified_and_audited(self):
        plan = removal.create_removal_plan(self.connection, [{"name": "DiskGuardian Test App"}])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        states = iter([True, False])  # installed before, gone after

        result = removal.execute_removal_plan(
            self.connection,
            plan["plan_id"],
            issued["approval_id"],
            runner=lambda executable, arguments, timeout: (0, "uninstalled", None),
            lookup=lambda software, item: next(states),
        )
        self.assertTrue(result["success"])
        self.assertTrue(result["verification"]["verified"])
        self.assertEqual(result["affected_items"][0]["software"], "DiskGuardian Test App")
        entries = self.connection.execute(
            "SELECT operation, result FROM action_logs WHERE plan_id = ?", (plan["plan_id"],)
        ).fetchall()
        self.assertIn(("removal.run", "completed"), {(row["operation"], row["result"]) for row in entries})

    def test_uninstaller_that_changes_nothing_fails_verification(self):
        plan = removal.create_removal_plan(self.connection, [{"name": "DiskGuardian Test App"}])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        result = removal.execute_removal_plan(
            self.connection,
            plan["plan_id"],
            issued["approval_id"],
            runner=lambda executable, arguments, timeout: (0, "cancelled by user", None),
            lookup=lambda software, item: True,
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["failed_items"][0]["code"], "E_VERIFY_FAILED")

    def test_elevation_required_is_reported_not_retried(self):
        plan = removal.create_removal_plan(self.connection, [{"name": "DiskGuardian Test App"}])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        result = removal.execute_removal_plan(
            self.connection,
            plan["plan_id"],
            issued["approval_id"],
            runner=lambda executable, arguments, timeout: (None, "", "E_ELEVATION_REQUIRED"),
            lookup=lambda software, item: True,
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["failed_items"][0]["code"], "E_ELEVATION_REQUIRED")

    def test_rerun_is_rejected_after_use(self):
        plan = removal.create_removal_plan(self.connection, [{"name": "DiskGuardian Test App"}])
        issued = approvals.issue_approval(self.connection, plan["plan_id"])
        states = iter([True, False])
        removal.execute_removal_plan(
            self.connection,
            plan["plan_id"],
            issued["approval_id"],
            runner=lambda executable, arguments, timeout: (0, "", None),
            lookup=lambda software, item: next(states),
        )
        with self.assertRaises(EngineError) as caught:
            removal.execute_removal_plan(self.connection, plan["plan_id"], issued["approval_id"])
        self.assertEqual(caught.exception.code, "E_APPROVAL_USED")


if __name__ == "__main__":
    unittest.main()

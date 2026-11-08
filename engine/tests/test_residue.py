import os
import unittest
from unittest import mock

from diskguardian.actions import residue, removal
from diskguardian.protocol import EngineError
from tests.support import cleanup, unique_dir

ENTRY = {
    "hive": "HKLM",
    "key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Example",
    "name": "Example App",
    "version": "2.0",
    "publisher": "Example Inc.",
    "uninstall_string": r"C:\Program Files\Example\uninstall.exe",
    "quiet_uninstall_string": None,
}


class ResidueTests(unittest.TestCase):
    def setUp(self):
        self.root = unique_dir("residue")
        self.leftover = self.root / "leftover"
        self.leftover.mkdir()
        (self.leftover / "a.bin").write_bytes(b"a" * 1024)
        nested = self.leftover / "cache"
        nested.mkdir()
        (nested / "b.bin").write_bytes(b"b" * 512)
        self.addCleanup(cleanup, self.root)
        self.entries = mock.patch.object(removal, "_iter_uninstall_entries", side_effect=lambda: iter([dict(ENTRY)]))
        self.entries.start()
        self.addCleanup(self.entries.stop)

    def test_reports_still_registered(self):
        result = residue.inspect_residue("Example App")
        self.assertTrue(result["registered"])
        self.assertEqual(result["registrations"][0]["publisher"], "Example Inc.")
        self.assertFalse(result["leftovers"])

    def test_measures_leftover_directory(self):
        result = residue.inspect_residue("Example App", install_location=str(self.leftover))
        self.assertEqual(result["leftovers"][0]["status"], "present")
        self.assertGreaterEqual(result["leftovers"][0]["bytes"], 1536)
        self.assertEqual(result["leftovers"][0]["files"], 2)

    def test_missing_path_is_reported_not_raised(self):
        missing = self.root / "gone"
        result = residue.inspect_residue("Example App", candidate_paths=[str(missing)])
        self.assertEqual(result["leftovers"][0]["status"], "unavailable")
        self.assertIn(str(missing), result["missing_paths"])

    def test_empty_name_is_rejected(self):
        with self.assertRaises(EngineError):
            residue.inspect_residue("  ")

    def test_unregistered_software(self):
        with mock.patch.object(removal, "_iter_uninstall_entries", side_effect=lambda: iter([])):
            result = residue.inspect_residue("Example App")
        self.assertFalse(result["registered"])


if __name__ == "__main__":
    unittest.main()

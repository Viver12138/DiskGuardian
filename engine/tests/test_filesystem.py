import unittest
from pathlib import Path

from diskguardian.permissions.paths import ensure_readable_path
from diskguardian.protocol import E_INVALID_PARAMS, E_PATH_NOT_ALLOWED, EngineError
from diskguardian.scanner import filesystem
from tests.support import cleanup, unique_dir


class FilesystemScanTests(unittest.TestCase):
    def setUp(self):
        self.root = unique_dir("files")
        self.addCleanup(cleanup, self.root)
        (self.root / "a.bin").write_bytes(b"a" * 1000)
        (self.root / "b.bin").write_bytes(b"b" * 2000)
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "c.bin").write_bytes(b"c" * 3000)

    def test_directory_analysis_sums_children(self):
        budget = filesystem.ScanBudget(max_entries=10_000, max_seconds=30)
        analysis = filesystem.analyze_directories([str(self.root)], max_depth=2, budget=budget)
        self.assertEqual(len(analysis), 1)
        entry = analysis[0]
        self.assertEqual(entry["bytes"], 6000)
        self.assertEqual(entry["files"], 3)
        self.assertFalse(entry["truncated"])
        self.assertEqual(entry["top_children"][0]["name"], "nested")

    def test_budget_truncation_is_reported(self):
        budget = filesystem.ScanBudget(max_entries=1, max_seconds=30)
        analysis = filesystem.analyze_directories([str(self.root)], max_depth=2, budget=budget)
        self.assertTrue(analysis[0]["truncated"])
        self.assertEqual(budget.reason, "entries")

    def test_find_large_files_filters_and_sorts(self):
        budget = filesystem.ScanBudget(max_entries=10_000, max_seconds=30)
        files, scanned = filesystem.find_large_files(
            [str(self.root)], min_bytes=1500, limit=10, budget=budget
        )
        self.assertEqual([Path(item["path"]).name for item in files], ["c.bin", "b.bin"])
        self.assertEqual(files[0]["bytes"], 3000)
        self.assertEqual(scanned, 3)

    def test_rejects_relative_path(self):
        with self.assertRaises(EngineError) as caught:
            ensure_readable_path("relative\\path")
        self.assertEqual(caught.exception.code, E_INVALID_PARAMS)

    def test_rejects_unc_path(self):
        with self.assertRaises(EngineError) as caught:
            ensure_readable_path("\\\\server\\share")
        self.assertEqual(caught.exception.code, E_PATH_NOT_ALLOWED)


if __name__ == "__main__":
    unittest.main()

import os
import time
import unittest
from unittest import mock

from diskguardian import config
from diskguardian.scanner import candidates
from diskguardian.protocol import EngineError
from tests.support import cleanup, unique_dir


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.root = unique_dir("candidates")
        self.temp = self.root / "Temp"
        self.temp.mkdir()
        self.addCleanup(cleanup, self.root)
        self.patch = mock.patch.object(config, "temp_roots", return_value=[self.temp])
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.cache_patch = mock.patch.object(config, "known_cache_directories", return_value=[])
        self.cache_patch.start()
        self.addCleanup(self.cache_patch.stop)

    def write(self, name: str, size: int, age_days: float = 2):
        path = self.temp / name if "/" not in name else self.temp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
        stamp = time.time() - age_days * 86400
        os.utime(path, (stamp, stamp))
        return path

    def test_lists_old_files_only(self):
        old = self.write("old.tmp", 2048, age_days=3)
        self.write("fresh.tmp", 4096, age_days=0)
        result = candidates.list_candidates()
        paths = [item["path"] for item in result["candidates"]]
        self.assertEqual(paths, [str(old)])
        self.assertEqual(result["eligible"], 1)
        self.assertEqual(result["eligible_bytes"], 2048)
        self.assertGreaterEqual(result["skipped_recent"], 1)

    def test_walks_subdirectories(self):
        nested = self.write("sub/deep.tmp", 512, age_days=5)
        result = candidates.list_candidates()
        self.assertIn(str(nested), [item["path"] for item in result["candidates"]])

    def test_limit_keeps_largest(self):
        self.write("small.tmp", 100, age_days=2)
        big = self.write("big.tmp", 10_000, age_days=2)
        result = candidates.list_candidates(limit=1)
        self.assertEqual(result["candidates"][0]["path"], str(big))
        self.assertEqual(result["eligible"], 2)

    def test_rejects_roots_outside_cleanup_roots(self):
        outside = self.root / "Elsewhere"
        outside.mkdir()
        with self.assertRaises(EngineError) as caught:
            candidates.list_candidates(roots=[str(outside)])
        self.assertEqual(caught.exception.code, "E_PATH_NOT_ALLOWED")

    def test_rejects_relative_root(self):
        with self.assertRaises(EngineError) as caught:
            candidates.list_candidates(roots=["Temp"])
        self.assertEqual(caught.exception.code, "E_INVALID_PARAMS")

    def test_min_bytes_filters_small_files(self):
        self.write("small.tmp", 100, age_days=2)
        big = self.write("big.tmp", 5000, age_days=2)
        result = candidates.list_candidates(min_bytes=1000)
        self.assertEqual([item["path"] for item in result["candidates"]], [str(big)])
        self.assertEqual(result["eligible"], 1)
        self.assertGreaterEqual(result["skipped_small"], 1)


class BrowserCacheDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.root = unique_dir("browsercache")
        self.local = self.root / "Local"
        chrome = self.local / "Google" / "Chrome" / "User Data"
        for profile in ("Default", "Profile 1", "Crashpad"):
            (chrome / profile / "Cache").mkdir(parents=True)
        (chrome / "Default" / "Code Cache").mkdir(parents=True)
        (chrome / "Default" / "NotACache").mkdir(parents=True)
        edge = self.local / "Microsoft" / "Edge" / "User Data"
        (edge / "Default" / "GPUCache").mkdir(parents=True)
        self.env = mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.local)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(cleanup, self.root)

    def test_finds_profile_caches_only(self):
        found = {path.name for path in config.browser_cache_dirs()}
        self.assertIn("Cache", found)
        self.assertIn("Code Cache", found)
        self.assertIn("GPUCache", found)
        self.assertNotIn("NotACache", found)

    def test_crashpad_is_not_treated_as_a_profile(self):
        paths = [str(path) for path in config.browser_cache_dirs()]
        self.assertFalse(any("Crashpad" in path for path in paths))


if __name__ == "__main__":
    unittest.main()

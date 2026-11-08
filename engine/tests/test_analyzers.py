import unittest

from diskguardian.analyzers import browser, common, security, software, startup


class SoftwareAnalyzerTests(unittest.TestCase):
    def test_signed_system_install_is_trusted(self):
        finding = software.assess_software(
            {
                "name": "Example App",
                "version": "1.2.3",
                "publisher": "Example Inc.",
                "install_location": r"C:\Program Files\Example",
                "uninstall_string": r"C:\Program Files\Example\uninstall.exe",
                "signature": "valid",
                "source": "machine-64",
            }
        )
        self.assertEqual(finding["risk_level"], common.RISK_TRUSTED)
        self.assertEqual(finding["recommended_action"], common.RECOMMEND_NO_ACTION)
        self.assertLessEqual(finding["confidence"], 0.95)

    def test_unsigned_user_writable_install_is_suspicious(self):
        finding = software.assess_software(
            {
                "name": "Mystery Tool",
                "version": "",
                "publisher": None,
                "install_location": r"C:\Users\a\AppData\Local\Temp\mystery",
                "uninstall_string": None,
                "signature": "unsigned",
            }
        )
        self.assertEqual(finding["risk_level"], common.RISK_SUSPICIOUS)
        self.assertEqual(finding["recommended_action"], common.RECOMMEND_VERIFY_PUBLISHER)
        self.assertTrue(any("user-writable" in item for item in finding["evidence"]))

    def test_missing_metadata_is_unknown_not_malicious(self):
        finding = software.assess_software({"name": "Bare", "signature": None})
        self.assertIn(finding["risk_level"], {common.RISK_UNKNOWN, common.RISK_SUSPICIOUS})
        self.assertNotIn("confirmed-threat", finding["risk_level"])

    def test_summary_groups_by_risk(self):
        result = software.analyze_software(
            [
                {"name": "Good", "publisher": "X", "install_location": r"C:\Program Files\Good", "signature": "valid", "uninstall_string": "u"},
                {"name": "Bad", "install_location": r"C:\Users\x\AppData\Local\Temp\bad", "signature": "unsigned"},
            ]
        )
        self.assertEqual(result["summary"]["total"], 2)
        self.assertIn("suspicious", result["summary"]["by_risk"])
        self.assertTrue(result["summary"]["highlights"])


class StartupAnalyzerTests(unittest.TestCase):
    def test_interpreter_from_temp_is_suspicious(self):
        finding = startup.assess_startup_entry(
            {
                "name": "Updater",
                "source": "registry-run",
                "executable": r"C:\Users\a\AppData\Local\Temp\payload.exe",
                "executable_exists": True,
                "signature": "unsigned",
                "command": r"C:\Users\a\AppData\Local\Temp\payload.exe -silent",
            }
        )
        self.assertEqual(finding["risk_level"], common.RISK_SUSPICIOUS)
        self.assertEqual(finding["recommended_action"], common.RECOMMEND_INVESTIGATE)

    def test_powershell_entry_is_flagged(self):
        finding = startup.assess_startup_entry(
            {
                "name": "Hidden",
                "source": "scheduled-task",
                "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "executable_exists": True,
                "signature": "valid",
                "command": "powershell -enc ...",
            }
        )
        self.assertEqual(finding["risk_level"], common.RISK_SUSPICIOUS)
        self.assertTrue(any("interpreter" in item for item in finding["evidence"]))

    def test_signed_regular_entry(self):
        finding = startup.assess_startup_entry(
            {
                "name": "OneDrive",
                "source": "registry-run",
                "executable": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                "executable_exists": True,
                "signature": "valid",
                "command": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background",
            }
        )
        self.assertEqual(finding["risk_level"], common.RISK_TRUSTED)


class BrowserAnalyzerTests(unittest.TestCase):
    def test_sideloaded_all_sites_extension_is_suspicious(self):
        finding = browser.assess_extension(
            "Google Chrome",
            "Default",
            {
                "id": "abc",
                "name": "Unknown Helper",
                "from_webstore": False,
                "host_permissions": ["<all_urls>"],
                "permissions": ["proxy", "management"],
                "enabled": True,
            },
        )
        self.assertEqual(finding["risk_level"], common.RISK_SUSPICIOUS)

    def test_store_extension_with_narrow_permissions(self):
        finding = browser.assess_extension(
            "Microsoft Edge",
            "Default",
            {"id": "def", "name": "Reader", "from_webstore": True, "host_permissions": [], "permissions": ["storage"], "enabled": True},
        )
        self.assertEqual(finding["risk_level"], common.RISK_TRUSTED)

    def test_unknown_search_provider_is_reviewed(self):
        finding = browser.assess_search_provider("Chrome", "Default", {"name": "SearchIt", "keyword": "searchit.example"})
        self.assertIsNotNone(finding)
        self.assertEqual(finding["risk_level"], common.RISK_UNKNOWN)

    def test_known_search_provider_is_ignored(self):
        self.assertIsNone(browser.assess_search_provider("Chrome", "Default", {"name": "Google", "keyword": "google.com"}))


class SecurityAnalyzerTests(unittest.TestCase):
    def test_disabled_protection_is_high(self):
        result = security.analyze_security_status(
            {
                "defender": {
                    "available": True,
                    "antivirus_enabled": True,
                    "realtime_enabled": False,
                    "tamper_protection": False,
                    "signature_updated": None,
                },
                "firewall": [{"name": "public", "enabled": False}],
                "services": [{"name": "MpsSvc", "state": "stopped"}],
                "lifecycle": {"windows_generation": "windows-11"},
                "coverage": {"defender": {"query": "ok"}},
            }
        )
        levels = [item["risk_level"] for item in result["findings"]]
        self.assertGreaterEqual(levels.count("high"), 3)

    def test_unavailable_defender_is_unknown_not_high(self):
        result = security.analyze_security_status(
            {
                "defender": {"available": False, "error": "access denied"},
                "firewall": [{"name": "domain", "enabled": True}],
                "services": [],
                "lifecycle": {"windows_generation": "windows-11"},
            }
        )
        self.assertEqual(result["findings"][0]["risk_level"], "unknown")
        self.assertEqual(result["findings"][0]["recommended_action"], common.RECOMMEND_INVESTIGATE)

    def test_healthy_posture_has_no_high_findings(self):
        result = security.analyze_security_status(
            {
                "defender": {
                    "available": True,
                    "antivirus_enabled": True,
                    "realtime_enabled": True,
                    "tamper_protection": True,
                    "signature_updated": None,
                },
                "firewall": [{"name": "domain", "enabled": True}, {"name": "private", "enabled": True}],
                "services": [{"name": "WinDefend", "state": "running"}],
                "lifecycle": {"windows_generation": "windows-11"},
            }
        )
        self.assertFalse([item for item in result["findings"] if item["risk_level"] == "high"])


if __name__ == "__main__":
    unittest.main()

"""Static guards for the properties the security model depends on.

These read the engine sources; they do not execute anything. A regression here
means a capability that the rest of the design assumes cannot exist has appeared.
"""

import re
import unittest
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[1] / "diskguardian"


def engine_sources() -> list[Path]:
    return sorted(path for path in ENGINE_ROOT.rglob("*.py") if "__pycache__" not in path.parts)


class SourceHygieneTests(unittest.TestCase):
    def test_no_shell_execution(self):
        for path in engine_sources():
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("shell=True", text, f"{path} must not pass shell=True")
            self.assertNotRegex(text, r"\bos\.system\s*\(", f"{path} must not call os.system")

    def test_no_dynamic_code_evaluation(self):
        for path in engine_sources():
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"(?<![\w.])eval\s*\(", f"{path} must not call eval")
            self.assertNotRegex(text, r"(?<![\w.])exec\s*\(", f"{path} must not call exec")

    def test_no_network_clients(self):
        forbidden = ("import socket", "import urllib", "import requests", "import http.client", "from socket")
        for path in engine_sources():
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, text, f"{path} must not perform network I/O ({marker})")

    def test_browser_scanner_never_names_sensitive_files(self):
        text = (ENGINE_ROOT / "scanner" / "browser.py").read_text(encoding="utf-8")
        # Quoted literals would mean the scanner actually opens such a file.
        for name in ("History", "Cookies", "Login Data", "Web Data", "Local Storage"):
            self.assertNotIn(f'"{name}"', text, f"browser.py must not open {name}")
            self.assertNotIn(f"'{name}'", text, f"browser.py must not open {name}")

    def test_powershell_scripts_are_module_constants(self):
        text = (ENGINE_ROOT / "scanner" / "powershell.py").read_text(encoding="utf-8")
        self.assertIn("def run_fixed(script: str", text)
        # No code path may accept a script from request parameters: the only
        # caller-visible entry points take module constants.
        self.assertNotIn("params.get(\"script", text)

    def test_uninstaller_allowlist_is_present(self):
        text = (ENGINE_ROOT / "actions" / "removal.py").read_text(encoding="utf-8")
        for blocked in ("cmd.exe", "powershell.exe", "mshta.exe", "rundll32.exe"):
            self.assertIn(blocked, text)
        self.assertIn("E_ELEVATION_REQUIRED", text)

    def test_no_permanent_delete_of_user_files(self):
        """Cleanup must be quarantine-based: no unlink/remove of planned targets."""
        text = (ENGINE_ROOT / "actions" / "cleaner.py").read_text(encoding="utf-8")
        self.assertNotIn("os.remove(", text)
        self.assertNotIn("os.unlink(", text)
        self.assertIn("shutil.move", text)


if __name__ == "__main__":
    unittest.main()

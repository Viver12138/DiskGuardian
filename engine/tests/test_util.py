import os
import unittest
import xml.etree.ElementTree as ElementTree

from diskguardian import util
from diskguardian.scanner import startup


class CommandParsingTests(unittest.TestCase):
    def test_quoted_command(self):
        self.assertEqual(util.executable_from_command('"C:\\Program Files\\App\\app.exe" --flag'), "C:\\Program Files\\App\\app.exe")

    def test_unquoted_command(self):
        self.assertEqual(util.executable_from_command("C:\\Tools\\agent.exe -run"), "C:\\Tools\\agent.exe")

    def test_command_without_executable(self):
        self.assertIsNone(util.executable_from_command("echo hello"))

    def test_environment_expansion(self):
        previous = os.environ.get("DG_TEST_VAR")
        os.environ["DG_TEST_VAR"] = "C:\\Expanded"
        try:
            self.assertEqual(util.expand_env(r"%DG_TEST_VAR%\tool.exe"), "C:\\Expanded\\tool.exe")
        finally:
            if previous is None:
                os.environ.pop("DG_TEST_VAR", None)
            else:
                os.environ["DG_TEST_VAR"] = previous

    def test_iso_utc_format(self):
        self.assertRegex(util.iso_utc(0), r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Contoso</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><RunLevel>LeastPrivilege</RunLevel></Principal>
  </Principals>
  <Settings>
    <Enabled>false</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\\Program Files\\Updater\\updater.exe"</Command>
      <Arguments>--silent</Arguments>
    </Exec>
  </Actions>
</Task>
"""


class TaskDefinitionParsingTests(unittest.TestCase):
    def setUp(self):
        root = ElementTree.fromstring(TASK_XML)
        startup._strip_namespaces(root)
        self.entry = startup._task_entry_from_root(root, "Contoso\\Updater")

    def test_reports_disabled_state(self):
        self.assertEqual(self.entry["state"], "disabled")

    def test_extracts_command_line_and_executable(self):
        self.assertEqual(self.entry["executable"], "C:\\Program Files\\Updater\\updater.exe")
        self.assertIn("--silent", self.entry["command"])

    def test_marks_non_microsoft_tasks(self):
        self.assertEqual(self.entry["scope"], "other")
        self.assertEqual(self.entry["location"], "\\Contoso\\Updater")
        self.assertEqual(self.entry["triggers"], 1)
        self.assertEqual(self.entry["author"], "Contoso")


if __name__ == "__main__":
    unittest.main()

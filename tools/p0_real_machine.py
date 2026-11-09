#!/usr/bin/env python3
r"""P0 real-machine checks for DiskGuardian (Windows only).

What is real here:
- a real uninstaller process is spawned from a real HKCU uninstall registry
  entry, and the engine's verification is checked against that registry;
- real HKCU Run values are disabled and restored;
- real NTFS files are moved to the quarantine, with a real exclusive lock held
  on one of them to exercise E_TARGET_LOCKED / partial results;
- real quarantine files are restored, deleted, locked, and tampered with.

What is *not* real here:
- approval issuance: this script calls the engine's internal `issue_approval`
  operation directly. The real product only does that after the user confirms
  the in-tool card; the card itself is a Harness UI test and is not exercised
  by this script.
- HKLM startup writes and per-machine uninstallers: they need an elevated
  session. The script reports them as skipped when not elevated.

Safety:
- only HKCU test keys named DiskGuardianP0* are written, always removed in a
  finally block;
- no user software is uninstalled; the only uninstaller run is the fixture
  compiled by this script;
- the database, TEMP and quarantine live under .tmp-tests/p0-*;
- the script refuses to run without --yes.

Usage:
    python tools/p0_real_machine.py --yes
    python tools/p0_real_machine.py --yes --keep
    python tools/p0_real_machine.py --yes --msi-fixture .tmp-tests\p0\msi\p0.msi
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import traceback
import winreg
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "engine" / "run.py"

REAL_LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
TEST_APP_DIR = REAL_LOCALAPPDATA / "DiskGuardianP0"

UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

SUCCESS_KEY = "DiskGuardianP0App"
ELEVATED_KEY = "DiskGuardianP0Elevated"
STARTUP_NAME = "DiskGuardianP0Startup"
STARTUP_DATA = r'"C:\Windows\System32\notepad.exe" /?'

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
CreateFileW.restype = wintypes.HANDLE
CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class EngineFailure(RuntimeError):
    def __init__(self, code: str, message: str, details=None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details


class Engine:
    def __init__(self, env: dict[str, str]):
        self.env = env

    def call(self, operation: str, params: dict | None = None):
        request = {"request_id": "p0", "operation": operation, "params": params or {}}
        completed = subprocess.run(
            [sys.executable, "-I", str(ENGINE)],
            input=json.dumps(request).encode("utf-8"),
            capture_output=True,
            cwd=str(ROOT),
            env=self.env,
            timeout=180,
        )
        text = completed.stdout.decode("utf-8", "replace").strip()
        if not text:
            raise RuntimeError(f"engine returned no JSON for {operation}: {completed.stderr.decode('utf-8', 'replace')[-800:]}")
        response = json.loads(text)
        if not response.get("success"):
            error = response.get("error") or {}
            raise EngineFailure(str(error.get("code") or "E_ENGINE"), str(error.get("message") or "engine error"), error.get("details"))
        return response["data"]


class Recorder:
    def __init__(self):
        self.scenarios: list[dict] = []
        self.current: dict | None = None

    def start(self, name: str):
        self.current = {"name": name, "checks": [], "status": "PENDING", "error": None}
        self.scenarios.append(self.current)

    def check(self, label: str, condition: bool, detail: str = ""):
        self.current["checks"].append({"label": label, "ok": bool(condition), "detail": detail})
        return bool(condition)

    def fail(self, error: str):
        self.current["status"] = "FAIL"
        self.current["error"] = error

    def finish(self, skipped: str | None = None):
        checks = self.current["checks"]
        failed = [item for item in checks if not item["ok"]]
        if skipped:
            self.current["status"] = "SKIP"
            self.current["error"] = skipped
        elif failed or self.current["status"] == "FAIL":
            self.current["status"] = "FAIL"
        else:
            self.current["status"] = "PASS"


REC = Recorder()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def delete_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def arp_key(key_name: str) -> str:
    return f"{UNINSTALL_KEY}\\{key_name}"


def arp_exists(key_name: str) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, arp_key(key_name), 0, winreg.KEY_READ):
            return True
    except OSError:
        return False


def write_arp(key_name: str, display_name: str, uninstaller: Path, install_location: Path, arguments: str = "") -> None:
    delete_arp(key_name)
    command = f'"{uninstaller}"' + (f" {arguments}" if arguments else "")
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, arp_key(key_name), 0, winreg.KEY_WRITE) as key:
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, display_name)
        winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, "1.0.0")
        winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "DiskGuardian P0 Fixture")
        winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(install_location))
        winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, command)


def delete_arp(key_name: str) -> None:
    """Delete the fixture key and its values. DeleteKey only removes empty keys."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, arp_key(key_name), 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            while True:
                try:
                    value_name, _, _ = winreg.EnumValue(key, 0)
                except OSError:
                    break
                winreg.DeleteValue(key, value_name)
    except FileNotFoundError:
        return
    except OSError:
        return
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, arp_key(key_name))
    except OSError:
        pass


def write_run_value(name: str, data: str) -> None:
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_WRITE) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, data)


def read_run_value(name: str):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except OSError:
        return None


def delete_run_value(name: str) -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def hold_lock(path: Path) -> int:
    handle = CreateFileW(str(path), GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if handle == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(handle)


def release_lock(handle: int) -> None:
    if handle:
        CloseHandle(wintypes.HANDLE(handle))


def make_temp_file(temp_dir: Path, name: str, content: bytes, old: bool = True) -> Path:
    path = temp_dir / name
    path.write_bytes(content)
    if old:
        stamp = time.time() - 2 * 24 * 60 * 60
        os.utime(path, (stamp, stamp))
    return path


def quarantine_path(engine: Engine, quarantine_id: str) -> Path:
    listing = engine.call("list_quarantine", {"limit": 500})
    for item in listing["items"]:
        if item["quarantine_id"] == quarantine_id:
            return Path(item["quarantine_path"])
    raise AssertionError(f"quarantine record not found: {quarantine_id}")


def quarantine_cleanup(engine: Engine, quarantine_id: str) -> None:
    try:
        engine.call("purge_quarantine", {"quarantine_ids": [quarantine_id]})
    except Exception:
        pass


def find_msi_entry(display_name: str):
    """Find an ARP entry in HKCU/HKLM, 32/64-bit views."""
    for root, hive in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
        for view, view_name in ((0, "default"), (winreg.KEY_WOW64_32KEY, "32"), (winreg.KEY_WOW64_64KEY, "64")):
            path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
                    count = winreg.QueryInfoKey(key)[0]
                    for index in range(count):
                        try:
                            subkey = winreg.EnumKey(key, index)
                            with winreg.OpenKey(key, subkey) as child:
                                name, _ = winreg.QueryValueEx(child, "DisplayName")
                                if str(name).casefold() != display_name.casefold():
                                    continue

                                def value(field: str):
                                    try:
                                        return winreg.QueryValueEx(child, field)[0]
                                    except OSError:
                                        return None

                                return {
                                    "hive": hive,
                                    "view": view_name,
                                    "subkey": subkey,
                                    "display_name": name,
                                    "uninstall": value("UninstallString"),
                                    "quiet": value("QuietUninstallString"),
                                    "install_location": value("InstallLocation"),
                                }
                        except OSError:
                            continue
            except OSError:
                continue
    return None


def wait_for_msi_entry(display_name: str, timeout: float = 30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        entry = find_msi_entry(display_name)
        if entry is not None:
            return entry
        time.sleep(0.5)
    return None


def uninstall_msi(entry: dict) -> None:
    subprocess.run(
        ["msiexec.exe", "/x", str(entry["subkey"]), "/qn"],
        capture_output=True,
        timeout=180,
    )


def compile_fixtures() -> dict[str, Path]:
    csc = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe"
    if not csc.is_file():
        raise RuntimeError(f"csc.exe not found: {csc}")

    delete_tree(TEST_APP_DIR)
    TEST_APP_DIR.mkdir(parents=True, exist_ok=True)
    (TEST_APP_DIR / "app-data.bin").write_bytes(b"DiskGuardian P0 fixture data")

    manifest = TEST_APP_DIR / "require-admin.manifest"
    manifest.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\n'
        '  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">\n'
        "    <security>\n"
        "      <requestedPrivileges>\n"
        '        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />\n'
        "      </requestedPrivileges>\n"
        "    </security>\n"
        "  </trustInfo>\n"
        "</assembly>\n",
        encoding="utf-8",
    )

    source_template = """
using System;
using System.IO;
using Microsoft.Win32;

internal static class Program
{
    private static int Main()
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(@"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\__KEY__", false);
            try { File.Delete(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app-data.bin")); } catch { }
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 2;
        }
    }
}
"""

    fixtures: dict[str, Path] = {}
    for label, key_name, extra in (
        ("uninstall", SUCCESS_KEY, []),
        ("uninstall_elevated", ELEVATED_KEY, [f"/win32manifest:{manifest}"]),
    ):
        source = TEST_APP_DIR / f"{label}.cs"
        source.write_text(source_template.replace("__KEY__", key_name), encoding="utf-8")
        exe = TEST_APP_DIR / f"{label}.exe"
        command = [str(csc), "/nologo", "/target:exe", f"/out:{exe}", *extra, str(source)]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode != 0 or not exe.is_file():
            raise RuntimeError(f"csc failed for {label}: {completed.stdout} {completed.stderr}")
        fixtures[label] = exe
    return fixtures


def scenario_removal_success(engine: Engine, fixtures: dict[str, Path]):
    display = "DiskGuardian P0 Test App"
    try:
        write_arp(SUCCESS_KEY, display, fixtures["uninstall"], TEST_APP_DIR)
        REC.check("fixture registered under HKCU", arp_exists(SUCCESS_KEY))

        plan = engine.call("create_removal_plan", {"software": [display]})
        REC.check("plan_type is removal", plan["plan_type"] == "removal", plan["plan_type"])
        REC.check("plan has one vendor uninstaller item", len(plan["items"]) == 1, str(len(plan["items"])))
        REC.check("uninstaller is the fixture exe", Path(plan["items"][0]["uninstaller"]).name == "uninstall.exe", plan["items"][0]["uninstaller"])

        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        result = engine.call("execute_removal_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})

        REC.check("execute success=true", result["success"] is True, json.dumps(result, ensure_ascii=False)[:500])
        REC.check("status completed", result["status"] == "completed", result["status"])
        REC.check("verification.verified", result["verification"]["verified"] is True)
        REC.check("HKCU uninstall entry removed", not arp_exists(SUCCESS_KEY))
        REC.check("fixture data file removed by uninstaller", not (TEST_APP_DIR / "app-data.bin").exists())

        residue = engine.call(
            "inspect_removal_residue",
            {"software": display, "install_location": str(TEST_APP_DIR)},
        )
        REC.check("residue: no longer registered", residue["registered"] is False)
        REC.check("residue: leftover directory reported", any(item.get("status") == "present" for item in residue["leftovers"]), json.dumps(residue["leftovers"], ensure_ascii=False)[:400])

        audit = engine.call("get_audit_log", {"limit": 50})
        operations = [entry["operation"] for entry in audit["entries"]]
        REC.check("audit has removal.run", "removal.run" in operations, str(operations))
        REC.check("audit has removal.execute", "removal.execute" in operations, str(operations))
    finally:
        delete_arp(SUCCESS_KEY)


def scenario_removal_elevation(engine: Engine, fixtures: dict[str, Path]):
    display = "DiskGuardian P0 Elevated App"
    if is_admin():
        return "session is elevated; a requireAdministrator uninstaller cannot produce WinError 740"
    REC.check("session is not elevated", True, "IsUserAnAdmin()")
    try:
        write_arp(ELEVATED_KEY, display, fixtures["uninstall_elevated"], TEST_APP_DIR)
        plan = engine.call("create_removal_plan", {"software": [display]})
        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        result = engine.call("execute_removal_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})

        REC.check("execute success=false", result["success"] is False)
        REC.check("status failed", result["status"] == "failed", result["status"])
        failed = result["failed_items"][0] if result["failed_items"] else {}
        REC.check("failure code E_ELEVATION_REQUIRED", failed.get("code") == "E_ELEVATION_REQUIRED", json.dumps(failed, ensure_ascii=False)[:400])
        REC.check("software is still registered", arp_exists(ELEVATED_KEY))
        audit = engine.call("get_audit_log", {"limit": 50})
        REC.check("audit records failed removal", any(entry["operation"] == "removal.run" and entry["result"] == "failed" for entry in audit["entries"]))
    finally:
        delete_arp(ELEVATED_KEY)


def scenario_removal_msi_i_string(engine: Engine):
    """A bare `MsiExec.exe /I{GUID}` ARP entry must be resolved and rewritten.

    The fixture is only registered; nothing is executed. This covers the two
    gaps found by the earlier P0 run: relative MsiExec.exe and the /I form.
    """
    key_name = "DiskGuardianP0MsiI"
    display = "DiskGuardian P0 MSI I-String"
    try:
        write_arp(
            key_name,
            display,
            Path("MsiExec.exe"),
            TEST_APP_DIR,
            arguments="/I{00000000-0000-0000-0000-000000000000}",
        )
        plan = engine.call("create_removal_plan", {"software": [display]})
        REC.check("MSI /I plan created", plan["plan_type"] == "removal", plan["plan_type"])
        item = plan["items"][0] if plan.get("items") else {}
        arguments = [str(argument) for argument in item.get("arguments") or []]
        REC.check("planner rewrote /I to /X", any(argument.casefold().startswith("/x") for argument in arguments), str(arguments))
        REC.check("planner added /qn", any(argument.casefold() == "/qn" for argument in arguments), str(arguments))
        REC.check(
            "bare MsiExec.exe resolved to System32",
            str(item.get("uninstaller") or "").casefold().endswith("\\system32\\msiexec.exe"),
            str(item.get("uninstaller")),
        )
    finally:
        delete_arp(key_name)


def scenario_removal_msi_real(engine: Engine, msi_path: Path, display: str):
    """Install a real MSI fixture, let the engine uninstall it, verify the ARP entry.

    The fixture is built with WiX 5 and its ARP UninstallString is
    `MsiExec.exe /I{GUID}`; this is the case the rewrite in removal.py targets.
    The script refuses to touch the fixture if it is already installed.
    """
    msi_path = Path(msi_path)
    if not msi_path.is_file():
        return f"MSI fixture not found: {msi_path}"
    if find_msi_entry(display) is not None:
        return f"{display} is already installed; refusing to uninstall it"

    completed = subprocess.run(
        ["msiexec.exe", "/i", str(msi_path), "/qn"],
        capture_output=True,
        timeout=180,
    )
    entry = wait_for_msi_entry(display)
    if entry is None:
        REC.check("MSI fixture installed", False, f"msiexec exit {completed.returncode}")
        return
    REC.check("MSI fixture installed", True, f"msiexec exit {completed.returncode}")
    install_dir = Path(entry.get("install_location") or (REAL_LOCALAPPDATA / "DiskGuardianP0Msi"))
    try:
        command = str(entry.get("uninstall") or "")
        REC.check("fixture ARP uses /I", "/i" in command.casefold(), command)
        plan = engine.call("create_removal_plan", {"software": [display]})
        item = plan["items"][0] if plan.get("items") else {}
        arguments = [str(argument) for argument in item.get("arguments") or []]
        REC.check("planner rewrote /I to /X", any(argument.casefold().startswith("/x") for argument in arguments), str(arguments))
        REC.check("planner added /qn", any(argument.casefold() == "/qn" for argument in arguments), str(arguments))

        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        result = engine.call("execute_removal_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})
        REC.check("execute success", result["success"] is True, json.dumps(result, ensure_ascii=False)[:500])
        REC.check("ARP entry gone", find_msi_entry(display) is None)
        REC.check("install directory removed", not install_dir.exists(), str(install_dir))
    finally:
        remaining = find_msi_entry(display)
        if remaining is not None:
            uninstall_msi(remaining)
        if install_dir.exists():
            shutil.rmtree(install_dir, ignore_errors=True)


def scenario_startup_disable_enable(engine: Engine):
    try:
        write_run_value(STARTUP_NAME, STARTUP_DATA)
        REC.check("fixture HKCU Run value exists", read_run_value(STARTUP_NAME) == STARTUP_DATA)

        plan = engine.call("create_startup_plan", {"name": STARTUP_NAME, "action": "disable", "scope": "user"})
        REC.check("plan_type is startup", plan["plan_type"] == "startup", plan["plan_type"])
        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        disabled = engine.call("execute_startup_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})
        REC.check("disable success", disabled["success"] is True, json.dumps(disabled, ensure_ascii=False)[:400])
        REC.check("Run value removed", read_run_value(STARTUP_NAME) is None)

        changes = engine.call("list_startup_changes", {"limit": 20})
        row = next((item for item in changes["items"] if item["value_name"] == STARTUP_NAME), None)
        REC.check("original value stored", row is not None and row["value_data"] == STARTUP_DATA, json.dumps(row, ensure_ascii=False)[:400] if row else "missing")
        REC.check("change status is disabled", row is not None and row["status"] == "disabled")

        restore_plan = engine.call("create_startup_plan", {"name": STARTUP_NAME, "action": "enable", "scope": "user"})
        restore_approval = engine.call("issue_approval", {"plan_id": restore_plan["plan_id"]})
        restored = engine.call("execute_startup_plan", {"plan_id": restore_plan["plan_id"], "approval_id": restore_approval["approval_id"]})
        REC.check("enable success", restored["success"] is True, json.dumps(restored, ensure_ascii=False)[:400])
        REC.check("Run value restored exactly", read_run_value(STARTUP_NAME) == STARTUP_DATA, str(read_run_value(STARTUP_NAME)))
        changes = engine.call("list_startup_changes", {"limit": 20})
        row = next((item for item in changes["items"] if item["value_name"] == STARTUP_NAME), None)
        REC.check("change status is restored", row is not None and row["status"] == "restored")
    finally:
        delete_run_value(STARTUP_NAME)


def scenario_startup_drift(engine: Engine):
    name = STARTUP_NAME + "Drift"
    try:
        write_run_value(name, STARTUP_DATA)
        plan = engine.call("create_startup_plan", {"name": name, "action": "disable", "scope": "user"})
        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        write_run_value(name, r'"C:\Windows\System32\calc.exe"')
        try:
            engine.call("execute_startup_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})
            REC.check("drift rejected", False, "execute unexpectedly succeeded")
        except EngineFailure as error:
            REC.check("drift rejected with E_TARGET_CHANGED", error.code == "E_TARGET_CHANGED", error.code)
        REC.check("drifted value left untouched", read_run_value(name) == r'"C:\Windows\System32\calc.exe"', str(read_run_value(name)))
    finally:
        delete_run_value(name)


def scenario_cleanup_locked_partial(engine: Engine, temp_dir: Path):
    good = make_temp_file(temp_dir, "p0-good.tmp", b"good-data")
    locked = make_temp_file(temp_dir, "p0-locked.tmp", b"locked-data")
    handle = 0
    try:
        handle = hold_lock(locked)
        plan = engine.call("create_cleanup_plan", {"paths": [str(good), str(locked)]})
        REC.check("plan has two items", len(plan["items"]) == 2, str(len(plan["items"])))
        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        result = engine.call("execute_cleanup_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})

        REC.check("status partial", result["status"] == "partial", result["status"])
        REC.check("one affected item", len(result["affected_items"]) == 1, str(len(result["affected_items"])))
        failed = result["failed_items"][0] if result["failed_items"] else {}
        REC.check("locked item fails E_TARGET_LOCKED", failed.get("code") == "E_TARGET_LOCKED", json.dumps(failed, ensure_ascii=False)[:400])
        REC.check("locked source still exists", locked.exists())
        REC.check("good source moved away", not good.exists())
        REC.check("verification is not all-true", result["verification"]["verified"] is False)

        quarantine_id = result["affected_items"][0]["quarantine_id"]
        restored = engine.call("restore_quarantined_item", {"quarantine_id": quarantine_id})
        REC.check("restore of affected item verified", restored["verified"] is True)
        REC.check("restored content matches", good.read_bytes() == b"good-data", str(good.read_bytes()))
    finally:
        if handle:
            release_lock(handle)
        for path in (good, locked):
            try:
                path.unlink()
            except OSError:
                pass


def scenario_cleanup_readonly(engine: Engine, temp_dir: Path):
    target = make_temp_file(temp_dir, "p0-readonly.tmp", b"readonly-data")
    try:
        os.chmod(target, stat.S_IREAD)
        plan = engine.call("create_cleanup_plan", {"paths": [str(target)]})
        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        result = engine.call("execute_cleanup_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})
        failed = result["failed_items"][0] if result["failed_items"] else {}
        REC.check("read-only file is not silently deleted", target.exists())
        REC.check("read-only file reports E_TARGET_LOCKED", failed.get("code") == "E_TARGET_LOCKED", json.dumps(failed, ensure_ascii=False)[:400])
        REC.check("plan status is failed", result["status"] == "failed", result["status"])
    finally:
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            pass
        try:
            target.unlink()
        except OSError:
            pass


def scenario_restore_conflict(engine: Engine, temp_dir: Path):
    target = make_temp_file(temp_dir, "p0-conflict.tmp", b"original")
    quarantine_id = None
    try:
        plan = engine.call("create_cleanup_plan", {"paths": [str(target)]})
        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        result = engine.call("execute_cleanup_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})
        quarantine_id = result["affected_items"][0]["quarantine_id"]
        REC.check("file quarantined before conflict", not target.exists())

        target.write_bytes(b"recreated-by-user")
        try:
            engine.call("restore_quarantined_item", {"quarantine_id": quarantine_id})
            REC.check("restore conflict rejected", False, "restore unexpectedly succeeded")
        except EngineFailure as error:
            REC.check("restore conflict is E_TARGET_EXISTS", error.code == "E_TARGET_EXISTS", error.code)
        REC.check("recreated file is untouched", target.read_bytes() == b"recreated-by-user")

        listings = engine.call("list_quarantine", {"limit": 100})
        row = next(item for item in listings["items"] if item["quarantine_id"] == quarantine_id)
        REC.check("record still quarantined after refusal", row["status"] == "quarantined", row["status"])

        target.unlink()
        restored = engine.call("restore_quarantined_item", {"quarantine_id": quarantine_id})
        REC.check("restore succeeds after conflict removed", restored["verified"] is True)
        REC.check("original content restored", target.read_bytes() == b"original")
        quarantine_id = None
    finally:
        if quarantine_id:
            quarantine_cleanup(engine, quarantine_id)
        try:
            target.unlink()
        except OSError:
            pass


def scenario_restore_missing_copy(engine: Engine, temp_dir: Path):
    target = make_temp_file(temp_dir, "p0-missing.tmp", b"missing-copy")
    try:
        plan = engine.call("create_cleanup_plan", {"paths": [str(target)]})
        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        result = engine.call("execute_cleanup_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})
        quarantine_id = result["affected_items"][0]["quarantine_id"]
        copy = quarantine_path(engine, quarantine_id)
        copy.unlink()

        try:
            engine.call("restore_quarantined_item", {"quarantine_id": quarantine_id})
            REC.check("missing copy rejected", False, "restore unexpectedly succeeded")
        except EngineFailure as error:
            REC.check("missing copy is E_NOT_FOUND", error.code == "E_NOT_FOUND", error.code)
        REC.check("original path still absent", not target.exists())
    finally:
        try:
            target.unlink()
        except OSError:
            pass


def scenario_purge_locked(engine: Engine, temp_dir: Path):
    target = make_temp_file(temp_dir, "p0-purge-locked.tmp", b"purge-locked")
    handle = 0
    quarantine_id = None
    try:
        plan = engine.call("create_cleanup_plan", {"paths": [str(target)]})
        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        result = engine.call("execute_cleanup_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})
        quarantine_id = result["affected_items"][0]["quarantine_id"]
        copy = quarantine_path(engine, quarantine_id)
        handle = hold_lock(copy)

        purged = engine.call("purge_quarantine", {"quarantine_ids": [quarantine_id]})
        REC.check("purge did not report success", purged["purged"] == 0, json.dumps(purged, ensure_ascii=False)[:400])
        REC.check("locked quarantine copy reports a failure", len(purged["failed"]) == 1, json.dumps(purged["failed"], ensure_ascii=False)[:400])
        REC.check("locked copy still exists", copy.exists())
        listings = engine.call("list_quarantine", {"limit": 100})
        row = next(item for item in listings["items"] if item["quarantine_id"] == quarantine_id)
        REC.check("record remains quarantined", row["status"] == "quarantined", row["status"])

        release_lock(handle)
        handle = 0
        purged = engine.call("purge_quarantine", {"quarantine_ids": [quarantine_id]})
        REC.check("purge succeeds after unlock", purged["status"] == "completed" and purged["purged"] == 1, json.dumps(purged, ensure_ascii=False)[:400])
        REC.check("quarantine copy deleted", not copy.exists())
        quarantine_id = None
    finally:
        if handle:
            release_lock(handle)
        if quarantine_id:
            quarantine_cleanup(engine, quarantine_id)
        try:
            target.unlink()
        except OSError:
            pass


def scenario_purge_hash_mismatch(engine: Engine, temp_dir: Path):
    target = make_temp_file(temp_dir, "p0-purge-tamper.tmp", b"tamper-me")
    quarantine_id = None
    try:
        plan = engine.call("create_cleanup_plan", {"paths": [str(target)]})
        approval = engine.call("issue_approval", {"plan_id": plan["plan_id"]})
        result = engine.call("execute_cleanup_plan", {"plan_id": plan["plan_id"], "approval_id": approval["approval_id"]})
        quarantine_id = result["affected_items"][0]["quarantine_id"]
        copy = quarantine_path(engine, quarantine_id)
        copy.write_bytes(copy.read_bytes() + b"tampered")

        purged = engine.call("purge_quarantine", {"quarantine_ids": [quarantine_id]})
        REC.check("tampered copy is not deleted", purged["purged"] == 0, json.dumps(purged, ensure_ascii=False)[:400])
        REC.check("tampered copy reports E_VERIFY_FAILED", purged["failed"][0]["code"] == "E_VERIFY_FAILED", json.dumps(purged["failed"], ensure_ascii=False)[:400])
        REC.check("tampered copy still exists", copy.exists())
        listings = engine.call("list_quarantine", {"limit": 100})
        row = next(item for item in listings["items"] if item["quarantine_id"] == quarantine_id)
        REC.check("record remains quarantined", row["status"] == "quarantined", row["status"])
    finally:
        if quarantine_id:
            quarantine_cleanup(engine, quarantine_id)
        try:
            target.unlink()
        except OSError:
            pass


def run(name: str, function, *args):
    REC.start(name)
    try:
        skipped = function(*args)
        REC.finish(skipped)
    except EngineFailure as error:
        REC.fail(f"{error.code}: {error.message}")
    except Exception as error:
        REC.fail(f"{type(error).__name__}: {error}")
        traceback.print_exc()
    finally:
        scenario = REC.scenarios[-1]
        passed = sum(1 for item in scenario["checks"] if item["ok"])
        total = len(scenario["checks"])
        print(f"{scenario['status']:4}  {name:34} {passed}/{total}")
        for item in scenario["checks"]:
            if not item["ok"]:
                print(f"      FAIL {item['label']} {item['detail']}")
        if scenario["error"]:
            print(f"      {scenario['error']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="DiskGuardian P0 real-machine checks (Windows)")
    parser.add_argument("--yes", action="store_true", help="required: allow real HKCU writes and fixture uninstallers")
    parser.add_argument("--keep", action="store_true", help="keep the .tmp-tests/p0-* sandbox")
    parser.add_argument("--msi-fixture", type=Path, help="optional MSI package for the real MSI uninstall scenario")
    parser.add_argument("--msi-display-name", default="DiskGuardian P0 MSI", help="DisplayName of the MSI fixture")
    args = parser.parse_args()
    if not args.yes:
        print("Refusing to run: this writes HKCU test keys. Pass --yes after reviewing the script.")
        return 2

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = ROOT / ".tmp-tests" / f"p0-{stamp}"
    local = base / "Local"
    temp = base / "Temp"
    profile = base / "Profile"
    for directory in (local, temp, profile):
        directory.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "LOCALAPPDATA": str(local),
            "TEMP": str(temp),
            "TMP": str(temp),
            "USERPROFILE": str(profile),
        }
    )
    engine = Engine(env)

    print(f"sandbox: {base}")
    print(f"elevated: {is_admin()}")
    fixtures = compile_fixtures()
    print(f"fixtures: {TEST_APP_DIR}")

    try:
        run("removal-exe-success", scenario_removal_success, engine, fixtures)
        run("removal-elevation", scenario_removal_elevation, engine, fixtures)
        run("removal-msi-i-string", scenario_removal_msi_i_string, engine)
        if args.msi_fixture:
            run("removal-msi-real", scenario_removal_msi_real, engine, args.msi_fixture, args.msi_display_name)
        run("startup-hkcu-disable-enable", scenario_startup_disable_enable, engine)
        run("startup-value-drift", scenario_startup_drift, engine)
        run("cleanup-locked-partial", scenario_cleanup_locked_partial, engine, temp)
        run("cleanup-readonly-file", scenario_cleanup_readonly, engine, temp)
        run("restore-conflict", scenario_restore_conflict, engine, temp)
        run("restore-missing-copy", scenario_restore_missing_copy, engine, temp)
        run("purge-locked-copy", scenario_purge_locked, engine, temp)
        run("purge-hash-mismatch", scenario_purge_hash_mismatch, engine, temp)
    finally:
        delete_tree(TEST_APP_DIR)
        if not args.keep:
            shutil.rmtree(base, ignore_errors=True)

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "sandbox": str(base),
        "elevated": is_admin(),
        "scenarios": REC.scenarios,
    }
    report_path = base / "report.json"
    if args.keep:
        base.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"report: {report_path}")

    failed = [item for item in REC.scenarios if item["status"] == "FAIL"]
    skipped = [item for item in REC.scenarios if item["status"] == "SKIP"]
    print(f"\n{len(REC.scenarios) - len(failed)}/{len(REC.scenarios)} scenarios passed, {len(failed)} failed, {len(skipped)} skipped")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Fixed PowerShell bridge.

Every script is a module constant written by us. Nothing from a request, a model
argument, or a parameter reaches these command lines: there is no code path that
accepts a script string from a caller. This is the engine's only use of
PowerShell, and it reads Windows state through official CIM cmdlets.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

CREATE_NO_WINDOW = 0x08000000

_POWERSHELL = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
)


class PowerShellUnavailable(RuntimeError):
    pass


def run_fixed(script: str, *, timeout: int = 60) -> str:
    if not os.path.isfile(_POWERSHELL):
        raise PowerShellUnavailable(f"powershell.exe not found at {_POWERSHELL}")
    prelude = "$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;\n"
    try:
        process = subprocess.run(
            [
                _POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                prelude + script,
            ],
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as error:
        raise PowerShellUnavailable(f"PowerShell query timed out after {timeout}s") from error
    if process.returncode != 0:
        message = process.stderr.decode("utf-8", "replace").strip()[:800]
        raise PowerShellUnavailable(message or f"PowerShell exited with {process.returncode}")
    return process.stdout.decode("utf-8", "replace")


def run_json(script: str, *, timeout: int = 60) -> Any:
    text = run_fixed(script, timeout=timeout).strip()
    if not text:
        return None
    return json.loads(text)

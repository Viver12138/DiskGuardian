"""Small shared helpers: command parsing and formatting."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

_ENV_VAR = re.compile(r"%([^%]+)%")


def expand_env(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return os.environ.get(match.group(1), match.group(0))

    return _ENV_VAR.sub(replace, text)


def executable_from_command(command: str) -> str | None:
    """Extract the leading executable path from a Windows command line.

    This is a display/evidence helper, never an execution path: nothing in the
    engine runs the string it returns.
    """
    if not command:
        return None
    text = command.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        if end > 0:
            return expand_env(text[1:end])
        return None
    lower = text.lower()
    for executable in (".exe", ".com", ".bat", ".cmd", ".dll"):
        index = lower.find(executable)
        if index >= 0:
            return expand_env(text[: index + len(executable)].strip())
    return None


def iso_utc(timestamp: float | None = None) -> str:
    moment = datetime.now(timezone.utc) if timestamp is None else datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_command_line(command: str) -> tuple[str | None, list[str]]:
    """Split a Windows command line into (executable, arguments).

    The result is only used to describe and later invoke a vendor uninstaller
    that the engine already validated against its allowlist; it is never passed
    to a shell.
    """
    if not command:
        return None, []
    text = command.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        if end < 0:
            return None, []
        executable = expand_env(text[1:end])
        remainder = text[end + 1 :].strip()
    else:
        lower = text.lower()
        index = lower.find(".exe")
        if index < 0:
            return None, []
        executable = expand_env(text[: index + 4].strip())
        remainder = text[index + 4 :].strip()
    if not remainder:
        return executable, []
    try:
        import shlex

        return executable, shlex.split(remainder, posix=True)
    except ValueError:
        return executable, [remainder]


def clamp_text(value: object, limit: int = 400) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]

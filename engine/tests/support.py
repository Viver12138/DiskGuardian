"""Workspace-local fixtures.

The harness command sandbox permits `os.makedirs` below the workspace but denies
writing into directories created by `tempfile` (their DACL differs), so tests use
plain `makedirs` and best-effort cleanup instead of `tempfile`.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[2]
TEST_ROOT = WORKSPACE / ".tmp-tests"


def unique_dir(prefix: str) -> Path:
    TEST_ROOT.mkdir(parents=True, exist_ok=True)
    path = TEST_ROOT / f"{prefix}-{uuid.uuid4().hex[:10]}"
    path.mkdir(parents=True, exist_ok=False)
    return path


def cleanup(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)

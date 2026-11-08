"""Launcher: keeps `python -I run.py` working without PYTHONPATH."""

import sys
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))

from diskguardian.main import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())

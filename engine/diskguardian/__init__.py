"""DiskGuardian Python execution engine.

The engine owns every local system operation. It receives one JSON request per
line on stdin and answers one JSON object per line on stdout (JSONL). It never
prints anything else on stdout: logs go to stderr.

Design rules enforced here (see docs/ENVIRONMENT_REPORT.md and the project
specification):
- fixed operation names, structured parameters, no arbitrary command strings;
- permissions and approvals are validated inside the engine, never trusted
  from the calling plugin or model;
- every response carries the caller's request_id.
"""

__version__ = "0.9.1"

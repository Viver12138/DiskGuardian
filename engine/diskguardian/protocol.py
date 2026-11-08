"""Wire protocol: request parsing, response envelopes, bounded parameters."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Stable error codes. The plugin and the model-facing tool results rely on these
# strings; do not rename them without updating the TypeScript side.
E_BAD_REQUEST = "E_BAD_REQUEST"
E_INVALID_PARAMS = "E_INVALID_PARAMS"
E_UNKNOWN_OPERATION = "E_UNKNOWN_OPERATION"
E_TOO_LARGE = "E_TOO_LARGE"
E_TIMEOUT = "E_TIMEOUT"
E_PATH_NOT_ALLOWED = "E_PATH_NOT_ALLOWED"
E_NOT_FOUND = "E_NOT_FOUND"
E_ACCESS_DENIED = "E_ACCESS_DENIED"
E_ELEVATION_REQUIRED = "E_ELEVATION_REQUIRED"
E_ENGINE = "E_ENGINE"

# Plan and approval vocabulary (Phase D).
E_PLAN_EMPTY = "E_PLAN_EMPTY"
E_PLAN_NOT_FOUND = "E_PLAN_NOT_FOUND"
E_PLAN_EXPIRED = "E_PLAN_EXPIRED"
E_APPROVAL_NOT_FOUND = "E_APPROVAL_NOT_FOUND"
E_APPROVAL_USED = "E_APPROVAL_USED"
E_APPROVAL_EXPIRED = "E_APPROVAL_EXPIRED"
E_APPROVAL_STALE = "E_APPROVAL_STALE"
E_TARGET_CHANGED = "E_TARGET_CHANGED"
E_TARGET_LOCKED = "E_TARGET_LOCKED"
E_TARGET_EXISTS = "E_TARGET_EXISTS"
E_INVALID_STATE = "E_INVALID_STATE"


class EngineError(Exception):
    """An expected failure that maps onto a stable wire error code."""

    def __init__(self, code: str, message: str, details: Any | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


@dataclass(frozen=True)
class Request:
    request_id: str
    operation: str
    params: Mapping[str, Any] = field(default_factory=dict)


def _error(code: str, message: str) -> EngineError:
    return EngineError(code, message)


def decode_line(raw: bytes) -> Request:
    """Decode one request line, rejecting oversized or malformed input."""
    if len(raw) > MAX_REQUEST_BYTES:
        raise _error(E_TOO_LARGE, f"request exceeds {MAX_REQUEST_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _error(E_BAD_REQUEST, "request is not valid UTF-8") from exc
    text = text.strip()
    if not text:
        raise _error(E_BAD_REQUEST, "empty request")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _error(E_BAD_REQUEST, f"request is not valid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise _error(E_BAD_REQUEST, "request must be a JSON object")

    request_id = payload.get("request_id")
    if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
        raise _error(E_BAD_REQUEST, "request_id must be a non-empty string of at most 128 characters")
    operation = payload.get("operation")
    if not isinstance(operation, str) or not operation:
        raise _error(E_BAD_REQUEST, "operation must be a non-empty string")
    params = payload.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise _error(E_BAD_REQUEST, "params must be an object")
    return Request(request_id=request_id, operation=operation, params=params)


def success(request_id: str, data: Any) -> dict[str, Any]:
    return {"request_id": request_id, "success": True, "data": data, "error": None}


def failure(request_id: str | None, code: str, message: str, details: Any | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    return {"request_id": request_id, "success": False, "data": None, "error": error}


def encode_response(response: Mapping[str, Any]) -> bytes:
    """Serialize one response, enforcing the outbound size cap."""
    body = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_RESPONSE_BYTES:
        request_id = response.get("request_id")
        body = json.dumps(
            failure(
                request_id if isinstance(request_id, str) else None,
                E_TOO_LARGE,
                f"response exceeds {MAX_RESPONSE_BYTES} bytes; narrow the request "
                "(fewer paths, smaller limit, lower max_entries)",
            ),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    return body + b"\n"


# ── bounded parameter helpers ────────────────────────────────────────────────


def require_mapping(params: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(params, Mapping):
        raise _error(E_INVALID_PARAMS, "params must be an object")
    return params


def optional_int(
    params: Mapping[str, Any],
    key: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    value = params.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error(E_INVALID_PARAMS, f"{key} must be an integer")
    if value < minimum or value > maximum:
        raise _error(E_INVALID_PARAMS, f"{key} must be between {minimum} and {maximum}")
    return value


def optional_str_list(params: Mapping[str, Any], key: str, *, maximum_items: int = 16) -> list[str]:
    value = params.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise _error(E_INVALID_PARAMS, f"{key} must be an array of non-empty strings")
    if len(value) > maximum_items:
        raise _error(E_INVALID_PARAMS, f"{key} accepts at most {maximum_items} items")
    return value


def optional_bool(params: Mapping[str, Any], key: str, default: bool) -> bool:
    value = params.get(key, default)
    if not isinstance(value, bool):
        raise _error(E_INVALID_PARAMS, f"{key} must be a boolean")
    return value

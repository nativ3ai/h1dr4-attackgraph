from __future__ import annotations

import re
from typing import Any

_PATTERNS = (
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|secret)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"\b(?:0x)?[a-fA-F0-9]{64}\b"),
)

_INTEGRITY_VALUE = re.compile(r"(?i)(?:(?:sha256:|0x)?[a-f0-9]{64})")
_INTEGRITY_FIELDS = {
    "commitment",
    "digest",
    "hash",
    "integrity",
    "report_commitment",
    "scope_hash",
    "tx_hash",
}

_SENSITIVE_FIELDS = {
    "access_key",
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "password",
    "private_key",
    "secret",
    "session_cookie",
    "session_token",
    "token",
}


def redact_text(value: str) -> str:
    redacted = value
    for pattern in _PATTERNS:
        redacted = pattern.sub(
            lambda match: f"{match.group(1) if match.groups() else ''}[REDACTED]", redacted
        )
    return redacted


def _redact_item(key: Any, item: Any) -> Any:
    field = str(key).strip().lower().replace("-", "_")
    if field in _SENSITIVE_FIELDS and item not in (None, "", False):
        return "[REDACTED]"
    is_integrity_field = (
        field in _INTEGRITY_FIELDS
        or field.endswith("_digest")
        or field.endswith("_hash")
        or field.endswith("_commitment")
    )
    if (
        is_integrity_field
        and isinstance(item, str)
        and _INTEGRITY_VALUE.fullmatch(item.strip())
    ):
        return item
    return redact(item)


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: _redact_item(key, item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value

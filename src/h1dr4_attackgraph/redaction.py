from __future__ import annotations

import re
from typing import Any

_PATTERNS = (
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|secret)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"\b(?:0x)?[a-fA-F0-9]{64}\b"),
)


def redact_text(value: str) -> str:
    redacted = value
    for pattern in _PATTERNS:
        redacted = pattern.sub(
            lambda match: f"{match.group(1) if match.groups() else ''}[REDACTED]", redacted
        )
    return redacted


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value

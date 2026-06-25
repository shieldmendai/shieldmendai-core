"""Reusable redaction without secret resolution."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REDACTED = "<redacted>"
REDACTED_REFERENCE = "<redacted-env-reference>"

_SENSITIVE_KEY = re.compile(
    r"(token|password|secret|credential|api[_-]?key|private[_-]?key|"
    r"authorization|chat[_-]?id|webhook[_-]?(url|uri)|username_env|"
    r"password_env|account_id_env|signing_secret_env|url_env)",
    re.IGNORECASE,
)
_ENV_REFERENCE_KEY = re.compile(r".*_envs?$", re.IGNORECASE)
_AUTHENTICATED_URL = re.compile(r"^[a-z][a-z0-9+.-]*://[^/\s]+@", re.IGNORECASE)


def redact_url(value: str) -> str:
    """Remove URL user information and query/fragment data."""
    if not _AUTHENTICATED_URL.search(value):
        return value
    parts = urlsplit(value)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def redact(value: Any, key: str | None = None) -> Any:
    """Recursively redact sensitive values and credential references."""
    if key and _ENV_REFERENCE_KEY.fullmatch(key):
        return REDACTED_REFERENCE
    if key and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_url(value)
    return value


def sanitize_message(message: str) -> str:
    """Redact common inline credential assignments from an error message."""
    sanitized = re.sub(
        r"(?i)\b(token|password|secret|credential|api[_-]?key|private[_-]?key)"
        r"\s*[:=]\s*([^\s,;]+)",
        lambda match: f"{match.group(1)}={REDACTED}",
        message,
    )
    return redact_url(sanitized)

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re

_KEYWORDS = r"password|passwd|secret|token|api[_-]?key|authorization"
_SECRET_KEY = re.compile(rf"(?i){_KEYWORDS}")
_ASSIGNMENT = re.compile(
    rf"(?i)([A-Za-z0-9_]*(?:{_KEYWORDS})[A-Za-z0-9_]*)"
    r"(\"?\s*[=:]\s*)"
    r"(?:((?:bearer|basic)\s+)|(?!(?:bearer|basic)\s))(?!\[REDACTED)"
    r"(\"[^\"]*\"?|'[^']*'?|[^\s,;\"']+)"
)


def _mask_assignment(match: re.Match[str]) -> str:
    value = match.group(4)
    opening = value[0] if value[0] in "\"'" else ""
    # Truncated input may drop the closing quote; keep it only when present.
    closing = opening if opening and len(value) > 1 and value[-1] == opening else ""
    scheme = match.group(3) or ""
    return f"{match.group(1)}{match.group(2)}{scheme}{opening}[REDACTED]{closing}"


# 8.3: patterns applied per field before serialization (D4). Extend in one place.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # F5: URL userinfo (user:token@) masked whole; a bare ssh user is masked too.
    (re.compile(r"://[^/\s\"']+@"), "://***@"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "[REDACTED_AWS_STS]"),
    # Truncation runs before redaction, so the END marker may be cut off.
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
            r"(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*\Z)",
            re.S,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "[REDACTED_JWT]",
    ),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "[REDACTED_API_KEY]"),
    # After JWT so a JWT bearer keeps its typed marker.
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}"), r"\1 [REDACTED]"),
)


def redact_text(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return _ASSIGNMENT.sub(_mask_assignment, text)


def redact(value: object) -> object:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if isinstance(key, str) and isinstance(item, str) and _SECRET_KEY.search(key)
            else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value

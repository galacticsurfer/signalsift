"""Normalization of high-cardinality values.

Replaces identifiers that vary per-request (UUIDs, hashes, IPs, ports,
timestamps, numeric IDs) with stable placeholders so identical failures
collapse to identical normalized messages. Meaningful low-cardinality
values (HTTP status codes, exception types, endpoint paths, DB error
codes) are deliberately preserved.
"""

from __future__ import annotations

import re

# Order matters: longer/more specific shapes first, so e.g. a UUID is not
# partially consumed by the hex or number rules.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # ISO timestamps
    (
        re.compile(
            r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
        ),
        "<TIMESTAMP>",
    ),
    # Bare clock times (syslog/Apache style: `06:01:30`, `13:53:08.123`) —
    # must run before the port rule, which would otherwise mangle them
    # into `06:<PORT>:<PORT>` and split identical errors by hour.
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TIME>"),
    # Syslog/Apache full dates ("Sun Dec 04 <TIME> 2005") — runs after the
    # clock-time rule has already produced the <TIME> placeholder.
    (
        re.compile(r"\b[A-Z][a-z]{2} [A-Z][a-z]{2} {1,2}\d{1,2} <TIME> \d{4}\b"),
        "<TIMESTAMP>",
    ),
    # UUIDs
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<UUID>",
    ),
    # Long hex hashes (sha/md5/trace ids), 12+ hex chars
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<HASH>"),
    # Hex memory addresses
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<ADDR>"),
    # IPv4 (+ optional port)
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<IP>"),
    # :port suffix on hostnames
    (re.compile(r"(?<=[a-zA-Z0-9\]]):\d{2,5}\b"), ":<PORT>"),
    # Durations / sizes keep their unit but drop the value
    (re.compile(r"\b\d+(?:\.\d+)?(?=\s?(?:ms|s|sec|seconds|MB|KB|GB|bytes)\b)"), "<NUM>"),
    # HTTP status codes are preserved by matching them first and putting
    # them back verbatim (see normalize()); here we only handle leftovers:
    # long digit runs (ids), then generic integers of 3+ digits that are
    # NOT typical status codes handled earlier.
    (re.compile(r"\b\d{5,}\b"), "<ID>"),
    # Quoted numeric values (`KeyError: '4'`, `id="123"`) are per-request
    # identifiers, not meaningful constants.
    (re.compile(r"'(\d{1,4})'"), "'<ID>'"),
    (re.compile(r'"(\d{1,4})"'), '"<ID>"'),
    # Numeric path segments: /order/42/items -> /order/<id>/items.
    (re.compile(r"(?<=/)\d+(?=/|\s|$|[?\"'])"), "<id>"),
]

# Status codes we preserve (anything 100-599 in an http-ish context).
_STATUS_GUARD = re.compile(
    r"\b(?P<prefix>status(?:[ _-]?code)?\s*[=:]?\s*|HTTP/\d(?:\.\d)?\"?\s+|returned\s+|code\s+)"
    r"(?P<code>[1-5]\d{2})\b",
    re.IGNORECASE,
)

_REMAINING_INT = re.compile(r"\b\d{3,}\b")


def normalize_message(message: str) -> str:
    """Normalize one log message for fingerprinting/clustering."""
    text = message
    for pattern, placeholder in _PATTERNS:
        text = pattern.sub(placeholder, text)

    # Protect status codes appearing in an HTTP-ish context, then replace
    # other remaining 3+ digit integers with <ID>.
    protected: dict[str, str] = {}

    def _protect(match: re.Match[str]) -> str:
        token = f"\x00{len(protected)}\x00"
        protected[token] = match.group(0)
        return token

    text = _STATUS_GUARD.sub(_protect, text)
    text = _REMAINING_INT.sub("<ID>", text)
    for token, original in protected.items():
        text = text.replace(token, original)

    # Collapse repeated whitespace introduced by replacements.
    text = re.sub(r"[ \t]+", " ", text).strip()
    return text

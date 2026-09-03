"""Safe CloudWatch Logs Insights query construction.

User- or model-supplied values are never interpolated into queries
directly: strings are escaped for use inside `like` regex patterns and
quoted filters, and only whitelisted sort/filter shapes are produced.
Arbitrary Logs Insights queries are not supported in the MVP.
"""

from __future__ import annotations

import re

BASE_FIELDS = "fields @timestamp, @message, @logStream"

_REGEX_SPECIALS = re.compile(r"[.^$*+?()\[\]{}|\\/]")


def escape_regex(value: str) -> str:
    """Escape a literal string for use inside a Logs Insights /regex/."""
    return _REGEX_SPECIALS.sub(lambda m: "\\" + m.group(0), value)


def like_filter(field: str, value: str) -> str:
    return f"filter {field} like /{escape_regex(value)}/"


def build_error_search_query(
    *,
    level: str | None,
    service: str | None,
    exception_type: str | None,
    status_code: int | None,
    request_id: str | None,
    text: str | None,
    limit: int,
) -> str:
    lines = [BASE_FIELDS]
    if level:
        # Match common shapes: `ERROR`, `"level":"error"`, `level=error`.
        # One `filter` keyword with `or` between the conditions — repeating
        # `filter` after `or` is a Logs Insights syntax error
        # (MalformedQueryException: unexpected @ symbol).
        lines.append(
            f"filter @message like /{escape_regex(level.upper())}/"
            f" or @message like /{escape_regex(level.lower())}/"
        )
    if service:
        lines.append(like_filter("@message", service))
    if exception_type:
        lines.append(like_filter("@message", exception_type))
    if status_code is not None:
        lines.append(like_filter("@message", str(int(status_code))))
    if request_id:
        lines.append(like_filter("@message", request_id))
    if text:
        lines.append(like_filter("@message", text))
    lines.append("sort @timestamp desc")
    lines.append(f"limit {int(limit)}")
    return "\n| ".join(lines)


def build_trace_query(*, request_id: str, limit: int) -> str:
    lines = [
        BASE_FIELDS,
        like_filter("@message", request_id),
        "sort @timestamp asc",
        f"limit {int(limit)}",
    ]
    return "\n| ".join(lines)

"""Security policy enforcement.

The policy layer is checked BEFORE any AWS call is made:
- log groups must be explicitly allowlisted,
- time ranges must be bounded and sane,
- result limits are clamped to the configured maximum.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from signalsift.config import Settings
from signalsift.errors import (
    InvalidTimeRangeError,
    LogGroupNotAllowedError,
    TimeRangeTooLargeError,
)


class SecurityPolicy:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def check_log_group(self, log_group: str) -> None:
        allowed = self._settings.allowed_log_groups
        if not allowed:
            raise LogGroupNotAllowedError(
                "No log groups are allowlisted; refusing to query CloudWatch.",
                hint=(
                    "Set SIGNALSIFT_ALLOWED_LOG_GROUPS to a comma-separated list "
                    "of log groups SignalSift may access."
                ),
            )
        if log_group not in allowed:
            raise LogGroupNotAllowedError(
                f"Log group '{log_group}' is not in the allowlist.",
                hint=f"Allowed log groups: {', '.join(sorted(allowed))}",
            )

    def check_time_range(self, start: datetime, end: datetime) -> None:
        if start.tzinfo is None or end.tzinfo is None:
            raise InvalidTimeRangeError("Start and end times must be timezone-aware (use UTC).")
        if end <= start:
            raise InvalidTimeRangeError(
                f"End time ({end.isoformat()}) must be after start time ({start.isoformat()})."
            )
        max_range = timedelta(minutes=self._settings.max_time_range_minutes)
        if end - start > max_range:
            raise TimeRangeTooLargeError(
                f"Requested window of {(end - start)} exceeds the maximum of "
                f"{self._settings.max_time_range_minutes} minutes.",
                hint="Narrow the time range or raise SIGNALSIFT_MAX_TIME_RANGE_MINUTES.",
            )

    def clamp_limit(self, requested: int | None) -> int:
        maximum = self._settings.max_query_results
        if requested is None or requested <= 0:
            return maximum
        return min(requested, maximum)

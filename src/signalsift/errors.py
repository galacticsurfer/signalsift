"""SignalSift error hierarchy.

Every error carries a user-actionable message. MCP/CLI layers render
`message` (and `hint` when present) but never raw stack traces unless
debug mode is enabled.
"""

from __future__ import annotations


class SignalSiftError(Exception):
    """Base for all expected SignalSift failures."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def render(self) -> str:
        if self.hint:
            return f"{self.message}\n\nHint: {self.hint}"
        return self.message


class ConfigurationError(SignalSiftError):
    pass


class LogGroupNotAllowedError(SignalSiftError):
    pass


class TimeRangeTooLargeError(SignalSiftError):
    pass


class InvalidTimeRangeError(SignalSiftError):
    pass


class AwsAuthError(SignalSiftError):
    pass


class CloudWatchQueryError(SignalSiftError):
    pass


class CloudWatchTimeoutError(SignalSiftError):
    pass


class CloudWatchThrottledError(SignalSiftError):
    pass


class LLMUnavailableError(SignalSiftError):
    pass


class LLMModelMissingError(SignalSiftError):
    pass


class LLMTimeoutError(SignalSiftError):
    pass


class LLMOutputError(SignalSiftError):
    pass

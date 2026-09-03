"""Secret and PII redaction.

Logs are untrusted data. Redaction runs on every event BEFORE any LLM
prompt is constructed and before anything is written to debug logs.
Secret rules are always on; PII rules (email/phone/IP) are configurable.

Rules are ordered: specific credential shapes are redacted before the
generic key/value patterns so placeholders stay informative.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern

from signalsift.cloudwatch.models import LogEvent
from signalsift.config import Settings


@dataclass(frozen=True)
class RedactionRule:
    name: str
    pattern: Pattern[str]
    replacement: str


def _rule(name: str, pattern: str, replacement: str, flags: int = re.IGNORECASE) -> RedactionRule:
    return RedactionRule(name=name, pattern=re.compile(pattern, flags), replacement=replacement)


SECRET_RULES: list[RedactionRule] = [
    _rule(
        "private_key_block",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY]",
        flags=0,
    ),
    _rule(
        "aws_access_key",
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b",
        "[REDACTED_AWS_KEY]",
        flags=0,
    ),
    _rule(
        "aws_secret_key_assignment",
        r"(aws_secret_access_key|secret_access_key)(\s*[=:]\s*)\S+",
        r"\1\2[REDACTED]",
    ),
    _rule(
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*",
        "[REDACTED_JWT]",
        flags=0,
    ),
    _rule("bearer_token", r"\b(bearer)(\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1\2[REDACTED]"),
    _rule(
        "authorization_header",
        r"\b(authorization)(['\"]?\s*[=:]\s*['\"]?)([^'\"\s,}]+(?:\s+[^'\"\s,}]+)?)",
        r"\1\2[REDACTED]",
    ),
    _rule(
        "url_credentials",
        r"\b([a-z][a-z0-9+.-]*://[^/\s:@]+):([^@/\s]+)@",
        r"\1:[REDACTED]@",
    ),
    _rule(
        "keyvalue_secret",
        r"\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
        r"auth[_-]?token|session[_-]?id|sessionid|client[_-]?secret|private[_-]?key|token)"
        r"(['\"]?\s*[=:]\s*['\"]?)([^'\"\s,;&}]+)",
        r"\1\2[REDACTED]",
    ),
    _rule("cookie_header", r"\b(set-cookie|cookie)(\s*[=:]\s*)([^\r\n]+)", r"\1\2[REDACTED]"),
    _rule("github_token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "[REDACTED_TOKEN]", flags=0),
    _rule("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "[REDACTED_TOKEN]", flags=0),
]

EMAIL_RULE = _rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]")
PHONE_RULE = _rule(
    "phone",
    r"(?<![\d.])\+?\d{1,3}[ .-]?\(?\d{2,4}\)?[ .-]?\d{3,4}[ .-]?\d{3,4}(?![\d.])",
    "[PHONE]",
)
IP_RULE = _rule("ip_address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]")


class Redactor:
    def __init__(self, settings: Settings, extra_rules: list[RedactionRule] | None = None) -> None:
        rules = list(SECRET_RULES)
        if extra_rules:
            rules.extend(extra_rules)
        if settings.redact_emails:
            rules.append(EMAIL_RULE)
        if settings.redact_phone_numbers:
            rules.append(PHONE_RULE)
        if settings.redact_ip_addresses:
            rules.append(IP_RULE)
        self._rules = rules

    def redact_text(self, text: str) -> str:
        for rule in self._rules:
            text = rule.pattern.sub(rule.replacement, text)
        return text

    def redact_event(self, event: LogEvent) -> LogEvent:
        """Return a copy of the event with message and parsed fields redacted."""
        redacted_fields = {
            key: self.redact_text(value) if isinstance(value, str) else value
            for key, value in event.parsed_fields.items()
        }
        return event.model_copy(
            update={
                "message": self.redact_text(event.message),
                "parsed_fields": redacted_fields,
            }
        )

    def redact_events(self, events: list[LogEvent]) -> list[LogEvent]:
        return [self.redact_event(event) for event in events]

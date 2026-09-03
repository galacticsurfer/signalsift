"""Secret/PII redaction tests — secrets must never survive redaction."""

from __future__ import annotations

from datetime import UTC, datetime

from signalsift.cloudwatch.models import LogEvent
from signalsift.config import Settings
from signalsift.processing.redactor import Redactor

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


def _redactor(**overrides) -> Redactor:
    return Redactor(Settings(_env_file=None, **overrides))


class TestSecretRedaction:
    def test_aws_access_key(self) -> None:
        out = _redactor().redact_text("key AKIAIOSFODNN7EXAMPLE used")
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert "[REDACTED_AWS_KEY]" in out

    def test_jwt(self) -> None:
        out = _redactor().redact_text(f"token={JWT}")
        assert JWT not in out

    def test_bearer_token(self) -> None:
        out = _redactor().redact_text("Authorization: Bearer abcdef123456SECRET")
        assert "abcdef123456SECRET" not in out

    def test_authorization_header_basic(self) -> None:
        out = _redactor().redact_text("authorization: Basic dXNlcjpwYXNz")
        assert "dXNlcjpwYXNz" not in out

    def test_password_fields(self) -> None:
        for text in (
            "password=hunter2secret",
            'password: "hunter2secret"',
            '"password":"hunter2secret"',
        ):
            out = _redactor().redact_text(text)
            assert "hunter2secret" not in out, text

    def test_api_key(self) -> None:
        out = _redactor().redact_text("api_key=sk_live_abc123 apikey: xyz789")
        assert "sk_live_abc123" not in out
        assert "xyz789" not in out

    def test_database_url_with_password(self) -> None:
        out = _redactor().redact_text("postgres://admin:supersecret@db:5432/prod")
        assert "supersecret" not in out
        assert "admin" in out  # username survives, password does not

    def test_private_key_block(self) -> None:
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
        out = _redactor().redact_text(pem)
        assert "MIIEow" not in out

    def test_cookie_header(self) -> None:
        out = _redactor().redact_text("Cookie: session=deadbeefcafe123456")
        assert "deadbeefcafe123456" not in out

    def test_session_id(self) -> None:
        out = _redactor().redact_text("session_id=9f8e7d6c5b4a")
        assert "9f8e7d6c5b4a" not in out


class TestPiiRedaction:
    def test_email_redacted_by_default(self) -> None:
        out = _redactor().redact_text("user galacticsurfer@example.com failed")
        assert "galacticsurfer@example.com" not in out
        assert "[EMAIL]" in out

    def test_email_kept_when_disabled(self) -> None:
        out = _redactor(redact_emails=False).redact_text("user a@b.com failed")
        assert "a@b.com" in out

    def test_ip_redacted_when_enabled(self) -> None:
        out = _redactor(redact_ip_addresses=True).redact_text("from 10.1.2.3")
        assert "10.1.2.3" not in out


class TestEventRedaction:
    def test_redacts_message_and_parsed_fields(self) -> None:
        event = LogEvent(
            timestamp=datetime(2026, 9, 3, tzinfo=UTC),
            message="ERROR password=topsecret1",
            parsed_fields={"note": "api_key=abc123secret", "count": 3},
        )
        redacted = _redactor().redact_event(event)
        assert "topsecret1" not in redacted.message
        assert "abc123secret" not in redacted.parsed_fields["note"]
        assert redacted.parsed_fields["count"] == 3
        # Original event untouched (copy semantics).
        assert "topsecret1" in event.message

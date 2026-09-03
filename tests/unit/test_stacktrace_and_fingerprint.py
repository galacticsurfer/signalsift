"""Stack-trace parsing and deterministic fingerprinting tests."""

from __future__ import annotations

from signalsift.processing.fingerprint import fingerprint_message, fingerprint_trace
from signalsift.processing.normalizer import normalize_message
from signalsift.processing.stacktrace import (
    extract_exception_type,
    parse_stack_trace,
)

SIMPLE_TRACE = """Traceback (most recent call last):
  File "/app/payments/db.py", line 42, in get_connection
    return self.pool.acquire(timeout=5)
  File "/app/vendor/mongo/pool.py", line 88, in acquire
    raise MongoServerSelectionTimeout("no members")
MongoServerSelectionTimeout: No replica set members available"""

CHAINED_TRACE = """Traceback (most recent call last):
  File "/app/db.py", line 10, in connect
    sock.connect(addr)
ConnectionRefusedError: [Errno 111] Connection refused

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/app/handler.py", line 5, in handle
    db.connect()
DatabaseError: could not connect to server"""


class TestPythonTraceParsing:
    def test_parses_exception_type_and_message(self) -> None:
        parsed = parse_stack_trace(SIMPLE_TRACE)
        assert parsed is not None
        assert parsed.root.exception_type == "MongoServerSelectionTimeout"
        assert "replica set" in parsed.root.exception_message

    def test_parses_frames(self) -> None:
        parsed = parse_stack_trace(SIMPLE_TRACE)
        assert parsed is not None
        frames = parsed.root.frames
        assert frames[0].file == "/app/payments/db.py"
        assert frames[0].line == 42
        assert frames[0].function == "get_connection"
        assert frames[-1].function == "acquire"

    def test_chained_exceptions(self) -> None:
        parsed = parse_stack_trace(CHAINED_TRACE)
        assert parsed is not None
        assert len(parsed.exceptions) == 2
        assert parsed.outermost.exception_type == "DatabaseError"
        assert parsed.root.exception_type == "ConnectionRefusedError"

    def test_non_trace_returns_none(self) -> None:
        assert parse_stack_trace("plain ERROR message") is None

    def test_bare_exception_extraction(self) -> None:
        assert extract_exception_type("boom ValidationError: bad email") == "ValidationError"
        assert extract_exception_type("all fine here") is None


class TestFingerprinting:
    def test_identical_across_request_ids(self) -> None:
        msg_a = f"Request 1111 failed\n{SIMPLE_TRACE}"
        msg_b = f"Request 2222 failed\n{SIMPLE_TRACE}"
        fp_a = fingerprint_trace(parse_stack_trace(msg_a), normalize_message(msg_a))
        fp_b = fingerprint_trace(parse_stack_trace(msg_b), normalize_message(msg_b))
        assert fp_a == fp_b

    def test_different_exceptions_differ(self) -> None:
        fp_a = fingerprint_message("TimeoutError: db timeout")
        fp_b = fingerprint_message("ValidationError: bad input")
        assert fp_a != fp_b

    def test_message_fingerprint_includes_context(self) -> None:
        base = fingerprint_message("X failed", "ValueError", "/a", 500)
        assert fingerprint_message("X failed", "ValueError", "/b", 500) != base
        assert fingerprint_message("X failed", "ValueError", "/a", 500) == base

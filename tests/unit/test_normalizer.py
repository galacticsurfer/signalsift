"""Normalization tests: high-cardinality values out, meaning preserved."""

from __future__ import annotations

from signalsift.processing.normalizer import normalize_message


def test_uuid_replaced() -> None:
    out = normalize_message("Request 28d67b37-88cc-4e59-9f00-1234567890ab failed")
    assert "<UUID>" in out
    assert "28d67b37" not in out


def test_numeric_id_replaced() -> None:
    out = normalize_message("failed for user 839382")
    assert "839382" not in out
    assert "<ID>" in out


def test_same_error_different_ids_normalize_identically() -> None:
    a = normalize_message("Request 28d67b37-88cc-4e59-9f00-aaaaaaaaaaaa failed for user 839382")
    b = normalize_message("Request 99999999-1111-2222-3333-bbbbbbbbbbbb failed for user 111111")
    assert a == b


def test_http_status_code_preserved() -> None:
    out = normalize_message("POST /checkout returned status=502 for user 839382")
    assert "502" in out
    assert "839382" not in out


def test_exception_type_preserved() -> None:
    out = normalize_message("MongoServerSelectionTimeout: no members available")
    assert "MongoServerSelectionTimeout" in out


def test_endpoint_preserved() -> None:
    out = normalize_message("GET /api/orders failed")
    assert "/api/orders" in out


def test_timestamp_replaced() -> None:
    out = normalize_message("at 2026-09-03T14:07:22.123Z something broke")
    assert "2026-09-03" not in out
    assert "<TIMESTAMP>" in out


def test_ip_and_port_replaced() -> None:
    out = normalize_message("connecting to 10.42.1.7:5432 failed")
    assert "10.42.1.7" not in out


def test_hex_hash_replaced() -> None:
    out = normalize_message("trace deadbeefcafe4242deadbeef failed")
    assert "deadbeefcafe4242deadbeef" not in out


def test_memory_address_replaced() -> None:
    out = normalize_message("object at 0x7f9a2c003d10 leaked")
    assert "0x7f9a2c003d10" not in out


def test_bare_clock_time_replaced_not_port_mangled() -> None:
    out = normalize_message("worker restarted at 06:01:30 on port 8080")
    assert "06:<PORT>" not in out
    assert "<TIME>" in out


def test_apache_syslog_date_normalizes_identically() -> None:
    a = normalize_message(
        "[Sun Dec 04 06:01:30 2005] [error] mod_jk child workerEnv in error state 6"
    )
    b = normalize_message(
        "[Mon Dec 05 19:15:57 2005] [error] mod_jk child workerEnv in error state 6"
    )
    # Identical errors at different times/days must normalize identically.
    assert a == b
    assert "<TIMESTAMP>" in a


def test_quoted_numeric_ids_normalized() -> None:
    assert normalize_message("KeyError: '4'") == normalize_message("KeyError: '17'")
    assert "<ID>" in normalize_message("KeyError: '4'")
    # Quoted field NAMES are meaningful and must survive.
    assert "'email'" in normalize_message("ValidationError: field 'email' missing")


def test_numeric_path_segments_normalized() -> None:
    a = normalize_message('INFO: 1.2.3.4 - "GET /order/4 HTTP/1.1" 500')
    b = normalize_message('INFO: 5.6.7.8 - "GET /order/1234 HTTP/1.1" 500')
    assert a == b
    assert "/order/<id>" in a

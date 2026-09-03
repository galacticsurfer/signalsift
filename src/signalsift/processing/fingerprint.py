"""Deterministic fingerprinting of logical events.

Two events representing the same failure must produce the same
fingerprint regardless of request IDs, timestamps, UUIDs or user IDs —
those are removed by normalization before hashing.
"""

from __future__ import annotations

import hashlib

from signalsift.processing.stacktrace import ParsedTrace

# How many top (innermost) stack frames participate in the fingerprint.
FINGERPRINT_FRAME_COUNT = 5


def fingerprint_from_parts(*parts: str | None) -> str:
    canonical = "\n".join(part or "" for part in parts)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def fingerprint_trace(trace: ParsedTrace, normalized_message: str) -> str:
    root = trace.root
    top_frames = root.frames[-FINGERPRINT_FRAME_COUNT:]
    frame_repr = "|".join(f"{frame.file}:{frame.function or '?'}" for frame in top_frames)
    chain_repr = ">".join(exc.exception_type for exc in trace.exceptions)
    return fingerprint_from_parts(chain_repr, frame_repr, normalized_message)


def fingerprint_message(
    normalized_message: str,
    exception_type: str | None = None,
    endpoint: str | None = None,
    status_code: int | None = None,
) -> str:
    return fingerprint_from_parts(
        exception_type,
        normalized_message,
        endpoint,
        str(status_code) if status_code is not None else None,
    )

"""Stack-trace parsing.

Python tracebacks are parsed in the MVP; the `StackTraceParser` protocol
lets Java/Node parsers plug in later. A full traceback embedded in a log
message is collapsed into structured data (exception chain, frames) so a
repeated trace counts as ONE logical event, not one event per line.
"""

from __future__ import annotations

import re
from typing import Protocol

from pydantic import BaseModel, Field


class StackFrame(BaseModel):
    file: str
    line: int | None = None
    function: str | None = None


class ParsedException(BaseModel):
    exception_type: str
    exception_message: str
    frames: list[StackFrame] = Field(default_factory=list)


class ParsedTrace(BaseModel):
    """Full exception chain; `root` is the innermost (original) cause."""

    exceptions: list[ParsedException]

    @property
    def root(self) -> ParsedException:
        return self.exceptions[-1]

    @property
    def outermost(self) -> ParsedException:
        return self.exceptions[0]


class StackTraceParser(Protocol):
    def matches(self, message: str) -> bool: ...

    def parse(self, message: str) -> ParsedTrace | None: ...


_PY_FRAME = re.compile(r'^\s*File "(?P<file>[^"]+)", line (?P<line>\d+)(?:, in (?P<func>\S+))?')
_PY_EXC = re.compile(
    r"^(?P<type>[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Timeout|Warning|Interrupt|Exit|Fault|Failure))(?::\s?(?P<msg>.*))?$"
)
_TRACEBACK_HEADER = re.compile(r"^Traceback \(most recent call last\):", re.MULTILINE)


class PythonStackTraceParser:
    def matches(self, message: str) -> bool:
        return bool(_TRACEBACK_HEADER.search(message))

    def parse(self, message: str) -> ParsedTrace | None:
        if not self.matches(message):
            return None
        exceptions: list[ParsedException] = []
        frames: list[StackFrame] = []
        for raw_line in message.splitlines():
            line = raw_line.rstrip()
            frame_match = _PY_FRAME.match(line)
            if frame_match:
                frames.append(
                    StackFrame(
                        file=frame_match.group("file"),
                        line=int(frame_match.group("line")),
                        function=frame_match.group("func"),
                    )
                )
                continue
            exc_match = _PY_EXC.match(line.strip())
            if exc_match and frames:
                exceptions.append(
                    ParsedException(
                        exception_type=exc_match.group("type"),
                        exception_message=(exc_match.group("msg") or "").strip(),
                        frames=frames,
                    )
                )
                frames = []
        if not exceptions:
            return None
        # Python prints the ORIGINAL cause first ("During handling..." /
        # "direct cause" chains), so the last printed exception is the
        # outermost. Reverse so exceptions[0] is outermost, [-1] is root.
        exceptions.reverse()
        return ParsedTrace(exceptions=exceptions)


DEFAULT_PARSERS: list[StackTraceParser] = [PythonStackTraceParser()]


def parse_stack_trace(
    message: str, parsers: list[StackTraceParser] | None = None
) -> ParsedTrace | None:
    for parser in parsers or DEFAULT_PARSERS:
        if parser.matches(message):
            parsed = parser.parse(message)
            if parsed is not None:
                return parsed
    return None


# Fallback: bare "SomeError: message" lines without a full traceback.
_BARE_EXCEPTION = re.compile(
    r"\b(?P<type>[A-Z][A-Za-z0-9_]*(?:Error|Exception|Timeout|Failure|Fault))\b"
)


def extract_exception_type(message: str) -> str | None:
    """Best-effort exception type extraction for non-traceback messages."""
    match = _BARE_EXCEPTION.search(message)
    return match.group("type") if match else None

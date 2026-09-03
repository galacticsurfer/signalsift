"""Feed any raw log file through the SignalSift pipeline (offline, no AWS).

Handles plain text logs: extracts a timestamp per line when one exists
(ISO-ish formats), merges continuation lines (tracebacks, wrapped output)
into their parent event, then runs the full deterministic reducer and
prints the report. Use --llm to add real local-model analysis.

Usage:
    uv run python scripts/run_on_raw_log.py /path/to/app.log
    uv run python scripts/run_on_raw_log.py uvicorn.log --errors-only --llm
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from signalsift.analysis.render import render_incident_report
from signalsift.analysis.service import IncidentService
from signalsift.cloudwatch.client import CloudWatchLogsClient
from signalsift.cloudwatch.models import LogEvent
from signalsift.config import Settings

# Timestamp shapes commonly found at/near the start of log lines.
_TS_PATTERNS = [
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"),
    re.compile(r"\[(\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4})\]"),  # Apache
]
_LEVEL_HINT = re.compile(r"\b(CRITICAL|FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE)\b")
_CONTINUATION = re.compile(
    r"^(\s|Traceback |  File |    |\tat |Caused by|The above exception|During handling)"
)


def _parse_timestamp(line: str) -> datetime | None:
    for pattern in _TS_PATTERNS:
        match = pattern.search(line[:60])
        if not match:
            continue
        raw = match.group(1).replace(",", ".")
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%a %b %d %H:%M:%S %Y",
        ):
            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
    return None


def parse_raw_log(path: Path) -> list[LogEvent]:
    """Group raw lines into events; continuation lines join their parent."""
    events: list[LogEvent] = []
    current_lines: list[str] = []
    current_ts: datetime | None = None
    synthetic_base = datetime(2000, 1, 1, tzinfo=UTC)

    def flush() -> None:
        nonlocal current_lines, current_ts
        if not current_lines:
            return
        message = "\n".join(current_lines)
        ts = current_ts or synthetic_base + timedelta(seconds=len(events))
        events.append(LogEvent(timestamp=ts, message=message))
        current_lines = []
        current_ts = None

    for raw in path.read_text(errors="replace").splitlines():
        if not raw.strip():
            continue
        ts = _parse_timestamp(raw)
        is_continuation = ts is None and (
            _CONTINUATION.match(raw) or (current_lines and not _LEVEL_HINT.search(raw))
        )
        if current_lines and is_continuation:
            current_lines.append(raw)
            continue
        flush()
        current_lines = [raw]
        current_ts = ts
    flush()
    return events


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path)
    parser.add_argument(
        "--errors-only",
        action="store_true",
        help="Keep only events mentioning ERROR/CRITICAL/Traceback",
    )
    parser.add_argument("--llm", action="store_true", help="Run real local-model analysis")
    args = parser.parse_args()

    events = parse_raw_log(args.logfile)
    if args.errors_only:
        marker = re.compile(r"ERROR|CRITICAL|FATAL|Traceback", re.IGNORECASE)
        events = [e for e in events if marker.search(e.message)]
    if not events:
        print("No events parsed from the file.")
        sys.exit(1)
    print(f"Parsed {len(events)} events from {args.logfile}\n")

    settings = Settings(
        _env_file=None, allowed_log_groups=["/local/raw-log"], cache_path=":memory:"
    )
    start = min(e.timestamp for e in events)
    end = max(e.timestamp for e in events) + timedelta(seconds=1)

    llm = None
    if args.llm:
        from signalsift.llm.ollama import OllamaProvider

        candidate = OllamaProvider(settings)
        if await candidate.is_available():
            llm = candidate
        else:
            print("Ollama not reachable; deterministic-only.\n")

    service = IncidentService(settings, CloudWatchLogsClient(settings, None), llm)
    report = await service.analyze_events(
        events, window_start=start, window_end=end, log_group=str(args.logfile)
    )
    print(render_incident_report(report, settings.max_mcp_response_chars))


if __name__ == "__main__":
    asyncio.run(main())

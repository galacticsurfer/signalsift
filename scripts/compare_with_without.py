"""Side-by-side demo: raw CloudWatch dump vs the SignalSift report.

Shows exactly what Claude would have to ingest without SignalSift versus
what actually crosses the MCP boundary, on the same generated incident.
Runs fully offline (fake CloudWatch, simulated LLM analysis).

Usage:
    uv run python scripts/compare_with_without.py [--scenario mongodb] [--count 5000]
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from conftest import FakeLLMProvider, FakeLogsClient  # noqa: E402
from fixtures.generators import SCENARIOS, WINDOW_END, WINDOW_START  # noqa: E402

from signalsift.analysis.render import render_incident_report  # noqa: E402
from signalsift.analysis.service import IncidentService  # noqa: E402
from signalsift.cloudwatch.client import CloudWatchLogsClient  # noqa: E402
from signalsift.config import Settings  # noqa: E402
from signalsift.llm.ollama import OllamaProvider  # noqa: E402


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", default="mongodb", choices=sorted(SCENARIOS))
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument(
        "--llm", action="store_true", help="Use real Ollama instead of the simulated analysis"
    )
    args = parser.parse_args()

    generator = SCENARIOS[args.scenario]
    kwargs = {"count": args.count} if "count" in inspect.signature(generator).parameters else {}
    rows = generator(**kwargs)
    if not rows:
        print(f"Scenario {args.scenario} produced no events; nothing to compare.")
        return

    raw_lines = []
    for row in rows:
        fields = {f["field"]: f["value"] for f in row}
        raw_lines.append(f"[{fields['@timestamp']}] {fields['@message']}")
    raw_dump = "\n".join(raw_lines)

    print("=" * 74)
    print("WITHOUT SignalSift — raw CloudWatch dump sent to Claude")
    print("=" * 74)
    print(f"  events:            {len(rows):,}")
    print(f"  size:              {len(raw_dump):,} chars  (~{len(raw_dump) // 4:,} tokens)")
    print("  secrets redacted:  NO")
    print("  first event (the rest repeat with different UUIDs):\n")
    print("    " + raw_lines[0].replace("\n", "\n    "))
    print(f"    [... {len(rows) - 1:,} more events follow ...]\n")

    settings = Settings(
        _env_file=None,
        allowed_log_groups=["/aws/app/example"],
        cache_path=":memory:",
        query_poll_initial_seconds=0.001,
    )
    llm = None
    llm_label = "simulated (canned analysis, real schema/validation path)"
    if args.llm:
        candidate = OllamaProvider(settings)
        if await candidate.is_available():
            llm = candidate
            llm_label = f"real Ollama ({llm.model_name})"
        else:
            print("Ollama not reachable; falling back to simulated analysis.\n")
    if llm is None:
        llm = FakeLLMProvider()

    service = IncidentService(settings, CloudWatchLogsClient(settings, FakeLogsClient(rows)), llm)
    report_model = await service.analyze_incident(
        "/aws/app/example", WINDOW_START, WINDOW_END, service="example"
    )
    report = render_incident_report(report_model, settings.max_mcp_response_chars)

    print("=" * 74)
    print("WITH SignalSift — what actually crosses MCP to Claude")
    print("=" * 74)
    print(f"  local LLM:         {llm_label}")
    print(f"  size:              {len(report):,} chars  (~{len(report) // 4:,} tokens)")
    print(f"  reduction:         {(1 - len(report) / len(raw_dump)) * 100:.2f}%")
    print("  secrets redacted:  yes (before local LLM and before MCP)")
    print()
    print(report)


if __name__ == "__main__":
    asyncio.run(main())

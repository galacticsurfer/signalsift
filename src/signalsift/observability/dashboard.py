"""Static local dashboard generated from SignalSift's own telemetry.

Produces one self-contained HTML file (inline CSS, no external assets,
no server) summarizing recent operations: hero stats, duration and
compression charts, and a full table view. Everything reads from the
local SQLite telemetry — nothing leaves the machine.
"""

from __future__ import annotations

import statistics
from datetime import UTC, datetime
from html import escape
from typing import Any

_ANALYSIS_OPS = ("analyze_incident", "search_errors")

# Palette: reference dataviz palette, slot 1 (blue), validated for both
# light and dark surfaces; text wears text tokens, never the series color.
_CSS = """
:root {
  color-scheme: light;
  --surface: #fcfcfb; --card: #ffffff; --border: #e4e3df;
  --text-1: #0b0b0b; --text-2: #52514e; --series-1: #2a78d6;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --surface: #1a1a19; --card: #232322; --border: #3a3937;
    --text-1: #ffffff; --text-2: #c3c2b7; --series-1: #3987e5;
  }
}
* { box-sizing: border-box; margin: 0; }
body { background: var(--surface); color: var(--text-1);
  font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; padding: 24px; }
h1 { font-size: 20px; margin-bottom: 4px; }
.sub { color: var(--text-2); margin-bottom: 24px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px; margin-bottom: 28px; }
.tile { background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px 16px; }
.tile .v { font-size: 26px; font-weight: 650; letter-spacing: -0.02em; }
.tile .k { color: var(--text-2); font-size: 12px; margin-top: 2px; }
section { margin-bottom: 28px; }
h2 { font-size: 14px; font-weight: 600; margin-bottom: 10px; }
.row { display: grid; grid-template-columns: 130px 1fr 90px; align-items: center;
  gap: 10px; margin-bottom: 4px; }
.row .lbl { color: var(--text-2); font-size: 12px; text-align: right;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.track { height: 14px; }
.bar { height: 14px; background: var(--series-1); border-radius: 0 4px 4px 0;
  min-width: 2px; }
.row .val { font-size: 12px; color: var(--text-1); font-variant-numeric: tabular-nums; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { text-align: left; color: var(--text-2); font-weight: 500;
  border-bottom: 1px solid var(--border); padding: 6px 10px 6px 0; }
td { border-bottom: 1px solid var(--border); padding: 6px 10px 6px 0;
  font-variant-numeric: tabular-nums; }
.wrap { overflow-x: auto; }
.empty { color: var(--text-2); padding: 24px 0; }
"""


def _fmt_time(recorded_at: float) -> str:
    return datetime.fromtimestamp(recorded_at, tz=UTC).strftime("%m-%d %H:%M")


def _bar_rows(rows: list[dict[str, Any]], value_key: str, fmt) -> str:
    values = [float(r.get(value_key) or 0) for r in rows]
    peak = max(values) if values else 1.0
    peak = peak or 1.0
    out = []
    for row, value in zip(rows, values, strict=True):
        width = max(1.0, 100.0 * value / peak)
        label = escape(f"{_fmt_time(row['recorded_at'])} {row['operation']}")
        out.append(
            f'<div class="row"><div class="lbl">{label}</div>'
            f'<div class="track"><div class="bar" style="width:{width:.1f}%"></div></div>'
            f'<div class="val">{escape(fmt(value))}</div></div>'
        )
    return "\n".join(out)


def render_dashboard(metrics: list[dict[str, Any]], generated_at: str) -> str:
    analyses = [m for m in metrics if m.get("operation") in _ANALYSIS_OPS]
    llm_runs = [m for m in metrics if m.get("operation") == "llm_analyze"]
    with_ratio = [m for m in analyses if m.get("compression_ratio") is not None]
    cache_hits = sum(1 for m in analyses if m.get("cache_hit"))

    def tile(value: str, key: str) -> str:
        return (
            f'<div class="tile"><div class="v">{escape(value)}</div>'
            f'<div class="k">{escape(key)}</div></div>'
        )

    tiles = [
        tile(str(len(metrics)), "operations recorded"),
        tile(str(len(analyses)), "analyses / searches"),
        tile(
            f"{100 * cache_hits / len(analyses):.0f}%" if analyses else "–",
            "cache hit rate",
        ),
        tile(
            f"{statistics.median(m.get('duration_seconds', 0) for m in llm_runs):.1f}s"
            if llm_runs
            else "–",
            "median LLM latency",
        ),
        tile(
            f"{statistics.mean(float(m['compression_ratio']) for m in with_ratio):.4f}"
            if with_ratio
            else "–",
            "mean compression ratio",
        ),
    ]

    recent = [m for m in analyses if not m.get("cache_hit")][:15]
    duration_chart = (
        _bar_rows(recent, "duration_seconds", lambda v: f"{v:.1f}s")
        if recent
        else '<div class="empty">No analyses recorded yet.</div>'
    )
    volume_rows = [m for m in recent if m.get("cloudwatch_events")]
    volume_chart = (
        _bar_rows(volume_rows, "cloudwatch_events", lambda v: f"{int(v):,}")
        if volume_rows
        else '<div class="empty">No event volumes recorded yet.</div>'
    )

    table_rows = []
    for m in metrics[:40]:
        table_rows.append(
            "<tr>"
            f"<td>{escape(_fmt_time(m['recorded_at']))}</td>"
            f"<td>{escape(str(m.get('operation', '')))}</td>"
            f"<td>{m.get('duration_seconds', '')}</td>"
            f"<td>{m.get('cloudwatch_events', '')}</td>"
            f"<td>{m.get('clusters', '')}</td>"
            f"<td>{m.get('events_sent_to_llm', '')}</td>"
            f"<td>{m.get('compression_ratio', '')}</td>"
            f"<td>{'hit' if m.get('cache_hit') else ''}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SignalSift — local telemetry</title>
<style>{_CSS}</style></head>
<body>
<h1>SignalSift</h1>
<div class="sub">Local telemetry · generated {escape(generated_at)} ·
never leaves this machine</div>
<div class="tiles">{"".join(tiles)}</div>
<section><h2>Analysis duration (recent runs, seconds)</h2>{duration_chart}</section>
<section><h2>CloudWatch events processed per run</h2>{volume_chart}</section>
<section><h2>All recent operations</h2><div class="wrap">
<table>
<thead><tr><th>time (UTC)</th><th>operation</th><th>duration s</th>
<th>events</th><th>clusters</th><th>to LLM</th><th>ratio</th><th>cache</th></tr></thead>
<tbody>{"".join(table_rows)}</tbody>
</table></div></section>
</body></html>
"""

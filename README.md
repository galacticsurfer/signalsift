# SignalSift MCP

Local-first observability intelligence MCP server.

SignalSift connects to AWS CloudWatch Logs, aggressively reduces noisy log data
with deterministic Python processing, analyzes the reduced evidence with a
small **local** LLM (Ollama on Apple Silicon), and returns a compact,
evidence-validated incident report to an MCP client such as Claude Code or
Claude Desktop.

**The core goal: never send large volumes of CloudWatch logs to Claude.**

```text
CloudWatch → Logs Insights → filter → normalize → redact → dedup →
cluster → sample → local LLM → validated incident report → MCP → Claude
```

## Privacy boundary

```text
AWS CloudWatch
      │  authenticated read-only CloudWatch query
      ▼
SignalSift (runs locally)
      ├─ redacts secrets/PII
      ├─ reduces thousands of events to a handful of clusters
      └─ analyzes with a local Ollama model (no tools, no credentials)
      ▼
compact sanitized report (~1–2K tokens)
      ▼
Claude (via MCP)
```

Raw logs remain on your machine. Only the final sanitized, high-signal report
crosses the MCP boundary. No telemetry is ever sent externally.

## Requirements

- macOS on Apple Silicon (M1+) — Linux works too
- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- AWS CLI configured (AWS SSO recommended; read-only CloudWatch Logs policy)
- [Ollama](https://ollama.com) running locally

## Setup

**New machine? Follow [INSTALL.md](INSTALL.md)** — the complete
from-zero walkthrough (tooling, corporate-proxy TLS, AWS profiles, MCP
wiring for Cursor / Claude Code / Claude Desktop). Short version:

```bash
git clone https://github.com/galacticsurfer/signalsift.git
cd signalsift

uv sync

aws sso login --profile company

ollama pull qwen3:4b           # default model (thinking mode kept off by SignalSift)

cp .env.example .env           # then edit: allowlist, region, model

uv run signalsift health
```

`signalsift health` verifies configuration, AWS credentials, CloudWatch
access, Ollama connectivity, model availability and the SQLite cache.

## Configuration

Environment variables (or `.env`), all prefixed `SIGNALSIFT_`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `AWS_PROFILE` / `AWS_REGION` | auto | boto3 chain; if unset and the chain is empty, the sole configured profile is auto-selected |
| `ALLOWED_LOG_GROUPS` | *(empty = deny all)* | comma-separated allowlist; exact names or glob patterns (`/aws/app/*`) |
| `MAX_TIME_RANGE_MINUTES` | 120 | maximum query window |
| `MAX_QUERY_RESULTS` | 5000 | maximum CloudWatch events per query |
| `OLLAMA_URL` | `http://localhost:11434` | local inference endpoint |
| `LLM_MODEL` | `qwen3:4b` | any Ollama model (thinking mode force-disabled) |
| `LLM_TIMEOUT_SECONDS` | 120 | inference timeout |
| `MAX_LLM_INPUT_CHARS` | 40000 | evidence budget for the local model |
| `MAX_MCP_RESPONSE_CHARS` | 12000 | response size cap toward Claude |
| `CACHE_PATH` | `~/.signalsift/cache.sqlite3` | SQLite cache + local telemetry |
| `CACHE_TTL_SECONDS` | 900 | cache freshness |
| `REDACT_EMAILS` / `REDACT_PHONE_NUMBERS` / `REDACT_IP_ADDRESSES` | true/false/false | optional PII rules (secrets are always redacted) |
| `DEBUG` | false | expose stack traces in tool errors |

Model guidance — **thinking mode is always disabled** (`LLM_THINKING`
defaults to false): hidden reasoning chains cost seconds-to-minutes of
latency for no gain on structured extraction (our A/B: 48s-to-timeout
with thinking vs a stable handful of seconds without). Benchmark scores
(structured facts, not prose — `scripts/benchmark_model.py`):
`qwen3:4b` thinking-off 0.80 (default, 2.5 GB); `qwen2.5:7b` 0.73
(4.7 GB, no thinking capability at all); `qwen2.5:3b` 0.50 (8 GB RAM
fallback; often misses exact exception names). Re-run the benchmark on
your own hardware. Works the same on macOS and Linux.

## CLI

The CLI and the MCP server share the same service layer.

```bash
# full incident analysis (CloudWatch → reduction → local LLM → report)
uv run signalsift analyze --log-group /aws/app/payments-prod --last 30m

# deterministic pattern search (add --semantic for LLM interpretation)
uv run signalsift search --log-group /aws/app/payments-prod --last 1h --status-code 502

# trace one request ID
uv run signalsift trace --log-group /aws/app/payments-prod --request-id abc-123

# before/after a deployment
uv run signalsift compare \
  --log-group /aws/app/payments-prod \
  --baseline-start 2026-09-03T13:00:00Z --baseline-end 2026-09-03T14:00:00Z \
  --comparison-start 2026-09-03T14:00:00Z --comparison-end 2026-09-03T15:00:00Z

# discovery, health & local telemetry
uv run signalsift groups         # allowlisted log groups that exist in the account
uv run signalsift health
uv run signalsift stats
uv run signalsift dashboard      # self-contained HTML dashboard from local telemetry
```

## MCP setup (Claude Code / Claude Desktop)

Claude Code, from a local checkout:

```bash
claude mcp add signalsift -- uv --directory /path/to/signal_sift run signalsift serve
```

Or without cloning, straight from the git remote (uvx builds and caches it):

```bash
claude mcp add signalsift -- uvx --from git+https://github.com/galacticsurfer/signalsift signalsift serve
```

Configuration comes from environment variables either way — set at least
`SIGNALSIFT_ALLOWED_LOG_GROUPS`, `SIGNALSIFT_AWS_PROFILE`/`_REGION`.

### Cursor

Cursor uses the same stdio MCP protocol: copy `examples/cursor_mcp.json`
into `~/.cursor/mcp.json` (all projects) or `<repo>/.cursor/mcp.json`
(one project), fix the `--directory` path, then enable the server under
Cursor Settings → MCP. The `uvx --from git+...` form works there too.

Claude Desktop (`claude_desktop_config.json`, see `examples/claude_config.json`):

```json
{
  "mcpServers": {
    "signalsift": {
      "command": "uv",
      "args": ["--directory", "/path/to/signal_sift", "run", "signalsift", "serve"]
    }
  }
}
```

### MCP tools

| Tool | Purpose |
| --- | --- |
| `list_log_groups` | discover which allowlisted log groups exist (name, size, retention) — call first when the exact name is unknown |
| `analyze_incident` | general incident diagnosis for a log group + window |
| `search_errors` | deterministic error-pattern discovery (no LLM); lists **every** cluster found, not just the top-ranked ones |
| `trace_request` | chronological redacted events for one request ID |
| `compare_windows` | error-profile diff between two windows (deployments) |

Then ask Claude things like:

> Why did payments-service start returning 502s in the last 30 minutes?
> Compare errors before and after the deployment at 14:30.
> Trace request ID abc-123.

## How the reduction works

Everything that Python can do deterministically is done in Python; the local
LLM only interprets already-reduced evidence:

1. **Query** — typed, template-generated Logs Insights queries (no free-form
   queries), allowlist + time-range + result-limit enforcement *before* AWS is
   contacted.
2. **Redact** — secrets (AWS keys, JWTs, bearer/authorization headers,
   passwords, API keys, cookies, DB URLs, private keys) always; email/phone/IP
   optionally. Runs before anything else sees the text.
3. **Normalize** — UUIDs, request IDs, hashes, IPs, ports, timestamps and
   numeric IDs become placeholders; HTTP status codes, exception types and
   endpoints are preserved.
4. **Stack traces** — Python tracebacks are parsed into exception chains and
   frames; a repeated trace is one logical event, not fifty lines.
5. **Fingerprint & cluster** — deterministic SHA-256 fingerprints; exact
   grouping plus (exception type, normalized message) merging.
6. **Rank & sample** — deterministic incident score (frequency, recency,
   severity, 5xx association); first/middle/latest representative events per
   cluster, hard budgets at every layer.
7. **Full-window volume timeline** — a companion server-side
   `stats count(*) by bin(...)` query aggregates over the ENTIRE window, so
   the report shows the complete volume curve even when event retrieval hit
   the query limit; if events were truncated, the report states exactly
   which time range they cover.
8. **One local LLM call** — a single structured-JSON analysis over the top
   clusters (never one call per cluster).
9. **Validate** — every cluster ID and affected component the model claims is
   checked against the evidence it was given; unsupported claims are removed
   or flagged. The report separates *Observed* / *Likely interpretation* /
   *Unknown*.

Every report ends with the compression stats, e.g.:

```text
SIGNALSIFT STATS
----------------
CloudWatch events: 4,871
Unique logical events: 382
Clusters: 23
Clusters sent to local LLM: 8
Events sent to local LLM: 27
Compression ratio: 0.0055
```

If Ollama is down, SignalSift degrades gracefully: the deterministic report
(clusters, counts, endpoints, timeline) is still returned with
`semantic_analysis_status = unavailable`.

## Security model

- AWS access is read-only and uses the standard boto3 credential chain (SSO
  recommended); SignalSift never stores keys.
- Log groups must be explicitly allowlisted; unauthorized groups are rejected
  before any AWS call.
- Log content is treated as untrusted: prompt-injection text inside logs is
  data, never instructions. The local model has no tools, no filesystem, no
  network beyond its own inference endpoint, and no credentials.
- Secrets are redacted before LLM inference and before debug logging.
- Hard size limits at every boundary (query, clusters, examples, LLM input,
  LLM output, MCP response).

## Development

```bash
make test    # uv run pytest
make lint    # ruff check
uv run python scripts/generate_test_logs.py --scenario mongodb --count 2000
uv run python scripts/smoke_test.py              # full pipeline on fixtures, no AWS needed
uv run python scripts/compare_with_without.py    # raw-dump vs report, side by side
uv run python scripts/benchmark_model.py         # compare local models on fixture incidents

# real logs, no AWS: boot a genuinely buggy FastAPI app, capture real
# uvicorn tracebacks, then feed any raw log file through the pipeline
uv run python scripts/generate_fastapi_logs.py --requests 40
uv run python scripts/run_on_raw_log.py fastapi_sample.log --errors-only
uv run python scripts/sso_probe.py          # diagnose AWS SSO token-cache key mismatches
```

Tests never require AWS or Ollama; opt-in integration tests:

```bash
RUN_AWS_INTEGRATION_TESTS=1 uv run pytest tests/integration -q
RUN_OLLAMA_INTEGRATION_TESTS=1 uv run pytest tests/integration -q
```

## Roadmap (interfaces ready, not implemented)

Application-code RAG, Git diffs / GitHub PRs, SonarQube/Pylint/Flake8,
OpenTelemetry traces, CloudWatch metrics, Kubernetes logs, deployment
correlation, incident history — the provider abstractions (`LocalLLMProvider`,
`StackTraceParser`, typed request models, the evidence-packet format) were
designed so these can be added without restructuring.

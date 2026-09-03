# Installing SignalSift from zero

A complete walkthrough for a fresh machine. Written for macOS (Apple
Silicon); Linux differences are noted inline.

## Step 0 — Tooling (one-time)

```bash
# uv — Python toolchain
curl -LsSf https://astral.sh/uv/install.sh | sh

# Ollama — local LLM runtime
brew install ollama            # Linux: curl -fsSL https://ollama.com/install.sh | sh
ollama serve &                 # the Mac menu-bar app also works
ollama pull qwen3:4b           # default model, ~2.5 GB
```

**Corporate machine?** If your company runs a TLS-intercepting proxy
(Zscaler, Netskope, ...), uv's bundled certificate store won't trust it
and downloads fail with `invalid peer certificate: UnknownIssuer`. Make
uv use the system keychain permanently:

```bash
echo 'export UV_NATIVE_TLS=true' >> ~/.zshrc && source ~/.zshrc
```

## Step 1 — Get SignalSift

```bash
git clone https://github.com/galacticsurfer/signalsift.git ~/code/signalsift
cd ~/code/signalsift
uv sync
```

## Step 2 — AWS access (read-only CloudWatch Logs)

```bash
aws sso login --profile <your-profile>     # or however your org issues creds

# find your log group names for the next step:
aws logs describe-log-groups --profile <your-profile> \
  --query 'logGroups[].logGroupName' --output table
```

Prefer a named profile over exported `AWS_*` env vars: GUI-launched MCP
servers don't inherit your shell environment, but profiles live on disk
and work for every process.

## Step 3 — Configure

```bash
cp .env.example .env
```

Edit `.env` — three lines matter:

```
SIGNALSIFT_AWS_PROFILE=<your-profile>
SIGNALSIFT_AWS_REGION=<your-region>
SIGNALSIFT_ALLOWED_LOG_GROUPS=/real/log-group-1,/real/log-group-2
```

The allowlist is the security boundary: empty = every query refused.

## Step 4 — Verify before wiring anything

```bash
uv run signalsift health      # all rows should say OK

# optional zero-AWS dry run of the full pipeline, local LLM included:
uv run python scripts/generate_fastapi_logs.py --requests 40
uv run python scripts/run_on_raw_log.py fastapi_sample.log --errors-only --llm
```

## Step 5 — First real query from the terminal

```bash
uv run signalsift search  --log-group /real/log-group-1 --last 30m   # fast, no LLM
uv run signalsift analyze --log-group /real/log-group-1 --last 30m   # full report
```

## Step 6 — Hook into your editor/assistant

All clients use the same stdio MCP server.

### Cursor — `~/.cursor/mcp.json`

```json
{
  "mcpServers": {
    "signalsift": {
      "command": "uv",
      "args": ["--directory", "/Users/YOU/code/signalsift", "run", "signalsift", "serve"],
      "env": { "UV_NATIVE_TLS": "true" }
    }
  }
}
```

Fully restart Cursor (Cmd+Q) → Settings → MCP → toggle `signalsift` on →
4 tools appear. The `env` block matters: GUI apps don't read `~/.zshrc`,
so anything uv itself needs must be passed here. SignalSift's own config
comes from the repo's `.env` (the `--directory` flag sets the working
directory there).

### Claude Code

```bash
claude mcp add signalsift -- uv --directory ~/code/signalsift run signalsift serve
```

### Claude Desktop

Copy `examples/claude_config.json` into `claude_desktop_config.json` and
fix the path.

## Step 7 — Use it

Ask in plain English from the agent/chat panel:

> Why did payments-service start returning 502s in the last 30 minutes?
> Compare errors before and after the deployment at 14:30.
> Trace request ID abc-123.

## Clone-free alternative

Any machine with just uv — skips the checkout entirely. Configuration
must then live in the MCP `env` block, since there is no `.env`:

```bash
uvx --from git+https://github.com/galacticsurfer/signalsift@v0.2.0 signalsift serve
```

Note: uvx caches the build at first use and does not auto-pull new
commits — pin a tag and bump deliberately. For a fast-moving checkout,
the `--directory` form picks up `git pull` immediately.

## The three failure modes to know

Each returns an actionable message, and `signalsift health` diagnoses
all three:

1. **Allowlist empty or wrong** → query refused by design; fix
   `SIGNALSIFT_ALLOWED_LOG_GROUPS`.
2. **Expired AWS session** → re-run your login command.
3. **Ollama down** → you still get the full deterministic report, just
   marked `semantic analysis unavailable`.

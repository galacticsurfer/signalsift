"""Async-friendly wrapper around boto3 CloudWatch Logs Insights.

Flow: StartQuery -> poll GetQueryResults with exponential backoff ->
Complete/Failed/Timeout. On timeout or cancellation the query is
stopped server-side. All results convert immediately to `LogEvent`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Protocol

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from signalsift.cloudwatch.models import (
    LogEvent,
    QueryResult,
    QueryStats,
    parse_cloudwatch_timestamp,
)
from signalsift.cloudwatch.query_planner import PlannedQuery
from signalsift.config import Settings
from signalsift.errors import (
    AwsAuthError,
    CloudWatchQueryError,
    CloudWatchThrottledError,
    CloudWatchTimeoutError,
)

logger = logging.getLogger(__name__)

# Keys commonly used by structured JSON loggers, mapped to LogEvent fields.
_LEVEL_KEYS = ("level", "levelname", "log_level", "severity")
_REQUEST_ID_KEYS = ("request_id", "requestId", "req_id", "correlation_id")
_TRACE_ID_KEYS = ("trace_id", "traceId", "xray_trace_id")
_SERVICE_KEYS = ("service", "service_name", "app", "application", "logger")


class LogsInsightsClient(Protocol):
    """The subset of the boto3 `logs` client SignalSift uses (mockable)."""

    def start_query(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_query_results(self, *, queryId: str) -> dict[str, Any]: ...  # noqa: N803

    def stop_query(self, *, queryId: str) -> dict[str, Any]: ...  # noqa: N803

    def describe_log_groups(self, **kwargs: Any) -> dict[str, Any]: ...


def _probe_session(session: Any) -> str:
    """'valid', 'invalid' (bad/expired creds), or 'network' (can't tell)."""
    from botocore.config import Config
    from botocore.exceptions import EndpointConnectionError

    try:
        session.client(
            "sts",
            region_name=session.region_name or "us-east-1",
            config=Config(connect_timeout=5, read_timeout=5, retries={"max_attempts": 1}),
        ).get_caller_identity()
        return "valid"
    except EndpointConnectionError:
        return "network"
    except Exception:  # noqa: BLE001 - expired/invalid/unauthorized all mean "unusable"
        return "invalid"


_MAX_PROFILE_SCAN = 16


def _credentials_present(session: Any) -> bool:
    try:
        return session.get_credentials() is not None
    except Exception:  # noqa: BLE001 - SSOTokenLoadError etc. mean "not usable"
        return False


def _resolve_working(settings: Settings) -> tuple[str | None, list[str | None]]:
    """Pick the AWS profile whose credentials are actually live.

    Returns (chosen, all_working). `chosen` is None for the default chain.
    - Explicit SIGNALSIFT_AWS_PROFILE wins, used verbatim.
    - Otherwise probe the default chain, then every configured profile,
      keeping only those that authenticate (a live SSO token or valid
      keys). Deterministic: profiles are scanned in sorted order and the
      default chain ranks first when valid.
    Expired env vars / stale ~/.aws/credentials that merely *exist* but
    don't authenticate are skipped — so a fresh `aws sso login` is picked
    up with no SignalSift config at all.
    """
    import boto3

    if settings.aws_profile:
        return settings.aws_profile, [settings.aws_profile]

    working: list[str | None] = []
    base = boto3.Session(region_name=settings.aws_region)
    if _credentials_present(base) and _probe_session(base) == "valid":
        working.append(None)
    for profile in sorted(base.available_profiles)[:_MAX_PROFILE_SCAN]:
        candidate = boto3.Session(profile_name=profile, region_name=settings.aws_region)
        if _credentials_present(candidate) and _probe_session(candidate) == "valid":
            working.append(profile)

    chosen = working[0] if working else None
    if chosen is not None:
        logger.info("Auto-selected authenticated AWS profile %r", chosen)
    return chosen, working


def create_boto3_session(settings: Settings) -> Any:
    """boto3 session using the profile whose credentials are actually live.

    Survives the classic corporate trap where expired env vars or stale
    static keys in ~/.aws/credentials shadow a freshly logged-in SSO
    profile. Probing costs one STS call per candidate, once per process.
    """
    import boto3

    if settings.aws_profile:
        return boto3.Session(
            profile_name=settings.aws_profile, region_name=settings.aws_region
        )
    chosen, _ = _resolve_working(settings)
    return boto3.Session(profile_name=chosen, region_name=settings.aws_region)


async def resolve_active_profile(settings: Settings) -> tuple[str | None, list[str | None]]:
    """Async wrapper around profile resolution (for the CLI/health)."""
    return await asyncio.to_thread(_resolve_working, settings)


def create_boto3_logs_client(settings: Settings) -> Any:
    from botocore.config import Config

    from signalsift import __version__

    # Tag our traffic in CloudTrail/user-agent, per awslabs convention.
    config = Config(user_agent_extra=f"md/signalsift#{__version__}")
    return create_boto3_session(settings).client("logs", config=config)


class CloudWatchLogsClient:
    def __init__(self, settings: Settings, client: LogsInsightsClient | None = None) -> None:
        self._settings = settings
        self._client = client

    def _get_client(self) -> LogsInsightsClient:
        if self._client is None:
            self._client = create_boto3_logs_client(self._settings)
        return self._client

    async def run_query(self, planned: PlannedQuery) -> QueryResult:
        return convert_results(await self._execute(planned))

    async def run_stats_query(self, planned: PlannedQuery) -> list[dict[str, str]]:
        """Run an aggregation query; returns raw field->value rows."""
        response = await self._execute(planned)
        return [
            {item["field"]: item["value"] for item in row if "field" in item}
            for row in response.get("results", [])
        ]

    async def list_log_groups(self, max_groups: int = 500) -> list[dict[str, Any]]:
        """All log groups in the account/region (paginated, read-only)."""

        def _describe() -> list[dict[str, Any]]:
            client = self._get_client()
            groups: list[dict[str, Any]] = []
            kwargs: dict[str, Any] = {"limit": 50}
            while len(groups) < max_groups:
                try:
                    response = client.describe_log_groups(**kwargs)
                except NoCredentialsError as exc:
                    raise AwsAuthError(
                        "No AWS credentials found.",
                        hint="Run `aws sso login --profile <profile>` or configure credentials.",
                    ) from exc
                except ClientError as exc:
                    raise self._translate_client_error(exc) from exc
                groups.extend(response.get("logGroups", []))
                token = response.get("nextToken")
                if not token:
                    break
                kwargs["nextToken"] = token
            return groups[:max_groups]

        return await asyncio.to_thread(_describe)

    async def _execute(self, planned: PlannedQuery) -> dict[str, Any]:
        query_id = await asyncio.to_thread(self._start_query, planned)
        try:
            return await self._poll_results(query_id)
        except (asyncio.CancelledError, CloudWatchTimeoutError):
            await asyncio.to_thread(self._stop_query_quietly, query_id)
            raise

    def _start_query(self, planned: PlannedQuery) -> str:
        client = self._get_client()
        try:
            response = client.start_query(
                logGroupName=planned.log_group,
                startTime=int(planned.start_time.timestamp()),
                endTime=int(planned.end_time.timestamp()),
                queryString=planned.query_string,
                limit=planned.limit,
            )
        except NoCredentialsError as exc:
            raise AwsAuthError(
                "No AWS credentials found.",
                hint="Run `aws sso login --profile <profile>` or configure credentials.",
            ) from exc
        except ClientError as exc:
            raise self._translate_client_error(exc) from exc
        except BotoCoreError as exc:
            raise CloudWatchQueryError(f"AWS request failed: {exc}") from exc
        return response["queryId"]

    async def _poll_results(self, query_id: str) -> dict[str, Any]:
        delay = self._settings.query_poll_initial_seconds
        deadline = asyncio.get_running_loop().time() + self._settings.query_timeout_seconds
        while True:
            try:
                response = await asyncio.to_thread(
                    self._get_client().get_query_results, queryId=query_id
                )
            except ClientError as exc:
                raise self._translate_client_error(exc) from exc

            status = response.get("status", "Unknown")
            if status == "Complete":
                return response
            if status in ("Failed", "Cancelled", "Timeout"):
                raise CloudWatchQueryError(
                    f"CloudWatch Logs Insights query ended with status '{status}'."
                )
            if asyncio.get_running_loop().time() >= deadline:
                raise CloudWatchTimeoutError(
                    f"CloudWatch query did not complete within "
                    f"{self._settings.query_timeout_seconds}s.",
                    hint="Narrow the time range or reduce the result limit.",
                )
            await asyncio.sleep(delay)
            delay = min(delay * 2, self._settings.query_poll_max_seconds)

    def _stop_query_quietly(self, query_id: str) -> None:
        try:
            self._get_client().stop_query(queryId=query_id)
        except Exception:  # noqa: BLE001 - best effort cleanup
            logger.debug("Failed to stop CloudWatch query %s", query_id, exc_info=True)

    @staticmethod
    def _translate_client_error(exc: ClientError) -> Exception:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in (
            "ExpiredToken",
            "ExpiredTokenException",
            "UnrecognizedClientException",
            "InvalidClientTokenId",
            "AccessDeniedException",
            "UnauthorizedException",
        ):
            return AwsAuthError(
                f"AWS authentication/authorization failed ({code}).",
                hint="Refresh credentials, e.g. `aws sso login --profile <profile>`. "
                "If you HAVE just logged in, stale AWS_* env vars or old static "
                "keys in ~/.aws/credentials may be shadowing the SSO profile — "
                "unset/remove them, or set SIGNALSIFT_AWS_PROFILE explicitly. "
                "Also confirm the IAM policy grants CloudWatch Logs read access.",
            )
        if code in ("ThrottlingException", "Throttling", "LimitExceededException"):
            return CloudWatchThrottledError(
                "CloudWatch throttled the request.",
                hint="Wait a moment and retry; avoid running many queries in parallel.",
            )
        return CloudWatchQueryError(f"CloudWatch query failed ({code}): {exc}")


def convert_results(response: dict[str, Any]) -> QueryResult:
    """Convert a Complete GetQueryResults response into typed models."""
    raw_stats = response.get("statistics", {}) or {}
    stats = QueryStats(
        records_matched=raw_stats.get("recordsMatched", 0.0),
        records_scanned=raw_stats.get("recordsScanned", 0.0),
        bytes_scanned=raw_stats.get("bytesScanned", 0.0),
    )
    events: list[LogEvent] = []
    for row in response.get("results", []):
        fields = {item["field"]: item["value"] for item in row if "field" in item}
        event = _row_to_event(fields)
        if event is not None:
            events.append(event)
    truncated = stats.records_matched > len(events) > 0
    return QueryResult(events=events, stats=stats, truncated=truncated)


def _row_to_event(fields: dict[str, str]) -> LogEvent | None:
    raw_ts = fields.get("@timestamp")
    message = fields.get("@message", "")
    if not raw_ts:
        return None
    try:
        timestamp = parse_cloudwatch_timestamp(raw_ts)
    except ValueError:
        return None

    parsed: dict[str, Any] = {}
    stripped = message.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            loaded = json.loads(stripped)
            if isinstance(loaded, dict):
                parsed = loaded
        except (json.JSONDecodeError, ValueError):
            parsed = {}

    def first(keys: tuple[str, ...]) -> str | None:
        for key in keys:
            value = parsed.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    return LogEvent(
        timestamp=timestamp,
        message=message,
        log_stream=fields.get("@logStream"),
        level=(first(_LEVEL_KEYS) or "").upper() or None,
        request_id=first(_REQUEST_ID_KEYS),
        trace_id=first(_TRACE_ID_KEYS),
        service=first(_SERVICE_KEYS),
        parsed_fields=parsed,
    )

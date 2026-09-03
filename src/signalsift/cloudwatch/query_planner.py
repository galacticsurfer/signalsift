"""Typed query requests and the planner that turns them into safe queries.

The planner is the only component allowed to produce Logs Insights query
strings. It enforces the security policy (allowlist, time bounds, limit
clamp) before a query ever reaches AWS.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from signalsift.cloudwatch.query_templates import build_error_search_query, build_trace_query
from signalsift.config import Settings
from signalsift.security.policy import SecurityPolicy


class ErrorSearchRequest(BaseModel):
    log_group: str
    start_time: datetime
    end_time: datetime
    service: str | None = None
    level: str | None = "ERROR"
    exception_type: str | None = None
    status_code: int | None = None
    request_id: str | None = None
    text: str | None = None
    # None = use the configured maximum (SIGNALSIFT_MAX_QUERY_RESULTS);
    # explicit values are still clamped to that maximum.
    limit: int | None = Field(default=None, ge=1)


class TraceRequest(BaseModel):
    log_group: str
    request_id: str
    start_time: datetime
    end_time: datetime
    limit: int | None = Field(default=None, ge=1)


class PlannedQuery(BaseModel):
    log_group: str
    query_string: str
    start_time: datetime
    end_time: datetime
    limit: int


class QueryPlanner:
    def __init__(self, settings: Settings, policy: SecurityPolicy | None = None) -> None:
        self._settings = settings
        self._policy = policy or SecurityPolicy(settings)

    def plan_error_search(self, request: ErrorSearchRequest) -> PlannedQuery:
        self._policy.check_log_group(request.log_group)
        self._policy.check_time_range(request.start_time, request.end_time)
        limit = self._policy.clamp_limit(request.limit)
        query = build_error_search_query(
            level=request.level,
            service=request.service,
            exception_type=request.exception_type,
            status_code=request.status_code,
            request_id=request.request_id,
            text=request.text,
            limit=limit,
        )
        return PlannedQuery(
            log_group=request.log_group,
            query_string=query,
            start_time=request.start_time,
            end_time=request.end_time,
            limit=limit,
        )

    def plan_trace(self, request: TraceRequest) -> PlannedQuery:
        self._policy.check_log_group(request.log_group)
        self._policy.check_time_range(request.start_time, request.end_time)
        limit = self._policy.clamp_limit(request.limit)
        query = build_trace_query(request_id=request.request_id, limit=limit)
        return PlannedQuery(
            log_group=request.log_group,
            query_string=query,
            start_time=request.start_time,
            end_time=request.end_time,
            limit=limit,
        )

"""Application container: builds and wires all components once.

Both the CLI and the MCP server construct a `SignalSiftApp`, so there is
exactly one composition root and zero duplicated logic.
"""

from __future__ import annotations

import logging

from signalsift.analysis.service import IncidentService
from signalsift.cache.sqlite import SqliteCache
from signalsift.cloudwatch.client import CloudWatchLogsClient
from signalsift.config import Settings, load_settings
from signalsift.llm.ollama import OllamaProvider
from signalsift.observability.metrics import Telemetry


class SignalSiftApp:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or load_settings()
        logging.basicConfig(
            level=self.settings.log_level.upper(),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        self.cloudwatch = CloudWatchLogsClient(self.settings)
        self.llm = OllamaProvider(self.settings)
        try:
            self.cache: SqliteCache | None = SqliteCache(
                self.settings.cache_path, self.settings.cache_ttl_seconds
            )
        except Exception:  # noqa: BLE001 - cache is optional, never fatal
            logging.getLogger(__name__).warning(
                "Could not open cache at %s; continuing without cache",
                self.settings.cache_path,
            )
            self.cache = None
        self.telemetry = Telemetry(self.cache)
        self.service = IncidentService(
            settings=self.settings,
            cloudwatch=self.cloudwatch,
            llm=self.llm,
            cache=self.cache,
            telemetry=self.telemetry,
        )

"""Ollama provider for local inference.

Uses /api/chat with `format` set to the Pydantic JSON schema so Ollama
constrains generation to valid JSON. Output is validated with Pydantic;
one repair retry is attempted on malformed output before failing.
"""

from __future__ import annotations

import json
import logging

import httpx
from pydantic import BaseModel, ValidationError

from signalsift.config import Settings
from signalsift.errors import (
    LLMModelMissingError,
    LLMOutputError,
    LLMTimeoutError,
    LLMUnavailableError,
)
from signalsift.llm.base import ModelT

logger = logging.getLogger(__name__)


class OllamaProvider:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._base_url = settings.ollama_url.rstrip("/")
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(settings.llm_timeout_seconds, connect=5.0)
        )

    @property
    def model_name(self) -> str:
        return self._settings.llm_model

    async def is_available(self) -> bool:
        try:
            response = await self._client.get(f"{self._base_url}/api/version")
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def model_available(self) -> bool:
        try:
            response = await self._client.get(f"{self._base_url}/api/tags")
            response.raise_for_status()
        except httpx.HTTPError:
            return False
        models = {m.get("name", "") for m in response.json().get("models", [])}
        # Ollama lists "name:tag"; accept exact or name-only match.
        wanted = self.model_name
        return wanted in models or any(m.split(":")[0] == wanted for m in models)

    async def analyze(self, prompt: str, schema: type[ModelT]) -> ModelT:
        raw = await self._chat(prompt, schema)
        try:
            return schema.model_validate_json(raw)
        except ValidationError as exc:
            logger.warning("LLM output failed validation, retrying once: %s", exc)
            repair_prompt = (
                f"{prompt}\n\nYour previous response was not valid according to the "
                f"required JSON schema. Errors: {exc.errors()[:5]}. "
                "Respond again with ONLY valid JSON matching the schema."
            )
            raw = await self._chat(repair_prompt, schema)
            try:
                return schema.model_validate_json(raw)
            except ValidationError as exc2:
                raise LLMOutputError(
                    "Local model returned JSON that does not match the required schema.",
                    hint="Try a larger model via SIGNALSIFT_LLM_MODEL.",
                ) from exc2

    async def _chat(self, prompt: str, schema: type[BaseModel]) -> str:
        payload = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "format": schema.model_json_schema(),
            "options": {"temperature": 0.1},
        }
        if not self._settings.llm_thinking:
            # Suppress hidden chain-of-thought on thinking models (qwen3
            # etc.) — it multiplies latency for marginal gain here.
            payload["think"] = False
        try:
            response = await self._client.post(f"{self._base_url}/api/chat", json=payload)
            if (
                response.status_code == 400
                and "think" in payload
                and "think" in response.text.lower()
            ):
                # Model rejects the think option entirely; retry without it.
                del payload["think"]
                response = await self._client.post(f"{self._base_url}/api/chat", json=payload)
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError(
                f"Local model timed out after {self._settings.llm_timeout_seconds}s.",
                hint="Increase SIGNALSIFT_LLM_TIMEOUT_SECONDS or use a smaller model.",
            ) from exc
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(
                f"Cannot reach Ollama at {self._base_url}.",
                hint="Start Ollama (`ollama serve`) or fix SIGNALSIFT_OLLAMA_URL.",
            ) from exc

        if response.status_code == 404:
            raise LLMModelMissingError(
                f"Local model {self.model_name} is not available in Ollama.",
                hint=f"Run: ollama pull {self.model_name}",
            )
        if response.status_code >= 400:
            detail = ""
            try:
                detail = response.json().get("error", "")
            except (json.JSONDecodeError, ValueError):
                detail = response.text[:200]
            if "not found" in detail.lower():
                raise LLMModelMissingError(
                    f"Local model {self.model_name} is not available in Ollama.",
                    hint=f"Run: ollama pull {self.model_name}",
                )
            raise LLMUnavailableError(f"Ollama returned HTTP {response.status_code}: {detail}")

        content = response.json().get("message", {}).get("content", "")
        if not content:
            raise LLMOutputError("Local model returned an empty response.")
        return content[: self._settings.max_llm_output_chars]

    async def aclose(self) -> None:
        await self._client.aclose()

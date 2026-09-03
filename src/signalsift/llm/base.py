"""Local LLM provider abstraction.

Ollama is the initial implementation; MLX / llama.cpp / vLLM providers
can be added by implementing this protocol. The provider receives text
and returns a validated Pydantic model — it has no tools, no filesystem,
no network access beyond its own inference endpoint, and no credentials.
"""

from __future__ import annotations

from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

ModelT = TypeVar("ModelT", bound=BaseModel)


@runtime_checkable
class LocalLLMProvider(Protocol):
    async def analyze(self, prompt: str, schema: type[ModelT]) -> ModelT:
        """Run inference and return output validated against `schema`."""
        ...

    async def is_available(self) -> bool:
        """True if the inference runtime is reachable."""
        ...

    async def model_available(self) -> bool:
        """True if the configured model is loaded/pullable locally."""
        ...

    @property
    def model_name(self) -> str: ...

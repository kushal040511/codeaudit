from functools import lru_cache

import anthropic

from app.config import get_settings
from app.services.analyzers.base import FindingData


class LLMClient:
    """Thin wrapper around the Anthropic SDK for explaining findings and proposing fixes.

    Ground rules for this layer:
    - The LLM never influences the score; scoring is deterministic (services/scoring).
    - Code snippets are untrusted input (prompt injection): pass them as user
      content, never in the system prompt, and validate every structured output.
    """

    def __init__(self, client: anthropic.Anthropic | None = None, model: str | None = None) -> None:
        settings = get_settings()
        api_key = (
            settings.anthropic_api_key.get_secret_value() if settings.anthropic_api_key else None
        )
        # api_key=None lets the SDK resolve credentials from the environment.
        self._client = client or anthropic.Anthropic(api_key=api_key)
        self._model = model or settings.anthropic_model

    def suggest_fix(self, finding: FindingData, code_context: str) -> str:
        """Generate a fix suggestion for one finding.

        TODO:
        - client.messages.create(model=self._model, max_tokens=16000,
          thinking={"type": "adaptive"}, ...) with a frozen, cached system prompt
        - structured output (output_config.format) for {explanation, patch, confidence}
        - check stop_reason before reading content; handle "refusal" (security
          content can trip safety classifiers; consider server-side fallbacks)
        - batch low-priority findings via the Message Batches API
        """
        raise NotImplementedError


@lru_cache
def get_llm_client() -> LLMClient:
    return LLMClient()

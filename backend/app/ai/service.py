from datetime import datetime, timezone

from app import db
from app.ai.llm import AnthropicProvider, OpenAIProvider, ProviderError
from app.ai.mock import MockProvider
from app.config import get_settings
from app.models.schemas import AIAnalysis, Finding


def get_provider():
    """Return (provider, note). The note explains a fallback to the built-in explanations."""
    s = get_settings()
    name = s.ai_provider.strip().lower()
    if name in ("", "mock"):
        return MockProvider(), None
    if name not in ("anthropic", "openai"):
        return MockProvider(), f"AI_PROVIDER '{s.ai_provider}' is not supported, so the built-in explanation is shown."
    if not s.ai_api_key:
        return MockProvider(), f"AI_PROVIDER is '{name}' but AI_API_KEY is empty, so the built-in explanation is shown."
    cls = AnthropicProvider if name == "anthropic" else OpenAIProvider
    return cls(s.ai_api_key, s.ai_model, s.ai_base_url, s.ai_timeout_seconds), None


def explain_finding(finding: Finding, refresh: bool = False) -> AIAnalysis:
    if not refresh:
        cached = db.get_analysis(finding.id)
        if cached:
            return cached

    provider, note = get_provider()
    try:
        content = provider.explain(finding)
    except ProviderError as exc:
        provider, note = MockProvider(), f"The AI provider failed ({exc}), so the built-in explanation is shown."
        content = provider.explain(finding)

    analysis = AIAnalysis(
        **content.model_dump(), finding_id=finding.id, provider=provider.name,
        model=provider.model, created_at=datetime.now(timezone.utc), note=note,
    )
    db.save_analysis(analysis)
    return analysis

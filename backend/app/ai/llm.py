"""Real LLM providers over plain HTTPS (standard library only, no extra packages)."""
import json
import re
import urllib.error
import urllib.request

from app.ai.prompt import SYSTEM_PROMPT, build_user_prompt
from app.models.schemas import ExplanationContent, Finding


class ProviderError(Exception):
    """The provider failed. The message must never contain the API key."""


def _post_json(url: str, headers: dict, payload: dict, timeout: int) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        hint = {401: " (check AI_API_KEY)", 403: " (check AI_API_KEY and access)", 404: " (check AI_MODEL and AI_BASE_URL)", 429: " (rate limit reached)"}.get(exc.code, "")
        raise ProviderError(f"HTTP {exc.code} from the AI provider{hint}")
    except json.JSONDecodeError:
        raise ProviderError("the AI provider returned a response that is not JSON")
    except (urllib.error.URLError, OSError) as exc:  # includes timeouts
        raise ProviderError(f"could not reach the AI provider ({type(exc).__name__})")


def parse_explanation(text: str) -> ExplanationContent:
    """Accept the model's JSON, even if it is wrapped in code fences or extra text."""
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.IGNORECASE)
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ProviderError("the AI answer did not contain JSON")
    try:
        data = json.loads(cleaned[start : end + 1])
        steps = data.get("how_to_fix", [])
        if isinstance(steps, str):
            steps = [steps]
        example = data.get("secure_example") or None
        return ExplanationContent(
            problem=str(data["problem"]), why_dangerous=str(data["why_dangerous"]),
            location=str(data["location"]), impact=str(data["impact"]),
            how_to_fix=[str(s) for s in steps], secure_example=str(example) if example else None,
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ProviderError("the AI answer was not in the expected format")


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, base_url: str, timeout: int) -> None:
        self.api_key = api_key
        self.model = model or "claude-haiku-4-5-20251001"
        self.base_url = (base_url or "https://api.anthropic.com").rstrip("/")
        self.timeout = timeout

    def explain(self, f: Finding) -> ExplanationContent:
        data = _post_json(
            f"{self.base_url}/v1/messages",
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
            {
                "model": self.model, "max_tokens": 1000, "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": build_user_prompt(f)}],
            },
            self.timeout,
        )
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        return parse_explanation(text)


class OpenAIProvider:
    """OpenAI and any OpenAI-compatible API (set AI_BASE_URL), for example Gemini, Groq, or Ollama."""

    name = "openai"

    def __init__(self, api_key: str, model: str, base_url: str, timeout: int) -> None:
        self.api_key = api_key
        self.model = model or "gpt-4o-mini"
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.timeout = timeout

    def explain(self, f: Finding) -> ExplanationContent:
        data = _post_json(
            f"{self.base_url}/chat/completions",
            {"Authorization": f"Bearer {self.api_key}"},
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_prompt(f)},
                ],
            },
            self.timeout,
        )
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            raise ProviderError("the AI provider response had no message")
        return parse_explanation(text)

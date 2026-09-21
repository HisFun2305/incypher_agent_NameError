import os
import base64
import mimetypes
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Sequence, TypeVar

from openai import APIConnectionError, APIStatusError, OpenAI
import tools.config  # Loads .env before the client reads its settings.
from tools.send_logs import send_logs as print

# Initialized lazily so preflight can report missing settings cleanly.
client: OpenAI | None = None
openrouter_client: OpenAI | None = None

DEFAULT_MAX_ATTEMPTS = 3
_RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
_Result = TypeVar("_Result")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_MODEL = "anthropic/claude-sonnet-4"


class LLMResponseError(RuntimeError):
    """The gateway returned a successful but unusable completion payload."""


class OpenRouterUnavailableError(RuntimeError):
    """OpenRouter is not configured or could not serve this completion."""


def _get_client() -> OpenAI:
    """Return the shared configured SOCLAas client."""
    global client
    if client is None:
        api_key = os.getenv("SOCLAAS_API_KEY")
        base_url = os.getenv("SOCLAAS_BASE_URL")
        if not api_key or not base_url:
            raise ValueError("SOCLAAS_API_KEY and SOCLAAS_BASE_URL must be set")
        client = OpenAI(api_key=api_key, base_url=base_url)
    return client


def _get_openrouter_client() -> OpenAI:
    """Return the OpenRouter-compatible client when its API key is configured."""
    global openrouter_client
    if openrouter_client is None:
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise OpenRouterUnavailableError("OPENROUTER_API_KEY is not set")
        headers = {"X-OpenRouter-Title": "InCypher Agent"}
        referer = os.getenv("OPENROUTER_HTTP_REFERER")
        if referer:
            headers["HTTP-Referer"] = referer
        openrouter_client = OpenAI(
            api_key=api_key,
            base_url=os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL),
            default_headers=headers,
        )
    return openrouter_client


def _call_with_retry(
    operation: Callable[[], _Result],
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> _Result:
    """Run an OpenAI operation with bounded exponential-backoff retries."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    for attempt in range(1, max_attempts + 1):
        try:
            return operation()
        except APIStatusError as exc:
            if exc.status_code not in _RETRYABLE_STATUS_CODES or attempt == max_attempts:
                raise
        except APIConnectionError:
            if attempt == max_attempts:
                raise
        except LLMResponseError:
            if attempt == max_attempts:
                raise

        delay = min(2 ** (attempt - 1), 8)
        print(
            f"[llm] transient gateway failure; retrying in {delay}s "
            f"({attempt}/{max_attempts})"
        )
        time.sleep(delay)

    raise RuntimeError("LLM retry loop ended unexpectedly")


def _completion_content(response: Any) -> str:
    """Validate one chat completion before a solver uses its text."""
    choices = getattr(response, "choices", None)
    if not isinstance(choices, list) or not choices:
        raise LLMResponseError("LLM response did not contain a completion choice")
    message = getattr(choices[0], "message", None)
    content = getattr(message, "content", None)
    if not isinstance(content, str) or not content.strip():
        raise LLMResponseError("LLM completion content was empty or invalid")
    return content.strip()


def _complete(
    client_instance: OpenAI,
    *,
    model: str,
    prompt: str,
    extra_params: dict[str, Any],
) -> str:
    response = client_instance.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        **extra_params,
    )
    return _completion_content(response)


def call_openai(
    prompt: str,
    require_deep_reasoning: bool = False,
    *,
    chal_ID: int | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    response_format: dict[str, Any] | None = None,
) -> str:
    """Use OpenRouter first, falling back to SOCLAAS when it is unavailable."""
    model_name = "coding" if require_deep_reasoning else "default"
    extra_params: dict[str, Any] = {}
    if not require_deep_reasoning:
        extra_params["temperature"] = 0.0
    if response_format is not None:
        extra_params["response_format"] = response_format

    def complete(parameters: dict[str, Any]) -> str:
        try:
            return call_openrouter(
                prompt,
                chal_ID=chal_ID,
                max_attempts=max_attempts,
                extra_params=parameters,
            )
        except (OpenRouterUnavailableError, APIConnectionError, APIStatusError, LLMResponseError) as error:
            print(f"[llm] OpenRouter unavailable; falling back to SOCLAAS: {error}")
        return call_soclaas(
            prompt,
            model_name=model_name,
            chal_ID=chal_ID,
            max_attempts=max_attempts,
            extra_params=parameters,
        )

    try:
        return complete(extra_params)
    except APIStatusError as error:
        if response_format is None or error.status_code != 400:
            raise
        print("[llm] gateway does not support structured output; falling back to prompted JSON")
        fallback_params = dict(extra_params)
        fallback_params.pop("response_format", None)
        return complete(fallback_params)


def call_openrouter(
    prompt: str,
    *,
    chal_ID: int | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    extra_params: dict[str, Any] | None = None,
) -> str:
    """Call Claude Sonnet 4 through OpenRouter without SOCLAAS fallback."""
    return _call_with_retry(
        lambda: _complete(
            _get_openrouter_client(),
            model=OPENROUTER_MODEL,
            prompt=prompt,
            extra_params=extra_params or {},
        ),
        max_attempts=max_attempts,
    )


def call_soclaas(
    prompt: str,
    *,
    model_name: str = "default",
    chal_ID: int | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    extra_params: dict[str, Any] | None = None,
) -> str:
    """Call SOCLAAS directly as the OpenRouter fallback."""
    return _call_with_retry(
        lambda: _complete(
            _get_client(),
            model=model_name,
            prompt=prompt,
            extra_params=extra_params or {},
        ),
        max_attempts=max_attempts,
    )


def list_openai_models(
    *, max_attempts: int = DEFAULT_MAX_ATTEMPTS
) -> list[str]:
    """Return model IDs from the configured SOCLAas gateway."""
    response = _call_with_retry(
        lambda: _get_client().models.list(), max_attempts=max_attempts
    )
    return [model.id for model in response.data]


def _image_data_url(image_path: str | Path) -> str:
    """Return a supported local image as a base64 data URL."""
    path = Path(image_path)
    if not path.is_file():
        raise FileNotFoundError(f"Image file does not exist: {path}")

    mime_type, _ = mimetypes.guess_type(path.name)
    allowed_types = {"image/jpeg", "image/png", "image/gif", "image/webp"}
    if mime_type not in allowed_types:
        raise ValueError(
            "Unsupported image type. Use JPEG, PNG, GIF, or WebP images."
        )

    encoded_image = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime_type};base64,{encoded_image}"


def call_multimodal_openai(
    prompt: str,
    image_paths: Sequence[str | Path],
    model_name: str = "qwen3-vl:32b",
    *,
    chal_ID: int | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> str:
    """Send text and local images to a SOCLaas vision-capable chat model.

    SOCLaas exposes ``qwen3-vl:32b`` as a vision-capable model. The gateway
    must support OpenAI-style ``image_url`` message parts for this helper to
    work; images are encoded locally and are never written to the repository.
    """
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    if not image_paths:
        raise ValueError("image_paths must contain at least one image")

    content: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
    content.extend(
        {
            "type": "image_url",
            "image_url": {"url": _image_data_url(image_path)},
        }
        for image_path in image_paths
    )

    def complete_multimodal() -> str:
        response = _get_client().chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": content}], #type: ignore
                temperature=0.0,
            )
        return _completion_content(response)

    return _call_with_retry(complete_multimodal, max_attempts=max_attempts)

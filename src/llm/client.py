"""Lazy OpenAI-compatible inference with an environment-selected backend.

Set NOSANA_BASE_URL and NOSANA_API_KEY for Nosana, or leave NOSANA_BASE_URL
unset and supply OPENAI_API_KEY for OpenAI. NOSANA_MODEL pins the Nosana
model; OPENAI_MODEL may optionally pin the fallback model. Otherwise the
first model advertised by the active backend is discovered on first use.
Neither client creation nor model discovery happens at import time.
"""

from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache
from typing import Any, Iterable, cast

from openai import OpenAI, Stream
from openai.types.chat import ChatCompletionChunk, ChatCompletionMessageParam

__all__ = ["get_client", "chat", "complete", "extract_json"]

logger = logging.getLogger(__name__)


@lru_cache(maxsize=8)
def _client_for(base_url: str, api_key: str) -> OpenAI:
    # Explicit credentials keep the OpenAI fallback key out of Nosana requests.
    if base_url:
        return OpenAI(base_url=base_url, api_key=api_key)
    return OpenAI(api_key=api_key)


def get_client() -> OpenAI:
    """Return a cached client for the current environment, without network I/O.

    Clearing NOSANA_BASE_URL selects the standard OpenAI client. A configured
    Nosana backend is not silently bypassed on authentication or server errors.
    """
    base_url = os.getenv("NOSANA_BASE_URL", "").strip().rstrip("/")
    key_name = "NOSANA_API_KEY" if base_url else "OPENAI_API_KEY"
    api_key = os.getenv(key_name, "").strip()
    if not api_key:
        raise RuntimeError(f"{key_name} must be set for the selected LLM backend")

    client = _client_for(base_url, api_key)
    if base_url:
        logger.warning("LLM BACKEND ACTIVE: NOSANA (NOSANA_BASE_URL is set)")
    else:
        logger.warning(
            "LLM BACKEND ACTIVE: OPENAI FALLBACK (NOSANA_BASE_URL is unset)"
        )
    return client


@lru_cache(maxsize=16)
def _discover_model(client: OpenAI) -> str:
    # SDK list responses expose the first model through .data[0], not [0].
    models = client.models.list().data
    if not models or not models[0].id:
        raise RuntimeError(
            "The LLM backend advertised no models; set NOSANA_MODEL for Nosana "
            "or OPENAI_MODEL for OpenAI"
        )
    return models[0].id


def chat(
    messages: Iterable[ChatCompletionMessageParam], **kw: Any
) -> str | Stream[ChatCompletionChunk]:
    """Return assistant text, forwarding chat-completion options to the SDK.

    An explicit ``model=`` overrides the environment and skips discovery.
    ``stream=True`` returns the SDK stream instead of collecting its text.
    """
    client = get_client()
    model_env = (
        "NOSANA_MODEL"
        if os.getenv("NOSANA_BASE_URL", "").strip()
        else "OPENAI_MODEL"
    )
    model = kw.pop("model", None) or os.getenv(model_env, "").strip()
    if not model:
        model = _discover_model(client)

    # Qwen 3.5 is a hybrid reasoning model: with a small token budget it spends
    # everything in the hidden 'reasoning' channel and returns empty content.
    # Default a generous budget so the visible answer survives.
    kw.setdefault("max_tokens", 1024)

    response = client.chat.completions.create(model=model, messages=messages, **kw)
    if kw.get("stream"):
        return response
    if not response.choices:
        raise RuntimeError("The LLM backend returned no completion choices")
    message = response.choices[0].message
    content = (message.content or "").strip()
    if not content:
        # Fall back to the reasoning channel some Ollama/Qwen builds populate.
        content = (getattr(message, "reasoning", None) or "").strip()
    return content


def complete(prompt: str) -> str:
    """Return assistant text for a single user prompt."""
    return cast(str, chat([{"role": "user", "content": prompt}]))


def _extract_object(text: str) -> str | None:
    """Return the last balanced {...} block, so a reasoning preamble is ignored."""
    depth = start = 0
    start = -1
    best = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start >= 0:
                best = text[start:i + 1]
    return best


def _parse_json(content: str) -> Any:
    content = content.strip().lstrip("\ufeff").strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", content, re.I | re.S)
    if fenced:
        content = fenced.group(1).strip()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Hybrid reasoning models emit prose then JSON; pull the object out.
        obj = _extract_object(content)
        if obj is None:
            raise
        return json.loads(obj)


def _json_chat(messages: list[ChatCompletionMessageParam]) -> str:
    """Ask for JSON deterministically; drop response_format if unsupported."""
    kw: dict[str, Any] = {"temperature": 0, "max_tokens": 2600,
                          "response_format": {"type": "json_object"}}
    try:
        return cast(str, chat(messages, **kw))
    except Exception:
        kw.pop("response_format", None)
        return cast(str, chat(messages, **kw))


def extract_json(prompt: str, schema_hint: Any) -> Any:
    """Request JSON, strip optional Markdown fences, and retry parsing once.

    ``schema_hint`` can be descriptive text or a JSON-serializable shape/schema.
    It guides the model; this function parses JSON but does not validate a schema.
    Transport/API errors propagate without triggering a JSON correction request.
    """
    hint = (
        schema_hint
        if isinstance(schema_hint, str)
        else json.dumps(schema_hint, ensure_ascii=False)
    )
    messages: list[ChatCompletionMessageParam] = [
        {
            "role": "system",
            "content": (
                "/no_think\n"
                "Respond with ONLY a single JSON object and nothing else: no "
                "thinking out loud, no explanation, no Markdown fences, no "
                "trailing commas. The first character of your reply must be '{'.\n"
                f"It must match this schema or shape:\n{hint}"
            ),
        },
        {"role": "user", "content": prompt},
    ]
    for attempt in range(2):
        content = _json_chat(messages)
        try:
            return _parse_json(content)
        except json.JSONDecodeError as exc:
            if attempt == 1:
                raise ValueError("LLM returned invalid JSON after two attempts") from exc
            logger.warning("LLM returned invalid JSON; requesting one correction")
            messages = [
                *messages,
                {"role": "assistant", "content": content},
                {
                    "role": "user",
                    "content": (
                        f"JSON parsing failed: {exc.msg} at line {exc.lineno}, "
                        f"column {exc.colno}. Correct the response and return only "
                        "valid JSON matching the original schema hint."
                    ),
                },
            ]

    raise AssertionError("Unreachable JSON retry state")

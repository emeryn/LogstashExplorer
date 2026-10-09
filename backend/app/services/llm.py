"""LLM providers: local Ollama and OpenAI (or any OpenAI-compatible endpoint)."""

import json
from dataclasses import dataclass, field

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import tls_context
from app.services.settings_store import get_secret_setting, get_setting


class LLMError(RuntimeError):
    pass


@dataclass
class LLMConfig:
    provider: str
    base_url: str
    model: str
    temperature: float = 0.1
    timeout_s: int = 180
    api_key: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)


async def load_llm_config(db: AsyncSession) -> LLMConfig:
    cfg = await get_setting(db, "ai")
    extra = await get_secret_setting(db, "ai_extra_headers")
    return LLMConfig(
        provider=cfg["provider"],
        base_url=cfg["base_url"].rstrip("/"),
        model=cfg["model"],
        temperature=float(cfg["temperature"]),
        timeout_s=int(cfg["timeout_s"]),
        api_key=await get_secret_setting(db, "ai_api_key"),
        extra_headers=json.loads(extra) if extra else {},
    )


async def chat(cfg: LLMConfig, messages: list[dict[str, str]]) -> str:
    headers = {"Content-Type": "application/json", **cfg.extra_headers}
    verify = tls_context() if cfg.base_url.startswith("https://") else True
    try:
        async with httpx.AsyncClient(timeout=cfg.timeout_s, verify=verify) as client:
            if cfg.provider == "ollama":
                resp = await client.post(
                    f"{cfg.base_url}/api/chat",
                    headers=headers,
                    json={
                        "model": cfg.model,
                        "messages": messages,
                        "stream": False,
                        "options": {"temperature": cfg.temperature},
                    },
                )
                resp.raise_for_status()
                return resp.json()["message"]["content"]
            if cfg.provider == "openai":
                if cfg.api_key:
                    headers["Authorization"] = f"Bearer {cfg.api_key}"
                base = cfg.base_url if cfg.base_url.endswith("/v1") else f"{cfg.base_url}/v1"
                resp = await client.post(
                    f"{base}/chat/completions",
                    headers=headers,
                    json={"model": cfg.model, "messages": messages, "temperature": cfg.temperature},
                )
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]
    except httpx.HTTPStatusError as exc:
        raise LLMError(f"LLM endpoint returned HTTP {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise LLMError(f"LLM endpoint unreachable: {exc.__class__.__name__}") from exc
    except (KeyError, IndexError, ValueError) as exc:
        raise LLMError("Unexpected LLM response format") from exc
    raise LLMError(f"Unknown provider '{cfg.provider}'")


# ---- Model discovery ---------------------------------------------------------------------------
# OpenAI's /v1/models also lists embedding, audio, image and moderation models: hide them.
NON_CHAT = (
    "embedding", "tts", "whisper", "dall-e", "moderation", "davinci", "babbage", "audio", "realtime",
    "transcribe", "image", "search", "computer-use",
)  # fmt: skip


def _human_size(n: int | None) -> str | None:
    if not n:
        return None
    return f"{n / 1e9:.1f} Go" if n >= 1e9 else f"{n / 1e6:.0f} Mo"


def parse_ollama_tags(payload: dict) -> list[dict]:
    models = []
    for m in payload.get("models", []):
        name = m.get("name") or m.get("model")
        if not name:
            continue
        details = m.get("details") or {}
        info = [
            x
            for x in (details.get("parameter_size"), details.get("quantization_level"), _human_size(m.get("size")))
            if x
        ]
        models.append({"id": name, "label": f"{name} ({', '.join(info)})" if info else name})
    return sorted(models, key=lambda x: x["id"])


def parse_openai_models(payload: dict) -> list[dict]:
    ids = {m["id"] for m in payload.get("data", []) if isinstance(m, dict) and m.get("id")}
    chat = sorted(i for i in ids if not any(word in i.lower() for word in NON_CHAT))
    return [{"id": i, "label": i} for i in chat]


async def list_models(cfg: LLMConfig) -> list[dict]:
    """Query the configured endpoint for the models it serves."""
    headers = {**cfg.extra_headers}
    verify = tls_context() if cfg.base_url.startswith("https://") else True
    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            if cfg.provider == "ollama":
                resp = await client.get(f"{cfg.base_url}/api/tags", headers=headers)
                resp.raise_for_status()
                return parse_ollama_tags(resp.json())
            if cfg.provider == "openai":
                if cfg.api_key:
                    headers["Authorization"] = f"Bearer {cfg.api_key}"
                base = cfg.base_url if cfg.base_url.endswith("/v1") else f"{cfg.base_url}/v1"
                resp = await client.get(f"{base}/models", headers=headers)
                resp.raise_for_status()
                return parse_openai_models(resp.json())
    except httpx.HTTPStatusError as exc:
        hint = " (invalid API key?)" if exc.response.status_code in (401, 403) else ""
        raise LLMError(f"The server answered HTTP {exc.response.status_code}{hint}") from exc
    except httpx.HTTPError as exc:
        raise LLMError(f"Serveur injoignable : {exc.__class__.__name__}") from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise LLMError("Unexpected response: this is not an Ollama / OpenAI API") from exc
    raise LLMError(f"Fournisseur inconnu '{cfg.provider}'")

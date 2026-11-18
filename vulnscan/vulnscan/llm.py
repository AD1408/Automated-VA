"""Provider-agnostic LLM client: Ollama (local, free), Anthropic Claude, or any OpenAI-compatible API.

Switch provider with LLM_PROVIDER / LLM_MODEL in .env - no code changes.
"""
from __future__ import annotations

import json
import re

import httpx

from .config import Settings, get_settings

DEFAULT_MODELS = {
    "ollama": "gpt-oss:20b",
    "anthropic": "claude-sonnet-5-5",
    "openai_compat": "gemini-2.5-flash",
}


class LLMError(Exception):
    pass


class LLM:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()
        self.provider = (self.s.llm_provider or "none").lower()
        self.model = self.s.llm_model or DEFAULT_MODELS.get(self.provider, "")

    @property
    def enabled(self) -> bool:
        if self.provider == "ollama":
            return True
        if self.provider == "anthropic":
            return bool(self.s.anthropic_api_key)
        if self.provider == "openai_compat":
            return bool(self.s.openai_compat_base_url)
        return False

    def status(self) -> dict:
        info = {"provider": self.provider, "model": self.model, "enabled": self.enabled, "ready": False}
        if not self.enabled:
            return info
        try:
            if self.provider == "ollama":
                tags = httpx.get(f"{self.s.ollama_url}/api/tags", timeout=5).json()
                names = [m.get("name") for m in tags.get("models", [])]
                info["ready"] = any(n == self.model or n.split(":")[0] == self.model for n in names)
                info["installed_models"] = names
                if not info["ready"]:
                    info["hint"] = f"run: docker compose exec ollama ollama pull {self.model}"
            else:
                info["ready"] = True
        except httpx.HTTPError as e:
            info["error"] = str(e)[:200]
        return info

    def complete(self, system: str, user: str, max_tokens: int = 1500, temperature: float = 0.1,
                 timeout: float = 600) -> str:
        if not self.enabled:
            raise LLMError("No LLM configured (set LLM_PROVIDER in .env)")
        try:
            if self.provider == "ollama":
                body = {"model": self.model, "stream": False,
                        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                        "options": {"temperature": temperature, "num_predict": max_tokens, "num_ctx": 8192}}
                if self.model.startswith("gpt-oss"):
                    body["think"] = "low"
                r = httpx.post(f"{self.s.ollama_url}/api/chat", json=body, timeout=timeout)
                r.raise_for_status()
                return r.json()["message"]["content"]
            if self.provider == "anthropic":
                r = httpx.post("https://api.anthropic.com/v1/messages", timeout=timeout,
                               headers={"x-api-key": self.s.anthropic_api_key, "anthropic-version": "2023-06-01"},
                               json={"model": self.model, "max_tokens": max_tokens, "system": system,
                                     "temperature": temperature, "messages": [{"role": "user", "content": user}]})
                r.raise_for_status()
                return "".join(b.get("text", "") for b in r.json()["content"] if b.get("type") == "text")
            if self.provider == "openai_compat":
                r = httpx.post(self.s.openai_compat_base_url.rstrip("/") + "/chat/completions", timeout=timeout,
                               headers={"Authorization": f"Bearer {self.s.openai_compat_api_key}"},
                               json={"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                                     "messages": [{"role": "system", "content": system},
                                                  {"role": "user", "content": user}]})
                r.raise_for_status()
                return r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, ValueError) as e:
            raise LLMError(f"{self.provider} call failed: {e}") from e
        raise LLMError(f"Unknown LLM_PROVIDER {self.provider!r}")

    def complete_json(self, system: str, user: str, max_tokens: int = 1500):
        text = self.complete(system + "\nRespond with valid JSON only, no prose, no markdown fences.", user, max_tokens)
        return extract_json(text)


def extract_json(text: str):
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for open_c, close_c in (("{", "}"), ("[", "]")):
        start, end = text.find(open_c), text.rfind(close_c)
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                continue
    raise LLMError("LLM did not return valid JSON")

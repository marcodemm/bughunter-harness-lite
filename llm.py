"""OpenAI-compatible LLM client with backend auto-probe.

Supports LM Studio, Ollama, Llama.cpp local servers and cloud providers
(OpenAI, Anthropic-OAI-compat, Google Gemini, NVIDIA NIM). Function calling
required — the harness gives the model tools, not free-form text.

The `auto_probe()` helper does a single GET /v1/models against each of the
common local endpoints (in Ollama-first order for mobile-first target) and
returns the first that answers. Cloud providers require an explicit
`--servertype` in config because we don't want to leak DNS looking for them.
"""
from __future__ import annotations

import json
import os
from typing import Any

import requests

# Local backends probed in mobile-first order (Ollama is the default install
# for Termux+chroot targets). LM Studio second because it's the desktop
# default. Llama.cpp third for llama-server users.
LOCAL_BACKENDS = [
    ("ollama",   "http://127.0.0.1:11434/v1"),
    ("lmstudio", "http://127.0.0.1:1234/v1"),
    ("llamacpp", "http://127.0.0.1:8080/v1"),
]

# Cloud backends need explicit config.servertype (never auto-probed).
CLOUD_BACKENDS = {
    "openai":    ("https://api.openai.com/v1",                                  "OPENAI_API_KEY"),
    "anthropic": ("https://api.anthropic.com/v1",                               "ANTHROPIC_API_KEY"),
    "gemini":    ("https://generativelanguage.googleapis.com/v1beta/openai",    "GEMINI_API_KEY"),
    "nvidia":    ("https://integrate.api.nvidia.com/v1",                        "NVIDIA_API_KEY"),
}


def auto_probe(timeout_sec: float = 1.5) -> tuple[str, str] | None:
    """Return (servertype, base_url) of the first local backend that answers,
    or None if nothing local is up. Cloud backends are never probed."""
    for name, url in LOCAL_BACKENDS:
        try:
            r = requests.get(url + "/models", timeout=timeout_sec)
            if r.status_code < 500:
                return name, url
        except Exception:
            continue
    return None


def resolve_backend(cfg: dict) -> tuple[str, str, str]:
    """Return (servertype, base_url, api_key). CLI/env override config."""
    stype = (cfg.get("llm") or {}).get("servertype", "") or "auto"
    base_url = (cfg.get("llm") or {}).get("base_url", "") or ""
    api_key = (cfg.get("llm") or {}).get("api_key", "") or ""
    api_key_env = (cfg.get("llm") or {}).get("api_key_env", "") or ""

    if api_key_env and not api_key:
        api_key = os.environ.get(api_key_env, "") or ""

    if stype == "auto":
        probed = auto_probe()
        if probed is None:
            raise RuntimeError(
                "No local LLM backend detected on 127.0.0.1 "
                "(Ollama:11434, LM Studio:1234, Llama.cpp:8080). "
                "Start one, or set llm.servertype explicitly in config."
            )
        stype, base_url = probed
        api_key = api_key or "local"

    if stype in CLOUD_BACKENDS:
        default_url, env_key = CLOUD_BACKENDS[stype]
        base_url = base_url or default_url
        api_key = api_key or os.environ.get(env_key, "")
        if not api_key:
            raise RuntimeError(
                f"Cloud backend '{stype}' requires an API key "
                f"(env {env_key} or config.llm.api_key)."
            )

    if not base_url:
        raise RuntimeError(
            f"Backend '{stype}' has no base_url. "
            f"Set llm.base_url in config."
        )

    # Local placeholders don't care about the key value but require SOMETHING
    # (LM Studio + Ollama both accept 'local' or anything non-empty).
    api_key = api_key or "local"
    return stype, base_url, api_key


class LLMClient:
    """Thin OpenAI-compatible chat client with tool calling."""

    def __init__(self, servertype: str, base_url: str, api_key: str,
                 model: str, timeout_sec: int = 300):
        self.servertype = servertype
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_sec = timeout_sec

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             temperature: float = 0.1, max_tokens: int = 1024) -> dict:
        """Return the raw first `choices[0].message` dict from the server."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}/chat/completions"
        r = requests.post(url, headers=headers, json=payload,
                          timeout=self.timeout_sec)
        if r.status_code != 200:
            raise RuntimeError(
                f"LLM backend HTTP {r.status_code}: {r.text[:400]}"
            )
        data = r.json()
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as e:
            raise RuntimeError(
                f"LLM response malformed: {type(e).__name__} — "
                f"{json.dumps(data)[:400]}"
            )

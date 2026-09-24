"""Optional LLM layer (Anthropic Messages API over plain HTTPS; no SDK dependency).

The LLM gets GraphRAG context (graph evidence claims, retrieved policy/typology passages, similar past cases), not raw
rows, and writes the analyst summary, the SAR narrative and undocumented-pattern descriptions. It never chooses
actions: those come from policy.py. Without ANTHROPIC_API_KEY the agent uses deterministic templates.
"""
from __future__ import annotations

import json

import httpx

from .config import ANTHROPIC_API_KEY, LLM_ENABLED, LLM_MODEL

SYSTEM = ("You are a senior card-fraud investigator at a bank. Write precise, factual text grounded ONLY in the "
          "evidence provided. Never invent IDs, amounts, dates or facts. Cite policy rules as R1..R10 when relevant. "
          "Respond with JSON only.")


class LLM:
    def __init__(self):
        self.enabled = LLM_ENABLED
        self._client = httpx.Client(timeout=60) if self.enabled else None

    def complete_json(self, prompt: str, max_tokens: int = 900) -> tuple[dict | None, int]:
        """Returns (parsed JSON or None, tokens used). Failures degrade to templates instead of failing the case."""
        if not self.enabled:
            return None, 0
        try:
            r = self._client.post("https://api.anthropic.com/v1/messages",
                                  headers={"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01",
                                           "content-type": "application/json"},
                                  json={"model": LLM_MODEL, "max_tokens": max_tokens, "system": SYSTEM,
                                        "messages": [{"role": "user", "content": prompt}]})
            r.raise_for_status()
            body = r.json()
            used = body.get("usage", {})
            tokens = int(used.get("input_tokens", 0)) + int(used.get("output_tokens", 0))
            text = "".join(b.get("text", "") for b in body.get("content", []) if b.get("type") == "text").strip()
            text = text[text.find("{"): text.rfind("}") + 1]
            return json.loads(text), tokens
        except Exception:  # network, quota, malformed JSON: fall back to templates
            return None, 0

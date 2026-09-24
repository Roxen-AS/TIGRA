"""Process-wide singletons (store, knowledge base, memory, agent) built once and shared by API, CLI and MCP."""
from __future__ import annotations

import json
from functools import lru_cache

from . import config
from .agent import Tigra
from .kb import KnowledgeBase
from .llm import LLM
from .memory import CaseMemory
from .tools import make_store


@lru_cache(maxsize=1)
def runtime():
    store = make_store()
    kb = KnowledgeBase(store.closed_case_features())
    memory = CaseMemory(store)
    return store, kb, memory, Tigra(store, kb, memory, LLM())


def save_case(ans: dict, trace: list[dict]) -> None:
    """Answer file (cases/<id>.json, the submission format) + replayable event trace (cases/trace/<id>.json)."""
    cid = ans["case_id"]
    (config.CASES_DIR / "trace").mkdir(parents=True, exist_ok=True)
    (config.CASES_DIR / f"{cid}.json").write_text(json.dumps(ans, indent=2), encoding="utf-8")
    (config.CASES_DIR / "trace" / f"{cid}.json").write_text(
        json.dumps([e for e in trace if e["type"] != "done"], default=str), encoding="utf-8")

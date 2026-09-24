"""Tool bus: the agent's only door to data. Every graph/retrieval call goes through `call`, which
counts it (answer field `tool_calls`), times it, and streams a trace event to the UI.

Backends:
  local      - DuckDB mirror (default, offline)
  tigergraph - installed GSQL queries on TigerGraph Savanna / Community Edition (pyTigerGraph REST)
  mcp        - the same installed queries invoked through the official TigerGraph MCP server (tigergraph-mcp)
"""
from __future__ import annotations

import time
from typing import Any, Callable

from . import config

# Tool catalogue shown to the LLM / MCP clients (name -> description).
CATALOG = {
    "get_alert": "Load an alert from the case pack (trigger, flagged transaction, card, customer).",
    "get_transaction": "Transaction vertex with its device profile, identity flags and match flags.",
    "card_profile": "Behavioural baseline of a card before a timestamp: amounts, products, regions, emails, devices.",
    "card_window": "Card -> MADE -> Transaction in a time window (ordered).",
    "device_seen_on_card": "Has this device profile been used on this card before?",
    "device_neighbors": "DeviceProfile <- FROM_DEVICE <- Transaction <- MADE <- Card: other cards on the same device in a window, plus closed cases touching it.",
    "region_history": "Card history in one BillingRegion.",
    "email_seen_on_card": "Has this purchaser email domain been used on this card before?",
    "amount_recurrence": "Earlier same-product, same-amount charges on the card (recurring-charge check, R7).",
    "customer_cards": "Customer -> OWNS -> Card.",
    "prior_cases": "Closed cases and agent-written FraudCase vertices for the customer (case memory).",
    "similar_cases": "Vector + graph-proximity retrieval of similar past cases (case memory).",
    "kb_search": "GraphRAG document retrieval over the fraud policy, typologies, regulatory guidance and case narratives.",
    "write_case": "Upsert the FraudCase vertex and its edges (case memory for later investigations).",
}


def make_store():
    if config.GRAPH_BACKEND in ("tigergraph", "mcp"):
        from .store_tg import TigerGraphStore
        return TigerGraphStore(via_mcp=config.GRAPH_BACKEND == "mcp")
    from .store_local import LocalGraphStore
    return LocalGraphStore()


class ToolBus:
    def __init__(self, store, kb, memory, emit: Callable[[dict], None] | None = None):
        self.store, self.kb, self.memory = store, kb, memory
        self.emit = emit or (lambda e: None)
        self.calls = 0
        self.trace: list[dict] = []

    def call(self, name: str, summarize: Callable[[Any], str] | None = None, **kwargs) -> Any:
        t0 = time.perf_counter()
        if name == "kb_search":  # TigerGraph vectorSearch when available, in-process index otherwise
            out = self.store.kb_search(**kwargs) if hasattr(self.store, "kb_search") else self.kb.search(**kwargs)
        elif name == "similar_cases":
            out = self.memory.similar(**kwargs)
        else:
            out = getattr(self.store, name)(**kwargs)
        ms = (time.perf_counter() - t0) * 1000
        self.calls += 1
        shown = {k: v for k, v in kwargs.items() if k not in ("vec", "rec")}
        ev = {"type": "tool", "name": name, "args": {k: (sorted(v) if isinstance(v, set) else v) for k, v in shown.items()},
              "ms": round(ms, 1), "summary": summarize(out) if summarize else ""}
        self.trace.append(ev)
        self.emit(ev)
        return out

"""TIGRA MCP server exposing the fraud-investigation tools to any MCP client (Claude Desktop, Claude Code, IDEs).

  python -m tigra.mcp_server            (stdio)

Graph primitives come from the official TigerGraph MCP server (tigergraph-mcp) when GRAPH_BACKEND=mcp; this server
adds the investigation layer on top: behavioural baselines, device-ring traversal, case memory, GraphRAG and the
full policy-bound investigation.
"""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from .runtime import runtime

mcp = FastMCP("tigra")


def _rt():
    return runtime()


@mcp.tool()
def list_alerts() -> str:
    """List the 20 benchmark alerts (case pack) with trigger type and flagged transaction."""
    store, *_ = _rt()
    return json.dumps(store.list_alerts())


@mcp.tool()
def investigate_case(case_id: str) -> str:
    """Run the full investigation for a case-pack alert and return the answer file (case, SAR, next best actions)."""
    *_, agent = _rt()
    return json.dumps(agent.investigate(case_id=case_id))


@mcp.tool()
def card_profile(card_id: str, before_ts: str) -> str:
    """Behavioural baseline of a card before a timestamp (amounts, products, regions, emails, devices)."""
    store, *_ = _rt()
    return json.dumps(store.card_profile(card_id, before_ts), default=str)


@mcp.tool()
def card_window(card_id: str, start_ts: str, end_ts: str) -> str:
    """Transactions on a card within a time window."""
    store, *_ = _rt()
    return json.dumps(store.card_window(card_id, start_ts, end_ts), default=str)


@mcp.tool()
def device_neighbors(device_id: str, center_ts: str, days: int = 14) -> str:
    """Other cards that used the same device profile around a time, plus closed cases on that device."""
    store, *_ = _rt()
    return json.dumps(store.device_neighbors(device_id, center_ts, days), default=str)


@mcp.tool()
def prior_cases(customer_id: str, before_ts: str) -> str:
    """Closed cases and agent-written cases for a customer (case memory)."""
    store, *_ = _rt()
    return json.dumps(store.prior_cases(customer_id, before_ts), default=str)


@mcp.tool()
def kb_search(query: str, k: int = 4) -> str:
    """GraphRAG document retrieval over the fraud policy, typologies, regulatory guidance and case narratives."""
    _, kb, *_ = _rt()
    return json.dumps(kb.search(query, k))


if __name__ == "__main__":
    mcp.run()
